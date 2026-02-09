"""Terminal status line polling for thread-bound windows.

Provides background polling of terminal status lines for all active users:
  - Detects Claude Code status (working, waiting, etc.)
  - Detects interactive UIs (permission prompts) not triggered via JSONL
  - Detects Claude Code process exit and notifies user with restart button
  - Updates status messages in Telegram
  - Polls thread_bindings (each topic = one window)
  - Periodically probes topic existence via unpin_all_forum_topic_messages
    (silent no-op when no pins); cleans up deleted topics (kills tmux window
    + unbinds thread)

Key components:
  - STATUS_POLL_INTERVAL: Polling frequency (1 second)
  - TOPIC_CHECK_INTERVAL: Topic existence probe frequency (60 seconds)
  - status_poll_loop: Background polling task
  - update_status_message: Poll and enqueue status updates
  - set_expected_command / clear_expected_command: Track expected pane process
  - handle_restart_button: Restart CC when user clicks the inline button
"""

import asyncio
import logging
import shlex
import time

from telegram import Bot, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.error import BadRequest

from ..config import config
from ..session import session_manager
from ..terminal_parser import is_interactive_ui, parse_status_line
from ..tmux_manager import tmux_manager
from .callback_data import CB_RESTART
from .interactive_ui import (
    clear_interactive_msg,
    get_interactive_window,
    handle_interactive_ui,
)
from .cleanup import clear_topic_state
from .message_queue import enqueue_status_update, get_message_queue
from .message_sender import safe_send

logger = logging.getLogger(__name__)

# Status polling interval
STATUS_POLL_INTERVAL = 1.0  # seconds - faster response (rate limiting at send layer)

# Topic existence probe interval
TOPIC_CHECK_INTERVAL = 60.0  # seconds

# Module-level state for CC exit detection
_expected_commands: dict[str, str] = {}  # window_name → expected pane_current_command
_exit_notified: dict[str, str] = {}  # window_name → shell command at exit time


def _restart_command() -> str:
    """Return claude command with -c (continue) flag added for restart.

    Inspects config.claude_command; if it already contains -c or --continue,
    returns it unchanged.  Otherwise inserts -c after the program name.
    """
    parts = shlex.split(config.claude_command)
    for part in parts:
        if part in ("-c", "--continue"):
            return config.claude_command
        # Combined short flags like -cm
        if part.startswith("-") and not part.startswith("--") and "c" in part:
            return config.claude_command
    parts.append("-c")
    return shlex.join(parts)


def set_expected_command(window_name: str, command: str) -> None:
    """Record the expected pane command for a window (called after CC starts)."""
    _expected_commands[window_name] = command
    _exit_notified.pop(window_name, None)
    logger.debug("Set expected command for window '%s': %s", window_name, command)


def clear_expected_command(window_name: str) -> None:
    """Remove expected command tracking for a window (called on unbind/cleanup)."""
    _expected_commands.pop(window_name, None)
    _exit_notified.pop(window_name, None)


async def _notify_cc_exit(
    bot: Bot,
    user_id: int,
    thread_id: int,
    window_name: str,
    shell_cmd: str,
) -> None:
    """Send exit notification with restart button and command text."""
    _exit_notified[window_name] = shell_cmd
    chat_id = session_manager.resolve_chat_id(user_id, thread_id)
    cmd = _restart_command()
    keyboard = InlineKeyboardMarkup([[
        InlineKeyboardButton(
            "🔄 Restart",
            callback_data=f"{CB_RESTART}{window_name}"[:64],
        ),
    ]])
    await safe_send(
        bot, chat_id,
        f"⚠ Claude Code exited.\n\nRestart command:\n```shell\n{cmd}\n```\n"
        "Tap Restart or send a custom command.",
        message_thread_id=thread_id,
        reply_markup=keyboard,
    )
    logger.info("CC exit notification sent for window '%s' (shell=%s)", window_name, shell_cmd)


async def handle_restart_button(
    bot: Bot,
    window_name: str,
) -> bool:
    """Restart Claude Code via button click. Returns True if successful."""
    cmd = _restart_command()
    success = await tmux_manager.restart_claude_in_window(window_name, cmd)
    if not success:
        logger.warning("Failed to restart Claude in window '%s'", window_name)
        return False

    _exit_notified.pop(window_name, None)
    logger.info("Button-restart of Claude Code in window '%s' (cmd=%s)", window_name, cmd)

    # Wait for session_map entry and re-record expected command
    found = await session_manager.wait_for_session_map_entry(window_name)
    if found:
        w = await tmux_manager.find_window_by_name(window_name)
        if w and w.pane_current_command:
            _expected_commands[window_name] = w.pane_current_command

    return True


async def update_status_message(
    bot: Bot,
    user_id: int,
    window_name: str,
    thread_id: int | None = None,
) -> None:
    """Poll terminal and enqueue status update for user's active window.

    Also detects permission prompt UIs (not triggered via JSONL) and enters
    interactive mode when found.
    """
    w = await tmux_manager.find_window_by_name(window_name)
    if not w:
        # Window gone, enqueue clear
        await enqueue_status_update(bot, user_id, window_name, None, thread_id=thread_id)
        return

    pane_text = await tmux_manager.capture_pane(w.window_id)
    if not pane_text:
        # Transient capture failure - keep existing status message
        return

    interactive_window = get_interactive_window(user_id, thread_id)
    should_check_new_ui = True

    if interactive_window == window_name:
        # User is in interactive mode for THIS window
        if is_interactive_ui(pane_text):
            # Interactive UI still showing — skip status update (user is interacting)
            return
        # Interactive UI gone — clear interactive mode, fall through to status check.
        # Don't re-check for new UI this cycle (the old one just disappeared).
        await clear_interactive_msg(user_id, bot, thread_id)
        should_check_new_ui = False
    elif interactive_window is not None:
        # User is in interactive mode for a DIFFERENT window (window switched)
        # Clear stale interactive mode
        await clear_interactive_msg(user_id, bot, thread_id)

    # Check for permission prompt (interactive UI not triggered via JSONL)
    if should_check_new_ui and is_interactive_ui(pane_text):
        await handle_interactive_ui(bot, user_id, window_name, thread_id)
        return

    # Normal status line check
    status_line = parse_status_line(pane_text)

    if status_line:
        await enqueue_status_update(
            bot, user_id, window_name, status_line, thread_id=thread_id,
        )
    # If no status line, keep existing status message (don't clear on transient state)


async def status_poll_loop(bot: Bot) -> None:
    """Background task to poll terminal status for all thread-bound windows."""
    logger.info("Status polling started (interval: %ss)", STATUS_POLL_INTERVAL)
    last_topic_check = 0.0
    while True:
        try:
            # Periodic topic existence probe
            now = time.monotonic()
            if now - last_topic_check >= TOPIC_CHECK_INTERVAL:
                last_topic_check = now
                for user_id, thread_id, wname in list(
                    session_manager.iter_thread_bindings()
                ):
                    try:
                        await bot.unpin_all_forum_topic_messages(
                            chat_id=session_manager.resolve_chat_id(user_id, thread_id),
                            message_thread_id=thread_id,
                        )
                    except BadRequest as e:
                        if "Topic_id_invalid" in str(e):
                            # Topic deleted — kill window, unbind, and clean up state
                            w = await tmux_manager.find_window_by_name(wname)
                            if w:
                                await tmux_manager.kill_window(w.window_id)
                            session_manager.unbind_thread(user_id, thread_id)
                            await clear_topic_state(user_id, thread_id, bot)
                            logger.info(
                                "Topic deleted: killed window '%s' and "
                                "unbound thread %d for user %d",
                                wname,
                                thread_id,
                                user_id,
                            )
                        else:
                            logger.debug(
                                "Topic probe error for %s: %s", wname, e,
                            )
                    except Exception as e:
                        logger.debug(
                            "Topic probe error for %s: %s", wname, e,
                        )

            for user_id, thread_id, wname in list(
                session_manager.iter_thread_bindings()
            ):
                try:
                    # Clean up stale bindings (window no longer exists)
                    w = await tmux_manager.find_window_by_name(wname)
                    if not w:
                        clear_expected_command(wname)
                        session_manager.unbind_thread(user_id, thread_id)
                        await clear_topic_state(user_id, thread_id, bot)
                        logger.info(
                            f"Cleaned up stale binding: user={user_id} "
                            f"thread={thread_id} window={wname}"
                        )
                        continue

                    # Detect CC process exit / recovery
                    if wname in _expected_commands:
                        if w.pane_current_command != _expected_commands[wname]:
                            # CC has exited — notify once
                            if wname not in _exit_notified:
                                await _notify_cc_exit(
                                    bot, user_id, thread_id, wname,
                                    w.pane_current_command,
                                )
                            continue  # Skip status update while CC is down
                        elif wname in _exit_notified:
                            # CC is back (user manually restarted)
                            _exit_notified.pop(wname, None)
                            # Re-record in case process name changed
                            _expected_commands[wname] = w.pane_current_command
                            logger.info(
                                "CC recovered in window '%s' (cmd=%s)",
                                wname, w.pane_current_command,
                            )
                            chat_id = session_manager.resolve_chat_id(
                                user_id, thread_id,
                            )
                            await safe_send(
                                bot, chat_id,
                                f"✅ Claude Code restarted in *{wname}*.",
                                message_thread_id=thread_id,
                            )

                    queue = get_message_queue(user_id)
                    if queue and not queue.empty():
                        continue
                    await update_status_message(
                        bot, user_id, wname, thread_id=thread_id,
                    )
                except Exception as e:
                    logger.debug(
                        f"Status update error for user {user_id} "
                        f"thread {thread_id}: {e}"
                    )
        except Exception as e:
            logger.error(f"Status poll loop error: {e}")

        await asyncio.sleep(STATUS_POLL_INTERVAL)
