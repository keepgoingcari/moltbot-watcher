#!/usr/bin/env python3
"""
Moltbot Security Watcher

Monitors Moltbot session transcripts and provides:
- Real-time Telegram alerts when new input is received
- Suspicious input flagging based on configurable patterns
- Remote kill switch via Telegram command
"""

import asyncio
import json
import logging
import os
import re
import subprocess
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

import yaml
from telegram import Update
from telegram.ext import Application, CommandHandler, ContextTypes
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

# Configure logging
logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO,
)
logger = logging.getLogger(__name__)


class Config:
    """Configuration manager for the watcher."""

    def __init__(self, config_path: str = None):
        if config_path is None:
            config_path = os.path.expanduser("~/.config/moltbot-watcher/config.yaml")

        with open(config_path) as f:
            self._config = yaml.safe_load(f)

        self.bot_token = self._config["telegram"]["bot_token"]
        self.chat_id = str(self._config["telegram"]["chat_id"])
        self.watch_paths = [
            os.path.expanduser(p) for p in self._config["watch"]["paths"]
        ]
        self.alert_level = self._config["watch"].get("alert_level", "new_sender")
        self.digest_interval = self._config["watch"].get("digest_interval_minutes", 15)
        self.suspicious_patterns = [
            re.compile(p, re.IGNORECASE)
            for p in self._config["patterns"].get("suspicious", [])
        ]
        self.blocked_senders = set(self._config["patterns"].get("blocked_senders", []))
        self.stop_command = self._config["moltbot"].get(
            "stop_command", "moltbot gateway stop"
        )
        self.start_command = self._config["moltbot"].get(
            "start_command", "moltbot gateway start"
        )
        self.pid_file = self._config["moltbot"].get(
            "pid_file", "/tmp/moltbot/gateway.pid"
        )


class MoltbotWatcher:
    """Main watcher class that coordinates file monitoring and Telegram bot."""

    def __init__(self, config: Config):
        self.config = config
        self.known_senders: set[str] = set()
        self.file_positions: dict[str, int] = {}
        self.muted_until: Optional[datetime] = None
        self.recent_inputs: list[dict] = []
        self.digest_queue: list[dict] = []
        self.app: Optional[Application] = None

    def is_muted(self) -> bool:
        """Check if alerts are currently muted."""
        if self.muted_until is None:
            return False
        if datetime.now() >= self.muted_until:
            self.muted_until = None
            return False
        return True

    def check_suspicious(self, message: str) -> list[str]:
        """Check message against suspicious patterns."""
        matches = []
        for pattern in self.config.suspicious_patterns:
            if pattern.search(message):
                matches.append(pattern.pattern)
        return matches

    def is_moltbot_running(self) -> bool:
        """Check if Moltbot gateway is running."""
        try:
            result = subprocess.run(
                ["pgrep", "-f", "moltbot"],
                capture_output=True,
                text=True,
            )
            return result.returncode == 0
        except Exception:
            return False

    def kill_moltbot(self) -> tuple[bool, str]:
        """Stop the Moltbot gateway."""
        try:
            # Try the configured stop command first
            result = subprocess.run(
                self.config.stop_command.split(),
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                return True, "Moltbot stopped via CLI"

            # Fallback to pkill
            result = subprocess.run(
                ["pkill", "-f", "moltbot"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                return True, "Moltbot stopped via pkill"

            return False, f"Failed to stop: {result.stderr}"
        except subprocess.TimeoutExpired:
            return False, "Stop command timed out"
        except Exception as e:
            return False, f"Error: {e}"

    def start_moltbot(self) -> tuple[bool, str]:
        """Start the Moltbot gateway."""
        try:
            result = subprocess.run(
                self.config.start_command.split(),
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                return True, "Moltbot started"
            return False, f"Failed to start: {result.stderr}"
        except subprocess.TimeoutExpired:
            return False, "Start command timed out"
        except Exception as e:
            return False, f"Error: {e}"

    async def send_alert(self, message: str):
        """Send an alert message via Telegram."""
        if self.is_muted():
            logger.info("Alert suppressed (muted)")
            return

        if self.app is None:
            logger.error("Telegram app not initialized")
            return

        try:
            await self.app.bot.send_message(
                chat_id=self.config.chat_id,
                text=message,
                parse_mode="HTML",
            )
        except Exception as e:
            logger.error(f"Failed to send alert: {e}")

    def format_alert(self, entry: dict, is_suspicious: bool, flags: list[str]) -> str:
        """Format an alert message for Telegram."""
        sender = entry.get("sender", "unknown")
        channel = entry.get("channel", "unknown")
        message = entry.get("message", "")[:500]  # Truncate long messages
        timestamp = entry.get("timestamp", datetime.now().isoformat())

        is_new_sender = sender not in self.known_senders

        if is_suspicious:
            header = "<b>SUSPICIOUS INPUT DETECTED</b>"
        else:
            header = "<b>MOLTBOT INPUT</b>"

        sender_label = f"{sender} (NEW)" if is_new_sender else sender

        alert = f"""{header}

<b>Channel:</b> {channel}
<b>Sender:</b> {sender_label}
<b>Time:</b> {timestamp}

<b>Message:</b>
<code>{message}</code>

<b>Flags:</b>"""

        if flags:
            for flag in flags:
                alert += f"\n  - {flag}"
        else:
            alert += " None"

        alert += "\n\nReply /kill to stop Moltbot"

        return alert

    def process_jsonl_entry(self, entry: dict) -> Optional[dict]:
        """Process a JSONL entry and determine if it should trigger an alert."""
        # Skip non-input entries
        if entry.get("type") != "input" and "message" not in entry:
            return None

        sender = entry.get("sender", "unknown")
        message = entry.get("message", "")

        # Check if sender is blocked
        if sender in self.config.blocked_senders:
            logger.info(f"Blocked sender: {sender}")
            return None

        # Check for suspicious patterns
        suspicious_matches = self.check_suspicious(message)
        is_suspicious = len(suspicious_matches) > 0
        is_new_sender = sender not in self.known_senders

        # Determine if we should alert based on alert level
        should_alert = False
        if self.config.alert_level == "all":
            should_alert = True
        elif self.config.alert_level == "new_sender":
            should_alert = is_new_sender or is_suspicious
        elif self.config.alert_level == "suspicious":
            should_alert = is_suspicious
        elif self.config.alert_level == "digest":
            # Queue for digest
            self.digest_queue.append(entry)
            return None

        if should_alert:
            flags = []
            if suspicious_matches:
                flags.extend([f'Pattern: "{p}"' for p in suspicious_matches])
            if is_new_sender:
                flags.append("Unknown sender")

            # Track sender
            self.known_senders.add(sender)

            # Track recent inputs
            self.recent_inputs.append(entry)
            if len(self.recent_inputs) > 10:
                self.recent_inputs.pop(0)

            return {
                "entry": entry,
                "is_suspicious": is_suspicious,
                "flags": flags,
            }

        # Track sender even if no alert
        self.known_senders.add(sender)
        return None

    async def handle_file_change(self, file_path: str):
        """Handle a change to a watched JSONL file."""
        try:
            # Get current position
            current_pos = self.file_positions.get(file_path, 0)

            with open(file_path) as f:
                # Seek to last known position
                f.seek(current_pos)

                # Read new lines
                for line in f:
                    line = line.strip()
                    if not line:
                        continue

                    try:
                        entry = json.loads(line)
                        result = self.process_jsonl_entry(entry)
                        if result:
                            alert_msg = self.format_alert(
                                result["entry"],
                                result["is_suspicious"],
                                result["flags"],
                            )
                            await self.send_alert(alert_msg)
                    except json.JSONDecodeError:
                        logger.warning(f"Invalid JSON in {file_path}: {line[:50]}")

                # Update position
                self.file_positions[file_path] = f.tell()

        except Exception as e:
            logger.error(f"Error processing {file_path}: {e}")


class FileChangeHandler(FileSystemEventHandler):
    """Handles file system events from watchdog."""

    def __init__(self, watcher: MoltbotWatcher, loop: asyncio.AbstractEventLoop):
        self.watcher = watcher
        self.loop = loop

    def on_modified(self, event):
        if event.is_directory:
            return
        if event.src_path.endswith(".jsonl"):
            asyncio.run_coroutine_threadsafe(
                self.watcher.handle_file_change(event.src_path),
                self.loop,
            )

    def on_created(self, event):
        if event.is_directory:
            return
        if event.src_path.endswith(".jsonl"):
            # Initialize position for new file
            self.watcher.file_positions[event.src_path] = 0
            asyncio.run_coroutine_threadsafe(
                self.watcher.handle_file_change(event.src_path),
                self.loop,
            )


def is_authorized(update: Update, config: Config) -> bool:
    """Check if the message is from an authorized user."""
    return str(update.effective_chat.id) == config.chat_id


async def cmd_status(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /status command."""
    watcher: MoltbotWatcher = context.bot_data["watcher"]

    if not is_authorized(update, watcher.config):
        await update.message.reply_text("Unauthorized")
        return

    running = watcher.is_moltbot_running()
    status = "running" if running else "stopped"
    muted = "Yes" if watcher.is_muted() else "No"
    known = len(watcher.known_senders)

    await update.message.reply_text(
        f"<b>Moltbot Watcher Status</b>\n\n"
        f"Moltbot: {status}\n"
        f"Alerts muted: {muted}\n"
        f"Known senders: {known}\n"
        f"Alert level: {watcher.config.alert_level}",
        parse_mode="HTML",
    )


async def cmd_kill(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /kill command."""
    watcher: MoltbotWatcher = context.bot_data["watcher"]

    if not is_authorized(update, watcher.config):
        await update.message.reply_text("Unauthorized")
        return

    success, message = watcher.kill_moltbot()
    if success:
        await update.message.reply_text(f"Moltbot stopped: {message}")
    else:
        await update.message.reply_text(f"Failed to stop Moltbot: {message}")


async def cmd_start_moltbot(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /start_moltbot command."""
    watcher: MoltbotWatcher = context.bot_data["watcher"]

    if not is_authorized(update, watcher.config):
        await update.message.reply_text("Unauthorized")
        return

    success, message = watcher.start_moltbot()
    if success:
        await update.message.reply_text(f"Moltbot started: {message}")
    else:
        await update.message.reply_text(f"Failed to start Moltbot: {message}")


async def cmd_mute(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /mute command."""
    watcher: MoltbotWatcher = context.bot_data["watcher"]

    if not is_authorized(update, watcher.config):
        await update.message.reply_text("Unauthorized")
        return

    minutes = 30  # Default
    if context.args:
        try:
            minutes = int(context.args[0])
        except ValueError:
            await update.message.reply_text("Invalid minutes. Usage: /mute [minutes]")
            return

    watcher.muted_until = datetime.now() + timedelta(minutes=minutes)
    await update.message.reply_text(f"Alerts muted for {minutes} minutes")


async def cmd_unmute(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /unmute command."""
    watcher: MoltbotWatcher = context.bot_data["watcher"]

    if not is_authorized(update, watcher.config):
        await update.message.reply_text("Unauthorized")
        return

    watcher.muted_until = None
    await update.message.reply_text("Alerts unmuted")


async def cmd_recent(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /recent command."""
    watcher: MoltbotWatcher = context.bot_data["watcher"]

    if not is_authorized(update, watcher.config):
        await update.message.reply_text("Unauthorized")
        return

    if not watcher.recent_inputs:
        await update.message.reply_text("No recent inputs")
        return

    msg = "<b>Recent Inputs</b>\n\n"
    for i, entry in enumerate(watcher.recent_inputs[-5:], 1):
        sender = entry.get("sender", "unknown")
        message = entry.get("message", "")[:100]
        msg += f"{i}. <b>{sender}</b>: {message}\n\n"

    await update.message.reply_text(msg, parse_mode="HTML")


async def cmd_help(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /help command."""
    watcher: MoltbotWatcher = context.bot_data["watcher"]

    if not is_authorized(update, watcher.config):
        await update.message.reply_text("Unauthorized")
        return

    await update.message.reply_text(
        "<b>Moltbot Watcher Commands</b>\n\n"
        "/status - Check Moltbot status\n"
        "/kill - Stop Moltbot gateway\n"
        "/start_moltbot - Start Moltbot gateway\n"
        "/mute [minutes] - Mute alerts\n"
        "/unmute - Unmute alerts\n"
        "/recent - Show recent inputs\n"
        "/help - Show this help",
        parse_mode="HTML",
    )


def get_watch_directories(watch_patterns: list[str]) -> list[str]:
    """Expand glob patterns to get directories to watch."""
    from glob import glob

    directories = set()
    for pattern in watch_patterns:
        # Get the base directory before any wildcards
        parts = pattern.split("*")[0].rstrip("/")
        if os.path.isdir(parts):
            directories.add(parts)
        else:
            # Try parent directory
            parent = os.path.dirname(parts)
            if os.path.isdir(parent):
                directories.add(parent)

        # Also add any currently matching directories
        for match in glob(pattern):
            if os.path.isfile(match):
                directories.add(os.path.dirname(match))
            elif os.path.isdir(match):
                directories.add(match)

    return list(directories)


async def main():
    """Main entry point."""
    # Load configuration
    config_path = os.environ.get(
        "MOLTBOT_WATCHER_CONFIG",
        os.path.expanduser("~/.config/moltbot-watcher/config.yaml"),
    )

    if not os.path.exists(config_path):
        logger.error(f"Config file not found: {config_path}")
        sys.exit(1)

    config = Config(config_path)

    # Validate config
    if config.bot_token == "YOUR_BOT_TOKEN":
        logger.error("Please configure your Telegram bot token in config.yaml")
        sys.exit(1)

    if config.chat_id == "YOUR_CHAT_ID":
        logger.error("Please configure your Telegram chat ID in config.yaml")
        sys.exit(1)

    # Create watcher
    watcher = MoltbotWatcher(config)

    # Create Telegram application
    app = Application.builder().token(config.bot_token).build()
    app.bot_data["watcher"] = watcher
    watcher.app = app

    # Add command handlers
    app.add_handler(CommandHandler("status", cmd_status))
    app.add_handler(CommandHandler("kill", cmd_kill))
    app.add_handler(CommandHandler("start_moltbot", cmd_start_moltbot))
    app.add_handler(CommandHandler("mute", cmd_mute))
    app.add_handler(CommandHandler("unmute", cmd_unmute))
    app.add_handler(CommandHandler("recent", cmd_recent))
    app.add_handler(CommandHandler("help", cmd_help))
    app.add_handler(CommandHandler("start", cmd_help))  # Telegram default

    # Set up file watching
    loop = asyncio.get_event_loop()
    event_handler = FileChangeHandler(watcher, loop)
    observer = Observer()

    watch_dirs = get_watch_directories(config.watch_paths)
    if not watch_dirs:
        logger.warning("No watch directories found, creating default")
        default_dir = os.path.expanduser("~/.moltbot/agents")
        os.makedirs(default_dir, exist_ok=True)
        watch_dirs = [default_dir]

    for directory in watch_dirs:
        logger.info(f"Watching directory: {directory}")
        observer.schedule(event_handler, directory, recursive=True)

    observer.start()

    # Send startup message
    try:
        await app.bot.send_message(
            chat_id=config.chat_id,
            text="<b>Moltbot Watcher Started</b>\n\nMonitoring for new inputs...",
            parse_mode="HTML",
        )
    except Exception as e:
        logger.error(f"Failed to send startup message: {e}")

    # Start polling
    logger.info("Starting Telegram bot polling...")
    try:
        await app.initialize()
        await app.start()
        await app.updater.start_polling(drop_pending_updates=True)

        # Keep running
        while True:
            await asyncio.sleep(1)

    except KeyboardInterrupt:
        logger.info("Shutting down...")
    finally:
        observer.stop()
        observer.join()
        await app.stop()
        await app.shutdown()


if __name__ == "__main__":
    asyncio.run(main())
