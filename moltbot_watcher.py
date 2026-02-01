#!/usr/bin/env python3
"""
Moltbot Watcher - Monitor Moltbot conversations and send alerts via Telegram
"""

import asyncio
import logging
import os
import subprocess
import sys
from datetime import datetime
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
    """Load and manage configuration."""

    def __init__(self, config_path: Optional[str] = None):
        if config_path is None:
            config_path = os.path.expanduser(
                "~/.config/moltbot-watcher/config.yaml"
            )

        with open(config_path) as f:
            self.data = yaml.safe_load(f)

        self.bot_token = self.data["telegram"]["bot_token"]
        self.chat_id = str(self.data["telegram"]["chat_id"])
        self.watch_paths = self.data.get("watch", {}).get("paths", [])
        self.alert_level = self.data.get("watch", {}).get(
            "alert_level", "new_sender"
        )
        self.commands = self.data.get("commands", {})
        self.alerts = self.data.get("alerts", {})


class SessionWatcher(FileSystemEventHandler):
    """Watch for new session files and messages."""

    def __init__(self, config: Config, bot_app: Application):
        self.config = config
        self.bot_app = bot_app
        self.known_senders = set()
        self.watched_files = {}
        self._initialize_file_positions()

    def _initialize_file_positions(self):
        """Set file positions to EOF for existing files to avoid replaying history."""
        import glob
        for path_pattern in self.config.watch_paths:
            expanded = os.path.expanduser(path_pattern)
            for filepath in glob.glob(expanded):
                if os.path.isfile(filepath):
                    size = os.path.getsize(filepath)
                    self.watched_files[filepath] = size
                    logger.info(f"Initialized {filepath} at position {size}")

    def on_created(self, event):
        """Handle new file creation."""
        if event.is_directory:
            return

        if event.src_path.endswith(".jsonl"):
            logger.info(f"New session file: {event.src_path}")
            asyncio.run(self._process_new_file(event.src_path))

    def on_modified(self, event):
        """Handle file modifications."""
        if event.is_directory:
            return

        if event.src_path.endswith(".jsonl"):
            asyncio.run(self._process_modified_file(event.src_path))

    async def _process_new_file(self, filepath: str):
        """Process a newly created session file."""
        try:
            with open(filepath) as f:
                lines = f.readlines()
                if lines:
                    # Check first line for sender info
                    import json

                    first_msg = json.loads(lines[0])
                    sender = first_msg.get("sender", {})
                    sender_id = sender.get("id", "unknown")

                    if sender_id not in self.known_senders:
                        self.known_senders.add(sender_id)
                        await self._send_alert(
                            f"🆕 New sender: {sender.get('name', sender_id)}\n"
                            f"File: {Path(filepath).name}"
                        )
        except Exception as e:
            logger.error(f"Error processing new file: {e}")

    async def _process_modified_file(self, filepath: str):
        """Process changes to an existing session file."""
        last_pos = self.watched_files.get(filepath, 0)

        try:
            with open(filepath) as f:
                f.seek(last_pos)
                new_content = f.read()
                self.watched_files[filepath] = f.tell()

                if new_content.strip() and self.config.alert_level == "all":
                    import json

                    for line in new_content.strip().splitlines():
                        if line:
                            try:
                                msg = json.loads(line)
                                msg_data = msg.get("message", {})
                                role = msg_data.get("role", "unknown")
                                content_arr = msg_data.get("content", [])

                                # Extract text from content array
                                text = ""
                                if isinstance(content_arr, list):
                                    for item in content_arr:
                                        if isinstance(item, dict) and item.get("type") == "text":
                                            text = item.get("text", "")[:300]
                                            break
                                elif isinstance(content_arr, str):
                                    text = content_arr[:300]

                                # Only alert on user messages
                                if role == "user" and text:
                                    await self._send_alert(f"💬 {text}")
                            except json.JSONDecodeError:
                                pass
        except Exception as e:
            logger.error(f"Error processing modified file: {e}")

    async def _send_alert(self, message: str):
        """Send alert to admin via Telegram."""
        try:
            await self.bot_app.bot.send_message(
                chat_id=self.config.chat_id, text=message
            )
        except Exception as e:
            logger.error(f"Failed to send alert: {e}")


class WatcherBot:
    """Telegram bot for receiving commands and sending alerts."""

    def __init__(self, config: Config):
        self.config = config
        self.app = Application.builder().token(config.bot_token).build()
        self.watcher: Optional[SessionWatcher] = None
        self.observer: Optional[Observer] = None

        # Register command handlers
        self.app.add_handler(CommandHandler("start", self.cmd_start))
        self.app.add_handler(CommandHandler("status", self.cmd_status))
        self.app.add_handler(CommandHandler("kill", self.cmd_kill))
        self.app.add_handler(CommandHandler("restart", self.cmd_restart))
        self.app.add_handler(CommandHandler("logs", self.cmd_logs))
        self.app.add_handler(CommandHandler("help", self.cmd_help))

    async def cmd_start(
        self, update: Update, context: ContextTypes.DEFAULT_TYPE
    ):
        """Handle /start command."""
        if str(update.effective_chat.id) != self.config.chat_id:
            await update.message.reply_text("Unauthorized.")
            return

        await update.message.reply_text(
            "🤖 Moltbot Watcher active!\n\n"
            "Commands:\n"
            "/status - Check moltbot status\n"
            "/kill - Stop moltbot\n"
            "/restart - Restart moltbot\n"
            "/logs - View recent logs\n"
            "/help - Show this message"
        )

    async def cmd_help(
        self, update: Update, context: ContextTypes.DEFAULT_TYPE
    ):
        """Handle /help command."""
        await self.cmd_start(update, context)

    async def cmd_status(
        self, update: Update, context: ContextTypes.DEFAULT_TYPE
    ):
        """Handle /status command."""
        if str(update.effective_chat.id) != self.config.chat_id:
            return

        if not self.config.commands.get("status", {}).get("enabled", True):
            await update.message.reply_text("Status command disabled.")
            return

        try:
            result = subprocess.run(
                ["systemctl", "is-active", "moltbot"],
                capture_output=True,
                text=True,
            )
            status = result.stdout.strip()

            if status == "active":
                emoji = "✅"
            elif status == "inactive":
                emoji = "⏹️"
            else:
                emoji = "❌"

            await update.message.reply_text(f"{emoji} Moltbot status: {status}")
        except Exception as e:
            await update.message.reply_text(f"Error checking status: {e}")

    async def cmd_kill(
        self, update: Update, context: ContextTypes.DEFAULT_TYPE
    ):
        """Handle /kill command."""
        if str(update.effective_chat.id) != self.config.chat_id:
            return

        if not self.config.commands.get("kill", {}).get("enabled", True):
            await update.message.reply_text("Kill command disabled.")
            return

        service = self.config.commands.get("kill", {}).get(
            "service_name", "moltbot"
        )

        try:
            subprocess.run(["sudo", "systemctl", "stop", service], check=True)
            await update.message.reply_text(f"⏹️ Stopped {service}")
        except subprocess.CalledProcessError as e:
            await update.message.reply_text(f"Failed to stop: {e}")

    async def cmd_restart(
        self, update: Update, context: ContextTypes.DEFAULT_TYPE
    ):
        """Handle /restart command."""
        if str(update.effective_chat.id) != self.config.chat_id:
            return

        if not self.config.commands.get("restart", {}).get("enabled", True):
            await update.message.reply_text("Restart command disabled.")
            return

        service = self.config.commands.get("restart", {}).get(
            "service_name", "moltbot"
        )

        try:
            subprocess.run(
                ["sudo", "systemctl", "restart", service], check=True
            )
            await update.message.reply_text(f"🔄 Restarted {service}")
        except subprocess.CalledProcessError as e:
            await update.message.reply_text(f"Failed to restart: {e}")

    async def cmd_logs(
        self, update: Update, context: ContextTypes.DEFAULT_TYPE
    ):
        """Handle /logs command."""
        if str(update.effective_chat.id) != self.config.chat_id:
            return

        if not self.config.commands.get("logs", {}).get("enabled", True):
            await update.message.reply_text("Logs command disabled.")
            return

        lines = self.config.commands.get("logs", {}).get("lines", 20)

        try:
            result = subprocess.run(
                ["journalctl", "-u", "moltbot", "-n", str(lines), "--no-pager"],
                capture_output=True,
                text=True,
            )
            logs = result.stdout[-4000:]  # Telegram message limit
            await update.message.reply_text(f"📜 Recent logs:\n```\n{logs}\n```")
        except Exception as e:
            await update.message.reply_text(f"Failed to get logs: {e}")

    def start_file_watcher(self):
        """Start watching session files."""
        self.watcher = SessionWatcher(self.config, self.app)
        self.observer = Observer()

        for path_pattern in self.config.watch_paths:
            # Expand path and get directory
            expanded = os.path.expanduser(path_pattern)
            # Watch parent directory (glob patterns won't work directly)
            watch_dir = str(Path(expanded).parent.parent.parent)

            if os.path.exists(watch_dir):
                self.observer.schedule(
                    self.watcher, watch_dir, recursive=True
                )
                logger.info(f"Watching: {watch_dir}")
            else:
                logger.warning(f"Watch path does not exist: {watch_dir}")

        self.observer.start()

    def run(self):
        """Run the bot."""
        logger.info("Starting Moltbot Watcher...")

        # Start file watcher
        self.start_file_watcher()

        # Send startup message
        async def send_startup():
            await self.app.bot.send_message(
                chat_id=self.config.chat_id,
                text=f"🟢 Moltbot Watcher started at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            )

        asyncio.get_event_loop().run_until_complete(send_startup())

        # Run bot
        self.app.run_polling(allowed_updates=Update.ALL_TYPES)


def main():
    """Main entry point."""
    # Check for config file argument
    config_path = None
    if len(sys.argv) > 1:
        config_path = sys.argv[1]

    try:
        config = Config(config_path)
    except FileNotFoundError:
        logger.error(
            "Config file not found. Please create ~/.config/moltbot-watcher/config.yaml"
        )
        sys.exit(1)
    except Exception as e:
        logger.error(f"Failed to load config: {e}")
        sys.exit(1)

    # Validate config
    if "YOUR_" in config.bot_token or "YOUR_" in config.chat_id:
        logger.error("Please configure your Telegram bot token and chat ID")
        sys.exit(1)

    bot = WatcherBot(config)
    bot.run()


if __name__ == "__main__":
    main()
