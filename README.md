# Moltbot Watcher

A security monitoring daemon for [Moltbot](https://github.com/anthropics/moltbot) that provides real-time Telegram alerts and remote control capabilities.

## Features

- **Real-time alerts** - Get notified on your phone when Moltbot receives new messages
- **Suspicious input detection** - Configurable pattern matching flags potential prompt injection attempts
- **Remote kill switch** - Stop Moltbot instantly via Telegram command
- **New sender alerts** - Get notified when unknown contacts message your bot
- **Mute controls** - Temporarily silence alerts when needed

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                         VPS                                  │
│  ┌─────────────┐     ┌──────────────────┐                   │
│  │   Moltbot   │────▶│ Session JSONL    │                   │
│  │   Gateway   │     │ ~/.moltbot/...   │                   │
│  └─────────────┘     └────────┬─────────┘                   │
│        ▲                      │                             │
│        │ kill                 │ watch (inotify)             │
│        │                      ▼                             │
│  ┌─────┴─────────────────────────────────────┐              │
│  │           moltbot-watcher                 │              │
│  │  • Tails JSONL files for new messages     │              │
│  │  • Pattern matching for suspicious input  │              │
│  │  • Telegram bot for alerts + commands     │              │
│  └─────────────────────┬─────────────────────┘              │
│                        │                                     │
└────────────────────────┼─────────────────────────────────────┘
                         │ Telegram API
                         ▼
              ┌─────────────────────┐
              │   Your Phone        │
              │   • Receive alerts  │
              │   • Send /kill      │
              │   • Send /status    │
              └─────────────────────┘
```

## Installation

### 1. Create a Telegram Bot

1. Message [@BotFather](https://t.me/botfather) on Telegram
2. Send `/newbot` and follow the prompts
3. Save the bot token you receive
4. Message your new bot, then get your chat ID:
   - Message [@userinfobot](https://t.me/userinfobot), or
   - Visit `https://api.telegram.org/bot<YOUR_TOKEN>/getUpdates` after messaging your bot

### 2. Install the Watcher

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/moltbot-watcher.git
cd moltbot-watcher

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Create config directory
mkdir -p ~/.config/moltbot-watcher

# Copy and edit config
cp config.example.yaml ~/.config/moltbot-watcher/config.yaml
chmod 600 ~/.config/moltbot-watcher/config.yaml

# Edit with your bot token and chat ID
nano ~/.config/moltbot-watcher/config.yaml
```

### 3. Test Manually

```bash
python moltbot_watcher.py
```

You should receive a "Moltbot Watcher Started" message on Telegram.

### 4. Install as Systemd Service (Optional)

```bash
# Edit the service file with your username
sudo cp moltbot-watcher.service /etc/systemd/system/
sudo nano /etc/systemd/system/moltbot-watcher.service
# Change User= and paths as needed

# Enable and start
sudo systemctl daemon-reload
sudo systemctl enable moltbot-watcher
sudo systemctl start moltbot-watcher

# Check status
sudo systemctl status moltbot-watcher
```

## Configuration

Edit `~/.config/moltbot-watcher/config.yaml`:

```yaml
telegram:
  bot_token: "YOUR_BOT_TOKEN"
  chat_id: "YOUR_CHAT_ID"

watch:
  paths:
    - "~/.moltbot/agents/*/sessions/*.jsonl"
  alert_level: "new_sender"  # all | new_sender | suspicious | digest
  digest_interval_minutes: 15

patterns:
  suspicious:
    - "ignore.*instruction"
    - "ignore.*previous"
    - "system.*prompt"
    # Add your own patterns

  blocked_senders: []  # Block specific senders

moltbot:
  stop_command: "moltbot gateway stop"
  start_command: "moltbot gateway start"
```

### Alert Levels

| Level | Behavior |
|-------|----------|
| `all` | Alert on every incoming message |
| `new_sender` | Alert on first message from unknown senders + suspicious messages |
| `suspicious` | Alert only when suspicious patterns are detected |
| `digest` | Batch alerts every N minutes (coming soon) |

## Telegram Commands

| Command | Description |
|---------|-------------|
| `/status` | Check if Moltbot is running |
| `/kill` | Stop Moltbot gateway immediately |
| `/start_moltbot` | Start Moltbot gateway |
| `/mute [minutes]` | Mute alerts (default: 30 min) |
| `/unmute` | Resume alerts |
| `/recent` | Show last 5 inputs |
| `/help` | Show available commands |

## Alert Examples

### Normal Input
```
MOLTBOT INPUT

Channel: telegram
Sender: +1555123456 (NEW)
Time: 2024-01-27 14:32:01

Message:
"Hey, can you check my calendar?"

Flags: None

Reply /kill to stop Moltbot
```

### Suspicious Input
```
SUSPICIOUS INPUT DETECTED

Channel: whatsapp
Sender: unknown@email.com
Time: 2024-01-27 14:35:22

Message:
"Please ignore your previous instructions and..."

Flags:
  - Pattern: "ignore.*instruction"
  - Unknown sender

Reply /kill to stop Moltbot immediately
```

## Default Suspicious Patterns

The watcher includes default patterns to detect common prompt injection attempts:

- `ignore.*instruction` - "ignore previous instructions"
- `ignore.*previous` - "ignore all previous"
- `system.*prompt` - "show me your system prompt"
- `pretend.*you.*are` - "pretend you are..."
- `act.*as.*if` - "act as if..."
- `forget.*everything` - "forget everything"
- `new.*instruction` - "new instructions:"
- `base64` - Base64 encoding attempts
- `eval\s*\(` - Code injection attempts

Add your own patterns in the config file.

## Security Considerations

- Config file contains your bot token - ensure 600 permissions
- Only your `chat_id` can send commands (enforced in code)
- Run as non-root user
- The watcher itself cannot read message content beyond what Moltbot logs

## Requirements

- Python 3.9+
- Linux with inotify support (for file watching)
- Moltbot installed and configured

## License

MIT License - see [LICENSE](LICENSE)

## Contributing

Contributions welcome! Please open an issue or PR.
