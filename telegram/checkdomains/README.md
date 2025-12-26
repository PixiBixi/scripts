# DNS Compare Bot

A Telegram bot that compares the IP addresses of two domains and sends notifications if they differ.

---

## Features

- Periodically compares the IPs of **two domains**.
- Sends Telegram alerts in case of a **DNS mismatch**.
- `/check` command to manually trigger a DNS check from Telegram.
- Periodic **heartbeat** message to confirm DNS is OK.
- Dynamic reload of `config.yaml` without restarting the bot.
- Telegram messages on **bot start** and **bot shutdown** (Ctrl+C or SIGTERM).

---

## Requirements

- Python 3.11+
- Python packages:

## Installation

- Clone this repository
- Create the config.yaml (see below)
- Use the venv and install all requirements

```bash
python3 -m venv venv
source ./venv/bin/activate
pip install -r requirements.txt
```

- Start the bot `./bot.py`

## Configuration file

```yaml
bot_token: "123456789:ABCDEF_your_bot_token_here"
chat_ids:
  - 12345678
  - 87654321
domain_a: "example.com"
domain_b: "example.org"
check_interval: 300            # seconds between DNS checks
heartbeat_interval: 3600       # seconds between heartbeat messages
fast_alert_interval: 900       # seconds between alerts if mismatch is recent (< FAST_ALERT_DURATION)
slow_alert_interval: 3600      # seconds between alerts if mismatch is old
fast_alert_duration: 7200      # seconds during which fast alerts are used
```

## Telegram commands

- `/check` : triggers a manual DNS check and sends the result.

## How it works

1. The bot starts and sends a Telegram message indicating startup.
2. It periodically checks the IPs of the configured domains.
3. If the IPs differ:
4. Sends Telegram alerts based on the mismatch duration.
5. If the IPs match again:
6. Sends a recovery message.
7. Sends periodic heartbeat messages to confirm everything is OK.
8. Automatically reloads config.yaml every 60 seconds.
