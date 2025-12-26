#!/usr/bin/env python3
import asyncio
import time
import signal
import dns.resolver
import yaml
from datetime import datetime, timezone
from telegram import Update
from telegram.ext import ApplicationBuilder, CommandHandler, ContextTypes

CONFIG_FILE = "config.yaml"
CONFIG_RELOAD_INTERVAL = 60  # reload config à chaud toutes les 60 sec
stop_event = asyncio.Event()
config = {}


# ======================
# LOG UTILITY
# ======================
def log(msg: str):
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    print(f"[{timestamp}] {msg}")


# ======================
# CONFIG LOAD
# ======================
def load_config_sync():
    global config
    try:
        with open(CONFIG_FILE, "r") as f:
            config = yaml.safe_load(f)
    except Exception as e:
        log(f"[ERROR] Failed to load config: {e}")


async def load_config(bot=None):
    global config
    try:
        with open(CONFIG_FILE, "r") as f:
            new_config = yaml.safe_load(f)
        if new_config != config:
            log("[DEBUG] Config reloaded")
            for key in new_config:
                if new_config.get(key) != config.get(key):
                    log(f"  {key}: {config.get(key)} -> {new_config.get(key)}")
            config = new_config
            if bot:
                await send_to_all(bot, "🛠️ *Config reload détectée*")
        else:
            config = new_config
    except Exception as e:
        log(f"[ERROR] Failed to load config: {e}")


# ======================
# DNS RESOLUTION & DIFF
# ======================
def resolve_ips(domain):
    ips = set()
    try:
        answers = dns.resolver.resolve(domain, "A")
        for rdata in answers:
            ips.add(rdata.address)
    except Exception as e:
        log(f"[ERROR] DNS resolution failed for {domain}: {e}")
    return sorted(ips)


def format_dns_diff(domain, ips, reference_ips):
    lines = [f"🌐 *{domain}*"]
    all_ips = sorted(set(ips) | set(reference_ips))
    for ip in all_ips:
        if ip in ips and ip not in reference_ips:
            lines.append(f"`+ {ip}`")
        elif ip not in ips and ip in reference_ips:
            lines.append(f"`- {ip}`")
        else:
            lines.append(f"`  {ip}`")
    return "\n".join(lines)


# ======================
# TELEGRAM
# ======================
async def send_to_all(bot, message):
    for chat_id in config.get("chat_ids", []):
        try:
            await bot.send_message(chat_id=chat_id, text=message, parse_mode="Markdown")
        except Exception as e:
            log(f"[ERROR] Failed to send message to {chat_id}: {e}")


# ======================
# COMMAND /CHECK
# ======================
async def check_dns_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    domain_a = config.get("domain_a")
    domain_b = config.get("domain_b")
    log(f"[CHECK COMMAND] Triggered by chat_id={update.effective_chat.id}")
    ips_a = resolve_ips(domain_a)
    ips_b = resolve_ips(domain_b)
    log(f"[CHECK COMMAND] {domain_a} -> {ips_a}")
    log(f"[CHECK COMMAND] {domain_b} -> {ips_b}")
    set_a = set(ips_a)
    set_b = set(ips_b)
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    if set_a != set_b:
        message = (
            "🚨 *DNS mismatch détecté (commande /check)*\n\n"
            f"🕒 `{timestamp}`\n\n"
            f"{format_dns_diff(domain_a, set_a, set_b)}\n\n"
            f"{format_dns_diff(domain_b, set_b, set_a)}"
        )
        log("[CHECK COMMAND] DNS mismatch detected")
    else:
        message = (
            "✅ *DNS OK (commande /check)*\n\n"
            f"🕒 `{timestamp}`\n"
            f"🌐 `{domain_a}` et `{domain_b}` pointent vers les mêmes IPs\n"
            f"`{ips_a}`"
        )
        log("[CHECK COMMAND] DNS OK")
    await context.bot.send_message(
        chat_id=update.effective_chat.id,
        text=message,
        parse_mode="Markdown"
    )


# ======================
# SIGNAL HANDLER
# ======================
def shutdown():
    log("[SIGNAL] Shutdown requested")
    stop_event.set()


# ======================
# DNS CHECK FUNCTION
# ======================
async def perform_dns_check(bot):
    domain_a = config.get("domain_a")
    domain_b = config.get("domain_b")
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    ips_a = resolve_ips(domain_a)
    ips_b = resolve_ips(domain_b)
    set_a = set(ips_a)
    set_b = set(ips_b)
    return domain_a, domain_b, ips_a, ips_b, set_a, set_b, timestamp


# ======================
# PERIODIC TASK LOOP
# ======================
async def periodic_tasks(bot):
    mismatch_start_ts = None
    last_alert_ts = None
    last_heartbeat_ts = 0
    last_config_reload = 0
    last_dns_check = 0

    CHECK_INTERVAL = config.get("check_interval", 300)
    HEARTBEAT_INTERVAL = config.get("heartbeat_interval", 3600)
    FAST_ALERT_INTERVAL = config.get("fast_alert_interval", 900)
    SLOW_ALERT_INTERVAL = config.get("slow_alert_interval", 3600)
    FAST_ALERT_DURATION = config.get("fast_alert_duration", 7200)

    while not stop_event.is_set():
        now = time.time()

        # Reload config
        if now - last_config_reload >= CONFIG_RELOAD_INTERVAL:
            await load_config(bot)
            last_config_reload = now

        # DNS check périodique
        if now - last_dns_check >= CHECK_INTERVAL:
            (
                domain_a,
                domain_b,
                ips_a,
                ips_b,
                set_a,
                set_b,
                timestamp,
            ) = await perform_dns_check(bot)
            last_dns_check = now

            if set_a != set_b:
                if mismatch_start_ts is None:
                    mismatch_start_ts = now
                    last_alert_ts = 0
                    log("[ALERT] DNS mismatch started")
                elapsed = now - mismatch_start_ts
                alert_interval = (
                    FAST_ALERT_INTERVAL
                    if elapsed < FAST_ALERT_DURATION
                    else SLOW_ALERT_INTERVAL
                )
                if now - last_alert_ts >= alert_interval:
                    log("[ALERT] Sending DNS mismatch alert")
                    message = (
                        "🚨 *DNS mismatch détecté*\n\n"
                        f"🕒 `{timestamp}`\n"
                        f"⏳ Durée : `{int(elapsed // 60)} min`\n\n"
                        f"{format_dns_diff(domain_a, set_a, set_b)}\n\n"
                        f"{format_dns_diff(domain_b, set_b, set_a)}"
                    )
                    await send_to_all(bot, message)
                    last_alert_ts = now
            else:
                if mismatch_start_ts is not None:
                    log("[RECOVERY] DNS back to normal")
                    await send_to_all(
                        bot, f"🟢 *DNS OK – Résolution rétablie*\n\n🕒 `{timestamp}`"
                    )
                mismatch_start_ts = None
                last_alert_ts = None

                # Heartbeat
                log("[OK] DNS IPs are matching")
                if now - last_heartbeat_ts >= HEARTBEAT_INTERVAL:
                    heartbeat_message = (
                        "💓 *DNS OK – Heartbeat*\n\n"
                        f"🕒 `{timestamp}`\n"
                        f"🌐 `{domain_a}` et `{domain_b}` pointent vers les mêmes IPs\n"
                        f"`{ips_a}`"
                    )
                    await send_to_all(bot, heartbeat_message)
                    last_heartbeat_ts = now

        await asyncio.sleep(1)


# ======================
# MAIN
# ======================
def main():
    load_config_sync()
    bot_token = config.get("bot_token")
    if not bot_token:
        log("[ERROR] Bot token not set in config.yaml")
        return

    # Crée une nouvelle boucle pour Python 3.13+
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    app = ApplicationBuilder().token(bot_token).build()
    app.add_handler(CommandHandler("check", check_dns_command))

    # Signal
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, shutdown)

    async def start_tasks(application):
        print("========================================")
        print("🚀 DNS Compare Bot starting")
        print(f"Domain A : {config.get('domain_a')}")
        print(f"Domain B : {config.get('domain_b')}")
        print(f"Check interval : {config.get('check_interval')}")
        print(f"Chats : {config.get('chat_ids')}")
        print("========================================")

        await send_to_all(
            application.bot,
            f"🤖 *DNS Compare Bot démarré*\n🌐 `{config.get('domain_a')}` ↔ `{config.get('domain_b')}`\n"
            f"⏱ Check `{config.get('check_interval', 300)}s`\n📣 Alertes : 15 min pendant 2h → puis 1h\n"
            f"💓 Heartbeat `{config.get('heartbeat_interval', 3600)}s`",
        )
        asyncio.create_task(periodic_tasks(application.bot))

    app.post_init = start_tasks
    app.run_polling()  # Bloquant et gère la boucle asyncio


if __name__ == "__main__":
    main()
