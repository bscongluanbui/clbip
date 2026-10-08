"""Telegram notifications with bounded requests and secret-redacted errors."""
import logging
import os
import requests

logger = logging.getLogger(__name__)


def get_telegram_settings(settings=None):
    if settings is not None:
        return settings.get("telegram_bot_token"), settings.get("telegram_chat_id")
    # Dashboard has no persistent data mount; read the privileged config endpoint.
    from telegram_bot import ApiClient
    try:
        config = ApiClient().config()
        return config.get("token"), config.get("chat_id")
    except Exception:
        return None, None


def send_telegram_message(message, settings=None):
    token, chat_id = get_telegram_settings(settings)
    if not token or not chat_id:
        return False, "Telegram settings not configured"
    session = requests.Session()
    session.trust_env = False
    try:
        response = session.post(f"https://api.telegram.org/bot{token}/sendMessage",
            json={"chat_id": str(chat_id), "text": str(message), "parse_mode": "HTML"}, timeout=(5, 10))
        if response.status_code != 200:
            return False, f"Telegram API HTTP {response.status_code}"
        if response.json().get("ok") is not True:
            return False, "Telegram API rejected the message"
        return True, "Success"
    except requests.RequestException:
        return False, "Telegram connection failed"
    except ValueError:
        return False, "Telegram API returned invalid JSON"
    finally:
        session.close()
