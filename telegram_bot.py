"""Authenticated Telegram control client; no filesystem state or host trust bypass."""
import logging
import os
import secrets
import threading
import time
import uuid
from dataclasses import dataclass
import requests

logger = logging.getLogger(__name__)


def read_secret(name):
    path = os.environ.get(name + "_FILE")
    if path:
        with open(path, encoding="utf-8") as stream:
            return stream.read().strip()
    return os.environ.get(name, "").strip()


def local_api_url():
    port = int(os.environ.get("GUI_PORT", "7070"))
    if not 1024 <= port <= 65535:
        raise ValueError("Invalid GUI_PORT")
    return f"http://127.0.0.1:{port}/api"


class ApiClient:
    def __init__(self):
        self.session = requests.Session()
        self.session.trust_env = False

    def request(self, method, path, payload=None):
        token = read_secret("SERVICE_TOKEN")
        if len(token) < 32:
            raise RuntimeError("Service credentials not configured")
        response = self.session.request(method, local_api_url() + path,
            headers={"Authorization": "Bearer " + token, **({"Idempotency-Key": str(uuid.uuid4())} if method.upper() not in ("GET", "HEAD") else {})}, json=payload, timeout=(5, 300))
        response.raise_for_status()
        data = response.json()
        if data.get("success") is False:
            raise RuntimeError(data.get("error", "Operation failed"))
        return data

    def config(self):
        config = self.request("GET", "/internal/telegram-config")
        env_ids = os.environ.get("TELEGRAM_ALLOWED_USER_IDS", "").strip()
        if env_ids:
            config["allowed_user_ids"] = [int(x.strip()) for x in env_ids.split(",") if x.strip()]
        return config


def authorized(message, config):
    sender = getattr(message, "from_user", None)
    if sender is None or getattr(sender, "is_bot", False):
        return False
    if getattr(message, "sender_chat", None) is not None:
        return False
    if getattr(message, "forward_origin", None) is not None or getattr(message, "forward_from", None) is not None:
        return False
    try:
        allowed = {int(x) for x in config.get("allowed_user_ids", [])}
        return str(message.chat.id) == str(config.get("chat_id")) and int(sender.id) in allowed
    except (TypeError, ValueError, AttributeError):
        return False


@dataclass
class Pending:
    command: str
    nonce: str
    expires: float
    payload: dict


class Confirmations:
    def __init__(self, clock=time.monotonic):
        self.clock = clock
        self.pending = {}
        self.lock = threading.Lock()

    def issue(self, chat_id, user_id, command, payload=None):
        nonce = secrets.token_hex(4)
        with self.lock:
            now = self.clock()
            self.pending = {k: v for k, v in self.pending.items() if v.expires > now}
            self.pending[(str(chat_id), int(user_id))] = Pending(command, nonce, now + 60, payload or {})
        return nonce

    def consume(self, chat_id, user_id, nonce):
        key = (str(chat_id), int(user_id))
        with self.lock:
            pending = self.pending.get(key)
            if pending is None or pending.expires <= self.clock():
                self.pending.pop(key, None)
                return None
            if not secrets.compare_digest(pending.nonce, str(nonce)):
                return None
            return self.pending.pop(key)


def generation_payload(settings, count, start_port=None, recreate=False):
    if not 1 <= count <= 10000:
        raise ValueError("Số lượng phải từ 1 đến 10000")
    port = int(settings.get("start_port", 10000) if start_port is None else start_port)
    protocol = settings.get("protocol", "http")
    if protocol not in ("http", "socks5", "dual"):
        raise ValueError("Protocol không hợp lệ")
    if count * (2 if protocol == "dual" else 1) > 1024:
        raise ValueError("Tối đa 1024 dịch vụ proxy")
    if port < 1024 or port + count - 1 + (10000 if protocol == "dual" else 0) > 65535:
        raise ValueError("Dải port không hợp lệ")
    if not settings.get("subnet"):
        raise ValueError("Hãy cấu hình subnet trên dashboard trước")
    fields = ("subnet", "prefix_len", "interface", "protocol", "topology_mode", "routed_prefix", "listener_ipv4", "allowed_ips", "probe_url", "max_connections")
    payload = {key: settings[key] for key in fields if key in settings}
    payload.update(count=count, start_port=port, recreate=recreate, start=True)
    return payload


def run_bot():
    import telebot
    from telebot.types import BotCommand
    api = ApiClient()
    confirmations = Confirmations()
    while True:
        try:
            config = api.config()
            token = config.get("token")
            if not token or not config.get("chat_id") or not config.get("allowed_user_ids"):
                time.sleep(15)
                continue
            bot = telebot.TeleBot(token, threaded=False)
            snapshot = (token, str(config["chat_id"]), tuple(config["allowed_user_ids"]))
            bot.set_my_commands([BotCommand("help", "Hướng dẫn"), BotCommand("status", "Trạng thái"),
                BotCommand("create", "Tạo proxy: /create count port"), BotCommand("clear", "Xóa proxy sau xác nhận"),
                BotCommand("restart", "Restart sau xác nhận"), BotCommand("reset200", "Thay thế 200 proxy sau xác nhận"),
                BotCommand("confirm", "Xác nhận thao tác trong 60 giây")])

            @bot.message_handler(commands=["start", "help", "status", "create", "clear", "restart", "reset200", "confirm"])
            def handle(message):
                try:
                    current = api.config()  # Recheck identity on every command, not just startup.
                    if not authorized(message, current):
                        return
                    args = (message.text or "").split()
                    command = args[0].split("@")[0].lstrip("/")
                    if command in ("start", "help"):
                        bot.reply_to(message, "/status; /create [1-10000] [port]; /clear; /restart; /reset200. Lệnh thay đổi yêu cầu /confirm [mã] trong 60 giây.")
                    elif command == "status":
                        status = api.request("GET", "/status")
                        bot.reply_to(message, f"Proxy: {status.get('total_proxies', 0)}; desired: {status.get('desired_state', '?')}; running: {status.get('proxy_running', False)}")
                    elif command in ("clear", "restart", "reset200", "create"):
                        payload = {}
                        if command in ("reset200", "create"):
                            settings = api.request("GET", "/settings")
                            count = 200 if command == "reset200" else int(args[1])
                            port = int(args[2]) if command == "create" and len(args) > 2 else None
                            payload = generation_payload(settings, count, port, command == "reset200")
                        nonce = confirmations.issue(message.chat.id, message.from_user.id, command, payload)
                        bot.reply_to(message, f"Xác nhận {command}: /confirm {nonce} (60 giây, đúng user/chat này).")
                    elif command == "confirm" and len(args) == 2:
                        pending = confirmations.consume(message.chat.id, message.from_user.id, args[1])
                        if pending is None:
                            bot.reply_to(message, "Mã xác nhận sai hoặc hết hạn.")
                            return
                        if pending.command == "clear":
                            result = api.request("POST", "/proxies/delete-all", {})
                        elif pending.command == "restart":
                            result = api.request("POST", "/proxy/restart", {})
                        else:
                            result = api.request("POST", "/proxies/generate", pending.payload)
                        bot.reply_to(message, "Hoàn tất: " + str(result.get("message", pending.command)))
                except (ValueError, IndexError):
                    bot.reply_to(message, "Cú pháp: /create [số lượng] [port]; kiểm tra cấu hình subnet/dải port.")
                except Exception as error:
                    logger.error("Telegram command failed (%s)", type(error).__name__)
                    bot.reply_to(message, "Thao tác thất bại; xem log dashboard/worker để kiểm tra.")

            # Manual bounded getUpdates reloads configuration between every poll.
            offset = None
            while True:
                current = api.config()
                now = (current.get("token"), str(current.get("chat_id")), tuple(current.get("allowed_user_ids", [])))
                if now != snapshot:
                    bot.stop_polling()
                    break
                updates = bot.get_updates(offset=offset, timeout=10, long_polling_timeout=5, allowed_updates=["message"])
                if updates:
                    bot.process_new_updates(updates)
                    offset = max(update.update_id for update in updates) + 1
        except Exception as error:
            # Exception messages may contain a Telegram token URL; never log them.
            logger.error("Telegram polling unavailable (%s)", type(error).__name__)
            time.sleep(10)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    run_bot()
