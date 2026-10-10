"""Durable, bounded, best-effort Telegram incident notifications.

Enqueuing never performs network I/O. A single worker-owned consumer sends messages
outside SQLite and service mutation locks. Delivery is at least once: a crash after
Telegram accepts a message but before its acknowledgement can repeat that message.
"""
from contextlib import contextmanager
import hashlib
import html
import logging
import os
from pathlib import Path
import re
import socket
import sqlite3
import threading
import time

from telegram_notify import send_telegram_message

logger = logging.getLogger(__name__)

MAX_QUEUE = 1000
MAX_INCIDENTS = 1000
REMINDER_SECONDS = 300
RETRY_MIN_SECONDS = 10
RETRY_MAX_SECONDS = 300
MAX_SEND_BATCH = 3


def redact_message(value, settings=None):
    """Remove common credential shapes and known configured secrets, before HTML."""
    text = str(value or "")
    if isinstance(settings, dict):
        secrets = []
        for key, secret in settings.items():
            if re.search(r"(?i)(password|passwd|token|secret|api[_-]?key)", str(key)):
                if isinstance(secret, (str, int)) and str(secret):
                    secrets.append(str(secret))
        for secret in sorted(set(secrets), key=len, reverse=True):
            text = text.replace(secret, "[REDACTED]")
    text = re.sub(r"(?i)(https?://)[^\s/@]+(?::[^\s/@]*)?@", r"\1[REDACTED]@", text)
    text = re.sub(r"(?i)(https?://api\.telegram\.org/bot)[^/\s?]+", r"\1[REDACTED]", text)
    text = re.sub(r"(?i)(authorization\s*[:=]\s*)[^\r\n]+", r"\1[REDACTED]", text)
    text = re.sub(r"\b\d{5,}:[A-Za-z0-9_-]{8,}\b", "[REDACTED]", text)
    text = re.sub(
        r"(?i)((?:password|passwd|token|secret|api[_-]?key)[\"']?\s*[:=]\s*)"
        r"(?:\"[^\"]*\"|'[^']*'|[^\s,;&]+)", r"\1[REDACTED]", text)
    return text


class AlertOutbox:
    """Persist incidents and their ordered notifications in worker data only."""

    def __init__(self, data_dir, clock=time.time):
        self.clock = clock
        self.path = Path(data_dir) / "alerts.sqlite3"
        self._db_lock = threading.RLock()
        self._delivery_lock = threading.Lock()
        self._wake_event = None
        self._db_error = False
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    @contextmanager
    def _transaction(self):
        # New connections make access from producer and consumer threads explicit.
        # BEGIN IMMEDIATE also serializes deduplication across reopened instances.
        with self._db_lock:
            connection = sqlite3.connect(str(self.path), timeout=2)
            connection.row_factory = sqlite3.Row
            try:
                connection.execute("PRAGMA synchronous=FULL")
                connection.execute("PRAGMA max_page_count=8192")  # ~32 MiB upper bound.
                connection.execute("BEGIN IMMEDIATE")
                yield connection
                connection.commit()
            except Exception:
                connection.rollback()
                raise
            finally:
                connection.close()

    def _initialize(self):
        with self._transaction() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS incidents (
                key TEXT PRIMARY KEY, active INTEGER NOT NULL,
                occurrences INTEGER NOT NULL, first_at REAL NOT NULL,
                last_at REAL NOT NULL, last_notice_at REAL NOT NULL,
                title TEXT NOT NULL, detail TEXT NOT NULL)""")
            db.execute("""CREATE TABLE IF NOT EXISTS queue (
                id INTEGER PRIMARY KEY AUTOINCREMENT, key TEXT NOT NULL,
                kind TEXT NOT NULL, title TEXT NOT NULL, detail TEXT NOT NULL,
                occurrences INTEGER NOT NULL, created_at REAL NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0, next_at REAL NOT NULL)""")
            db.execute("CREATE TABLE IF NOT EXISTS event_keys (key TEXT PRIMARY KEY, last_at REAL NOT NULL)")
            db.execute("CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)")

    def _perform(self, callback, fallback=False):
        try:
            result = callback()
            self._db_error = False
            return result
        except Exception:
            # Exception text may include tokens, DB paths, or caller-provided data.
            self._db_error = True
            logger.warning("Telegram alert outbox operation failed")
            return fallback

    @staticmethod
    def _key(value):
        text = str(value or "unknown")
        return text[:180] + ":" + hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]

    @staticmethod
    def _content(title, detail):
        return redact_message(title)[:240], redact_message(detail)[:1600]

    @staticmethod
    def _get_meta(db, key, default="0"):
        row = db.execute("SELECT value FROM metadata WHERE key=?", (key,)).fetchone()
        return row[0] if row else default

    @staticmethod
    def _set_meta(db, key, value):
        # Idle consumers poll frequently. A no-op must not churn the journal or
        # fsync eMMC storage merely to persist an unchanged configuration flag.
        db.execute("""INSERT INTO metadata(key,value) VALUES (?,?)
            ON CONFLICT(key) DO UPDATE SET value=excluded.value
            WHERE metadata.value <> excluded.value""", (key, str(value)))

    def _increment(self, db, key, amount=1):
        self._set_meta(db, key, min(int(self._get_meta(db, key)) + amount, 2147483647))

    def _trim_incidents(self, db):
        count = db.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
        if count > MAX_INCIDENTS:
            excess = count - MAX_INCIDENTS
            db.execute("""DELETE FROM incidents WHERE key IN
                (SELECT key FROM incidents ORDER BY active ASC,last_at ASC LIMIT ?)""", (excess,))
            self._increment(db, "overflow_count", excess)

    def _enqueue(self, db, key, kind, title, detail, occurrences, now):
        # Pending reminders coalesce; outage and recovery transitions remain ordered.
        if kind == "reminder":
            row = db.execute("SELECT id,kind FROM queue WHERE key=? ORDER BY id DESC LIMIT 1",
                             (key,)).fetchone()
            if row and row["kind"] == "reminder":
                db.execute("UPDATE queue SET title=?,detail=?,occurrences=? WHERE id=?",
                           (title, detail, occurrences, row[0]))
                return
        count = db.execute("SELECT COUNT(*) FROM queue").fetchone()[0]
        if count >= MAX_QUEUE:
            excess = count - MAX_QUEUE + 1
            # Prefer dropping reminders and ordinary events over state transitions.
            db.execute("""DELETE FROM queue WHERE id IN (SELECT id FROM queue
                ORDER BY CASE WHEN kind='reminder' THEN 0 WHEN kind='event' THEN 1 ELSE 2 END,id LIMIT ?)""",
                       (excess,))
            self._increment(db, "overflow_count", excess)
        db.execute("""INSERT INTO queue(key,kind,title,detail,occurrences,created_at,next_at)
                      VALUES (?,?,?,?,?,?,?)""", (key, kind, title, detail, occurrences, now, now))

    def _wake(self):
        event = self._wake_event
        if event is not None:
            event.set()

    def failure(self, key, title, detail=""):
        """Record an active incident; emit first failure and periodic reminders."""
        key, (title, detail), now = self._key(key), self._content(title, detail), self.clock()

        def record():
            with self._transaction() as db:
                row = db.execute("SELECT * FROM incidents WHERE key=?", (key,)).fetchone()
                if row and row["active"]:
                    occurrences = min(row["occurrences"] + 1, 2147483647)
                    emit = now - row["last_notice_at"] >= REMINDER_SECONDS
                    db.execute("""UPDATE incidents SET occurrences=?,last_at=?,title=?,detail=?,
                        last_notice_at=? WHERE key=?""", (occurrences, now, title, detail,
                        now if emit else row["last_notice_at"], key))
                    if emit:
                        self._enqueue(db, key, "reminder", title, detail, occurrences, now)
                else:
                    db.execute("""INSERT OR REPLACE INTO incidents
                        VALUES (?,1,1,?,?,?,?,?)""", (key, now, now, now, title, detail))
                    self._enqueue(db, key, "failure", title, detail, 1, now)
                self._trim_incidents(db)
            self._wake()
            return True
        return self._perform(record)

    def resolve(self, key, title, detail=""):
        """Emit recovery once, only for a previously recorded active incident."""
        key, (title, detail), now = self._key(key), self._content(title, detail), self.clock()

        def record():
            with self._transaction() as db:
                row = db.execute("SELECT * FROM incidents WHERE key=?", (key,)).fetchone()
                if not row or not row["active"]:
                    return False
                elapsed = max(0, int(now - row["first_at"]))
                detail_with_time = (detail + ("\n" if detail else "") + f"Incident duration: {elapsed}s")[:1800]
                db.execute("UPDATE incidents SET active=0,last_at=?,title=?,detail=? WHERE key=?",
                           (now, title, detail, key))
                self._enqueue(db, key, "recovery", title, detail_with_time, row["occurrences"], now)
            self._wake()
            return True
        return self._perform(record)

    def event(self, key, title, detail=""):
        """Enqueue an informational event; identical keys have a 5-minute cooldown."""
        key, (title, detail), now = self._key(key), self._content(title, detail), self.clock()

        def record():
            with self._transaction() as db:
                row = db.execute("SELECT last_at FROM event_keys WHERE key=?", (key,)).fetchone()
                if row and now - row[0] < REMINDER_SECONDS:
                    return False
                db.execute("INSERT OR REPLACE INTO event_keys VALUES (?,?)", (key, now))
                db.execute("""DELETE FROM event_keys WHERE key IN
                    (SELECT key FROM event_keys ORDER BY last_at DESC LIMIT -1 OFFSET ?)""", (MAX_INCIDENTS,))
                self._enqueue(db, key, "event", title, detail, 1, now)
            self._wake()
            return True
        return self._perform(record)

    def status(self):
        """Return counters only, never incident payloads, credentials, or chat IDs."""
        def read():
            with self._transaction() as db:
                row = db.execute("SELECT next_at FROM queue ORDER BY id LIMIT 1").fetchone()
                return {
                    "queued": db.execute("SELECT COUNT(*) FROM queue").fetchone()[0],
                    "active_incidents": db.execute("SELECT COUNT(*) FROM incidents WHERE active=1").fetchone()[0],
                    "overflow_count": int(self._get_meta(db, "overflow_count")),
                    "delivery_failures": int(self._get_meta(db, "delivery_failures")),
                    "last_attempt_at": float(self._get_meta(db, "last_attempt_at")) or None,
                    "last_delivery_at": float(self._get_meta(db, "last_delivery_at")) or None,
                    "last_error": self._get_meta(db, "last_error", ""),
                    "next_retry_at": row[0] if row else None,
                    "configured": self._get_meta(db, "configured") == "1",
                    "storage_error": False,
                }
        default = {"queued": None, "active_incidents": None, "overflow_count": None,
                   "delivery_failures": None, "last_attempt_at": None, "last_delivery_at": None,
                   "last_error": "Alert storage unavailable", "next_retry_at": None,
                   "configured": False, "storage_error": True}
        return self._perform(read, default)

    @staticmethod
    def _configured(settings):
        return (isinstance(settings, dict) and
                bool(str(settings.get("telegram_bot_token") or "").strip()) and
                bool(str(settings.get("telegram_chat_id") or "").strip()))

    def _message(self, row, settings):
        server = os.environ.get("TELEGRAM_SERVER_NAME") or socket.gethostname()
        parts = [f"clbip | {server[:120]}",
                 {"failure": "ERROR", "reminder": "ERROR REMINDER", "recovery": "RECOVERED", "event": "INFO"}[row["kind"]],
                 row["title"]]
        if row["detail"]:
            parts.append(row["detail"])
        if row["occurrences"] > 1:
            parts.append(f"Occurrences: {row['occurrences']}")
        parts.append(time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(row["created_at"])))
        # Redacting even a one-character configured password can expand text;
        # Telegram limits the parsed message to 4096 characters, not HTML bytes.
        return html.escape(redact_message("\n".join(parts), settings)[:3800], quote=False)

    @staticmethod
    def _retry_after(reason):
        # Optional richer senders can preserve Telegram's parameters.retry_after.
        if isinstance(reason, dict):
            parameters = reason.get("parameters")
            value = reason.get("retry_after", parameters.get("retry_after") if isinstance(parameters, dict) else None)
            try:
                return max(0, min(float(value), 86400))
            except (TypeError, ValueError):
                return 0
        return 0

    def flush_once(self, settings, sender=send_telegram_message):
        """Attempt at most three messages; stop at the oldest retry/failure."""
        return self._flush(settings, sender, MAX_SEND_BATCH)

    def _flush(self, settings, sender, max_messages):
        configured = bool(self._configured(settings))
        result = {"configured": configured, "attempted": 0, "sent": 0, "queued": None}
        if not self._delivery_lock.acquire(blocking=False):
            return result
        try:
            def config_state():
                with self._transaction() as db:
                    self._set_meta(db, "configured", int(configured))
            if self._perform(config_state, False) is False:
                return result
            if not configured:
                result["queued"] = self.status()["queued"]
                return result
            for _ in range(max_messages):
                now = self.clock()
                def next_row():
                    with self._transaction() as db:
                        row = db.execute("SELECT * FROM queue ORDER BY id LIMIT 1").fetchone()
                        return dict(row) if row else None
                row = self._perform(next_row, None)
                if row is None or row["next_at"] > now:
                    break
                # Critically, no SQLite or producer/service lock is held here.
                try:
                    sent, reason = sender(self._message(row, settings), settings=settings)
                    sent = sent is True
                except Exception:
                    sent, reason = False, "Telegram sender failed"
                result["attempted"] += 1
                completed_at = self.clock()
                def acknowledge():
                    with self._transaction() as db:
                        self._set_meta(db, "last_attempt_at", completed_at)
                        if sent:
                            db.execute("DELETE FROM queue WHERE id=?", (row["id"],))
                            self._set_meta(db, "last_delivery_at", completed_at)
                            self._set_meta(db, "last_error", "")
                        else:
                            attempts = row["attempts"] + 1
                            delay = min(RETRY_MAX_SECONDS, RETRY_MIN_SECONDS * 2 ** min(attempts - 1, 10))
                            delay = max(delay, self._retry_after(reason))
                            db.execute("UPDATE queue SET attempts=?,next_at=? WHERE id=?",
                                       (min(attempts, 2147483647), completed_at + delay, row["id"]))
                            self._increment(db, "delivery_failures")
                            # Avoid storing arbitrary sender error text in status.
                            self._set_meta(db, "last_error", "Telegram delivery failed; retry scheduled")
                    return True
                acknowledged = self._perform(acknowledge)
                if sent and acknowledged:
                    result["sent"] += 1
                if not sent or not acknowledged:
                    break
            result["queued"] = self.status()["queued"]
            return result
        finally:
            self._delivery_lock.release()

    def run(self, settings_provider, stop_event, wake_event=None):
        """Worker loop; each iteration reloads settings and sends at most one item.

        Stop is checked between sends. An in-flight sender obeys its own bounded
        HTTP timeout; this loop never creates an additional unbounded send thread.
        """
        wake = wake_event or threading.Event()
        self._wake_event = wake
        try:
            while not stop_event.is_set():
                try:
                    settings = settings_provider()
                    result = self._flush(settings, send_telegram_message, 1)
                except Exception:
                    logger.warning("Telegram alert settings or consumer unavailable")
                    result = {"sent": 0}
                if result["sent"] and not stop_event.is_set():
                    continue
                wake.wait(.5)
                wake.clear()
        finally:
            self._wake_event = None
