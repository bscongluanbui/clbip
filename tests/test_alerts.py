"""Offline tests for the durable Telegram outbox; no real network or bot calls."""
import json
import html
from contextlib import closing, contextmanager
from pathlib import Path
import sqlite3
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock, patch

from alerts import AlertOutbox, MAX_INCIDENTS, MAX_QUEUE, redact_message


SETTINGS = {"telegram_bot_token": "123456789:TEST_TOKEN_SECRET_123456789", "telegram_chat_id": "-1001234567"}


class AlertOutboxTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.now = 1000.0
        self.box = AlertOutbox(self.root, clock=lambda: self.now)
        self.messages = []

    def sender(self, message, settings=None):
        self.messages.append(message)
        return True, "Success"

    def rows(self, table="queue"):
        with closing(sqlite3.connect(str(self.box.path))) as db:
            db.row_factory = sqlite3.Row
            return [dict(row) for row in db.execute(f"SELECT * FROM {table}")]

    def flush_all(self):
        for _ in range(10):
            if not self.box.flush_once(SETTINGS, self.sender)["queued"]:
                break

    def test_constructor_and_enqueue_never_send_or_start_threads(self):
        with patch("alerts.send_telegram_message", side_effect=AssertionError("network forbidden")), \
             patch("threading.Thread.start", side_effect=AssertionError("thread forbidden")):
            box = AlertOutbox(self.root / "independent")
            self.assertTrue(box.failure("ipv6", "IPv6 lost"))
            self.assertTrue(box.resolve("ipv6", "IPv6 recovered"))
            self.assertTrue(box.event("start", "Worker started"))

    def test_offline_restart_preserves_failure_then_recovery_in_exact_order(self):
        self.box.failure("ipv6", "IPv6 failed", "no route")
        self.now += 12
        self.box.resolve("ipv6", "IPv6 restored", "route ready")
        failed_sender = Mock(return_value=(False, "No network"))
        result = self.box.flush_once(SETTINGS, failed_sender)
        self.assertEqual(result, {"configured": True, "attempted": 1, "sent": 0, "queued": 2})
        self.box = AlertOutbox(self.root, clock=lambda: self.now)
        self.assertEqual(self.box.status()["queued"], 2)
        self.now += 10
        self.flush_all()
        self.assertEqual(len(self.messages), 2)
        self.assertIn("ERROR\nIPv6 failed", self.messages[0])
        self.assertIn("RECOVERED\nIPv6 restored", self.messages[1])
        self.assertIn("Incident duration: 12s", self.messages[1])
        self.assertEqual(self.box.status()["queued"], 0)

    def test_missing_configuration_retains_queue_and_later_configuration_flushes(self):
        self.box.failure("worker", "Worker failed")
        sender = Mock(return_value=(True, "Success"))
        for settings in (None, {}, {"telegram_bot_token": "x"}, {"telegram_bot_token": " ", "telegram_chat_id": "1"}):
            self.assertFalse(self.box.flush_once(settings, sender)["configured"])
        sender.assert_not_called()
        self.assertEqual(self.box.status()["queued"], 1)
        self.assertEqual(self.box.flush_once(SETTINGS, sender)["sent"], 1)
        self.assertTrue(self.box.status()["configured"])

    def test_idle_flush_performs_no_database_changes_after_configuration_initialized(self):
        original_transaction = self.box._transaction
        for settings in ({}, SETTINGS):
            self.box.flush_once(settings, self.sender)
            changes = []

            @contextmanager
            def observed_transaction():
                with original_transaction() as db:
                    yield db
                    changes.append(db.total_changes)

            with patch.object(self.box, "_transaction", observed_transaction):
                for _ in range(5):
                    result = self.box.flush_once(settings, self.sender)
                    self.assertEqual(result["attempted"], 0)
            self.assertTrue(changes)
            self.assertEqual(sum(changes), 0)

    def test_delivery_is_independent_of_telegram_polling_enabled(self):
        self.box.failure("worker", "Worker failed")
        settings = dict(SETTINGS, telegram_enabled=False, TELEGRAM_ENABLED="false")
        self.assertEqual(self.box.flush_once(settings, self.sender)["sent"], 1)

    def test_failure_reminder_cooldown_deduplicates_and_retains_occurrence_count(self):
        self.box.failure("dns", "DNS failed")
        for i in range(20):
            self.now += 1
            self.box.failure("dns", "DNS still failed")
        self.assertEqual(self.box.status()["queued"], 1)
        self.assertEqual(self.rows("incidents")[0]["occurrences"], 21)
        self.now = 1300
        self.box.failure("dns", "DNS still failed")
        self.assertEqual(self.box.status()["queued"], 2)
        self.now = 1600
        self.box.failure("dns", "Latest DNS failure")
        self.assertEqual(self.box.status()["queued"], 2)
        self.assertEqual(self.rows()[-1]["occurrences"], 23)
        self.flush_all()
        self.assertIn("ERROR REMINDER", self.messages[1])
        self.assertIn("Occurrences: 23", self.messages[1])

    def test_deduplication_and_active_incident_survive_restart(self):
        self.box.failure("pool", "Pool unavailable")
        self.box = AlertOutbox(self.root, clock=lambda: self.now)
        self.now += 10
        self.box.failure("pool", "Pool still unavailable")
        self.assertEqual(self.box.status()["queued"], 1)
        self.assertEqual(self.box.status()["active_incidents"], 1)
        self.assertTrue(self.box.resolve("pool", "Pool recovered"))
        self.assertFalse(self.box.resolve("pool", "Pool recovered again"))
        self.assertEqual(self.box.status()["active_incidents"], 0)
        self.assertEqual(self.box.status()["queued"], 2)

    def test_resolve_never_emits_spurious_recovery(self):
        self.assertFalse(self.box.resolve("missing", "Recovered"))
        self.assertEqual(self.box.status()["queued"], 0)

    def test_new_failure_after_recovery_creates_distinct_ordered_episode(self):
        self.box.failure("net", "First failure")
        self.now += 300
        self.box.failure("net", "First reminder")
        self.box.resolve("net", "First recovery")
        self.now += 1
        self.box.failure("net", "Second failure")
        self.now += 300
        self.box.failure("net", "Second reminder")
        self.assertEqual([r["kind"] for r in self.rows()], ["failure", "reminder", "recovery", "failure", "reminder"])
        self.assertEqual([r["title"] for r in self.rows()], ["First failure", "First reminder", "First recovery", "Second failure", "Second reminder"])

    def test_retry_backoff_grows_from_ten_to_three_hundred_seconds(self):
        self.box.failure("net", "Offline")
        sender = Mock(return_value=(False, "offline"))
        for expected_delay in (10, 20, 40, 80, 160, 300, 300):
            before = self.now
            result = self.box.flush_once(SETTINGS, sender)
            self.assertEqual(result["attempted"], 1)
            self.assertEqual(self.box.status()["next_retry_at"], before + expected_delay)
            self.now += expected_delay - 1
            self.assertEqual(self.box.flush_once(SETTINGS, sender)["attempted"], 0)
            self.now += 1
        self.assertEqual(self.box.status()["delivery_failures"], 7)

    def test_retry_after_http_429_can_extend_delay(self):
        self.box.failure("net", "Offline")
        sender = Mock(return_value=(False, {"parameters": {"retry_after": 900}}))
        self.box.flush_once(SETTINGS, sender)
        self.assertEqual(self.box.status()["next_retry_at"], 1900)
        self.assertEqual(AlertOutbox._retry_after({"parameters": "invalid"}), 0)
        self.assertEqual(AlertOutbox._retry_after({"retry_after": "invalid"}), 0)

    def test_sender_exception_is_contained_and_never_recursively_enqueued(self):
        self.box.failure("net", "Offline")
        sender = Mock(side_effect=RuntimeError(SETTINGS["telegram_bot_token"]))
        self.assertEqual(self.box.flush_once(SETTINGS, sender)["attempted"], 1)
        self.assertEqual(self.box.status()["queued"], 1)
        self.assertEqual(self.box.status()["delivery_failures"], 1)
        self.assertNotIn(SETTINGS["telegram_bot_token"], json.dumps(self.box.status()))

    def test_invalid_configured_bot_is_retryable_not_an_infinite_busy_loop(self):
        self.box.failure("net", "Offline")
        sender = Mock(return_value=(False, "Telegram API HTTP 401"))
        self.box.flush_once(SETTINGS, sender)
        for _ in range(20):
            self.box.flush_once(SETTINGS, sender)
        self.assertEqual(sender.call_count, 1)
        self.assertEqual(self.box.status()["queued"], 1)

    def test_batch_is_bounded_to_three_attempts(self):
        for i in range(5):
            self.box.event(f"item-{i}", f"Event {i}")
        self.assertEqual(self.box.flush_once(SETTINGS, self.sender)["sent"], 3)
        self.assertEqual(self.box.status()["queued"], 2)

    def test_first_failure_blocks_later_recovery_delivery_until_retry(self):
        self.box.failure("net", "Offline")
        self.box.resolve("net", "Online")
        sender = Mock(return_value=(False, "offline"))
        self.assertEqual(self.box.flush_once(SETTINGS, sender)["attempted"], 1)
        self.assertEqual(self.box.flush_once(SETTINGS, self.sender)["attempted"], 0)
        self.assertEqual(self.messages, [])

    def test_event_cooldown_is_persistent(self):
        self.assertTrue(self.box.event("boot", "Boot"))
        self.box = AlertOutbox(self.root, clock=lambda: self.now)
        self.assertFalse(self.box.event("boot", "Boot again"))
        self.now += 300
        self.assertTrue(self.box.event("boot", "Boot again"))

    def test_concurrent_producers_deduplicate_failure_and_recovery(self):
        barrier = threading.Barrier(12)
        def fail():
            barrier.wait()
            self.box.failure("net", "Offline")
        threads = [threading.Thread(target=fail) for _ in range(12)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(5)
            self.assertFalse(thread.is_alive())
        self.assertEqual(self.box.status()["queued"], 1)
        self.assertEqual(self.rows("incidents")[0]["occurrences"], 12)
        threads = [threading.Thread(target=lambda: self.box.resolve("net", "Online")) for _ in range(12)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(5)
        self.assertEqual(self.box.status()["queued"], 2)

    def test_reopened_instances_have_atomic_deduplication(self):
        boxes = [AlertOutbox(self.root, clock=lambda: self.now) for _ in range(4)]
        threads = [threading.Thread(target=box.failure, args=("net", "Offline")) for box in boxes]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(5)
        self.assertEqual(self.box.status()["queued"], 1)
        self.assertEqual(self.rows("incidents")[0]["occurrences"], 4)

    def test_blocking_delivery_holds_neither_sqlite_nor_producer_lock(self):
        self.box.failure("net", "Offline")
        entered, release = threading.Event(), threading.Event()
        def blocking_sender(message, settings=None):
            entered.set()
            release.wait(3)
            return True, "Success"
        thread = threading.Thread(target=self.box.flush_once, args=(SETTINGS, blocking_sender))
        thread.start()
        self.addCleanup(release.set)
        self.assertTrue(entered.wait(2))
        before = time.monotonic()
        self.assertTrue(self.box.resolve("net", "Online"))
        self.assertTrue(self.box.event("other", "Another event"))
        self.assertLess(time.monotonic() - before, .5)
        self.assertEqual(self.box.status()["queued"], 3)
        second = Mock(return_value=(True, "Success"))
        self.assertEqual(self.box.flush_once(SETTINGS, second)["attempted"], 0)
        second.assert_not_called()
        release.set()
        thread.join(5)
        self.assertFalse(thread.is_alive())

    def test_queue_and_incidents_have_explicit_capacity_and_overflow_counter(self):
        # Lower constants keep the fixture quick; same production trimming paths.
        with patch("alerts.MAX_QUEUE", 10), patch("alerts.MAX_INCIDENTS", 10):
            for i in range(35):
                self.box.failure(f"failure-{i}", "Offline")
            self.assertEqual(self.box.status()["queued"], 10)
            self.assertEqual(self.box.status()["active_incidents"], 10)
            self.assertGreater(self.box.status()["overflow_count"], 0)
            for i in range(35):
                self.box.event(f"event-{i}", "Event")
            self.assertLessEqual(len(self.rows("event_keys")), 10)
            self.assertEqual(self.box.status()["queued"], 10)
        self.assertEqual(MAX_QUEUE, 1000)
        self.assertEqual(MAX_INCIDENTS, 1000)
        self.assertLess(self.box.path.stat().st_size, 32 * 1024 * 1024)

    def test_capacity_prefers_dropping_event_over_failure_and_recovery(self):
        with patch("alerts.MAX_QUEUE", 3):
            self.box.failure("net", "Offline")
            self.box.resolve("net", "Online")
            self.box.event("ordinary", "Ordinary")
            self.box.event("latest", "Latest")
            self.assertEqual([r["kind"] for r in self.rows()], ["failure", "recovery", "event"])

    def test_credentials_redacted_and_untrusted_html_escaped(self):
        settings = dict(SETTINGS, proxy_password="custom-secret-value", secret_key="flask-key")
        detail = ("token=123456789:TEST_TOKEN_SECRET_123456789\n"
                  "password='some password'\nhttps://alice:private-pass@example.test/\n"
                  "Authorization: Bearer abcdef\ncustom-secret-value flask-key <script>x</script>")
        self.box.failure("net", "<b>Network down</b>", detail)
        with patch.dict("os.environ", {"TELEGRAM_SERVER_NAME": "My <server>"}):
            self.box.flush_once(settings, self.sender)
        message = self.messages[0]
        for secret in (SETTINGS["telegram_bot_token"], "some password", "alice", "private-pass", "abcdef", "custom-secret-value", "flask-key"):
            self.assertNotIn(secret, message)
        self.assertIn("&lt;b&gt;Network down&lt;/b&gt;", message)
        self.assertIn("My &lt;server&gt;", message)
        self.assertIn("[REDACTED]", message)

    def test_status_never_exposes_payload_or_sender_error_credentials(self):
        self.box.failure("net", "secret-title", "secret-detail")
        self.box.flush_once(SETTINGS, Mock(return_value=(False, "https://api.telegram.org/bot" + SETTINGS["telegram_bot_token"])))
        status = json.dumps(self.box.status())
        for secret in ("secret-title", "secret-detail", SETTINGS["telegram_bot_token"], SETTINGS["telegram_chat_id"]):
            self.assertNotIn(secret, status)

    def test_short_password_redaction_cannot_exceed_telegram_message_limit(self):
        self.box.failure("net", "Error", "a" * 1600)
        self.box.flush_once(dict(SETTINGS, proxy_password="a"), self.sender)
        self.assertLessEqual(len(html.unescape(self.messages[0])), 3800)

    def test_redactor_handles_key_value_json_and_short_known_password(self):
        message = redact_message("{\"password\": \"hello world\", 'token': 'private'} xy secret", {"proxy_password": "xy", "secret_key": "secret"})
        for secret in ("hello world", "private", "xy", "secret"):
            self.assertNotIn(secret, message)

    def test_telegram_url_credentials_are_redacted_before_persistence(self):
        token = SETTINGS["telegram_bot_token"]
        self.box.failure("net", "Offline", "https://api.telegram.org/bot" + token + "/sendMessage")
        self.assertNotIn(token, self.rows()[0]["detail"])

    def test_database_failure_is_contained_without_recursive_alerts(self):
        with patch.object(self.box, "_transaction", side_effect=sqlite3.OperationalError("bad secret")):
            self.assertFalse(self.box.failure("net", "Offline"))
            self.assertFalse(self.box.resolve("net", "Online"))
            self.assertFalse(self.box.event("boot", "Boot"))
            self.assertTrue(self.box.status()["storage_error"])
            self.assertEqual(self.box.flush_once(SETTINGS, self.sender)["attempted"], 0)
        self.assertEqual(self.box.status()["queued"], 0)

    def test_run_reloads_settings_and_stops_without_starting_extra_threads(self):
        self.box.failure("net", "Offline")
        stop, delivered = threading.Event(), threading.Event()
        settings = {}
        def provider():
            return dict(settings)
        def sender(message, settings=None):
            delivered.set()
            stop.set()
            return True, "Success"
        with patch("alerts.send_telegram_message", side_effect=sender):
            thread = threading.Thread(target=self.box.run, args=(provider, stop))
            thread.start()
            time.sleep(.1)
            self.assertFalse(delivered.is_set())
            settings.update(SETTINGS)
            self.assertTrue(delivered.wait(2))
            thread.join(2)
            self.assertFalse(thread.is_alive())
        self.assertEqual(self.box.status()["queued"], 0)

    def test_run_provider_exception_is_contained_and_stop_is_bounded(self):
        stop = threading.Event()
        thread = threading.Thread(target=self.box.run, args=(Mock(side_effect=RuntimeError("secret")), stop))
        thread.start()
        time.sleep(.05)
        before = time.monotonic()
        stop.set()
        thread.join(1.5)
        self.assertFalse(thread.is_alive())
        self.assertLess(time.monotonic() - before, 1)

    def test_success_clears_delivery_error_and_preserves_failure_statistics(self):
        self.box.failure("net", "Offline")
        self.box.flush_once(SETTINGS, Mock(return_value=(False, "offline")))
        self.now += 10
        self.box.flush_once(SETTINGS, self.sender)
        status = self.box.status()
        self.assertEqual(status["last_error"], "")
        self.assertEqual(status["delivery_failures"], 1)
        self.assertEqual(status["last_delivery_at"], 1010)
        self.assertIsNone(status["next_retry_at"])


if __name__ == "__main__":
    unittest.main()
