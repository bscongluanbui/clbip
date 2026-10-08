import os
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import patch, Mock
from telegram_bot import authorized, Confirmations, ApiClient, generation_payload, run_bot


def message(user=11, chat=-42, **attributes):
    return SimpleNamespace(from_user=SimpleNamespace(id=user, is_bot=False), chat=SimpleNamespace(id=chat), **attributes)


class TelegramSecurityTests(unittest.TestCase):
    def test_both_user_and_chat_required(self):
        config = {'chat_id': '-42', 'allowed_user_ids': [11]}
        self.assertTrue(authorized(message(), config))
        self.assertFalse(authorized(message(user=12), config))
        self.assertFalse(authorized(message(chat=-43), config))
        self.assertFalse(authorized(message(sender_chat=SimpleNamespace(id=-42)), config))
        self.assertFalse(authorized(message(forward_origin=object()), config))
        self.assertFalse(authorized(message(), {'chat_id': '-42', 'allowed_user_ids': []}))

    def test_confirmation_bound_expiring_one_shot(self):
        now = [100.0]
        confirmations = Confirmations(lambda: now[0])
        nonce = confirmations.issue(-42, 11, 'clear')
        self.assertIsNone(confirmations.consume(-42, 12, nonce))
        self.assertIsNone(confirmations.consume(-43, 11, nonce))
        self.assertEqual(confirmations.consume(-42, 11, nonce).command, 'clear')
        self.assertIsNone(confirmations.consume(-42, 11, nonce))
        nonce = confirmations.issue(-42, 11, 'restart')
        now[0] += 61
        self.assertIsNone(confirmations.consume(-42, 11, nonce))

    def test_service_token_and_configured_port(self):
        with patch.dict(os.environ, {'SERVICE_TOKEN': 'fixture-token-' * 4, 'GUI_PORT': '9090'}, clear=True):
            with patch('telegram_bot.requests.Session') as session:
                response = Mock()
                response.json.return_value = {'success': True}
                session.return_value.request.return_value = response
                client = ApiClient()
                client.request('POST', '/proxy/restart', {})
                args, kwargs = session.return_value.request.call_args
                self.assertEqual(args[1], 'http://127.0.0.1:9090/api/proxy/restart')
                self.assertTrue(kwargs['headers']['Authorization'].startswith('Bearer '))
                self.assertIn('Idempotency-Key', kwargs['headers'])
                self.assertFalse(session.return_value.trust_env)

    def test_generation_preflight(self):
        base = {'subnet': '2001:db8::', 'protocol': 'http', 'start_port': 10000}
        self.assertEqual(generation_payload(base, 5)['count'], 5)
        for count in (0, 1025):
            with self.assertRaises(ValueError): generation_payload(base, count)
        with self.assertRaises(ValueError): generation_payload(dict(base, protocol='dual'), 513)
        with self.assertRaises(ValueError): generation_payload(base, 5, 65535)
        with self.assertRaises(ValueError): generation_payload({}, 5)

    def test_token_reload_between_bounded_polls(self):
        created = []
        class FakeBot:
            def __init__(self, token, **kwargs): created.append(token)
            def set_my_commands(self, commands): pass
            def message_handler(self, **kwargs): return lambda callback: callback
            def get_updates(self, **kwargs): return []
            def stop_polling(self): pass
        config_a = {'token': 'fixture-a', 'chat_id': '-42', 'allowed_user_ids': [11]}
        config_b = dict(config_a, token='fixture-b')
        fake_types = SimpleNamespace(BotCommand=lambda *args: args)
        with patch.dict(sys.modules, {'telebot': SimpleNamespace(TeleBot=FakeBot), 'telebot.types': fake_types}):
            with patch('telegram_bot.ApiClient') as api:
                api.return_value.config.side_effect = [config_a, config_a, config_b, config_b, KeyboardInterrupt()]
                with self.assertRaises(KeyboardInterrupt): run_bot()
        self.assertEqual(created, ['fixture-a', 'fixture-b'])


if __name__ == '__main__':
    unittest.main()
