"""Worker host controller client does not need Docker access."""
import unittest
from unittest.mock import patch
from host_control import HostControlClient,HostControlError
from validation import settings_patch,ValidationError


class HostControlClientTests(unittest.TestCase):
    def test_thread_budget_validation(self):
        self.assertEqual(settings_patch({'thread_limit':4608})['thread_limit'],4608)
        for x in (True,255,16385,'4096'):
            with self.assertRaises(ValidationError):settings_patch({'thread_limit':x})

    def test_apply_requires_exact_effective_confirmation(self):
        c=HostControlClient()
        with patch.object(c,'_call',return_value={'previous_limit':4096,'effective_limit':4608}):
            self.assertEqual(c.apply_limit(4608)['effective_limit'],4608)
        with patch.object(c,'_call',return_value={'previous_limit':4096,'effective_limit':4096}):
            with self.assertRaises(HostControlError):c.apply_limit(4608)

    def test_missing_helper_is_unknown_not_zero(self):
        c=HostControlClient()
        with patch.object(c,'_call',side_effect=HostControlError('fixture absent')):
            status=c.status();self.assertFalse(status['available']);self.assertIsNone(status['effective_limit'])

    def test_cached_status_is_copy(self):
        c=HostControlClient()
        with patch.object(c,'_call',return_value={'effective_limit':4096}) as mock:
            one=c.status();one['effective_limit']=1;two=c.status()
            self.assertEqual(two['effective_limit'],4096);self.assertEqual(mock.call_count,1)

    def test_restore_checks_confirmation(self):
        c=HostControlClient()
        with patch.object(c,'_call',return_value={'effective_limit':4096}):self.assertEqual(c.restore_limit(4096)['effective_limit'],4096)
        with patch.object(c,'_call',return_value={'effective_limit':4608}):
            with self.assertRaises(HostControlError):c.restore_limit(4096)

    def test_restore_unlimited_leaf_uses_local_limit_when_parent_is_finite(self):
        c = HostControlClient()
        with patch.object(c, '_call', return_value={'local_limit': 'max', 'effective_limit': 8192}):
            self.assertEqual(c.restore_limit('max')['local_limit'], 'max')


if __name__=='__main__':unittest.main()
