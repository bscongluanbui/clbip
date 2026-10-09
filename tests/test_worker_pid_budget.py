"""Offline Compose contract: bound the worker's process/thread budget only."""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]


def mapping_block(text, name, indentation):
    """Read this Compose file's indentation-delimited mapping without PyYAML."""
    lines = text.splitlines()
    header = re.compile(r'^' + ' ' * indentation + re.escape(name) + r':(?:\s|$)')
    start = next(index for index, line in enumerate(lines) if header.match(line))
    result = []
    for line in lines[start + 1:]:
        if line.strip() and not line.lstrip().startswith('#'):
            depth = len(line) - len(line.lstrip())
            if depth <= indentation:
                break
        result.append(line)
    return '\n'.join(result)


class WorkerPidBudgetTests(unittest.TestCase):
    def setUp(self):
        self.compose = (ROOT / 'docker-compose.yml').read_text(encoding='utf-8')

    def test_worker_has_explicit_finite_thread_budget(self):
        worker = mapping_block(self.compose, 'worker', 2)
        limits = re.findall(r'^    pids_limit:\s*(\S+)\s*$', worker, re.MULTILINE)
        self.assertEqual(limits, ['${WORKER_THREAD_LIMIT:-4096}'])

    def test_dashboard_has_no_new_pid_override(self):
        dashboard = mapping_block(self.compose, 'dashboard', 2)
        self.assertNotRegex(dashboard, r'(?m)^    pids_limit:')

    def test_shared_defaults_do_not_disable_pid_limits(self):
        common = mapping_block(self.compose, 'x-common', 0)
        self.assertNotRegex(common, r'(?m)^  pids_limit:')
        self.assertEqual(len(re.findall(r'(?m)^\s*pids_limit:', self.compose)), 1)


if __name__ == '__main__':
    unittest.main()
