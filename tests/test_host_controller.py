"""Host PID target, finite budget, persistence and rollback fixtures."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SPEC=importlib.util.spec_from_file_location('pid_helper_module',Path(__file__).resolve().parents[1]/'scripts/host_controller.py')
helper=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(helper)


class HostControllerTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        root=Path(self.temp.name);self.root=root;self.commands=[]
        self.cg=root/'sys/fs/cgroup/system.slice/fixed.scope';self.cg.mkdir(parents=True)
        (self.cg/'pids.max').write_text('4096');(self.cg/'pids.current').write_text('3200')
        (root/'proc/123').mkdir(parents=True);(root/'proc/123/cgroup').write_text('0::/system.slice/fixed.scope\n')
        self.obj={'Id':'fixed-worker-id','Config':{'Labels':{'com.docker.compose.project':'ipv6-proxy-manager',
                  'com.docker.compose.service':'worker'}},'State':{'Running':True,'Pid':123},
                  'Mounts':[{'Destination':'/run/ipv6-manager','Source':str(root/'runtime')}]}
        self.env=root/'.env';self.env.write_text('GUI_BIND=0.0.0.0\nOTHER=value\n');self.env.chmod(0o600)
        (root/'docker-compose.yml').write_text('services:\n  worker:\n    pids_limit: ${WORKER_THREAD_LIMIT:-4096}\n  dashboard:\n    image: fixture\n')
        def run(command):
            self.commands.append(command)
            if command[:2]==['docker','inspect']:return json.dumps([self.obj])
            if command[:2]==['docker','update']:
                self.assertEqual(command[-1],'fixed-worker-id');value=command[-2]
                (self.cg/'pids.max').write_text('max' if value=='-1' else value)
                return 'fixed-worker-id\n'
            self.fail(str(command))
        self.controller=helper.PidController(compose=root/'docker-compose.yml',runner=run,fs_root=root)

    def test_status_reads_actual_cgroup_not_hostconfig_default(self):
        self.assertEqual(self.controller.dispatch('status',{})['effective_limit'],4096)

    def test_set_persists_only_managed_env_key_no_restart(self):
        result=self.controller.dispatch('set_limit',{'limit':4608})
        self.assertEqual(result['previous_limit'],4096);self.assertEqual(result['effective_limit'],4608)
        self.assertFalse(result['restarted'])
        self.assertEqual(self.env.read_text(),'GUI_BIND=0.0.0.0\nOTHER=value\nWORKER_THREAD_LIMIT=4608\n')

    def test_lower_below_load_headroom_is_rejected_before_update(self):
        with self.assertRaisesRegex(helper.ControllerError,'3264'):self.controller.dispatch('set_limit',{'limit':3200})
        self.assertFalse(any(c[1]=='update' for c in self.commands))

    def test_bool_unlimited_large_or_arbitrary_commands_rejected(self):
        for value in (True,-1,'4096',20000,0):
            with self.assertRaises(helper.ControllerError):self.controller.dispatch('set_limit',{'limit':value})
        for method,params in [('exec',{}),('set_limit',{'limit':5000,'container':'other'}),('status',{'command':'x'})]:
            with self.assertRaises(helper.ControllerError):self.controller.dispatch(method,params)

    def test_wrong_compose_role_never_updates(self):
        self.obj['Config']['Labels']['com.docker.compose.service']='dashboard'
        with self.assertRaises(helper.ControllerError):self.controller.dispatch('set_limit',{'limit':4608})
        self.assertFalse(any(c[1]=='update' for c in self.commands))

    def test_rollback_only_matches_last_confirmed_limit(self):
        with self.assertRaises(helper.ControllerError):self.controller.dispatch('restore_limit',{'limit':4096})
        self.controller.dispatch('set_limit',{'limit':4608})
        with self.assertRaises(helper.ControllerError):self.controller.dispatch('restore_limit',{'limit':8192})
        restored=self.controller.dispatch('restore_limit',{'limit':4096})
        self.assertEqual(restored['effective_limit'],4096)
        self.assertEqual(self.env.read_text(),'GUI_BIND=0.0.0.0\nOTHER=value\n')

    def test_persistence_failure_restores_effective_limit(self):
        def fail(value):raise OSError('fixture disk error')
        self.controller._persist=fail
        with self.assertRaises(helper.ControllerError):self.controller.dispatch('set_limit',{'limit':4608})
        self.assertEqual((self.cg/'pids.max').read_text(),'4096')

    def test_parent_limit_is_effective_and_higher_requests_never_update(self):
        (self.cg.parent/'pids.max').write_text('3500')
        status=self.controller.dispatch('status',{})
        self.assertEqual(status['local_limit'],4096)
        self.assertEqual(status['effective_limit'],3500)
        self.assertEqual(status['parent_limit'],3500)
        with self.assertRaisesRegex(helper.ControllerError,'ancestor: 3500'):
            self.controller.dispatch('set_limit',{'limit':4608})
        self.assertFalse(any(c[1]=='update' for c in self.commands))

    def test_restoring_unlimited_leaf_preserves_finite_ancestor_and_original_env(self):
        (self.cg/'pids.max').write_text('max')
        (self.cg.parent/'pids.max').write_text('6000')
        self.controller.dispatch('set_limit',{'limit':4608})
        restored=self.controller.dispatch('restore_limit',{'limit':'max'})
        self.assertEqual(restored['local_limit'],'max')
        self.assertEqual(restored['effective_limit'],6000)
        self.assertEqual(self.env.read_text(),'GUI_BIND=0.0.0.0\nOTHER=value\n')

    def test_compose_must_consume_managed_variable_on_worker_field(self):
        for value in ('services:\n  worker:\n    pids_limit: 4096\n',
                      'services:\n  worker:\n    image: fixture\n  dashboard:\n    pids_limit: ${WORKER_THREAD_LIMIT:-4096}\n',
                      'x-example:\n  worker:\n    pids_limit: ${WORKER_THREAD_LIMIT:-4096}\nservices:\n  worker:\n    pids_limit: 4096\n'):
            with self.subTest(compose=value):
                self.controller.compose.write_text(value)
                with self.assertRaisesRegex(helper.ControllerError,'Compose worker'):
                    self.controller.dispatch('set_limit',{'limit':4608})
                self.assertFalse(any(c[1]=='update' for c in self.commands))

    def test_readback_failure_restores_live_and_exact_env(self):
        original=self.env.read_bytes();status=self.controller.status;calls=0
        def observe():
            nonlocal calls
            calls+=1
            if calls==2:raise OSError('fixture transient cgroup observation failure')
            return status()
        with patch.object(self.controller,'status',side_effect=observe):
            with self.assertRaisesRegex(helper.ControllerError,'đã xác nhận phục hồi'):
                self.controller.dispatch('set_limit',{'limit':4608})
        self.assertEqual((self.cg/'pids.max').read_text(),'4096')
        self.assertEqual(self.env.read_bytes(),original)
        self.assertIsNone(self.controller.rollback_ticket)

    def test_update_error_after_mutation_still_restores(self):
        runner=self.controller.runner;updates=0
        def run(command):
            nonlocal updates
            result=runner(command)
            if command[1]=='update':
                updates+=1
                if updates==1:raise helper.ControllerError('fixture update acknowledgement failure')
            return result
        self.controller.runner=run
        with self.assertRaisesRegex(helper.ControllerError,'đã xác nhận phục hồi'):
            self.controller.dispatch('set_limit',{'limit':4608})
        self.assertEqual((self.cg/'pids.max').read_text(),'4096')
        self.assertEqual(updates,2)

    def test_persistence_error_after_replace_restores_exact_env(self):
        original=self.env.read_bytes();persist=self.controller._persist
        def fail(value):
            persist(value)
            raise OSError('fixture acknowledgement failure after replace')
        self.controller._persist=fail
        with self.assertRaisesRegex(helper.ControllerError,'đã xác nhận phục hồi'):
            self.controller.dispatch('set_limit',{'limit':4608})
        self.assertEqual((self.cg/'pids.max').read_text(),'4096')
        self.assertEqual(self.env.read_bytes(),original)

    def test_failed_rollback_is_not_reported_as_restored(self):
        status=self.controller.status;calls=0
        def observe():
            nonlocal calls
            calls+=1
            if calls>=2:raise OSError('fixture persistent observation error')
            return status()
        with patch.object(self.controller,'status',side_effect=observe):
            with self.assertRaisesRegex(helper.ControllerError,'rollback chưa xác nhận'):
                self.controller.dispatch('set_limit',{'limit':4608})

    def test_ticket_does_not_restore_recreated_worker(self):
        self.controller.dispatch('set_limit',{'limit':4608})
        self.obj['Id']='replacement-worker-id'
        with self.assertRaisesRegex(helper.ControllerError,'ticket không khớp'):
            self.controller.dispatch('restore_limit',{'limit':4096})

    def test_rollback_removes_env_if_absent_before_apply(self):
        self.env.unlink()
        self.controller.dispatch('set_limit',{'limit':4608})
        self.assertTrue(self.env.exists())
        self.controller.dispatch('restore_limit',{'limit':4096})
        self.assertFalse(self.env.exists())

    def test_env_owner_preserved_when_root_replaces_file(self):
        metadata=self.env.stat()
        with patch.object(helper.os,'chown',create=True) as chown:
            self.controller.dispatch('set_limit',{'limit':4608})
            chown.assert_called_once()
            self.assertEqual(chown.call_args.args[1:],(metadata.st_uid,metadata.st_gid))

    def test_new_env_owner_matches_compose_owner(self):
        self.env.unlink();metadata=self.controller.compose.stat()
        with patch.object(helper.os,'chown',create=True) as chown:
            self.controller.dispatch('set_limit',{'limit':4608})
            self.assertEqual(chown.call_args.args[1:],(metadata.st_uid,metadata.st_gid))

    def test_parent_counter_invalid_is_not_treated_as_unlimited(self):
        (self.cg.parent/'pids.max').write_text('unknown')
        with self.assertRaisesRegex(helper.ControllerError,'counter không hợp lệ'):
            self.controller.dispatch('set_limit',{'limit':4608})
        self.assertFalse(any(c[1]=='update' for c in self.commands))


if __name__=='__main__':unittest.main()
