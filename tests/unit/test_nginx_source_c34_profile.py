"""Controls for the fixed private NEWC34_INTEROP artifact/profile foundation."""
import importlib.util
import contextlib
import io
import ipaddress
import os
from pathlib import Path
import time
import tempfile
from types import SimpleNamespace, MethodType
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
PROVIDER_PATH = ROOT / 'tools/nginx_source_c34_artifact_provider.py'
C22_PATH = ROOT / 'tools/nginx_source_c22_provider.py'
CONTROLLER_PATH = ROOT / 'tools/nginx_source_shell_controller.py'
KER_RUN_PATH = ROOT / 'tools/ker-run.py'


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    import sys
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class PrivateC34ArtifactTests(unittest.TestCase):
    def setUp(self):
        self.provider = load_module('_ker_nginx_source_c34_artifacts', PROVIDER_PATH)

    def _require_private_capture(self):
        if not self.provider._BUILD_MANIFEST.exists():
            self.skipTest('fixed C34 artifact build manifest is unavailable')

    def test_fixed_capture_holds_reviewed_artifacts_and_abi1_helper(self):
        self._require_private_capture()
        capture = self.provider.PrivateC34ArtifactCapture.capture(
            time.monotonic_ns() + 15_000_000_000)
        try:
            self.assertEqual(capture.profile_id, 'NEWC34_INTEROP')
            self.assertEqual(capture.test_backend_role,
                'TEST_ONLY_RX_OWNER_RELAY_CONTROL_ADAPTER')
            self.assertEqual(capture.artifact('nginx').sha256,
                'f9e1e4d01720f1050e6521e22d7d1dc10dd4aaadab62448aac83a4e51dfa4c10')
            self.assertEqual(capture.artifact('shim').sha256,
                'b2938bfe9123ddb5a49f5ef20729422215580cd5ebd52702150d2854a57112cb')
            self.assertEqual(capture.helper_capture.build_id,
                '8de64befb2531f8af86217930097ffa4668d1f82')
            self.assertEqual(capture.helper_capture.source_command_abi, 1)
            self.assertEqual(capture.artifact('test_backend').sha256,
                '18a432bdf8e0ef65b5f7e9df59d2022568cd41607d4813f9d2b765c0bc726e25')
            self.assertEqual(capture.source_head, '646a641cfff77f4815e1e29829a09e1ed15a2999')
            self.assertEqual(capture.source_symbols['ngx_cycle'], (0x624608, 'B'))
            self.assertGreaterEqual(capture.artifact('runner_aliases').identity[2], 1)
            self.assertGreaterEqual(len(capture._artifacts), 17)
            self.assertEqual(capture.artifact('abi2_ini_header').sha256,
                'acd7345019b57d5bfa8cccb532459c64fb330196de5f22b7a72ad57c608f52fa')
            capture.verify(time.monotonic_ns() + 15_000_000_000)
            with self.assertRaises(TypeError):
                capture._artifacts['nginx'] = capture.artifact('shim')
            with self.assertRaises(AttributeError):
                capture.artifact('nginx').sha256 = '0' * 64
        finally:
            capture.close()


    def test_capture_rejects_manifest_replacement_from_a_separate_path(self):
        self._require_private_capture()
        import hashlib
        with tempfile.TemporaryDirectory(prefix='newc34-manifest-tamper-') as directory:
            replacement = Path(directory) / 'manifest.json'
            replacement.write_text('{"source_head":"stale"}')
            original = self.provider._FIXED_ARTIFACTS['build_manifest']
            with mock.patch.dict(self.provider._FIXED_ARTIFACTS,
                    {'build_manifest':(replacement,original[1],None)}):
                with self.assertRaisesRegex(PermissionError, 'differs from accepted digest'):
                    self.provider.PrivateC34ArtifactCapture.capture(
                        time.monotonic_ns()+15_000_000_000)

    def test_helper_fd_transfer_preserves_bytes_digest_contract(self):
        self._require_private_capture()
        capture = self.provider.PrivateC34ArtifactCapture.capture(
            time.monotonic_ns() + 15_000_000_000)
        helper = capture.helper_capture
        # Keep the parent capture and its held anchors alive through transfer.
        fd, metadata, digest = helper._take_helper_fd(helper._deadline_ns)
        try:
            self.assertIs(type(digest), bytes)
            self.assertEqual(len(digest), 32)
            self.assertEqual(digest.hex(),
                'ac3b9a8dd1754e169ec89632a02d8854c529388e3298d939a3de01e102449310')
            self.assertEqual((os.fstat(fd).st_dev, os.fstat(fd).st_ino), metadata[:2])
            self.assertEqual(os.get_inheritable(fd), False)
        finally:
            os.close(fd)
            capture.close()

    def test_private_capture_constructor_cannot_accept_caller_artifacts(self):
        with self.assertRaises(TypeError):
            self.provider.PrivateC34ArtifactCapture(object(), {})
        with self.assertRaises(TypeError):
            self.provider.PrivateC34HelperCapture(object(), ())

    def test_c22_dispatch_rejects_abi1_capture_without_private_dispatch(self):
        provider = load_module('_c34_c22_provider_negative_test', C22_PATH)
        capture = object.__new__(self.provider.PrivateC34HelperCapture)
        object.__setattr__(capture, '_sealed', True)
        object.__setattr__(capture, 'source_command_abi', 1)
        context = type('Context', (), {'shell_mode': True, 'nonce': b'a' * 16, 'epoch': 1})()
        with self.assertRaises(TypeError):
            provider.SourceShellC22Provider(context, object(), capture)

    def test_private_provider_dispatch_requires_exact_capture_type(self):
        provider = load_module('_c34_c22_provider_private_test', C22_PATH)
        with self.assertRaises(TypeError):
            provider.SourceShellC34InteropProvider(object(), object(), object())

    def test_retry_helper_argv_requires_matching_origin_context_and_capture(self):
        module = load_module('_c34_retry_helper_launch_test', C22_PATH)
        helper_type = self.provider.PrivateC34HelperCapture
        class BeforeExec(Exception):
            pass

        for fault, origin_fault, retry, enabled, expected in (
                (None, None, False, False, '--source-shell'),
                ('flip_fail_once', 'flip_fail_once', True, True,
                    '--source-shell-abort-retry'),
                (None, 'flip_fail_once', True, True, None),
                ('flip_fail_once', 'flip_fail_once', False, True, None),
                ('flip_fail_once', None, True, True, None),
                ('flip_fail_once', 'flip_fail_once', True, False, None)):
            with self.subTest(fault=fault, origin_fault=origin_fault, retry=retry, enabled=enabled):
                helper = object.__new__(helper_type)
                helper.sha256 = bytes.fromhex(self.provider._HELPER_SHA256)
                helper.build_id = self.provider._HELPER_BUILD_ID
                helper.source_command_abi = 1
                helper.source_fault = fault
                context = SimpleNamespace(shell_mode=True, nonce=b's' * 16,
                    epoch=1, deadline_ns=time.monotonic_ns() + 5_000_000_000,
                    original_supervisor_identity=object(), allow_abort_retry=retry)
                origin = SimpleNamespace(context=context,
                    c34_artifact_capture=SimpleNamespace(source_fault=origin_fault),
                    artifact_binding=SimpleNamespace(broker_path='/private/broker.sock'),
                    environment={'KER_SOCKET_BROKER_PATH': '/private/broker.sock'})
                if enabled:
                    origin.environment['KER_NGINX_SOURCE_ABORT_RETRY_ENABLE'] = '1'
                context.owner_live = MethodType(lambda self, deadline: None, origin)
                readiness = SimpleNamespace(ready=True, stopped=False, nonce=b'b' * 16, epoch=1)

                def take_helper(deadline):
                    return os.open('/dev/null', os.O_RDONLY | os.O_CLOEXEC), (), helper.sha256

                with mock.patch.object(helper_type, '_take_helper_fd', side_effect=take_helper), \
                        mock.patch.object(module, '_source_listener_tuple',
                            return_value=('0.0.0.0', 80, 511)), \
                        mock.patch.object(module.subprocess, 'Popen', side_effect=BeforeExec) as launch:
                    if expected is None:
                        with self.assertRaisesRegex(PermissionError, 'accepted fault launch'):
                            module.SourceShellC34InteropProvider(context, readiness, helper)
                        launch.assert_not_called()
                    else:
                        with self.assertRaises(BeforeExec):
                            module.SourceShellC34InteropProvider(context, readiness, helper)
                        self.assertEqual(launch.call_args.args[0][3], expected)

    def test_sdk_rt24_rejects_production_bundle_before_artifact_capture(self):
        ker_run = load_module('_c34_fault_selector_negative_test', KER_RUN_PATH)
        with tempfile.TemporaryDirectory(prefix='c34-fault-selector-') as path:
            broker = str(Path(path) / 'broker.sock')
            nginx = self.provider._FIXED_ARTIFACTS['nginx'][0]
            args = SimpleNamespace(command=['/fixed/backend', broker],
                control_nginx_owner_module=None)
            env = {'KER_SOCKET_BROKER_PATH': broker,
                'KER_FSTACK_NGINX_INI': str(Path(path) / 'out/fstack_rt24.ini')}
            control = (nginx, None, None, env, None, None, True, True)
            with mock.patch.object(self.provider.PrivateC34ArtifactCapture, 'capture') as capture:
                with self.assertRaisesRegex(ValueError, 'matching pinned fault build'):
                    ker_run._capture_private_c34_source_controller(
                        args, {'deadline_ns': time.monotonic_ns() + 10_000_000_000}, control)
                capture.assert_not_called()

    def _profile(self, case='rt01', ini_case=None):
        self._require_private_capture()
        ker_run = load_module('_c34_profile_ker_run_test', KER_RUN_PATH)
        controller = load_module('_c34_profile_controller_test', CONTROLLER_PATH)
        startup = ker_run.source_network_startup
        origin = load_module('_c34_profile_origin_test', ROOT / 'tools/nginx_source_origin.py')
        deadline = time.monotonic_ns() + 10_000_000_000
        directory = tempfile.TemporaryDirectory(prefix='newc34-profile-test-')
        try:
            root = Path(directory.name); scope = root / 'scope'; scope.mkdir(mode=0o700)
            template = root / 'fstack.conf'; template.write_text('fixture\n')
            output = root / 'new-output'
            expectation = startup.SourceNetworkExpectation(str(template), 'a' * 64,
                '198.18.0.2', '255.255.255.0', '198.18.0.255', '198.18.0.1',
                deadline, None)
            environment = {
                'KER_NGINX_SOURCE_SHELL_ENABLE':'1',
                'KER_NGINX_SOURCE_FIRST_HUP_ENABLE':'1',
                'KER_NGINX_SOURCE_BOOTSTRAP_NONCE':'a'*32,
                'KER_NGINX_SOURCE_BOOTSTRAP_EPOCH':'19',
                startup.BOOTSTRAP_DEADLINE_ENV:str(deadline),
                'KER_FSTACK_NGINX_INI':str(output / f'fstack_{ini_case or case}.ini'),
                'KER_NGINX_SOURCE_BOOTSTRAP_SUPERVISOR_PID':str(os.getpid()),
                'KER_NGINX_SOURCE_BOOTSTRAP_SUPERVISOR_START':str(ker_run.process_start_ticks(os.getpid())),
            }
            profile_module=controller._c34_profile_module()
            args=['--cases',f'precheck,{case}','--workers','1','--graceful','1',
                '--target-ip',expectation.address,'--out',str(output),
                '--fstack-conf',str(template),'--nginx',
                str(self.provider.PrivateC34ArtifactCapture.capture.__func__.__globals__['_FIXED_ARTIFACTS']['nginx'][0]),
                '--build-manifest',str(self.provider._BUILD_MANIFEST)]
            profile=profile_module.PrivateNewC34InteropProfile.capture(origin,startup,
                source_root=self.provider._SOURCE_ROOT,arguments=args,environment=environment,
                network_expectation=expectation,scope_directory=scope,stdout=None,
                stderr=None,port_name='eth0')
            return controller,profile,directory
        except BaseException:
            directory.cleanup()
            raise

    def test_traffic_profiles_require_matching_generated_ini(self):
        for case in ('rt02', 'rt23', 'rt30', 'rt31'):
            with self.subTest(case=case):
                _, profile, temporary = self._profile(case)
                try:
                    self.assertIn(f'precheck,{case}', profile.arguments)
                    self.assertEqual(profile.environment['KER_FSTACK_NGINX_INI'],
                        str(Path(profile.output) / f'fstack_{case}.ini'))
                finally:
                    profile.close()
                    temporary.cleanup()
                with self.assertRaisesRegex(PermissionError, 'INI path'):
                    self._profile(case, ini_case='rt01')

    def test_private_profile_exact_dispatch_and_helper_provider_route(self):
        controller_module, profile, temporary = self._profile()
        try:
            controller=controller_module.SourceShellController(profile)
            self.assertIs(controller.profile,profile)
            context=SimpleNamespace(control_only=True)
            controller.bootstrap_context=context
            launch=object.__new__(profile.origin_module.PrivateC34OriginalShellLaunch)
            launch.context=context
            launch.c34_artifact_capture=profile.artifact_capture
            controller.launch=launch
            sentinel=object()
            provider=controller_module._c22_provider_module()
            readiness=object()
            with mock.patch.object(provider,'SourceShellC34InteropProvider',
                    return_value=sentinel) as construct:
                self.assertIs(controller.start_c34_interop_provider(readiness),sentinel)
            construct.assert_called_once_with(context,readiness,profile.helper_capture)
        finally:
            profile.close()
            temporary.cleanup()

    def test_private_pump_readiness_dispatches_c34_provider_not_c22(self):
        controller_module, profile, temporary = self._profile()
        try:
            controller=controller_module.SourceShellController(profile)
            controller.bootstrap_context=SimpleNamespace()
            controller.launch=SimpleNamespace(process=None)
            called=[]
            controller.start_c34_interop_provider=lambda readiness: called.append(('c34',readiness))
            controller.start_c22_provider=lambda readiness: self.fail('private pump selected C22')
            controller.pump_bootstrap_listener=lambda: False
            controller.poll_source_preexit=lambda: None
            readiness=SimpleNamespace(ready=True,stopped=False)
            self.assertFalse(controller.pump_source_requests(readiness))
            self.assertEqual(called,[('c34',readiness)])
        finally:
            profile.close(); temporary.cleanup()

    def test_private_pump_constructs_exact_abi1_provider_at_mocked_popen_boundary(self):
        controller_module, profile, temporary = self._profile()
        try:
            provider_module=controller_module._c22_provider_module()
            origin=object.__new__(profile.origin_module.PrivateC34OriginalShellLaunch)
            bootstrap=profile.origin_module.bootstrap
            context=object.__new__(bootstrap.SourceBootstrapSupervisor)
            origin_context_id={'pid':os.getpid()}
            context.control_only=True; context.shell_mode=True
            context.nonce=b'n'*16; context.epoch=19; context.deadline_ns=profile.deadline_ns
            context.original_supervisor_identity=origin_context_id
            origin.context=context
            origin.c34_artifact_capture=profile.artifact_capture
            origin.original_supervisor_identity=origin_context_id
            origin.environment={'KER_SOCKET_BROKER_PATH':'/private/fixed-broker.sock'}
            config_data=b'listen 80;\n'
            artifact=SimpleNamespace(broker_path='/private/fixed-broker.sock',
                config=SimpleNamespace(data=config_data),
                config_file_sha256=__import__('hashlib').sha256(config_data).hexdigest(),
                config_sha256=(b'a'*32).hex(),ini_sha256=(b'b'*32).hex())
            origin.artifact_binding=artifact
            origin.origin_proof=SimpleNamespace(adapter_cycle_serial=1,opaque_cycle_token=22)
            cycle=SimpleNamespace(adapter_cycle_serial=1,opaque_cycle_token=22,
                config_sha256=b'a'*32,ini_sha256=b'b'*32)
            context.initial_cycle_proof=cycle
            context.expected_config_sha256=b'a'*32; context.expected_ini_sha256=b'b'*32
            origin.deadline_ns=profile.deadline_ns; origin.epoch=context.epoch; origin.nonce=context.nonce
            origin.live_supervisor=MethodType(lambda self,_deadline: True,origin)
            origin._original_artifacts_live=MethodType(lambda self,_deadline: True,origin)
            context.owner_live=origin.live_supervisor
            context.live=MethodType(lambda self: True,context)
            self.assertEqual(cycle.adapter_cycle_serial, origin.origin_proof.adapter_cycle_serial)
            self.assertEqual(cycle.opaque_cycle_token, origin.origin_proof.opaque_cycle_token)
            self.assertEqual(cycle.config_sha256.hex(), artifact.config_sha256)
            self.assertEqual(cycle.ini_sha256.hex(), artifact.ini_sha256)
            self.assertEqual(context.expected_config_sha256.hex(), artifact.config_sha256)
            self.assertEqual(context.expected_ini_sha256.hex(), artifact.ini_sha256)
            self.assertEqual(context.deadline_ns, origin.deadline_ns)
            self.assertEqual((context.epoch,context.nonce),(origin.epoch,origin.nonce))
            self.assertEqual(provider_module._source_listener_tuple(context),
                ('0.0.0.0',80,511))
            context.owner_live=lambda: None
            with self.assertRaises(PermissionError):
                provider_module._source_listener_tuple(context)
            context.owner_live=origin.live_supervisor
            controller=controller_module.SourceShellController(profile)
            controller.bootstrap_context=context
            controller.launch=origin
            readiness=SimpleNamespace(ready=True,stopped=False,nonce=b'b'*16,epoch=21)
            command_box={}
            class CapturedBeforeExec(Exception): pass
            def capture_popen(argv,**kwargs):
                command_box['argv']=list(argv); command_box['kwargs']=kwargs
                raise CapturedBeforeExec('stop before helper execution')
            with mock.patch.object(provider_module.subprocess,'Popen',side_effect=capture_popen):
                with self.assertRaises(CapturedBeforeExec):
                    controller.pump_source_requests(readiness)
            argv=command_box['argv']; kwargs=command_box['kwargs']
            self.assertEqual(len(argv),15)
            self.assertEqual(argv[0],f'/proc/self/fd/{kwargs["pass_fds"][1]}')
            self.assertEqual(argv[1],'/private/fixed-broker.sock')
            self.assertEqual(argv[3],'--source-shell')
            self.assertEqual(argv[7:9],[context.nonce.hex(),str(context.epoch)])
            self.assertEqual(argv[9:11],[readiness.nonce.hex(),str(readiness.epoch)])
            self.assertEqual(len(kwargs['pass_fds']),3)
            self.assertTrue(kwargs['close_fds'])
            self.assertEqual(profile.helper_capture.source_command_abi,1)
            self.assertIsNone(controller.c22_provider)
        finally:
            profile.close(); temporary.cleanup()

    def test_sdk_selector_keeps_old_default_and_selects_only_fixed_private_profile(self):
        ker_run = load_module('_c34_selector_ker_run_test', KER_RUN_PATH)
        existing = object()
        ordinary = SimpleNamespace(control_nginx_source_private_c34_profile=False)
        self.assertIs(ker_run._select_source_shell_controller(
            ordinary, existing, None, None), existing)
        selected = SimpleNamespace(control_nginx_source_private_c34_profile=True)
        sentinel = object()
        expected = object()
        control = (object(),) * 8
        with mock.patch.object(ker_run, '_capture_private_c34_source_controller',
                return_value=sentinel) as capture:
            self.assertIs(ker_run._select_source_shell_controller(
                selected, None, expected, control), sentinel)
        capture.assert_called_once_with(selected, expected, control, None, None)
        with self.assertRaises(ValueError):
            ker_run._select_source_shell_controller(selected, existing, expected, control)

    def test_sdk_private_selector_captures_fixed_artifact_tuple_without_launch(self):
        self._require_private_capture()
        ker_run = load_module('_c34_sdk_capture_ker_run_test', KER_RUN_PATH)
        startup = ker_run.source_network_startup
        deadline = time.monotonic_ns() + 60_000_000_000
        with tempfile.TemporaryDirectory(prefix='newc34-sdk-selection-') as directory:
            root = Path(directory)
            output = root / 'fresh-output'
            origin = ker_run._load_source_origin_module()
            module = self.provider
            nginx = Path(module._FIXED_ARTIFACTS['nginx'][0])
            fixed_backend = Path(module._FIXED_ARTIFACTS['test_backend'][0])
            preload = ':'.join(str(Path(module._FIXED_ARTIFACTS[name][0]))
                for name in ('runtime', 'preload', 'shim'))
            args = SimpleNamespace(port='eth0', control_nginx_owner_module=None,
                address=ipaddress.IPv4Interface('192.168.1.2/24'),
                gateway=ipaddress.IPv4Address('192.168.1.1'),
                command=[str(fixed_backend), str(root/'broker.sock')], control_nginx_binary=nginx,
                control_nginx_config=root/'nginx.conf', control_nginx_prefix=root,
                control_nginx_env=[
                    'LD_PRELOAD=' + preload,
                    'KER_SOCKET_BROKER_PATH=' + str(root/'broker.sock'),
                    'KER_FSTACK_NGINX_INI=' + str(output/'fstack_rt01.ini')],
                control_nginx_owner_ready=True,
                control_nginx_source_bootstrap_required=True,
                control_nginx_rx_relay=True, control_nginx_source_shell_profile=True,
                control_nginx_source_private_c34_profile=True,
                broker_readiness=True,runtime_service=True,rx_decision=True,
                queues=1,rx_lcores='1')
            launch_environment, network_temp, typed = ker_run._new_private_c34_network_input(
                args, {'KER_NGINX_SOURCE_SHELL_ENABLE':'1',
                    'KER_NGINX_SOURCE_BOOTSTRAP_DEADLINE_NS':str(deadline)})
            expectation = startup.prepare_expected('1', typed.readback_setting(),
                launch_environment['KER_NGINX_SOURCE_BOOTSTRAP_DEADLINE_NS'],
                ipaddress.IPv4Interface(typed.address + '/24'),
                ipaddress.IPv4Address(typed.gateway), now_ns=time.monotonic_ns())
            config = root / 'nginx.conf'; config.write_text('events {}\n')
            args = SimpleNamespace(port='eth0', control_nginx_owner_module=None,
                address=ipaddress.IPv4Interface('192.168.1.2/24'),
                gateway=ipaddress.IPv4Address('192.168.1.1'),
                command=[str(fixed_backend), str(root/'broker.sock')], control_nginx_binary=nginx,
                control_nginx_config=config, control_nginx_prefix=root,
                control_nginx_env=list(args.control_nginx_env),
                control_nginx_owner_ready=True,
                control_nginx_source_bootstrap_required=True,
                control_nginx_rx_relay=True,
                control_nginx_source_shell_profile=True,
                control_nginx_source_private_c34_profile=True,
                broker_readiness=True,runtime_service=True,rx_decision=True,
                queues=1,rx_lcores='1',vlans=[],vlan_gateways=[],vlan_gateways6=[],
                interfaces=[],bonds=[],vdevs=[],address6=None,gateway6=None,
                vip_addresses=[],vip_addresses6=[],promiscuous=None,all_multicast=False,
                exception_iface=None,sysctls={},tcp_ecn=None)
            control = ker_run.control_nginx_profile(args)
            controller = ker_run._capture_private_c34_source_controller(
                args, expectation, control, typed, network_temp)
            network_temp = None
            try:
                profile_type = ker_run._load_source_shell_controller()._c34_profile_module().PrivateNewC34InteropProfile
                self.assertIs(type(controller.profile),
                    profile_type)
                self.assertEqual(controller.profile.epoch, 1)
                self.assertEqual(controller.profile.profile_id, 'NEWC34_INTEROP')
                self.assertEqual(controller.profile.nginx, nginx)
                self.assertEqual(controller.profile.helper_capture.source_command_abi, 1)
                self.assertEqual(controller.profile.source_root,
                    self.provider._SOURCE_ROOT.resolve(strict=True))
                self.assertTrue(controller.profile.scope_directory.is_relative_to('/dev/shm'))
                self.assertFalse(ker_run._needs_nginx_companion(controller, control))
                self.assertTrue(ker_run._needs_nginx_companion(None, control))
                self.assertEqual(controller.profile.arguments[-2:], ('--build-manifest',
                    str(self.provider._BUILD_MANIFEST)))
                self.assertFalse(output.exists())
                self.assertIsNone(controller.launch)
                controller_module = ker_run._load_source_shell_controller()
                args.control_nginx_source_private_c34_profile = False
                controller.validate_main(expectation, control, args)
                with mock.patch.object(ker_run, 'parse_arguments', return_value=args), \
                        mock.patch.object(startup, 'prepare_from_launch', return_value=expectation), \
                        mock.patch.object(ker_run.subprocess, 'Popen') as popen, \
                        contextlib.redirect_stderr(io.StringIO()) as stderr:
                    self.assertEqual(ker_run.main(source_shell_controller=controller), 125)
                    self.assertIn('NEWC34_INTEROP held pending end-to-end qualification',
                        stderr.getvalue())
                    self.assertNotIn('source controller does not match', stderr.getvalue())
                    popen.assert_not_called()
                self.assertFalse(Path(controller._private_c34_network_temp.name).exists())
            finally:
                ker_run._close_private_c34_source_controller(controller)
                if network_temp is not None:
                    typed.template_file.close(); network_temp.cleanup()

    def test_sdk_private_selector_rejects_conflicting_nginx_artifact(self):
        ker_run = load_module('_c34_sdk_reject_ker_run_test', KER_RUN_PATH)
        startup = ker_run.source_network_startup
        deadline = time.monotonic_ns() + 60_000_000_000
        with tempfile.TemporaryDirectory(prefix='newc34-sdk-reject-') as directory:
            root = Path(directory)
            template = root / 'source.ini'; template.write_text('fixture\n')
            expectation = startup.SourceNetworkExpectation(str(template), 'a' * 64,
                '198.18.0.2', '255.255.255.0', '198.18.0.255', '198.18.0.1',
                deadline, None)
            environment = {'KER_FSTACK_NGINX_INI':str(root/'fresh'/'fstack_rt01.ini'),
                'KER_SOCKET_BROKER_PATH':str(root/'broker.sock')}
            backend = Path(self.provider._FIXED_ARTIFACTS['test_backend'][0])
            args = SimpleNamespace(port='eth0', control_nginx_owner_module=None,
                command=[str(backend),str(root/'broker.sock')])
            expected_deadline = time.monotonic_ns()+10_000_000_000
            expected = {'record':'v1|'+'a'*64+'|192.168.1.2|255.255.255.0|192.168.1.255|192.168.1.1|'+str(expected_deadline),
                'template_sha256':'a'*64,'address':'192.168.1.2','netmask':'255.255.255.0',
                'broadcast':'192.168.1.255','gateway':'192.168.1.1',
                'deadline_ns':expected_deadline}
            expected['record'] = 'v1|'+expected['template_sha256']+'|'+expected['address']+'|'+expected['netmask']+'|'+expected['broadcast']+'|'+expected['gateway']+'|'+str(expected['deadline_ns'])
            with self.assertRaisesRegex(ValueError, 'conflicting Nginx'):
                ker_run._capture_private_c34_source_controller(args, expected,
                    (root/'wrong-nginx', root/'config', root, environment, True, True, True, True))
            nginx = Path(self.provider._FIXED_ARTIFACTS['nginx'][0])
            wrong_owner = root / 'wrong-owner.so'; wrong_owner.write_bytes(b'wrong')
            args.control_nginx_owner_module = wrong_owner
            with self.assertRaisesRegex(ValueError, 'rejects an external owner module'):
                ker_run._capture_private_c34_source_controller(args, expected,
                    (nginx, root/'config', root, environment, True, True, True, True))

    def test_cli_private_profile_renders_parsed_network_and_holds_without_actor(self):
        self._require_private_capture()
        ker_run = load_module('_c34_cli_capture_ker_run_test', KER_RUN_PATH)
        module = self.provider
        nginx = Path(module._FIXED_ARTIFACTS['nginx'][0])
        backend = Path(module._FIXED_ARTIFACTS['test_backend'][0])
        preload = ':'.join(str(Path(module._FIXED_ARTIFACTS[name][0]))
            for name in ('runtime', 'preload', 'shim'))
        with tempfile.TemporaryDirectory(prefix='newc34-cli-') as directory:
            root = Path(directory)
            config = root/'nginx.conf'; config.write_text('events {}\n')
            output = root/'fresh-output'
            argv = ['ker-run', '--address', '192.168.1.2/24', '--gateway',
                '192.168.1.1', '--eal=--no-huge', '--port', 'eth0', '--runtime-service',
                '--rx-decision', '--broker-readiness', '--queues', '1',
                '--rx-lcores', '1', '--control-nginx-binary', str(nginx),
                '--control-nginx-config', str(config), '--control-nginx-prefix', str(root),
                '--control-nginx-owner-ready', '--control-nginx-source-bootstrap-required',
                '--control-nginx-source-shell-profile', '--control-nginx-source-private-c34-profile',
                '--control-nginx-rx-relay', '--control-nginx-env',
                'LD_PRELOAD=' + preload,
                '--control-nginx-env', 'KER_SOCKET_BROKER_PATH='+str(root/'broker.sock'),
                '--control-nginx-env', 'KER_FSTACK_NGINX_INI='+str(output/'fstack_rt01.ini'),
                '--', str(backend), str(root/'broker.sock')]
            controller_module = ker_run._load_source_shell_controller()
            with mock.patch.object(ker_run.sys, 'argv', argv), \
                    mock.patch.object(ker_run.subprocess, 'Popen') as popen, \
                    contextlib.redirect_stderr(io.StringIO()) as stderr:
                self.assertEqual(ker_run.main(), 125)
                self.assertIn('NEWC34_INTEROP held pending end-to-end qualification',
                    stderr.getvalue())
                self.assertNotIn('source controller does not match', stderr.getvalue())
                popen.assert_not_called()
            self.assertFalse(output.exists())

    def test_private_launch_default_covers_timed_probe_and_startup(self):
        ker_run = load_module('_c34_timed_launch_ker_run_test', KER_RUN_PATH)
        args = SimpleNamespace(address=ipaddress.IPv4Interface('192.168.1.2/24'),
            gateway=ipaddress.IPv4Address('192.168.1.1'),
            control_nginx_env=['KER_SOCKET_BROKER_PATH=/run/ker/broker.sock'])
        before = time.monotonic_ns()
        environment, temporary, capture = ker_run._new_private_c34_network_input(args, {})
        try:
            self.assertGreater(capture.deadline_ns - before, 208_000_000_000)
            self.assertLessEqual(capture.deadline_ns - before,
                ker_run.source_network_startup.MAX_DEADLINE_AHEAD_NS)
            self.assertEqual(environment[ker_run.source_network_startup.BOOTSTRAP_DEADLINE_ENV],
                str(capture.deadline_ns))
        finally:
            capture.template_file.close()
            temporary.cleanup()

    def test_private_input_render_failures_remove_temporary_directory(self):
        ker_run = load_module('_c34_input_cleanup_ker_run_test', KER_RUN_PATH)
        with tempfile.TemporaryDirectory(prefix='newc34-input-cleanup-') as directory:
            root = Path(directory)
            args = SimpleNamespace(address=ipaddress.IPv4Interface('192.168.1.2/24'),
                gateway=ipaddress.IPv4Address('192.168.1.1'),
                control_nginx_env=['KER_SOCKET_BROKER_PATH='+str(root/'broker.sock')])
            original = tempfile.TemporaryDirectory
            created = []
            def tracked(*args, **kwargs):
                item = original(*args, **kwargs); created.append(item); return item
            for fail in ('write', 'origin_import'):
                before_fds = set(os.listdir('/proc/self/fd'))
                with mock.patch.object(ker_run.tempfile, 'TemporaryDirectory', side_effect=tracked):
                    if fail == 'write':
                        with mock.patch.object(ker_run.os, 'fsync', side_effect=OSError('injected fsync failure')):
                            with self.assertRaisesRegex(OSError, 'injected fsync failure'):
                                ker_run._new_private_c34_network_input(args, {})
                    else:
                        with mock.patch.object(ker_run, '_load_source_origin_module',
                                side_effect=ImportError('injected Origin import failure')):
                            with self.assertRaisesRegex(ImportError, 'injected Origin import failure'):
                                ker_run._new_private_c34_network_input(args, {})
                    self.assertTrue(created[-1].name.startswith('/dev/shm/ker-newc34-input-'))
                    self.assertFalse(Path(created[-1].name).exists())
                self.assertEqual(set(os.listdir('/proc/self/fd')), before_fds)


    def test_sdk_private_selector_rejects_command_broker_mismatch_before_capture(self):
        ker_run = load_module('_c34_sdk_command_reject_ker_run_test', KER_RUN_PATH)
        with tempfile.TemporaryDirectory(prefix='newc34-command-reject-') as directory:
            root = Path(directory)
            args = SimpleNamespace(command=['/fixed/backend',str(root/'other.sock')],
                control_nginx_owner_module=None)
            control = (Path('/fixed/nginx'),None,None,
                {'KER_SOCKET_BROKER_PATH':str(root/'broker.sock')},True,True,True,True)
            deadline=time.monotonic_ns()+10_000_000_000; digest='a'*64
            record=f'v1|{digest}|192.168.1.2|255.255.255.0|192.168.1.255|192.168.1.1|{deadline}'
            expected={'record':record,'template_sha256':digest,'address':'192.168.1.2',
                'netmask':'255.255.255.0','broadcast':'192.168.1.255',
                'gateway':'192.168.1.1','deadline_ns':deadline}
            with mock.patch.object(ker_run._load_source_shell_controller(), '_c34_profile_module') as unused:
                unused.side_effect = AssertionError('must reject before artifact capture')
                with self.assertRaisesRegex(ValueError, 'canonical broker run path'):
                    ker_run._capture_private_c34_source_controller(args, expected, control)
                args.command = ['/fixed/backend']
                with self.assertRaisesRegex(ValueError, r'exactly \[fixed backend, broker path\]'):
                    ker_run._capture_private_c34_source_controller(args, expected, control)

    def test_controller_rejects_untyped_start_and_c22_without_launch(self):
        controller_module, profile, temporary = self._profile()
        try:
            untyped = object.__new__(controller_module.SourceShellController)
            untyped.profile = SimpleNamespace(origin_module=profile.origin_module)
            untyped.started = False
            with self.assertRaises(TypeError):
                untyped.start()

            controller = object.__new__(controller_module.SourceShellController)
            controller.profile = profile
            controller.bootstrap_context = SimpleNamespace(control_only=True)
            controller.launch = None
            controller.c22_provider = None
            with self.assertRaises(PermissionError):
                controller.start_c22_provider(SimpleNamespace(ready=True, stopped=False))
        finally:
            profile.close(); temporary.cleanup()

    def test_private_bootstrap_provider_pairing_is_exact_and_capture_bound(self):
        controller_module, profile, temporary = self._profile()
        try:
            bootstrap=load_module('_c34_bootstrap_provider_gate_test',
                ROOT/'tools/nginx_source_bootstrap_supervisor.py')
            provider_module=controller_module._c22_provider_module()
            context=SimpleNamespace(control_only=True,shell_mode=True)
            private_origin=object.__new__(profile.origin_module.PrivateC34OriginalShellLaunch)
            private_origin.context=context
            private_origin.c34_artifact_capture=profile.artifact_capture
            context.owner_live=private_origin.live_supervisor
            private_provider=object.__new__(provider_module.SourceShellC34InteropProvider)
            private_provider.context=context
            private_provider._private_c34_helper_capture=profile.helper_capture
            private_provider._source_command_abi=1
            self.assertTrue(bootstrap._source_provider_matches_context(context,private_provider))
            old_origin=object.__new__(profile.origin_module.OriginalShellLaunch)
            old_origin.context=context
            context.owner_live=old_origin.live_supervisor
            old_provider=object.__new__(provider_module.SourceShellC22Provider)
            old_provider.context=context
            old_provider._private_c34_helper_capture=None
            self.assertTrue(bootstrap._source_provider_matches_context(context,old_provider))
            self.assertFalse(bootstrap._source_provider_matches_context(context,private_provider))
            context.owner_live=private_origin.live_supervisor
            self.assertFalse(bootstrap._source_provider_matches_context(context,old_provider))
        finally:
            profile.close(); temporary.cleanup()

    def test_private_start_dispatches_only_to_private_origin_launch(self):
        controller_module, profile, temporary = self._profile()
        events=[]
        class Capsules:
            def __init__(self, _origin): events.append('capsules')
            def publish_bootstrap(self, _path): events.append('bootstrap')
            def close(self): events.append('capsules-close')
        class Launch:
            def __init__(self,*args,**kwargs):
                events.append(('private-launch',kwargs.get('artifact_capture')))
                self.process=None
                self.capture=kwargs.get('artifact_capture')
            def wait_supervisor(self): events.append('wait')
        original=profile.origin_module.PrivateC34OriginalShellLaunch
        profile.origin_module.PrivateC34OriginalShellLaunch=Launch
        controller=None
        try:
            controller=controller_module.SourceShellController(profile)
            controller.scope_api=SimpleNamespace(SourceScopeCapsules=Capsules)
            launch=controller.start()
            self.assertEqual(events[0:2],['capsules','bootstrap'])
            self.assertEqual(events[2],('private-launch',profile.artifact_capture))
            self.assertTrue(controller.started)
            self.assertIs(launch,controller.launch)
            self.assertIs(launch.capture,profile.artifact_capture)
            self.assertGreaterEqual(launch.capture.artifact('build_manifest').fd,0)
        finally:
            profile.origin_module.PrivateC34OriginalShellLaunch=original
            if controller is not None: controller._close_unstarted()
            profile.close()
            temporary.cleanup()

    def test_companion_attach_recognizes_only_exact_captured_private_launch(self):
        _controller, profile, temporary = self._profile()
        try:
            attach=load_module('_c34_attach_exact_launch_test',ROOT/'tools/nginx_companion_attach.py')
            old=object.__new__(profile.origin_module.OriginalShellLaunch)
            private=object.__new__(profile.origin_module.PrivateC34OriginalShellLaunch)
            private.c34_artifact_capture=profile.artifact_capture
            self.assertTrue(attach._is_original_shell_launch(old))
            self.assertTrue(attach._is_original_shell_launch(private))
            impostor=type('PrivateC34OriginalShellLaunch',(),{})()
            self.assertFalse(attach._is_original_shell_launch(impostor))
        finally:
            profile.close(); temporary.cleanup()

    def test_original_launch_public_type_rejects_private_capture(self):
        controller_module, profile, temporary = self._profile()
        try:
            origin=profile.origin_module
            old=origin.OriginalShellLaunch.__new__(origin.OriginalShellLaunch)
            with self.assertRaises(PermissionError):
                old._initialize(str(ROOT),[],{},profile.nginx,profile.nginx_hash,
                    network_expectation=object(),stdout=None,stderr=None,
                    private_c34_capture=profile.artifact_capture)
        finally:
            profile.close()
            temporary.cleanup()


if __name__ == '__main__':
    unittest.main()
