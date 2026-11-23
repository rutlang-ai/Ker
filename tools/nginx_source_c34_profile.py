"""Exact private profile for the captured NEWC34_INTEROP source path."""
import os
from pathlib import Path
import re
import stat
import time
from types import MappingProxyType

_PROVIDER_NAME = '_ker_nginx_source_c34_artifacts'
_PROVIDER_PATH = Path(__file__).with_name('nginx_source_c34_artifact_provider.py').resolve(strict=True)
_PROFILE_TOKEN = object()


def _provider():
    import importlib.util
    import sys
    cached = sys.modules.get(_PROVIDER_NAME)
    if cached is not None:
        if Path(cached.__file__).resolve(strict=True) != _PROVIDER_PATH:
            raise ImportError('cached C34 artifact provider belongs to another path')
        return cached
    spec = importlib.util.spec_from_file_location(_PROVIDER_NAME, _PROVIDER_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules[_PROVIDER_NAME] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        if sys.modules.get(_PROVIDER_NAME) is module:
            del sys.modules[_PROVIDER_NAME]
        raise
    return module


class PrivateNewC34InteropProfile:
    __slots__ = ('origin_module', 'source_root', 'arguments', 'environment',
        'nginx', 'nginx_hash', 'network_expectation', 'scope_directory', 'stdout',
        'stderr', 'cwd', 'nonce', 'epoch', 'deadline_ns', 'output', 'port_name',
        'artifact_capture', 'helper_capture', 'build_manifest_path',
        'build_manifest_sha256', 'profile_id', '_sealed')

    def __setattr__(self, name, value):
        if getattr(self, '_sealed', False):
            raise AttributeError('private NEWC34_INTEROP profile is immutable')
        object.__setattr__(self, name, value)

    def __init__(self, token, origin_module, source_root, arguments, environment,
            network_expectation, scope_directory, stdout, stderr, port_name, cwd,
            artifact_capture):
        if token is not _PROFILE_TOKEN:
            raise TypeError('NEWC34_INTEROP profiles are factory-created')
        provider = _provider()
        if type(artifact_capture) is not provider.PrivateC34ArtifactCapture:
            raise TypeError('NEWC34_INTEROP requires the fixed private C34 artifact capture')
        self._sealed = False
        self.origin_module = origin_module
        self.source_root = Path(source_root).resolve(strict=True)
        self.arguments = tuple(arguments)
        self.environment = MappingProxyType(dict(environment))
        nginx = artifact_capture.artifact('nginx')
        self.nginx, self.nginx_hash = nginx.path, bytes.fromhex(nginx.sha256)
        self.network_expectation = network_expectation
        self.scope_directory = Path(scope_directory).resolve(strict=True)
        self.stdout, self.stderr, self.cwd = stdout, stderr, cwd
        self.nonce = bytes.fromhex(environment['KER_NGINX_SOURCE_BOOTSTRAP_NONCE'])
        self.epoch = int(environment['KER_NGINX_SOURCE_BOOTSTRAP_EPOCH'])
        self.deadline_ns = int(environment['KER_NGINX_SOURCE_BOOTSTRAP_DEADLINE_NS'])
        self.output = self.arguments[self.arguments.index('--out') + 1]
        self.port_name = port_name
        self.artifact_capture = artifact_capture
        self.helper_capture = artifact_capture.helper_capture
        manifest = artifact_capture.artifact('build_manifest')
        self.build_manifest_path = str(manifest.path)
        self.build_manifest_sha256 = manifest.sha256
        self.profile_id = 'NEWC34_INTEROP'
        self._sealed = True

    @classmethod
    def capture(cls, origin_module, startup_module, *, source_root, arguments,
            environment, network_expectation, scope_directory, stdout, stderr,
            port_name, cwd=None, artifact_capture=None):
        require = origin_module.require
        require(type(arguments) in (tuple, list) and all(type(arg) is str for arg in arguments),
            'private C34 arguments must be captured strings')
        require(type(environment) is dict and all(type(k) is str and type(v) is str
            for k, v in environment.items()), 'private C34 environment must be exact strings')
        require(Path(getattr(origin_module, '__file__', '')).resolve(strict=True) ==
            Path(__file__).with_name('nginx_source_origin.py').resolve(strict=True),
            'private C34 profile requires the canonical Origin module')
        require(type(network_expectation) is startup_module.SourceNetworkExpectation,
            'private C34 profile requires the captured source network expectation')
        require(environment.get('KER_NGINX_SOURCE_SHELL_ENABLE') == '1' and
            environment.get('KER_NGINX_SOURCE_FIRST_HUP_ENABLE') == '1',
            'private C34 source-shell flags are incomplete')
        nonce = environment.get('KER_NGINX_SOURCE_BOOTSTRAP_NONCE', '')
        epoch_text = environment.get('KER_NGINX_SOURCE_BOOTSTRAP_EPOCH', '')
        deadline_text = environment.get(startup_module.BOOTSTRAP_DEADLINE_ENV, '')
        require(re.fullmatch(r'[0-9a-f]{32}', nonce) is not None and nonce != '0' * 32 and
            epoch_text.isascii() and epoch_text.isdecimal() and epoch_text[0] != '0' and
            deadline_text.isascii() and deadline_text.isdecimal() and deadline_text[0] != '0',
            'private C34 session fields are not canonical')
        epoch, deadline = int(epoch_text), int(deadline_text)
        now = time.monotonic_ns()
        bound = (origin_module.SOURCE_RV9_AUTHORITY_NS if network_expectation.repeated else
            origin_module.SOURCE_BASELINE_AUTHORITY_NS
            if 'precheck,baseline' in arguments else 300_000_000_000)
        require(0 < epoch < (1 << 64) and now < deadline <= now + bound and
            deadline == network_expectation.deadline_ns,
            'private C34 deadline/session is outside its bound')
        require(environment.get('KER_NGINX_SOURCE_BOOTSTRAP_SUPERVISOR_PID') == str(os.getpid()) and
            environment.get('KER_NGINX_SOURCE_BOOTSTRAP_SUPERVISOR_START') ==
                str(origin_module.identity._start_ticks(os.getpid())),
            'private C34 supervisor identity differs from this process')
        require(isinstance(port_name, str) and 1 <= len(port_name) <= 63 and
            port_name.isascii() and all(ch.isalnum() or ch in '_.-' for ch in port_name),
            'private C34 port name is not canonical')
        args = list(arguments)
        def option(names):
            found, i = [], 0
            while i < len(args):
                if args[i] in names:
                    require(i + 1 < len(args), 'private C34 option is missing a value')
                    found.append(args[i + 1]); i += 2
                else: i += 1
            require(len(found) == 1, 'private C34 option is missing or duplicated')
            return found[0]
        case = origin_module.source_hup_case(option(('--cases','-c')))
        require(option(('--workers',)) == '1' and option(('--graceful',)) == '1' and
            option(('--target-ip','-t')) == network_expectation.address,
            'private C34 profile requires one worker with graceful reload enabled')
        output, template = option(('--out','-o')), option(('--fstack-conf',))
        require(network_expectation.repeated == (case == 'rv9'),
            'extended successor authority is specific to the original rv9 case')
        if case not in ('baseline', 'rv9'):
            require(deadline <= now + 300_000_000_000,
                'extended private lifetime is scoped to the original baseline')
        tag = origin_module.SOURCE_CASE_TAGS[case]
        expected_ini = f'{output}/fstack_{tag}.ini'
        require(environment.get('KER_FSTACK_NGINX_INI') == expected_ini,
            'private C34 runtime INI path is not bound to fresh output')
        require(not any(environment.get(key) for key in ('LD_PRELOAD','LD_AUDIT','LD_LIBRARY_PATH')),
            'private C34 source launch rejects alternate loader environment')
        require(Path(output).is_absolute() and str(Path(output).resolve(strict=False)) == output and
            not Path(output).exists() and template == network_expectation.template_path and
            args.count('--out') == 1 and args.count('--fstack-conf') == 1,
            'private C34 output/template is not the captured fresh runtime path')
        scope = Path(scope_directory).resolve(strict=True)
        info = os.stat(scope, follow_symlinks=False)
        require(scope.is_dir() and info.st_uid == os.geteuid() and
            stat.S_IMODE(info.st_mode) == 0o700 and
            len(os.fsencode(scope / 'origin.sock')) < 108 and
            not (scope / 'origin.sock').exists() and not (scope / 'bootstrap.json').exists(),
            'private C34 scope is not a fresh owned private directory')
        provider = _provider()
        fixture = (type(artifact_capture) is provider.PrivateC34ArtifactCapture
            and artifact_capture.is_test_fixture)
        fault = artifact_capture.source_fault if fixture else provider._SOURCE_FAULT
        root = artifact_capture.source_root if fixture else provider._SOURCE_ROOT
        expected_manifest = (artifact_capture.artifact('build_manifest').path
            if fixture else provider._BUILD_MANIFEST)
        origin_module.validate_source_hup_fault(case, args, environment, fault)
        require(Path(source_root).resolve(strict=True) == root.resolve(strict=True),
            'private C34 source root differs from its fixed original-case build root')
        manifest_text = option(('--build-manifest',))
        require(manifest_text == str(expected_manifest) and args.count('--build-manifest') == 1,
            'private C34 build manifest path differs from its fixed capture input')
        # The descriptor is included in the private capture and stays held
        # until the profile/Origin launch relinquishes that capture.
        copied = dict(environment)
        copied[startup_module.READBACK_ENV] = network_expectation.readback_setting()
        capture = (provider.PrivateC34ArtifactCapture.capture(deadline)
            if artifact_capture is None else artifact_capture)
        require(type(capture) is provider.PrivateC34ArtifactCapture,
            'private C34 artifact capture has the wrong exact type')
        try:
            manifest = capture.artifact('build_manifest')
            require(manifest.path == expected_manifest and
                (fixture or manifest.sha256 == provider._BUILD_MANIFEST_SHA256) and
                capture.source_fault == fault and
                capture.helper_capture.source_fault == capture.source_fault,
                'private C34 held build manifest differs from its fixed input')
            nginx_options = []
            i = 0
            while i < len(args):
                if args[i] == '--nginx':
                    require(i + 1 < len(args), 'private C34 Nginx option lacks a value')
                    nginx_options.append(args[i + 1]); i += 2
                else: i += 1
            require(nginx_options == [str(capture.artifact('nginx').path)],
                'private C34 launch must select exactly its fixed Nginx artifact')
            return cls(_PROFILE_TOKEN, origin_module, source_root, args, copied,
                network_expectation, scope, stdout, stderr, port_name, cwd, capture)
        except BaseException:
            capture.close()
            network_expectation.template_file.close()
            raise

    def close(self):
        self.artifact_capture.close()
        network_file = getattr(self.network_expectation, 'template_file', None)
        if network_file is not None:
            network_file.close()

    def __del__(self):
        try: self.close()
        except BaseException: pass
