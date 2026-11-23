import re
import os
from pathlib import Path
import unittest


REPO = Path(__file__).resolve().parents[2]
MODULE = (REPO / 'src/posix/fstack-nginx-owner-activation-module.c').read_text()
SOURCE_ROOT = os.environ.get('KER_FSTACK_SOURCE_ROOT')


class SourceShellEnvironmentControls(unittest.TestCase):
    """Source-inspection controls; these do not execute the C registration path."""

    def test_builtin_allowlist_is_exact_and_contains_no_fd_capabilities(self):
        block = MODULE.split('source_shell_environment_names[] = {', 1)[1].split('};', 1)[0]
        names = re.findall(r'"(KER_[A-Z0-9_]+)"', block)
        self.assertEqual(names, [
            'KER_NGINX_SOURCE_SHELL_ENABLE',
            'KER_NGINX_SOURCE_BOOTSTRAP_PATH',
            'KER_NGINX_SOURCE_BOOTSTRAP_NONCE',
            'KER_NGINX_SOURCE_BOOTSTRAP_SUPERVISOR_PID',
            'KER_NGINX_SOURCE_BOOTSTRAP_SUPERVISOR_START',
            'KER_NGINX_SOURCE_BOOTSTRAP_EPOCH',
            'KER_NGINX_SOURCE_BOOTSTRAP_DEADLINE_NS',
            'KER_SOCKET_BROKER_PATH',
            'KER_FSTACK_NGINX_INI',
            'KER_NGINX_SOURCE_FIRST_HUP_ENABLE',
            'KER_FSTACK_RUNTIME_TRACE',
            'KER_NGINX_SOURCE_ABORT_RETRY_ENABLE',
            'KER_NGINX_SOURCE_READY_DELAY_ENABLE',
            'KER_NGINX_SOURCE_ABORT_ENABLE',
            'KER_NGINX_SOURCE_SYNACK_FAULT_ENABLE',
            'KER_NGINX_SOURCE_KNI_ENABLE',
            'KER_NGINX_SOURCE_SUCCESSOR_ENABLE',
            'KER_NGINX_SOURCE_UPGRADE_ENABLE',
        ])
        self.assertFalse(any('FD' in name or 'SLOT' in name for name in names))
        self.assertIn('getenv("KER_NGINX_SOURCE_SUCCESSOR_ENABLE")', MODULE)
        self.assertIn('getenv(source_shell_environment_names[SOURCE_SHELL_RETRY_INDEX])',
                      MODULE)
        self.assertIn('"ker_fstack_nginx_source_fault_profile"', MODULE)

    def test_registration_is_builtin_optin_and_rejects_environment_conflicts(self):
        self.assertIn('#ifdef KER_NGINX_OWNER_BUILTIN\nstatic bool source_shell_environment_captured', MODULE)
        self.assertIn('source_shell_register_environment(cycle)', MODULE)
        self.assertIn('ccf->environment != NULL', MODULE)
        self.assertIn('configured[i].data[name_len] == \'=\'', MODULE)
        self.assertIn('entries[j++].data = (u_char *) source_shell_environment_names[i];', MODULE)
        self.assertIn('strcmp(enabled, "1") != 0', MODULE)

    def test_launch_environment_values_are_snapshotted_and_revalidated(self):
        self.assertIn('copies[i] = strdup(values[i]);', MODULE)
        self.assertIn('strcmp(source_shell_environment_values[i], value) != 0', MODULE)
        self.assertIn('source_shell_environment_captured = true;', MODULE)
        self.assertIn('source_shell_module_pid != getpid()', MODULE)
        self.assertIn('cycle != source_shell_validated_cycle', MODULE)

    def test_source_guard_bounds_every_value_before_snapshot(self):
        bounds = MODULE.split('source_shell_environment_max_lengths[] = {', 1)[1].split('};', 1)[0]
        self.assertIn('source-shell environment bounds must cover the complete allowlist', MODULE)
        self.assertIn('sizeof(((struct sockaddr_un *) 0)->sun_path) - 1', bounds)
        self.assertIn('KER_SOCKET_BROKER_PATH_MAX', bounds)
        self.assertIn('PATH_MAX - 1', bounds)
        capture = MODULE.split(
            'const char *value = getenv(source_shell_environment_names[i]);', 1)[1]
        capture = capture.split('source_shell_environment_captured = true;', 1)[0]
        self.assertIn('strnlen(value, max_length + 1)', capture)
        self.assertIn('value_len > max_length', capture)
        self.assertLess(capture.index('value_len > max_length'),
                        capture.index('if (!source_shell_environment_captured)'))
        self.assertIn('copies[i] = strdup(values[i]);', capture)

    def test_source_negative_guards_cover_nonce_numeric_and_boolean_inputs(self):
        decimal = MODULE.split('source_shell_environment_decimal(const char *value', 1)[1].split('\n}', 1)[0]
        nonce = MODULE.split('source_shell_environment_nonce(const char *value', 1)[1].split('\n}', 1)[0]
        self.assertIn("value[0] == '0'", decimal)
        self.assertIn('length > 20', decimal)
        self.assertIn('(maximum - digit) / 10', decimal)
        self.assertIn('return parsed != 0;', decimal)
        self.assertIn('length != 32', nonce)
        self.assertIn("value[i] >= 'a' && value[i] <= 'f'", nonce)
        self.assertNotIn("value[i] >= 'A' && value[i] <= 'F'", nonce)
        self.assertIn('strcmp(value, "1") != 0', MODULE)

    def test_optional_trace_may_be_absent_or_empty_but_is_still_bounded(self):
        self.assertIn('i < SOURCE_SHELL_TRACE_INDEX && (!value || value_len == 0)', MODULE)
        self.assertIn('i >= SOURCE_SHELL_RETRY_INDEX && values[i] == NULL', MODULE)
        bounds = MODULE.split('source_shell_environment_max_lengths[] = {', 1)[1].split('};', 1)[0]
        self.assertEqual(bounds.count('PATH_MAX - 1'), 2)
        self.assertIn('value_len > max_length', MODULE)

    @unittest.skipUnless(SOURCE_ROOT,
        'set KER_FSTACK_SOURCE_ROOT to the original F-Stack source checkout')
    def test_upstream_exec_environment_filters_by_name_from_original_snapshot(self):
        upstream_path = Path(SOURCE_ROOT) / 'app/nginx-1.28.0/src/core/nginx.c'
        upstream = upstream_path.read_text()
        env_fn = upstream.split('ngx_set_environment(ngx_cycle_t *cycle, ngx_uint_t *last)', 1)[1]
        env_fn = env_fn.split('\n}\n', 1)[0]
        self.assertIn('if (last == NULL && ccf->environment)', env_fn)
        self.assertIn('for (p = ngx_os_environ; *p; p++)', env_fn)
        self.assertIn('(*p)[var[i].len] == \'=\'', env_fn)
        self.assertIn('ccf->environment = env;', env_fn)
        self.assertIn('env = ngx_set_environment(cycle, &n);', upstream)


if __name__ == '__main__':
    unittest.main()
