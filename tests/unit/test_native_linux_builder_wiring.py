import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest import mock


BUILDER = Path(__file__).resolve().parents[2] / 'tools/build-native-linux.py'
spec = importlib.util.spec_from_file_location('native_builder', BUILDER)
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)


class NativeLinuxBuilderWiringTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='ker-native-wiring-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        makefile = self.root / 'arch/lkl/kernel/Makefile'
        makefile.parent.mkdir(parents=True)
        makefile.write_text('obj-y = setup.o misc.o \\\n\tconsole.o\n')
        self.makefile = makefile

    def test_kernel_config_fragment_has_distinct_fingerprint(self):
        (self.root / 'config').mkdir()
        (self.root / 'config/native-linux.json').write_text('{}\n')
        (self.root / 'config/native-linux.defconfig').write_text('CONFIG_INET=y\n')
        (self.root / 'config/netfilter.config').write_text('CONFIG_NETFILTER_XTABLES=y\n')
        (self.root / 'src/posix/lkl-overlay').mkdir(parents=True)
        default = builder.source_fingerprint(self.root)
        profile = builder.source_fingerprint(self.root, 'config/netfilter.config')
        self.assertNotEqual(default, profile)
        self.assertEqual(profile, builder.source_fingerprint(
            self.root, self.root / 'config/netfilter.config'))
        self.assertEqual(profile, builder.source_fingerprint(self.root, 'config/netfilter.config'))
        outside = self.root.parent / 'outside.config'; outside.write_text('CONFIG_X=y\n')
        with self.assertRaisesRegex(ValueError, 'must be tracked under'):
            builder.source_fingerprint(self.root, outside)

    def test_adds_exact_separate_builtin_objects_after_continued_list(self):
        with mock.patch.object(builder, 'git') as git:
            builder.wire_ker_builtin_adapters(self.root)
        self.assertEqual(self.makefile.read_text(),
            'obj-y = setup.o misc.o \\\n\tconsole.o\nobj-y += ker_tcp_payload.o\n'
            'obj-y += ker_tcp_request_revoke.o\n'
            'obj-y += ker_ff_admission_queue.o\n')
        git.assert_called_once_with(self.root, 'add', '--',
            'arch/lkl/kernel/Makefile')

    def test_paired_kconfig_input_changes_fingerprint_and_cannot_reuse_old_proof(self):
        (self.root / 'config').mkdir()
        (self.root / 'config/native-linux.json').write_text('{}\n')
        (self.root / 'config/native-linux.defconfig').write_text('CONFIG_INET=y\n')
        fragment = self.root / 'config/timers.config'; fragment.write_text('CONFIG_HZ=1000\n')
        before = builder.source_fingerprint(self.root, fragment)
        prelude = fragment.with_suffix('.Kconfig'); prelude.write_text('config HZ\n\tint\n\tdefault 1000\n')
        after = builder.source_fingerprint(self.root, fragment)
        self.assertNotEqual(before, after)
        prelude.write_text('config HZ\n\tint\n\tdefault 250\n')
        self.assertNotEqual(after, builder.source_fingerprint(self.root, fragment))

    def test_external_root_preserves_original_bytes_and_places_default_before_includes(self):
        original = b'# SPDX-License-Identifier: GPL-2.0\nmainmenu "Linux"\nsource "init/Kconfig"\n'
        prelude = b'config HZ\n\tint\n\tdefault 1000\n'
        result = builder.external_kconfig_root(original, prelude)
        self.assertEqual(result.replace(b'\n' + prelude + b'\n', b'', 1), original)
        self.assertLess(result.index(b'default 1000'), result.index(b'source "init/Kconfig"'))
        with self.assertRaisesRegex(RuntimeError, 'exactly one'):
            builder.external_kconfig_root(b'config HZ\n', prelude)

    def test_refuses_duplicate_generated_wiring_for_each_adapter(self):
        for object_name in ('ker_tcp_payload.o', 'ker_tcp_request_revoke.o',
                            'ker_ff_admission_queue.o'):
            with self.subTest(object_name=object_name):
                self.makefile.write_text('obj-y = setup.o misc.o\nobj-y += ' +
                    object_name + '\n')
                with self.assertRaisesRegex(RuntimeError, 'already wires'):
                    builder.wire_ker_builtin_adapters(self.root)

    def test_refuses_unexpected_obj_y_layout(self):
        self.makefile.write_text('obj-y += setup.o\n')
        with self.assertRaisesRegex(RuntimeError, 'exactly one'):
            builder.wire_ker_builtin_adapters(self.root)


if __name__ == '__main__':
    unittest.main(verbosity=2)
