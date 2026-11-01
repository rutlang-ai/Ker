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

    def test_adds_exact_separate_builtin_objects_after_continued_list(self):
        with mock.patch.object(builder, 'git') as git:
            builder.wire_ker_builtin_adapters(self.root)
        self.assertEqual(self.makefile.read_text(),
            'obj-y = setup.o misc.o \\\n\tconsole.o\nobj-y += ker_tcp_payload.o\n'
            'obj-y += ker_tcp_request_revoke.o\n')
        git.assert_called_once_with(self.root, 'add', '--',
            'arch/lkl/kernel/Makefile')

    def test_refuses_duplicate_generated_wiring_for_each_adapter(self):
        for object_name in ('ker_tcp_payload.o', 'ker_tcp_request_revoke.o'):
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
