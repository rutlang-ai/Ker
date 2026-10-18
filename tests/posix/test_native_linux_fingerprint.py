import argparse
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

TEST_ARGS = None


class NativeLinuxFingerprintTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.args = TEST_ARGS
        for name in ('builder', 'verifier'):
            setattr(cls.args, name, getattr(cls.args, name).resolve())
        cmake = shutil.which(str(cls.args.cmake)) or str(cls.args.cmake)
        cls.args.cmake = Path(cmake).resolve()

    def run_mutation_case(self, mutation):
        with tempfile.TemporaryDirectory(prefix='ker-native-fingerprint-') as temporary:
            root = Path(temporary) / 'source'
            config = root / 'config'
            overlay = root / 'src/posix/lkl-overlay'
            tools = root / 'tools'
            build = Path(temporary) / 'build'
            config.mkdir(parents=True)
            overlay.mkdir(parents=True)
            tools.mkdir(parents=True)
            builder = tools / 'build-native-linux.py'
            shutil.copyfile(self.args.builder, builder)
            (config / 'native-linux.json').write_text('{"fixture":"pins"}\n')
            (config / 'native-linux.defconfig').write_text('CONFIG_FIXTURE=y\n')
            (overlay / 'fixture.h').write_text('#define FIXTURE 1\n')
            fingerprint = subprocess.check_output([
                sys.executable, builder, '--print-fingerprint',
                '--fingerprint-root', root], text=True).strip()
            proof = Path(temporary) / 'native-linux.json'
            proof.write_text(json.dumps({'fingerprint': fingerprint}) + '\n')
            artifact = Path(temporary) / 'fixture-artifact.bin'
            artifact.write_bytes(b'known-good fixture artifact\n')
            (root / 'CMakeLists.txt').write_text(f'''cmake_minimum_required(VERSION 3.20)
project(native_fingerprint_fixture NONE)
include("{self.args.verifier}")
ker_verify_native_linux_fingerprint("{root}" "{proof}" "{builder}")
add_custom_target(fingerprint-fixture ALL COMMAND "${{CMAKE_COMMAND}}" -E echo valid)
''')
            configured = subprocess.run([
                self.args.cmake, '-S', root, '-B', build],
                text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            self.assertEqual(configured.returncode, 0, configured.stdout)
            proof_bytes = proof.read_bytes()
            artifact_bytes = artifact.read_bytes()
            baseline = subprocess.run([
                self.args.cmake, '--build', build],
                text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            self.assertEqual(baseline.returncode, 0, baseline.stdout)
            self.assertEqual(proof.read_bytes(), proof_bytes)
            self.assertEqual(artifact.read_bytes(), artifact_bytes)

            if mutation == 'defconfig':
                (config / 'native-linux.defconfig').write_text('CONFIG_FIXTURE=n\n')
            elif mutation == 'overlay-add':
                (overlay / 'new-overlay-file.h').write_text('#define NEW_FIXTURE 1\n')
            elif mutation == 'overlay-edit':
                (overlay / 'fixture.h').write_text('#define FIXTURE 2\n')
            elif mutation == 'overlay-remove':
                (overlay / 'fixture.h').unlink()
            elif mutation == 'builder-edit':
                with builder.open('ab') as script:
                    script.write(b'\n# changed builder behavior\n')
            else:
                self.fail('unknown mutation case')

            rebuilt = subprocess.run([
                self.args.cmake, '--build', build],
                text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            self.assertNotEqual(rebuilt.returncode, 0, rebuilt.stdout)
            self.assertIn('source inputs differ from the artifact fingerprint', rebuilt.stdout)
            self.assertEqual(proof.read_bytes(), proof_bytes)
            self.assertEqual(artifact.read_bytes(), artifact_bytes)

    def test_defconfig_change_rejects_stale_native_artifacts(self):
        self.run_mutation_case('defconfig')

    def test_overlay_addition_reconfigures_and_rejects_stale_artifacts(self):
        self.run_mutation_case('overlay-add')

    def test_overlay_edit_reconfigures_and_rejects_stale_artifacts(self):
        self.run_mutation_case('overlay-edit')

    def test_overlay_removal_reconfigures_and_rejects_stale_artifacts(self):
        self.run_mutation_case('overlay-remove')

    def test_builder_change_reconfigures_and_rejects_stale_artifacts(self):
        self.run_mutation_case('builder-edit')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('--builder', type=Path, required=True)
    parser.add_argument('--verifier', type=Path, required=True)
    parser.add_argument('--cmake', type=Path, required=True)
    TEST_ARGS, remaining = parser.parse_known_args()
    sys.argv = [sys.argv[0], *remaining]
    unittest.main(verbosity=2)
