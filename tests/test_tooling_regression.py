"""Offline regressions for the compatibility launcher and publication checks."""
from contextlib import redirect_stderr, redirect_stdout
import importlib.util
import io
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
BASH = os.environ.get('TEST_BASH', shutil.which('bash') or 'bash')
SPEC = importlib.util.spec_from_file_location('public_files', ROOT / 'scripts/check-public-files.py')
PUBLIC_FILES = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PUBLIC_FILES)


class CompatibilityLauncherTests(unittest.TestCase):
    def test_cdpath_does_not_hide_adjacent_script(self):
        with tempfile.TemporaryDirectory(prefix='exitray-launcher-') as directory:
            root = Path(directory)
            launcher = root / 'launcher'
            launcher.mkdir()
            shutil.copyfile(ROOT / 'splitcheck.sh', launcher / 'splitcheck.sh')
            (launcher / 'exitray.sh').write_text(
                'printf "local:%s\\n" "$1"; exit 7\n', encoding='utf-8', newline='\n')
            # An exported function makes accidental network fallback fail immediately.
            result = subprocess.run(
                [BASH, '-c', 'curl() { echo unexpected-download >&2; return 99; }; '
                 'export -f curl; "$BASH" launcher/splitcheck.sh "two words"'],
                cwd=root, env={**os.environ, 'CDPATH': '.'}, text=True, encoding='utf-8',
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
            self.assertEqual((result.returncode, result.stdout), (7, 'local:two words\n'), result.stderr)
            self.assertNotIn('unexpected-download', result.stderr)


class PublicationPathTests(unittest.TestCase):
    def check_paths(self, paths, *args):
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch.object(PUBLIC_FILES.subprocess, 'check_output', return_value=paths) as git:
            with patch('sys.argv', ['check-public-files.py', *args]):
                with redirect_stdout(stdout), redirect_stderr(stderr):
                    result = PUBLIC_FILES.main()
        return result, stdout.getvalue(), stderr.getvalue(), git.call_args.args[0]

    def test_missing_worktree_file_is_still_checked_in_index(self):
        # Git still commits an indexed file after an unstaged filesystem deletion.
        with tempfile.TemporaryDirectory(prefix='exitray-index-') as directory:
            with patch.object(PUBLIC_FILES, 'ROOT', Path(directory)):
                code, _, errors, _ = self.check_paths(b'.env\0README.md\0')
        self.assertEqual(code, 1)
        self.assertIn('.env', errors)
        self.assertNotIn('README.md', errors)

    def test_staged_private_file_is_rejected(self):
        code, _, errors, _ = self.check_paths(b'credentials.json\0', '--staged')
        self.assertEqual(code, 1)
        self.assertIn('credentials.json', errors)

    def test_public_examples_are_allowed(self):
        code, _, errors, _ = self.check_paths(b'README.md\0.env.example\0docs/report-split.svg\0')
        self.assertEqual((code, errors), (0, ''))


if __name__ == '__main__':
    unittest.main()
