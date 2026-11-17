"""Input validation and target normalization regressions; no network access."""
from pathlib import Path
import tempfile
import unittest

import test_regression as regression


class ArgumentBoundaryTests(unittest.TestCase):
    def test_rejects_overflow_and_excessive_work_before_running(self):
        for option, values in (
                ('-n', ('101', '999', '18446744073709551616', '08', '-1')),
                ('-p', ('257', '999', '18446744073709551616', '08', '-1'))):
            for value in values:
                with self.subTest(option=option, value=value):
                    result = regression.shell(f"parse_args {option} {value}; echo accepted")
                    self.assertEqual(result.returncode, 1)
                    self.assertNotIn('accepted', result.stdout)
                    self.assertIn('exitray:', result.stderr)

    def test_accepts_boundaries(self):
        for rounds, parallel in ((1, 1), (100, 256)):
            result = regression.shell(
                f'parse_args -n {rounds} -p {parallel}; echo "$ROUNDS $PARALLEL"')
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip(), f'{rounds} {parallel}')

    def test_rejects_directory_as_target_file(self):
        with tempfile.TemporaryDirectory() as directory:
            result = regression.shell(f"parse_args -f '{regression.posix(directory)}'")
            self.assertEqual(result.returncode, 1)
            self.assertIn('普通文件', result.stderr)

    def test_rejects_malformed_extra_targets_early(self):
        for value in ('missing-colon', ':a.example', 'ai:', 'ai:-evil',
                      'ai:https://a.example', 'ai:a.example other', 'ai\nshop:a.example'):
            with self.subTest(value=value):
                result = regression.shell(f"parse_args -a '{value}'; echo accepted")
                self.assertEqual(result.returncode, 1)
                self.assertNotIn('accepted', result.stdout)
                self.assertIn('-a 的格式', result.stderr)


class TargetNormalizationTests(unittest.TestCase):
    def test_case_insensitive_deduplication_preserves_first_category(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            targets = root / 'input.txt'
            regression.write(targets, '\ufeffai A.Example\nshop a.example\nmeta B.Example\n')
            result = regression.shell(f"""
                WORK='{regression.posix(root)}'
                parse_args -c none -f '{regression.posix(targets)}' -a ai:B.EXAMPLE -a dev:C.Example
                load_targets
                cat "$WORK/targets.txt"
            """)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, 'ai a.example\nmeta b.example\ndev c.example\n')

    def test_regional_targets_precede_common_targets_with_one_catalog_read(self):
        with tempfile.TemporaryDirectory() as directory:
            result = regression.shell(f"""
                WORK='{regression.posix(directory)}'
                REGION=tw CATS=bank
                catalog() {{
                    echo read >> "$WORK/catalog.calls"
                    printf '%s\\n' 'bank COMMON.example' '@jp bank jp.example' '@tw bank TW.example' 'ai ignored.example'
                }}
                load_targets
                cat "$WORK/targets.txt" "$WORK/catalog.calls"
            """)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, 'bank tw.example\nbank common.example\nread\n')


if __name__ == '__main__':
    unittest.main()
