"""Task6a render-output gate only; private repositories and fail-closed executables."""
import json
import os
from pathlib import Path
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
CANARY = 'synthetic-secret-canary-not-a-customer-value'


class RenderPrivacyTest(unittest.TestCase):
    def setUp(self):
        scratch = tempfile.TemporaryDirectory(prefix='byoc-render-privacy-')
        self.addCleanup(scratch.cleanup)
        self.base = Path(scratch.name)
        self.repo = self.base / 'source'
        (self.repo / 'scripts').mkdir(parents=True)
        shutil.copy2(ROOT / 'scripts/render.sh', self.repo / 'scripts/render.sh')
        for name in ('connection-config.py', 'connection_yaml.py', 'connection_contract.py'):
            shutil.copy2(ROOT / 'scripts' / name, self.repo / 'scripts' / name)
        for name in ('contracts', 'defaults'):
            shutil.copytree(ROOT / name, self.repo / name)
        shutil.copy2(ROOT / 'release.yaml', self.repo / 'release.yaml')
        for name in ('values.json', 'secrets.json'):
            (self.base / name).write_text('{}\n')
        self.bin = self.base / 'bin'
        self.bin.mkdir()
        yq = shutil.which('yq')
        if not yq:
            raise RuntimeError('pinned yq required for the real local gate')
        (self.bin / 'yq').symlink_to(Path(yq).resolve())
        (self.bin / 'python3').symlink_to(sys.executable)
        self.observed = self.base / 'observed.jsonl'
        spy = '''#!{python}
import json, os, pathlib, signal, stat, sys, time
from pathlib import Path
name = Path(sys.argv[0]).name
repo = Path(os.environ['TEST_REPO'])
render = repo / '.rendered'
files = list(render.glob('.render.*/all.yaml'))
record = {{'name':name, 'argv':sys.argv[1:], 'dirMode':stat.S_IMODE(render.stat().st_mode),
          'stageDirMode':stat.S_IMODE(files[0].parent.stat().st_mode) if files else None,
          'staged':len(files), 'stagedMode':stat.S_IMODE(files[0].stat().st_mode) if files else None,
          'published':(render/'all.yaml').exists(),
          'logs':[(x.name, stat.S_IMODE(x.stat().st_mode)) for x in render.glob('.render.*/*.log')]}}
def observe():
    with open(os.environ['TEST_OBSERVED'],'a') as output: output.write(json.dumps(record)+'\\n')
if name == 'helmfile':
    assert sys.argv[1:] == ['template', '--skip-deps', '--quiet']
    observe()
    sys.stdout.write('private-render\\n')
    sys.stdout.flush()
    print(os.environ['TEST_CANARY'], file=sys.stderr)
    if os.environ['TEST_MODE'] == 'partial': sys.exit(29)
    if os.environ['TEST_MODE'] == 'redirect-fail':
        log = files[0].parent / 'kubeconform.log'
        log.unlink()
        log.symlink_to(repo / 'missing-parent' / 'log')
    if os.environ['TEST_MODE'] == 'signal':
        os.kill(os.getppid(), signal.SIGTERM)
        time.sleep(0.2)
else:
    manifest = Path(sys.argv[-1])
    assert sys.argv[1:-1] == ['-kubernetes-version','1.32.0','-strict','-summary',
                              '-ignore-missing-schemas']
    assert manifest in [render / 'all.yaml', *files]
    assert manifest.read_text() == 'private-render\\n'
    record['validationOutcome'] = 'reject:31' if os.environ['TEST_MODE'] == 'kube-fail' else 'accept'
    observe()
    print(os.environ['TEST_CANARY'], file=sys.stderr)
    if os.environ['TEST_MODE'] == 'kube-fail': sys.exit(31)
'''.format(python=sys.executable)
        for name in ('helmfile', 'kubeconform'):
            tool = self.bin / name
            tool.write_text(spy)
            tool.chmod(0o700)
        self.env = {'PATH': str(self.bin) + ':/usr/bin:/bin', 'HOME': str(self.base),
                    'KUBECONFIG': str(self.base / 'no-kubeconfig'),
                    'PHOENIX_BYOC_VALUES_FILE': str(self.base / 'values.json'),
                    'PHOENIX_BYOC_SECRETS_FILE': str(self.base / 'secrets.json'),
                    'HELMFILE_CACHE_HOME': str(self.base / 'cache'),
                    'TEST_REPO': str(self.repo), 'TEST_OBSERVED': str(self.observed),
                    'TEST_CANARY': CANARY, 'TEST_MODE': 'success'}

    def run_render(self, mode='success'):
        return subprocess.run(['/bin/bash', str(self.repo / 'scripts/render.sh')],
                              env={**self.env, 'TEST_MODE': mode}, cwd=self.repo,
                              capture_output=True, text=True, timeout=15)

    def records(self):
        return [json.loads(row) for row in self.observed.read_text().splitlines()] if self.observed.exists() else []

    def assert_clean(self):
        render = self.repo / '.rendered'
        self.assertFalse((render / 'all.yaml').exists())
        self.assertEqual(list(render.glob('.render.*')), [])

    def test_partial_failure_removes_stale_and_withholds_canary(self):
        render = self.repo / '.rendered'
        render.mkdir()
        (render / 'all.yaml').write_text('stale')
        result = self.run_render('partial')
        self.assertNotEqual(result.returncode, 0)
        self.assert_clean()
        self.assertNotIn(CANARY, result.stdout + result.stderr)
        self.assertNotIn(str(self.repo), result.stderr)
        self.assertEqual([row['name'] for row in self.records()], ['helmfile'])

    def test_late_kubeconform_failure_never_publishes(self):
        (self.repo / '.rendered').mkdir()
        (self.repo / '.rendered/all.yaml').write_text('stale')
        result = self.run_render('kube-fail')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.records()[-1]['validationOutcome'], 'reject:31')
        self.assert_clean()
        self.assertNotIn(CANARY, result.stdout + result.stderr)
        self.assertEqual([row['name'] for row in self.records()], ['helmfile', 'kubeconform'])
        self.assertFalse(self.records()[-1]['published'])

    def test_private_modes_and_publish_after_optional_check(self):
        result = self.run_render()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.records()[-1]['validationOutcome'], 'accept')
        self.assertEqual((self.repo / '.rendered/all.yaml').read_text(), 'private-render\n')
        self.assertEqual(stat.S_IMODE((self.repo / '.rendered').stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((self.repo / '.rendered/all.yaml').stat().st_mode), 0o600)
        for row in self.records():
            self.assertEqual((row['dirMode'], row['stageDirMode'], row['stagedMode'], row['published']),
                             (0o700, 0o700, 0o600, False))
            self.assertTrue(all(mode == 0o600 for _, mode in row['logs']))
        self.assertEqual(list((self.repo / '.rendered').glob('.render.*')), [])
        self.assertNotIn(CANARY, result.stdout + result.stderr)

    def test_redirection_open_failure_withholds_sensitive_path(self):
        destination = self.base / ('source-' + CANARY)
        self.repo.rename(destination)
        self.repo = destination
        self.env['TEST_REPO'] = str(self.repo)
        result = self.run_render('redirect-fail')
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn(CANARY, result.stdout + result.stderr)
        self.assertEqual(result.stderr, 'ERROR: render_kubeconform_failed\n')
        self.assertEqual([row['name'] for row in self.records()], ['helmfile'])
        self.assert_clean()

    def test_signal_cleans_staging_and_prior_output(self):
        (self.repo / '.rendered').mkdir()
        (self.repo / '.rendered/all.yaml').write_text('stale')
        result = self.run_render('signal')
        self.assertNotEqual(result.returncode, 0)
        self.assert_clean()
        self.assertNotIn(CANARY, result.stdout + result.stderr)

    def test_cache_error_withholds_path_and_removes_stale_output(self):
        (self.repo / '.rendered').mkdir()
        (self.repo / '.rendered/all.yaml').write_text('stale')
        (self.base / 'cache').write_text('not a directory')
        result = self.run_render()
        self.assertNotEqual(result.returncode, 0)
        self.assert_clean()
        self.assertEqual(self.records(), [])
        self.assertNotIn(str(self.base), result.stderr)

    def test_output_links_and_non_directory_fail_without_touching_target(self):
        outside = self.base / 'outside'
        outside.mkdir()
        sentinel = outside / 'all.yaml'
        sentinel.write_text('sentinel')
        (self.repo / '.rendered').symlink_to(outside, target_is_directory=True)
        result = self.run_render()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(sentinel.read_text(), 'sentinel')
        self.assertEqual(self.records(), [])
        (self.repo / '.rendered').unlink()
        (self.repo / '.rendered').mkdir()
        (self.repo / '.rendered/all.yaml').symlink_to(sentinel)
        result = self.run_render()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(sentinel.read_text(), 'sentinel')
        self.assertEqual(self.records(), [])
        self.assertNotIn(str(outside), result.stderr)
        (self.repo / '.rendered/all.yaml').unlink()
        (self.repo / '.rendered').rmdir()
        (self.repo / '.rendered').write_text('not a directory')
        result = self.run_render()
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn(str(self.repo), result.stderr)


if __name__ == '__main__':
    unittest.main()
