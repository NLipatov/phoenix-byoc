"""Real installer, controlled gate spies; no real preflight/render/cluster calls.

The same test bytes run over BASE and candidate exports. Failures must include a
completed render and actual mutation events, never a missing-tool/stub failure.
"""
import base64
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[1]
YQ = shutil.which('yq')

SPY = r'''
import base64
import json
import os
from pathlib import Path
import signal
import sys

name = Path(sys.argv[0]).name
if name == 'spy.py':
    name = sys.argv.pop(1)
args = sys.argv[1:]
root = Path(os.environ['FIXTURE_ROOT'])
event_file = Path(os.environ['EVENTS'])

def event(kind):
    keys = ('PHOENIX_BYOC_NAMESPACE', 'PHOENIX_BYOC_VALUES_FILE',
            'PHOENIX_BYOC_SECRETS_FILE', 'PHOENIX_BYOC_LOCAL_CHARTS',
            'HELMFILE_CACHE_HOME', 'PHOENIX_AGENTFS_CONTEXT',
            'PHOENIX_AGENTFS_RETAINED_IMAGES_JSON')
    with event_file.open('a') as stream:
        stream.write(json.dumps({'event': kind, 'args': args,
                                'env': {k: os.environ.get(k) for k in keys}}) + '\n')

def change(stage):
    if os.environ.get('CHANGE_STAGE') == stage:
        target = Path(os.environ['CHANGE_TARGET'])
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open('ab') as stream:
            stream.write(b'\n# changed fixture input\n')
        event('changed:' + stage)

def unknown():
    event('UNKNOWN:' + name)
    sys.exit(91)

if name == 'preflight.sh':
    if args: unknown()
    event('preflight')
    change('preflight')
elif name == 'agentfs.sh':
    if args == ['enabled']:
        print('true')
    elif args == ['retain']:
        print('["fixture-retained-image"]')
    elif args == ['managed']:
        print('true')
        change('managed')
    elif args == ['namespace']:
        print('fixture-system')
    elif args == ['capacity']:
        event('capacity')
        change('capacity')
    else: unknown()
elif name == 'render.sh':
    if args: unknown()
    event('render')
    output = root / '.rendered/all.yaml'
    output.parent.mkdir(mode=0o700, exist_ok=True)
    output.write_text('kind: List\nitems: []\n')
    output.chmod(0o600)
    if os.environ.get('POPULATE_CACHE'):
        chart = root / '.tmp/helmfile-cache/new-chart'
        chart.mkdir(parents=True)
        (chart / 'Chart.yaml').write_text('apiVersion: v2\nname: new-chart\nversion: 1.0.0\n')
    guards = list(Path(os.environ['TMPDIR']).glob('phoenix-install-inputs.*'))
    modes = []
    for guard in guards:
        for path in [guard] + list(guard.rglob('*')):
            modes.append([path.is_dir(), path.stat().st_mode & 0o777])
    with event_file.open('a') as stream:
        stream.write(json.dumps({'event': 'private-modes', 'modes': modes}) + '\n')
    change('render')
    event('render-complete')
    if os.environ.get('SIGNAL_RENDER'):
        os.kill(os.getppid(), signal.SIGTERM)
        sys.exit(1)
elif name == 'check-cache-upgrade.sh':
    if args != ['fixture-ns', str(root / '.rendered/all.yaml')]: unknown()
    event('cache-guard')
    change('cache-guard')
elif name == 'upgrade-poc-cache.py':
    if args != ['--namespace', 'fixture-ns', '--context', 'fixture-context',
                '--rendered', str(root / '.rendered/all.yaml'), '--discard-redis-state']: unknown()
    event('MUTATE:cutover')
    change('cutover')
elif name == 'verify.sh':
    if args != ['--namespace', 'fixture-ns', '--values', os.environ['PHOENIX_BYOC_VALUES_FILE'],
                '--secrets', os.environ['PHOENIX_BYOC_SECRETS_FILE']]: unknown()
    event('verify')
    sys.exit(int(os.environ.get('VERIFY_FAIL', '0')))
elif name == 'kubectl':
    if args == ['config', 'current-context']:
        print('fixture-context')
    elif args == ['get', 'namespace', 'fixture-ns']:
        change('namespace-read')
    elif args == ['-n', 'fixture-ns', 'get', 'secret', 'phoenix-remote-ssh-encryption',
                  '--ignore-not-found', '-o', 'jsonpath={.data.PHOENIX_REMOTE_SSH_ENCRYPTION_KEY}']:
        change('secret-read')
    elif args == ['-n', 'fixture-ns', 'create', 'secret', 'generic', 'phoenix-remote-ssh-encryption',
                  '--from-file=PHOENIX_REMOTE_SSH_ENCRYPTION_KEY=/dev/stdin']:
        sys.stdin.buffer.read()
        event('MUTATE:secret')
        change('secret-create')
    elif args == ['--context', 'fixture-context', '-n', 'fixture-system', 'rollout', 'status',
                  'daemonset/fuse-device-plugin', '--timeout=600s']:
        event('rollout')
    elif len(args) == 3 and args[:2] == ['apply', '-f']:
        if Path(args[2]).read_text().startswith('apiVersion: v1\nkind: ServiceAccount\n'):
            event('MUTATE:service-account')
        else: unknown()
    else: unknown()
elif name == 'helmfile':
    if args == ['--selector', 'name=fuse-device-plugin', 'sync']:
        event('MUTATE:fuse')
    elif args == ['sync']:
        event('MUTATE:sync')
        change('sync')
    else: unknown()
elif name == 'openssl':
    if args == ['base64', '-d', '-A']:
        sys.stdout.buffer.write(base64.b64decode(sys.stdin.buffer.read()))
    elif len(args) == 3 and args[0] == 'rand' and args[1] in ('-hex', '-base64'):
        data = b'x' * int(args[2])
        print(data.hex() if args[1] == '-hex' else base64.b64encode(data).decode())
    else: unknown()
else:
    unknown()
'''


class InstallInputGuardTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='install-guard-test-')
        self.addCleanup(self.temp.cleanup)
        self.workspace = Path(self.temp.name)
        self.repo = self.workspace / 'repo'
        self.repo.mkdir()
        # Complete shipped installer trees, never operator files/config homes.
        for directory in ('scripts', 'charts', 'contracts', 'defaults', 'values', 'examples'):
            shutil.copytree(REPO / directory, self.repo / directory,
                            ignore=shutil.ignore_patterns('__pycache__'))
        for filename in ('release.yaml', 'helmfile.yaml.gotmpl', 'BYOC_CONTRACT.md'):
            shutil.copyfile(REPO / filename, self.repo / filename)
        self.bin = self.workspace / 'bin'
        self.bin.mkdir()
        self.home = self.workspace / 'home'
        self.home.mkdir(mode=0o700)
        self.tmp = self.workspace / 'tmp'
        self.tmp.mkdir(mode=0o700)
        self.events_path = self.workspace / 'events.jsonl'
        self.spy = self.workspace / 'spy.py'
        self.spy.write_text(SPY)
        for tool in ('bash', 'dirname', 'pwd', 'mktemp', 'chmod', 'rm', 'awk',
                     'wc', 'tr', 'mkdir', 'cp', 'mv', 'git'):
            source = shutil.which(tool, path='/usr/bin:/bin')
            self.assertIsNotNone(source, tool)
            (self.bin / tool).symlink_to(source)
        (self.bin / 'python3').symlink_to(sys.executable)
        self.assertIsNotNone(YQ, 'yq required on isolated PATH, never skipped/downloaded')
        (self.bin / 'yq').symlink_to(YQ)
        for tool in ('kubectl', 'helmfile', 'helm', 'openssl', 'kubeconform', 'curl', 'wget', 'aws'):
            self.write_spy(self.bin / tool, tool)
        for script in ('preflight.sh', 'render.sh', 'agentfs.sh', 'check-cache-upgrade.sh', 'verify.sh'):
            self.write_spy(self.repo / 'scripts' / script, script)
        (self.repo / 'scripts/upgrade-poc-cache.py').write_text(SPY)
        self.values = self.repo / 'selected-values.yaml'
        self.values.write_text('imagePullSecrets:\n  - name: fixture-pull\n' +
                               '\n'.join(name + ':\n  bundled:\n    enabled: true' for name in
                                         ('postgresql', 'redis', 'cortex', 'clickhouse')) + '\n')
        self.secrets = self.repo / 'selected-secrets.yaml'
        self.canary = base64.b64encode(b'synthetic-private-input-canary!!').decode()
        self.secrets.write_text('secrets:\n  gateway:\n    remoteSshEncryptionKey: ' + self.canary + '\n')
        self.secrets.chmod(0o600)
        # Selected fixture secrets are not tracked; no real operator files used.
        self.assertFalse((self.repo / '.git').exists())
        self.local = self.workspace / 'local-charts'
        (self.local / 'phoenix-web/templates').mkdir(parents=True)
        (self.local / 'phoenix-web/Chart.yaml').write_text('apiVersion: v2\nname: phoenix-web\nversion: 0.2.4\n')
        (self.local / 'phoenix-web/templates/example.yaml').write_text('kind: ConfigMap\n')
        self.cache = self.repo / '.tmp/helmfile-cache/existing-chart'
        self.cache.mkdir(parents=True)
        (self.cache / 'Chart.yaml').write_text('apiVersion: v2\nname: fixture\nversion: 1.0.0\n')
        self.env = {
            'HOME': str(self.home), 'TMPDIR': str(self.tmp), 'PATH': str(self.bin),
            'FIXTURE_ROOT': str(self.repo), 'EVENTS': str(self.events_path),
            'PHOENIX_BYOC_LOCAL_CHARTS': str(self.local),
        }

    def write_spy(self, path, name):
        path.write_text('#!/bin/bash\nexec "' + sys.executable + '" -I -B "' +
                        str(self.spy) + '" ' + name + ' "$@"\n')
        path.chmod(0o700)

    def run_install(self, *flags):
        result = subprocess.run([
            '/bin/bash', str(self.repo / 'scripts/install.sh'), '--namespace', 'fixture-ns',
            '--values', str(self.values), '--secrets', str(self.secrets), *flags,
        ], env=self.env, cwd=self.workspace, capture_output=True, text=True, timeout=30)
        event_text = self.events_path.read_text() if self.events_path.exists() else ''
        self.events = [json.loads(line) for line in event_text.splitlines()]
        self.names = [entry['event'] for entry in self.events]
        self.mutations = [name for name in self.names if name.startswith('MUTATE:')]
        self.assertFalse(any(name.startswith('UNKNOWN:') for name in self.names), self.names)
        self.assertNotIn(self.canary, result.stdout + result.stderr + event_text)
        self.assertEqual(list(self.tmp.iterdir()), [], 'private snapshots and SA tempfile cleaned')
        return result

    def change_at(self, stage, path):
        self.env.update(CHANGE_STAGE=stage, CHANGE_TARGET=str(path))

    def assert_rejected(self, result):
        self.assertIn('render-complete', self.names)
        # On BASE these fail because installer succeeds and mutates, not from a stub error.
        self.assertEqual((result.returncode != 0, self.mutations), (True, []),
                         'behavioral rejection required; events=' + repr(self.names))
        self.assertIn('install_inputs_changed_or_unavailable', result.stderr)

    def test_changed_values_at_render_has_zero_mutations(self):
        self.change_at('render', self.values)
        self.assert_rejected(self.run_install())

    def test_changed_secrets_at_render_has_zero_mutations(self):
        self.change_at('render', self.secrets)
        self.assert_rejected(self.run_install())

    def test_changed_release_at_render_has_zero_mutations(self):
        self.change_at('render', self.repo / 'release.yaml')
        self.assert_rejected(self.run_install())

    def test_changed_defaults_at_render_has_zero_mutations(self):
        self.change_at('render', self.repo / 'defaults/values.yaml')
        self.assert_rejected(self.run_install())

    def test_changed_contract_at_render_has_zero_mutations(self):
        self.change_at('render', self.repo / 'contracts/agent-input-delivery/v1/contract.json')
        self.assert_rejected(self.run_install())

    def test_changed_local_chart_at_render_has_zero_mutations(self):
        self.change_at('render', self.local / 'phoenix-web/templates/example.yaml')
        self.assert_rejected(self.run_install())

    def test_changed_bundled_chart_at_render_has_zero_mutations(self):
        self.change_at('render', self.repo / 'charts/artifact-publisher/Chart.yaml')
        self.assert_rejected(self.run_install())

    def test_changed_values_template_at_render_has_zero_mutations(self):
        self.change_at('render', self.repo / 'values/phoenix-web.yaml.gotmpl')
        self.assert_rejected(self.run_install())

    def test_changed_helmfile_at_render_has_zero_mutations(self):
        self.change_at('render', self.repo / 'helmfile.yaml.gotmpl')
        self.assert_rejected(self.run_install('--discard-redis-state'))

    def test_changed_existing_cache_chart_at_render_has_zero_mutations(self):
        self.change_at('render', self.cache / 'Chart.yaml')
        self.assert_rejected(self.run_install())

    def test_newly_populated_cache_chart_is_sealed_after_render(self):
        self.env['POPULATE_CACHE'] = '1'
        self.change_at('cache-guard', self.repo / '.tmp/helmfile-cache/new-chart/Chart.yaml')
        self.assert_rejected(self.run_install())

    def test_added_local_template_after_render_has_zero_mutations(self):
        self.change_at('cache-guard', self.local / 'phoenix-web/templates/added.yaml')
        self.assert_rejected(self.run_install())

    def test_changed_rendered_artifact_after_render_has_zero_mutations(self):
        self.change_at('cache-guard', self.repo / '.rendered/all.yaml')
        self.assert_rejected(self.run_install())

    def test_changed_source_during_gateway_read_has_zero_mutations(self):
        self.change_at('secret-read', self.secrets)
        self.assert_rejected(self.run_install())

    def test_changed_source_during_preflight_stops_before_render(self):
        self.change_at('preflight', self.values)
        result = self.run_install()
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('render', self.names)
        self.assertEqual(self.mutations, [])

    def test_unchanged_legacy_preserves_environment_order_and_private_modes(self):
        self.env['POPULATE_CACHE'] = '1'
        result = self.run_install('--discard-redis-state')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.mutations, ['MUTATE:cutover', 'MUTATE:secret', 'MUTATE:fuse',
                                         'MUTATE:sync', 'MUTATE:service-account'])
        self.assertEqual(self.names[-1], 'verify')
        self.assert_full_install_order()
        self.assertLess(self.names.index('render-complete'), self.names.index(self.mutations[0]))
        modes = next(e['modes'] for e in self.events if e['event'] == 'private-modes')
        self.assertTrue(modes, 'guard snapshot must exist during render')
        self.assertTrue(all(mode == (0o700 if directory else 0o600) for directory, mode in modes))
        for event in self.events:
            if 'env' not in event:
                continue
            env = event['env']
            self.assertEqual(env['PHOENIX_BYOC_NAMESPACE'], 'fixture-ns')
            self.assertEqual(env['PHOENIX_BYOC_VALUES_FILE'], str(self.values))
            self.assertEqual(env['PHOENIX_BYOC_SECRETS_FILE'], str(self.secrets))
            self.assertEqual(env['PHOENIX_BYOC_LOCAL_CHARTS'], str(self.local))
            self.assertEqual(env['PHOENIX_AGENTFS_CONTEXT'], 'fixture-context')
            if event['event'] != 'preflight':
                self.assertEqual(env['PHOENIX_AGENTFS_RETAINED_IMAGES_JSON'], '["fixture-retained-image"]')

    def assert_full_install_order(self):
        required = ['render-complete', 'MUTATE:cutover', 'MUTATE:secret', 'MUTATE:fuse',
                    'rollout', 'capacity', 'MUTATE:sync', 'MUTATE:service-account', 'verify']
        self.assertEqual([name for name in self.names if name in required], required)

    def test_readiness_order_assertion_detects_omissions_and_reordering(self):
        # Mutate only this test's disposable installer copy, before input capture.
        path = self.repo / 'scripts/install.sh'
        original = path.read_text()
        rollout = ('    kubectl --context "$context" -n "$plugin_namespace" rollout status \\\n'
                   '      daemonset/fuse-device-plugin --timeout=600s')
        capacity = '  "$repo_root/scripts/agentfs.sh" capacity'
        self.assertEqual(original.count(rollout), 1)
        self.assertEqual(original.count(capacity), 1)
        mutants = [original.replace(rollout, '    :'), original.replace(capacity, '  :'),
                   original.replace(capacity, '  :').replace(
                       rollout, '    "$repo_root/scripts/agentfs.sh" capacity\n' + rollout)]
        try:
            for index, mutant in enumerate(mutants):
                with self.subTest(mutation=index):
                    path.write_text(mutant)
                    self.events_path.unlink(missing_ok=True)
                    result = self.run_install('--discard-redis-state')
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(self.mutations, ['MUTATE:cutover', 'MUTATE:secret',
                                                     'MUTATE:fuse', 'MUTATE:sync',
                                                     'MUTATE:service-account'])
                    with self.assertRaises(AssertionError):
                        self.assert_full_install_order()
        finally:
            path.write_text(original)

    def test_relative_local_chart_root_is_preserved(self):
        self.env['PHOENIX_BYOC_LOCAL_CHARTS'] = '../local-charts'
        result = self.run_install()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(all(e['env']['PHOENIX_BYOC_LOCAL_CHARTS'] == '../local-charts'
                            for e in self.events if 'env' in e))

    def test_oversized_selected_input_fails_safely_before_gates(self):
        with self.values.open('wb') as stream:
            stream.truncate(16 * 1024 * 1024 + 1)
        result = self.run_install()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.names, [])
        self.assertIn('install_inputs_changed_or_unavailable', result.stderr)

    def test_special_selected_input_fails_without_blocking(self):
        self.values.unlink()
        os.mkfifo(self.values)
        result = self.run_install()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.names, [])
        self.assertIn('install_inputs_changed_or_unavailable', result.stderr)

    def test_external_cache_is_root_binding_only(self):
        external = self.workspace / 'external-cache'
        external.mkdir()
        (external / 'unrelated-private-file').write_text('not an installer input')
        self.env['HELMFILE_CACHE_HOME'] = str(external)
        self.change_at('render', external / 'unrelated-private-file')
        result = self.run_install()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(all(e['env']['HELMFILE_CACHE_HOME'] == str(external)
                            for e in self.events if 'env' in e))

    def test_cutover_change_blocks_later_mutations(self):
        self.change_at('cutover', self.values)
        result = self.run_install('--discard-redis-state')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.mutations, ['MUTATE:cutover'])

    def test_change_before_fuse_blocks_fuse_and_sync(self):
        self.change_at('managed', self.values)
        result = self.run_install()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.mutations, ['MUTATE:secret'])

    def test_change_before_full_sync_blocks_sync(self):
        self.change_at('capacity', self.values)
        result = self.run_install()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.mutations, ['MUTATE:secret', 'MUTATE:fuse'])

    def test_change_during_sync_blocks_service_account(self):
        self.change_at('sync', self.values)
        result = self.run_install()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.mutations, ['MUTATE:secret', 'MUTATE:fuse', 'MUTATE:sync'])

    def test_signal_cleans_private_snapshots(self):
        self.env['SIGNAL_RENDER'] = '1'
        result = self.run_install()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.mutations, [])

    def test_verify_remains_final_success_gate(self):
        self.env['VERIFY_FAIL'] = '1'
        result = self.run_install()
        self.assertEqual(result.returncode, 1)
        self.assertEqual(self.names[-1], 'verify')

    def test_generate_secrets_precedes_capture(self):
        self.secrets.unlink()
        result = self.run_install('--generate-secrets')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('Internal secret generation completed.', result.stdout)
        self.assertEqual(stat.S_IMODE(self.secrets.stat().st_mode), 0o600)
        self.assertEqual(self.names[-1], 'verify')


if __name__ == '__main__':
    unittest.main()
