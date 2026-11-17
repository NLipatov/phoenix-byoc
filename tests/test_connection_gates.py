"""Real local gate scripts in private source fixtures; no cluster/network tools."""
import copy
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
CANARY = 'PRIVATE_GATE_CANARY_9281'


class GateFixture:
    def __init__(self):
        self.scratch = tempfile.TemporaryDirectory(prefix='connection-gates-')
        self.base = Path(self.scratch.name)
        self.repo = self.base / 'source'
        self.repo.mkdir(mode=0o700)
        # Copy shipped source directories only, never ignored operator inputs,
        # auth homes, sibling checkouts or the repository's untracked documents.
        for name in ('scripts', 'contracts', 'defaults', 'examples', 'values', 'charts'):
            shutil.copytree(ROOT / name, self.repo / name, ignore=shutil.ignore_patterns('__pycache__'))
        for name in ('release.yaml', 'helmfile.yaml.gotmpl'):
            shutil.copy2(ROOT / name, self.repo / name)
        for name in ('bin', 'home', 'tmp'):
            (self.base / name).mkdir(mode=0o700)
        self.bin = self.base / 'bin'
        self.log = self.base / 'events.jsonl'
        self.values_path = self.repo / 'selected-values.yaml'
        self.secrets_path = self.repo / 'selected-secrets.yaml'
        self.yq = shutil.which('yq')
        self.helm = os.environ.get('PHOENIX_TEST_HELM') or shutil.which('helm')
        if not self.yq or not self.helm:
            raise RuntimeError('pinned yq/Helm required; no fallback')
        self.env = {'PATH': str(self.bin) + ':/usr/bin:/bin', 'HOME': str(self.base / 'home'),
                    'TMPDIR': str(self.base / 'tmp'), 'KUBECONFIG': '/dev/null',
                    'PHOENIX_BYOC_NAMESPACE': 'fixture',
                    'PHOENIX_BYOC_VALUES_FILE': str(self.values_path),
                    'PHOENIX_BYOC_SECRETS_FILE': str(self.secrets_path),
                    'HELMFILE_CACHE_HOME': str(self.base / 'chart-cache'),
                    'PHOENIX_BYOC_LOCAL_CHARTS': str(self.repo / 'charts'),
                    'PHOENIX_AGENTFS_RETAINED_IMAGES_JSON': '[]',
                    'TEST_RENDER_MODE': 'success', 'TEST_VERIFY_FAIL': '0'}
        (self.bin / 'yq').symlink_to(Path(self.yq).resolve())
        (self.bin / 'python3').symlink_to(sys.executable)
        version = subprocess.run([self.yq, '--version'], env=self.env, capture_output=True, timeout=10)
        if version.returncode or version.stdout.strip() != b'yq (https://github.com/mikefarah/yq/) version v4.49.2':
            raise RuntimeError('yq4.49.2 required')
        version = subprocess.run([self.helm, 'version', '--short'], env=self.env, capture_output=True, timeout=10)
        if version.returncode or not version.stdout.startswith(b'v3.18.6+'):
            raise RuntimeError('Helm3.18.6 required')
        self.values = self.yaml_json(ROOT / 'tests/fixtures/values.yaml')
        self.secrets = self.yaml_json(ROOT / 'tests/fixtures/values.secrets.yaml')
        self.values['application']['mailer']['deliveryMethod'] = 'test'
        self.write_values(self.values)
        self.write_secrets(self.secrets)
        self.vectors = json.loads((self.repo / 'contracts/llm-connections/v1/semantic-vectors.json').read_text())
        spy = '''import json, os, pathlib, sys
ROLE = sys.argv[1]
a = sys.argv[2:]
LOG = pathlib.Path(%r)
HELM = %r
keys = ('PHOENIX_BYOC_NAMESPACE', 'PHOENIX_BYOC_VALUES_FILE', 'PHOENIX_BYOC_SECRETS_FILE',
        'PHOENIX_BYOC_LOCAL_CHARTS', 'HELMFILE_CACHE_HOME', 'PHOENIX_AGENTFS_RETAINED_IMAGES_JSON')
def event(kind, detail=''):
    with LOG.open('a') as out:
        out.write(json.dumps({'kind': kind, 'tool': ROLE, 'argv': a, 'detail': detail,
                             'env': {k: os.environ.get(k) for k in keys}}) + '\\n')
def unknown():
    event('unexpected')
    print('unexpected_spy_command', file=sys.stderr)
    sys.exit(97)
if ROLE == 'helm':
    if len(a) < 5 or a[:2] != ['template', 'connection-validation']: unknown()
    event('schema')
    os.execv(HELM, [HELM, *a])
elif ROLE == 'kubectl':
    if a == ['config', 'current-context']:
        event('context'); print('fixture-context')
    elif a == ['version', '--output=json']:
        event('read'); print('{}')
    elif len(a) == 3 and a[:2] == ['get', 'customresourcedefinition'] and a[2] in (
            'batchsandboxes.sandbox.opensandbox.io', 'pools.sandbox.opensandbox.io', 'sandboxsnapshots.sandbox.opensandbox.io'):
        event('read'); sys.exit(1)
    elif a == ['get', 'namespace', 'fixture']:
        event('read')
    elif a == ['-n', 'fixture', 'get', 'secret', 'fixture-pull']:
        event('read')
    elif a == ['-n', 'fixture', 'get', 'secret', 'phoenix-remote-ssh-encryption', '--ignore-not-found', '-o',
               'jsonpath={.data.PHOENIX_REMOTE_SSH_ENCRYPTION_KEY}']:
        event('read')
    elif a == ['-n', 'fixture', 'create', 'secret', 'generic', 'phoenix-remote-ssh-encryption',
               '--from-file=PHOENIX_REMOTE_SSH_ENCRYPTION_KEY=/dev/stdin']:
        sys.stdin.buffer.read(); event('mutation', 'gateway-secret')
    elif len(a) == 3 and a[:2] == ['apply', '-f']:
        data = pathlib.Path(a[2]).read_text()
        if 'kind: ServiceAccount' not in data or '  namespace: fixture' not in data: unknown()
        event('mutation', 'service-account')
    else: unknown()
elif ROLE == 'helmfile':
    if a == ['template', '--skip-deps', '--quiet']:
        event('render-start', 'early-chart-accepted')
        print('apiVersion: v1\\nkind: ConfigMap\\nmetadata: {name: fixture}')
        mode = os.environ['TEST_RENDER_MODE']
        if mode in ('late-web', 'late-retention'):
            event('render-reject', mode)
            print(%r, file=sys.stderr); sys.exit(33)
        if mode != 'success': unknown()
        event('render-complete')
    elif a == ['sync'] or a == ['--selector', 'name=fuse-device-plugin', 'sync']:
        event('mutation', 'helmfile-sync')
    else: unknown()
elif ROLE == 'cache-cutover':
    expected = ['--namespace', 'fixture', '--context', 'fixture-context', '--rendered',
                str(pathlib.Path(os.environ['PHOENIX_BYOC_VALUES_FILE']).parent / '.rendered/all.yaml'), '--discard-redis-state']
    if a != expected: unknown()
    event('mutation', 'cache-cutover')
elif ROLE == 'verify':
    if a != ['--namespace', 'fixture', '--values', os.environ['PHOENIX_BYOC_VALUES_FILE'],
             '--secrets', os.environ['PHOENIX_BYOC_SECRETS_FILE']]: unknown()
    event('verify')
    if os.environ['TEST_VERIFY_FAIL'] == '1': sys.exit(42)
else: unknown()
''' % (str(self.log), str(Path(self.helm).resolve()), CANARY)
        self.spy = self.base / 'spy.py'
        self.spy.write_text(spy)
        for role in ('helm', 'helmfile', 'kubectl', 'curl', 'wget', 'docker', 'aws', 'gcloud', 'kubeconform'):
            if role == 'kubeconform':
                continue  # Optional tool absent, not a permissive stub.
            self.wrapper(self.bin / role, role)
        self.wrapper(self.repo / 'scripts/verify.sh', 'verify')
        # The real installer calls this Python entrypoint, not a shell wrapper.
        (self.repo / 'scripts/upgrade-poc-cache.py').write_text(
            'import runpy, sys\nsys.argv.insert(1, "cache-cutover")\nrunpy.run_path(' + repr(str(self.spy)) + ', run_name="__main__")\n')

    def wrapper(self, path, role):
        path.write_text('#!/bin/sh\nexec ' + shlex.quote(sys.executable) + ' -I -B ' +
                        shlex.quote(str(self.spy)) + ' ' + shlex.quote(role) + ' "$@"\n')
        path.chmod(0o700)

    def yaml_json(self, path):
        result = subprocess.run([self.yq, '-o=json', '.', str(path)], env=self.env, capture_output=True, timeout=10)
        if result.returncode:
            raise RuntimeError('synthetic fixture parse failed')
        return json.loads(result.stdout)

    def write_values(self, value):
        if isinstance(value, str):
            self.values_path.write_text(value)
        else:
            # install.sh's legacy pull-secret reader expects block-style YAML.
            result = subprocess.run([self.yq, '-P', '.', '-'], input=json.dumps(value).encode(),
                                    env=self.env, capture_output=True, timeout=10)
            if result.returncode:
                raise RuntimeError('synthetic values serialization failed')
            self.values_path.write_bytes(result.stdout)

    def write_secrets(self, value):
        self.secrets_path.write_text(value if isinstance(value, str) else json.dumps(value))

    def events(self):
        return [json.loads(row) for row in self.log.read_text().splitlines()] if self.log.exists() else []

    def run(self, script, *args):
        result = subprocess.run(['/bin/bash', str(self.repo / 'scripts' / script), *args], cwd=self.repo,
                                env=self.env, capture_output=True, text=True, timeout=90)
        if any(e['kind'] == 'unexpected' for e in self.events()):
            raise AssertionError('unexpected spy command (not a behavioral rejection)')
        if CANARY in result.stdout + result.stderr or CANARY in json.dumps(self.events()):
            raise AssertionError('private canary disclosed')
        return result

    def vector(self, name):
        return copy.deepcopy(next(v['input'] for v in self.vectors if v['id'] == name))


class ConnectionGatesTest(unittest.TestCase):
    def setUp(self):
        self.fixture = GateFixture()
        self.addCleanup(self.fixture.scratch.cleanup)

    def test_invalid_and_unsupported_gate_before_reads_or_render(self):
        f = self.fixture
        cases = [f.vector('generic_only'), f.vector('subscription_auth_rejected'),
                 f.vector('valid/portkey-anthropic/openai-responses/api-key'),
                 {'agentInputDelivery': {'enabled': False, 'env': {'PAD': CANARY}}}, {'llm': None}]
        for script in ('preflight.sh', 'render.sh'):
            for index, config in enumerate(cases):
                with self.subTest(script=script, case=index):
                    f.log.unlink(missing_ok=True)
                    f.write_values({**f.values, **config})
                    render = f.repo / '.rendered'
                    render.mkdir(exist_ok=True)
                    (render / 'all.yaml').write_text('stale')
                    result = f.run(script)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertFalse(any(e['kind'] in ('read', 'mutation', 'render-start') for e in f.events()))
                    if script == 'render.sh':
                        self.assertFalse((render / 'all.yaml').exists())
                        self.assertEqual(list(render.glob('.render.*')), [])

    def test_raw_duplicates_and_invalid_final_overlay(self):
        f = self.fixture
        for script in ('preflight.sh', 'render.sh'):
            for raw in ('agentInputDelivery: null\nagentInputDelivery: {enabled: false}\n',
                        'agentInputDelivery: {enabled: false, enabled: false}\n',
                        'agentInputDelivery: {}\n', 'llm: [unterminated_' + CANARY):
                with self.subTest(script=script, case=raw.split(':')[0]):
                    f.log.unlink(missing_ok=True)
                    f.write_values(f.values)
                    f.write_secrets('secrets: ' + json.dumps(f.secrets['secrets']) + '\n' + raw)
                    result = f.run(script)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertFalse(any(e['kind'] in ('read', 'mutation', 'render-start') for e in f.events()))

    def test_legacy_and_disabled_controls_and_absent_contract_assets(self):
        f = self.fixture
        for config in ({}, {'agentInputDelivery': {'enabled': False}}):
            f.write_values({**f.values, **config})
            self.assertEqual(f.run('preflight.sh').returncode, 0)
            self.assertEqual(f.run('render.sh').returncode, 0)
        f.write_values(f.values)
        shutil.rmtree(f.repo / 'contracts')
        self.assertEqual(f.run('preflight.sh').returncode, 0)
        self.assertEqual(f.run('render.sh').returncode, 0)

    def test_authoring_check_remains_not_install_permission(self):
        f = self.fixture
        f.write_values({**f.values, **f.vector('generic_only')})
        script = f.repo / 'scripts/connection-config.py'
        bootstrap = 'import runpy,sys; sys.path.insert(0, ' + repr(str(script.parent)) + '); sys.argv=["connection-config.py","check-yaml",*sys.argv[1:]]; runpy.run_path(' + repr(str(script)) + ',run_name="__main__")'
        result = subprocess.run([sys.executable, '-I', '-B', '-c', bootstrap, str(f.repo / 'release.yaml'),
                                 str(f.repo / 'defaults/values.yaml'), str(f.values_path), str(f.secrets_path)],
                                env=f.env, capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 0)
