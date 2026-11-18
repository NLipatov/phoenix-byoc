"""Real installer/preflight/render ordering with synthetic, fail-closed tool spies."""
import json
from pathlib import Path
import shutil
import unittest

from test_connection_gates import CANARY, GateFixture


class ConnectionInstallTest(unittest.TestCase):
    def setUp(self):
        self.fixture = GateFixture()
        self.addCleanup(self.fixture.scratch.cleanup)

    def install(self, *options):
        f = self.fixture
        return f.run('install.sh', '--namespace', 'fixture', '--values', str(f.values_path),
                     '--secrets', str(f.secrets_path), *options)

    def mutations(self):
        return [e for e in self.fixture.events() if e['kind'] == 'mutation']

    def test_invalid_typed_connection_has_zero_mutations(self):
        f = self.fixture
        cases = [f.vector('subscription_auth_rejected'), f.vector('generic_only'),
                 f.vector('valid/portkey-anthropic/openai-responses/api-key'),
                 {'llm': None}, {'agentInputDelivery': {'enabled': False, 'env': {'PAD': CANARY}}}]
        for index, config in enumerate(cases):
            with self.subTest(case=index):
                f.log.unlink(missing_ok=True)
                f.write_values({**f.values, **config})
                result = self.install()
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(self.mutations(), [])
                self.assertFalse(any(e['kind'] == 'read' for e in f.events()))
                self.assertFalse(any(e['kind'] == 'render-start' for e in f.events()))

    def test_raw_duplicate_and_invalid_secrets_overlay_have_zero_reads(self):
        f = self.fixture
        for raw in ('agentInputDelivery: null\nagentInputDelivery: {enabled: false}',
                    'agentInputDelivery: {enabled: false, enabled: false}', 'llm: {}'):
            with self.subTest(case=raw.split(':')[0]):
                f.log.unlink(missing_ok=True)
                f.write_secrets('secrets: ' + json.dumps(f.secrets['secrets']) + '\n' + raw)
                result = self.install()
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(self.mutations(), [])
                self.assertFalse(any(e['kind'] == 'read' for e in f.events()))

    def test_late_release_schema_failure_has_zero_mutations(self):
        self.late_render_failures(())

    def test_discard_redis_state_still_waits_for_full_render(self):
        self.late_render_failures(('--discard-redis-state',))

    def late_render_failures(self, options):
        f = self.fixture
        # These controlled late-chart failures exercise real installer/render
        # order. Real published chart/schema behavior has separate render tests.
        for mode in ('late-web', 'late-retention'):
            with self.subTest(mode=mode):
                f.log.unlink(missing_ok=True)
                f.env['TEST_RENDER_MODE'] = mode
                rendered = f.repo / '.rendered'
                rendered.mkdir(exist_ok=True)
                (rendered / 'all.yaml').write_text('stale success')
                result = self.install(*options)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(self.mutations(), [])
                self.assertEqual([e['detail'] for e in f.events() if e['kind'] == 'render-reject'], [mode])
                self.assertFalse((rendered / 'all.yaml').exists())
                self.assertEqual(list(rendered.glob('.render.*')), [])

    def test_generate_secrets_rejects_raw_duplicates_before_normalization(self):
        f = self.fixture
        # Generation adds the example's external placeholders unless disabled
        # ECR credentials are explicitly empty; keep that unrelated gate valid.
        f.secrets['secrets']['registry'] = {'ecr': {'accessKeyId': '', 'secretAccessKey': ''}}
        for name, raw in (
            ('root', 'agentInputDelivery: null\nagentInputDelivery: {enabled: false}'),
            ('nested', 'agentInputDelivery: {enabled: false, enabled: false}'),
        ):
            with self.subTest(case=name):
                f.log.unlink(missing_ok=True)
                f.write_secrets('secrets: ' + json.dumps(f.secrets['secrets']) + '\n' + raw)
                original = f.secrets_path.read_bytes()
                result = self.install('--generate-secrets')
                observed = (result.returncode, sum(e['kind'] == 'read' for e in f.events()),
                            [e['detail'] for e in self.mutations()])
                self.assertEqual(observed, (1, 0, []))
                self.assertTrue(f.secrets_path.read_bytes() == original,
                                'raw selected secrets were overwritten before validation')
                self.assertFalse(any(e['kind'] == 'render-start' for e in f.events()))

    def test_generate_secrets_valid_legacy_controls(self):
        f = self.fixture
        f.secrets['secrets']['registry'] = {'ecr': {'accessKeyId': '', 'secretAccessKey': ''}}
        f.secrets['secrets']['application']['secretKeyBase'] = 'GENERATE_HEX_64'
        for name, config in (('absent', {}), ('disabled', {'agentInputDelivery': {'enabled': False}}),
                             ('absent-without-contracts', {})):
            with self.subTest(case=name):
                f.log.unlink(missing_ok=True)
                if name == 'absent-without-contracts':
                    shutil.rmtree(f.repo / 'contracts')
                f.write_secrets({**f.secrets, **config})
                result = self.install('--generate-secrets')
                self.assertEqual(result.returncode, 0)
                self.assertEqual([e['detail'] for e in self.mutations()], ['gateway-secret', 'helmfile-sync'])
                self.assertEqual(f.events()[-1]['kind'], 'verify')
                generated = f.yaml_json(f.secrets_path)['secrets']
                self.assertEqual(f.secrets_path.stat().st_mode & 0o777, 0o600)
                self.assertRegex(generated['application']['secretKeyBase'], r'^[0-9a-f]{128}$')
                self.assertTrue(all(value == f.secrets['secrets']['agents'].get(key, '')
                                    for key, value in generated['agents'].items()), 'provider credential changed')
                self.assertTrue(generated['application']['secretKeyBase'] not in
                                result.stdout + result.stderr + json.dumps(f.events()), 'generated secret disclosed')

    def test_generate_secrets_only_local_writes_on_failure(self):
        f = self.fixture
        f.write_values({**f.values, **f.vector('generic_only')})
        f.secrets_path.unlink()
        result = self.install('--generate-secrets')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.mutations(), [])
        self.assertFalse(any(e['kind'] == 'read' for e in f.events()))
        generated = f.yaml_json(f.secrets_path)['secrets']
        self.assertEqual(f.secrets_path.stat().st_mode & 0o777, 0o600)
        self.assertTrue(all(value == '' for value in generated['agents'].values()))
        self.assertRegex(generated['application']['secretKeyBase'], r'^[0-9a-f]{128}$')
        for value in (generated['application']['secretKeyBase'], generated['application']['workflowEngineToken'],
                      generated['gateway']['remoteSshEncryptionKey']):
            self.assertNotIn(value, result.stdout + result.stderr + json.dumps(f.events()))

    def test_source_environment_is_safe_before_reads_or_mutations(self):
        f = self.fixture
        release_path = f.repo / 'release.yaml'
        release = f.yaml_json(release_path)
        for value in ('preview\n' + CANARY, '\x1b[31m' + CANARY, 'x' * 65, False, ['preview']):
            with self.subTest(kind=type(value).__name__):
                f.log.unlink(missing_ok=True)
                release['release']['sourceEnvironment'] = value
                release_path.write_text(json.dumps(release))
                result = self.install()
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('release_source_environment_invalid', result.stderr)
                self.assertEqual(self.mutations(), [])
                self.assertFalse(any(e['kind'] == 'read' for e in f.events()))
                self.assertNotIn(CANARY, result.stdout + result.stderr)

    def test_absent_source_environment_preserves_legacy_install(self):
        f = self.fixture
        release_path = f.repo / 'release.yaml'
        release = f.yaml_json(release_path)
        release['release'].pop('sourceEnvironment', None)
        release_path.write_text(json.dumps(release))
        result = self.install()
        self.assertEqual(result.returncode, 0)
        self.assertIn('Source environment: unspecified', result.stdout)

    def test_valid_install_gates_all_mutations_and_verify_is_final(self):
        f = self.fixture
        f.write_values({**f.values, 'imagePullSecrets': [{'name': 'fixture-pull'}]})
        for verify_fail in ('0', '1'):
            with self.subTest(verify_fail=verify_fail):
                f.log.unlink(missing_ok=True)
                f.env['TEST_VERIFY_FAIL'] = verify_fail
                result = self.install('--discard-redis-state')
                self.assertEqual(result.returncode, 0 if verify_fail == '0' else 42)
                events = f.events()
                complete = next(i for i, e in enumerate(events) if e['kind'] == 'render-complete')
                self.assertTrue(all(i > complete for i, e in enumerate(events) if e['kind'] == 'mutation'))
                self.assertEqual([e['detail'] for e in self.mutations()],
                                 ['cache-cutover', 'gateway-secret', 'helmfile-sync', 'service-account'])
                self.assertEqual(events[-1]['kind'], 'verify')
                for event in events:
                    if event['kind'] != 'schema':
                        self.assertEqual(event['env'], {k: f.env[k] for k in event['env']})
                for text in ('0.2.6 (stable)', 'Source environment: preview', 'fixture-context', 'Bundled PostgreSQL:',
                             'OpenSandbox ctrl:', 'ECR token refresh:', 'all.yaml'):
                    self.assertIn(text, result.stdout)
