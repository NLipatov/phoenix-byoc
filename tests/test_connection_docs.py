"""Guide examples through the real owner contract, yq adapter and Helm validator."""
import copy
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from connection_contract import (ContractError, NamedCapability, check_named_capabilities,
                                 load_contract, validate_connections)
from connection_yaml import YQ_VERSION, load_yaml_authoring

GUIDE = ROOT / 'docs/connection-inputs.md'
LINK_DOCS = ('README.md', 'BYOC_CONTRACT.md', 'docs/installation.md',
             'docs/configuration.md', 'docs/prerequisites.md', 'docs/rollback.md')


class ConnectionDocsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        for tool, args, expected in (
            ('yq', ['--version'], YQ_VERSION),
            ('helm', ['version', '--template', '{{.Version}}'], b'v3.18.6'),
        ):
            executable = shutil.which(tool)
            if not executable:
                raise RuntimeError('required pinned tool missing: ' + tool)
            result = subprocess.run([executable, *args], capture_output=True, timeout=10)
            if result.returncode or result.stdout.strip() != expected:
                raise RuntimeError('required pinned tool mismatch: ' + tool)
        cls.bundle = load_contract(ROOT)

    def guide(self):
        self.assertTrue(GUIDE.is_file(), 'consolidated guide must exist')
        return GUIDE.read_text()

    def examples(self):
        blocks = re.findall(r'<!-- example: ([a-z-]+) -->\n```yaml\n(.*?)```',
                            self.guide(), re.S)
        self.assertEqual([name for name, _ in blocks],
                         ['generic', 'secret-only', 'portkey', 'disabled'])
        return dict(blocks)

    def load_example(self, text):
        with tempfile.TemporaryDirectory(prefix='connection-docs-') as folder:
            paths = [Path(folder) / name for name in ('release', 'defaults', 'values', 'secrets')]
            for path in paths:
                path.write_text('{}\n')
                path.chmod(0o600)
            paths[2].write_text(text)
            # Exercise the documented existing CLI with isolated Python imports.
            script = ROOT / 'scripts/connection-config.py'
            bootstrap = ('import runpy,sys; from pathlib import Path; '
                         'sys.path.insert(0,str(Path(sys.argv[1]).parent)); '
                         'sys.argv=sys.argv[1:]; runpy.run_path(sys.argv[0],run_name="__main__")')
            result = subprocess.run([sys.executable, '-I', '-B', '-c', bootstrap,
                                     str(script), 'check-yaml', *map(str, paths)],
                                    capture_output=True, timeout=45)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout + result.stderr, b'')
            return load_yaml_authoring(*paths, bundle=self.bundle)

    def test_documented_examples_validate(self):
        configs = {name: self.load_example(raw) for name, raw in self.examples().items()}
        for name, config in configs.items():
            self.assertEqual(validate_connections(config, self.bundle).enabled, name != 'disabled')
        portkey = configs['portkey']['llm']
        canonical = next(v['input'] for v in json.loads(self.bundle.vectors.read_text())
                         if v['id'] == 'valid/portkey-anthropic/openai-completions/api-key')
        expected = copy.deepcopy(canonical['llm']['connections']['example'])
        expected['API_KEY_ENV'] = 'PORTKEY_API_KEY'
        expected['HEADERS_JSON'] = {'x-portkey-config': '$PORTKEY_CONFIG_ID'}
        self.assertEqual(portkey['connections'], {'portkey_internal': expected})
        self.assertEqual(portkey['secretEnv']['PORTKEY_API_KEY'],
                         {'name': 'existing-portkey-secret', 'key': 'api-key'})
        self.assertEqual(validate_connections(configs['secret-only'], self.bundle).plain_env, {})

    def test_examples_do_not_promote_blocked_capabilities(self):
        capabilities = json.loads(self.bundle.capabilities.read_text())
        self.assertEqual(len(capabilities['entries']), 27)
        self.assertEqual({entry['status'] for entry in capabilities['entries']}, {'blocked'})
        self.assertEqual(capabilities['liveAcceptance'], [])
        for name, raw in self.examples().items():
            config = self.load_example(raw)
            validated = validate_connections(config, self.bundle)
            if name == 'portkey':
                with self.assertRaises(ContractError) as caught:
                    check_named_capabilities(config, validated, self.bundle)
                self.assertEqual(caught.exception.code, 'connection_capability_unsupported')
            else:
                self.assertIs(check_named_capabilities(config, validated, self.bundle),
                              NamedCapability.NOT_APPLICABLE)

    def test_default_examples_remain_legacy(self):
        config = load_yaml_authoring(ROOT / 'release.yaml', ROOT / 'defaults/values.yaml',
                                     ROOT / 'examples/values.yaml', ROOT / 'examples/values.secrets.yaml',
                                     bundle=self.bundle)
        self.assertEqual(config, {})
        self.assertFalse(validate_connections(config, self.bundle).enabled)

    def test_rollback_requires_disabling_and_drain(self):
        guide = ' '.join(self.guide().split())
        for phrase in ('Pause admission', 'drain', 'remove `llm`', 'PVCs', 'IAM',
                       'secret rotation', 'Web-before-Engine', 'retained images'):
            self.assertIn(phrase, guide)
        disabled = self.load_example(self.examples()['disabled'])
        self.assertNotIn('llm', disabled)
        self.assertEqual(disabled['agentInputDelivery'],
                         {'enabled': False, 'allowedEnterpriseIds': [], 'env': {}, 'secretEnv': {}})

    def test_docs_distinguish_schema_runtime_live(self):
        text = self.guide()
        for phrase in ('authoring-only', 'all 27', '0.2.6', '0.2.8', '0.2.9',
                       'feature-branch', 'not installation approval', 'Pi 1.4.0',
                       'modelIds', 'ExecutionEnterpriseID', 'not an agent bundle PIN',
                       'same-UID', 'remote artifacts', 'canonical output', 'Entra',
                       'key-presence', 'per delivery', 'live acceptance', 'private snapshots'):
            self.assertIn(phrase, text)

    def test_no_model_knobs_or_provider_key_generation_claim(self):
        for raw in self.examples().values():
            config = self.load_example(raw)  # Owner schema, not a copied field allowlist.
            for key in ('modelIds', 'profiles', 'allowedAgentDigests', 'compatibility', 'allowUnsupported'):
                self.assertNotIn(key, json.dumps(config))
        self.assertIn('never generated', self.guide())
        self.assertIn('Generic `PHOENIX_LLM_*`', self.guide())

    def test_guide_links_and_entry_points(self):
        text = self.guide()
        for target in re.findall(r'\[[^\]]+\]\(([^)]+)\)', text):
            self.assertNotIn('://', target)  # This guide links only checked-in sources.
            self.assertTrue((GUIDE.parent / target.split('#')[0]).is_file(), target)
        for path in LINK_DOCS:
            doc = ROOT / path
            target = 'docs/connection-inputs.md' if doc.parent == ROOT else 'connection-inputs.md'
            self.assertIn('](' + target, doc.read_text(), path)


if __name__ == '__main__':
    unittest.main()
