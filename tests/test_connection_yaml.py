"""Raw authoring checks through real pinned yq and the existing Helm validator."""
import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from connection_contract import ContractError, load_contract
import connection_yaml


class ConnectionYamlTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        tool = shutil.which('yq')
        if not tool:
            raise RuntimeError('pinned yq required')
        version = subprocess.run([tool, '--version'], capture_output=True, timeout=10)
        if version.returncode or version.stdout.strip() != connection_yaml.YQ_VERSION:
            raise RuntimeError('yq 4.49.2 required; no fallback')
        cls.bundle = load_contract(ROOT)
        vectors = json.loads(cls.bundle.vectors.read_text())
        cls.named = next(v['input'] for v in vectors if v['id'] == 'valid/portkey-anthropic/openai-responses/api-key')
        cls.generic = next(v['input'] for v in vectors if v['id'] == 'generic_only')

    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory(prefix='connection-yaml-test-')
        self.addCleanup(self.scratch.cleanup)
        self.folder = Path(self.scratch.name)
        self.paths = [self.folder / name for name in ('release', 'defaults', 'values', 'secrets')]
        self.canary = 'PRIVATE_CANARY_9f51'
        for path in self.paths:
            path.write_text('{}\n')

    def layer(self, index, value):
        self.paths[index].write_text(value if isinstance(value, str) else json.dumps(value))

    def cli(self, env=None):
        result = subprocess.run([sys.executable, '-B', str(ROOT / 'scripts/connection-config.py'),
                                 'check-yaml', *map(str, self.paths)], env=env,
                                capture_output=True, timeout=45)
        self.assertNotIn(self.canary.encode(), result.stdout + result.stderr)
        self.assertNotIn(str(self.folder).encode(), result.stdout + result.stderr)
        self.assertNotIn(b'Traceback', result.stdout + result.stderr)
        self.assertEqual(result.stdout, b'')
        return result

    def rejected(self, code=None):
        result = self.cli()
        self.assertEqual(result.returncode, 1)
        if code:
            self.assertTrue(result.stderr.startswith(code.encode() + b': '), result.stderr)
        self.assertRegex(result.stderr.decode(), r'^[a-z_]+: /(?:llm|agentInputDelivery)?\n$')

    def load(self):
        return connection_yaml.load_yaml_authoring(*self.paths, bundle=self.bundle)

    def test_duplicate_authoring_keys_before_merge(self):
        # Duplicate-preserving JSON is essential: yq recursive descent sees only
        # the last node, and a normal JSON decoder or merge hides the first one.
        for raw in (
            'agentInputDelivery: {enabled: false, enabled: false}\n',
            'agentInputDelivery: null\nagentInputDelivery: {enabled: false}\n',
            'agentInputDelivery: {enabled: true, allowedEnterpriseIds: ["00000000-0000-4000-8000-000000000001"], env: {PAD: bad, PAD: good}}\n',
            'llm: null\nllm: ' + json.dumps(self.named['llm']) + '\n',
        ):
            with self.subTest(raw=raw):
                self.layer(2, raw.replace('bad', self.canary))
                self.rejected('yaml_duplicate_authoring_key')

    def test_secrets_overlay_overrides_are_validated(self):
        for key in ('llm', 'agentInputDelivery'):
            for invalid in ({}, None, [], 0, False, self.canary):
                with self.subTest(key=key, invalid=invalid):
                    self.layer(2, self.named)
                    self.layer(3, {key: invalid})
                    self.rejected('connection_schema_invalid')

    def test_valid_legacy_generic_and_named(self):
        for config in ({}, self.generic, self.named):
            with self.subTest(kind=list(config)):
                self.layer(2, config)
                self.assertEqual(self.cli().returncode, 0)
                self.assertEqual(self.load(), config)
        # The repository examples contain unrelated aliases; do not ban them.
        self.paths = [ROOT / 'release.yaml', ROOT / 'defaults/values.yaml',
                      ROOT / 'examples/values.yaml', ROOT / 'examples/values.secrets.yaml']
        self.assertEqual(self.cli().returncode, 0)
        self.assertEqual(self.load(), {})

    def test_malformed_presence_cannot_be_repaired_by_later_layer(self):
        for key in ('llm', 'agentInputDelivery'):
            for invalid in ({}, None, [], False, 1, self.canary):
                self.layer(2, {key: invalid})
                self.layer(3, self.named)
                self.rejected('connection_schema_invalid')

    def test_partial_maps_merge_in_order_and_final_semantics_apply(self):
        config = copy.deepcopy(self.named)
        self.layer(0, config)
        for index, value in ((1, 'defaults'), (2, 'values'), (3, 'secrets')):
            self.layer(index, {'llm': {'env': {'LAYER': value}}})
        merged = self.load()
        self.assertEqual(merged['llm']['env']['LAYER'], 'secrets')
        self.assertEqual(merged['llm']['connections'], config['llm']['connections'])
        self.assertEqual(self.cli().returncode, 0)
        self.layer(3, {'llm': {'connections': {'example': {'BASE_URL': 'https://gateway.example.invalid/?token=' + self.canary}}}})
        self.rejected()  # The existing schema/semantics own URL rejection.
        self.layer(3, {'llm': {'connections': {'example': {'API_KEY_ENV': 'MISSING'}}}})
        result = self.cli()
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stderr, b'secret_reference_required: /llm/connections/API_KEY_ENV\n')

    def test_presence_types_and_malformed_yaml(self):
        for key in ('llm', 'agentInputDelivery'):
            for value in ('{}', 'null', '[]', 'false', '1', '"' + self.canary + '"'):
                self.layer(2, key + ': ' + value)
                self.rejected('connection_schema_invalid')
        self.layer(2, 'llm: [unterminated_' + self.canary)
        self.rejected('yaml_parse_invalid')
        self.layer(2, 'agentInputDelivery: {enabled: false, env: {PAD: .nan}}')
        self.rejected('yaml_parse_invalid')

    def test_nested_duplicates_in_protected_mappings(self):
        for field in ('env', 'secretEnv', 'connections'):
            self.layer(2, 'llm: {' + field + ': {' + self.canary + ': 1, ' + self.canary + ': 2}}')
            self.rejected('yaml_duplicate_authoring_key')
        self.layer(2, 'agentInputDelivery: {secretEnv: {KEY: {name: bad, name: good, key: token}}}')
        self.rejected('yaml_duplicate_authoring_key')

    def test_unsupported_protected_alias_merge_tag_key_and_multidocument(self):
        for raw in (
            'base: &base {enabled: false}\nagentInputDelivery: *base',
            'base: &base {enabled: false}\nagentInputDelivery: {<<: *base}',
            'base: &base {agentInputDelivery: {enabled: false}}\n<<: *base',
            'base: &base {llm: null}\n<<: *base\nllm: {}',
            'agentInputDelivery: !custom {enabled: false}',
            'agentInputDelivery: {enabled: false, env: {1: value}}',
            'agentInputDelivery: {enabled: false, env: {? [KEY]: value}}',
            'agentInputDelivery: {enabled: false}\n---\nlegacy: true',
            'legacy: true\n---\nllm: null',
            'base: &base {llm: null}\n<<: *base\n"<<": {legacy: true}\nagentInputDelivery: {enabled: false}',
        ):
            with self.subTest(raw=raw):
                self.layer(2, raw)
                self.rejected('yaml_representation_unsupported')

    def test_hidden_nested_merge_entries_rejected(self):
        scope = 'enabled: true, allowedEnterpriseIds: ["00000000-0000-4000-8000-000000000001"]'
        locations = (
            ('block', '{enabled: false}', 'agentInputDelivery: {%s}'),
            ('env', '{TRACE: ' + self.canary + '}', 'agentInputDelivery: {' + scope + ', env: {%s}}'),
            ('reference', '{name: synthetic-provider-secret, key: api-key}',
             'agentInputDelivery: {' + scope + ', secretEnv: {KEY: {%s}}}'),
            ('headers', '{x-trace: ' + self.canary + '}',
             'llm: {connections: {example: {HEADERS_JSON: {%s}}}}'),
        )
        for location, anchor, template in locations:
            self.layer(0, self.named if location == 'headers' else {})
            for merge_key in ('<<', '"<<"'):
                for operand in ('*base', '[*base]'):
                    for reverse in (False, True):
                        with self.subTest(location=location, quoted=merge_key != '<<',
                                          list_form=operand.startswith('['), reverse=reverse):
                            entries = [merge_key + ': ' + operand, '"<<": {' + self.canary + ': true}']
                            if reverse:
                                entries.reverse()
                            self.layer(2, 'base: &base ' + anchor + '\n' + template % ', '.join(entries))
                            self.rejected('yaml_representation_unsupported')

    def test_hidden_merge_shadow_variants_and_ancestor_duplicates(self):
        for shadow in ('null', '[]', '"' + self.canary + '"'):
            with self.subTest(shadow_type=shadow[:1]):
                self.layer(2, 'base: &base {enabled: false}\n'
                           'agentInputDelivery: {<<: *base, "<<": ' + shadow + '}')
                self.rejected('yaml_representation_unsupported')
        # Even quoted, unaliased << entries disappear during yq JSON encoding.
        self.layer(2, 'agentInputDelivery: {enabled: false, "<<": {' + self.canary + ': true}}')
        self.rejected('yaml_representation_unsupported')
        for reverse in (False, True):
            entries = ['env: {<<: *base, "<<": {' + self.canary + ': true}}', 'env: {}']
            if reverse:
                entries.reverse()
            self.layer(2, 'base: &base {TRACE: safe}\nagentInputDelivery: {enabled: false, '
                       + ', '.join(entries) + '}')
            self.rejected('yaml_duplicate_authoring_key')

    def test_unrelated_hidden_merge_with_valid_partial_overlay(self):
        self.layer(0, self.named)
        self.layer(3, {'llm': {'env': {'LAYER': 'secrets'}}})
        for reverse in (False, True):
            entries = ['<<: [*base]', '"<<": {' + self.canary + ': true}']
            if reverse:
                entries.reverse()
            self.layer(2, 'base: &base {legacy: true}\nlegacy: {' + ', '.join(entries) + '}\n'
                       'legacyAlias: *base\nllm: {env: {LAYER: values}}')
            self.assertEqual(self.cli().returncode, 0)
            merged = self.load()
            self.assertEqual(merged['llm']['env']['LAYER'], 'secrets')
            self.assertEqual(merged['llm']['connections'], self.named['llm']['connections'])

    def test_unrelated_legacy_representations_are_not_banned(self):
        for raw in (
            'legacy: {X: a, X: b}',
            'base: &base {legacy: true}\n<<: *base',
            'legacy: !custom value',
            'legacy: true\n---\nother: false',
            'base: &base {legacy: true}\n<<: *base\nagentInputDelivery: {enabled: false}',
        ):
            self.layer(2, raw)
            self.assertEqual(self.cli().returncode, 0)

    def test_template_selected_paths_rejected_before_tools(self):
        for index in (2, 3):
            with self.subTest(layer=index):
                original = self.paths[index]
                selected = original.with_suffix('.yaml.gotmpl')
                selected.write_text('{}\n# {{ "agentInputDelivery: {enabled: true}" }}\n')
                self.paths[index] = selected
                result = self.cli(dict(os.environ, PATH=str(self.folder)))
                self.assertEqual(result.returncode, 1)
                self.assertEqual(result.stderr, b'yaml_template_unsupported: /\n')
            self.paths[index] = original

    def test_glob_selected_paths_rejected_before_tools(self):
        for index in (2, 3):
            for suffix in ('.[g]otmpl', '.y?ml', '.y*ml', '.ya\\ml'):
                with self.subTest(layer=index, suffix=suffix):
                    original = self.paths[index]
                    selected = original.with_name(original.name + suffix)
                    selected.write_text('{}\n')
                    self.paths[index] = selected
                    result = self.cli(dict(os.environ, PATH=str(self.folder)))
                    self.assertEqual(result.returncode, 1)
                    self.assertEqual(result.stderr, b'yaml_path_pattern_unsupported: /\n')
                self.paths[index] = original

    def test_missing_and_wrong_yq_fail_closed(self):
        env = dict(os.environ, PATH=str(self.folder))
        missing = self.cli(env)
        self.assertEqual(missing.returncode, 1)
        self.assertEqual(missing.stderr, b'yaml_tool_unavailable: /\n')
        # Real yq still executes; changing the expected version exercises mismatch
        # without a fake executable, download, or dependency on an old installation.
        with patch.object(connection_yaml, 'YQ_VERSION', b'not the pinned version'):
            with self.assertRaises(ContractError) as caught:
                self.load()
        self.assertEqual(caught.exception.code, 'yaml_tool_version')

    def test_null_documents_do_not_change_legacy_or_disabled_projection(self):
        for config in ({'legacy': True}, {'agentInputDelivery': {'enabled': False}}):
            for suffix in ('\n---\n', '\n---\n# empty\n', '\n---\nnull\n---\n~\n'):
                with self.subTest(config=config, suffix=suffix):
                    self.layer(2, json.dumps(config) + suffix)
                    self.assertEqual(self.cli().returncode, 0)
                    self.assertEqual(self.load(), {k: v for k, v in config.items()
                                                   if k in connection_yaml.BLOCKS})
                    self.assertEqual(self.paths[2].read_text(), json.dumps(config) + suffix)
        for raw, code in (('[]', 'yaml_representation_unsupported'),
                          ('42', 'yaml_parse_invalid'), ('!custom null', 'yaml_parse_invalid')):
            self.layer(2, raw)
            self.rejected(code)

    def test_selected_symlink_reads_bounded_target(self):
        selected = self.paths[2]
        target = self.folder / 'target.yaml'
        selected.unlink()
        selected.symlink_to(target.name)
        target.write_text(json.dumps(self.generic))
        self.assertEqual(self.cli().returncode, 0)
        self.assertEqual(self.load(), self.generic)
        self.assertTrue(selected.is_symlink())
        target.write_bytes(b'x' * (connection_yaml.MAX_FILE_BYTES + 1))
        self.rejected('input_size_limit')
        target.unlink()
        self.rejected('yaml_input_invalid')
        os.mkfifo(target)
        self.rejected('yaml_input_invalid')
        target.unlink()
        target.symlink_to(selected.name)
        self.rejected('yaml_input_invalid')

    def test_bounded_regular_file_reads(self):
        self.paths[2].write_bytes(b'x' * (connection_yaml.MAX_FILE_BYTES + 1))
        self.rejected('input_size_limit')
        self.paths[2].unlink()
        self.rejected('yaml_input_invalid')
        os.mkfifo(self.paths[2])
        self.rejected('yaml_input_invalid')
        self.paths[2].unlink()
        self.paths[2].symlink_to(self.paths[0])
        self.assertEqual(self.cli().returncode, 0)

    def test_child_output_and_time_budgets(self):
        self.layer(2, self.generic)
        for field, value in (('MAX_OUTPUT_BYTES', 1), ('PROCESS_TIMEOUT', 0)):
            with patch.object(connection_yaml, field, value):
                with self.assertRaises(ContractError) as caught:
                    self.load()
            self.assertEqual(caught.exception.code, 'yaml_process_limit')
        # Production budgets still work after child cleanup.
        self.assertEqual(self.cli().returncode, 0)
