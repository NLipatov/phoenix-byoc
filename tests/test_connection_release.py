"""Task4a only: offline named capability predicate, not release/install admission."""
import copy
from dataclasses import replace
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from connection_contract import ContractError, load_contract, validate_connections
import connection_contract


class NamedCapabilityTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.bundle = load_contract(ROOT)
        cls.semantic = {row['id']: row['input'] for row in json.loads(cls.bundle.vectors.read_text())}
        cls.vectors = json.loads(cls.bundle.capability_vectors.read_text())

    def check(self, config, entries=None):
        validated = validate_connections(config, self.bundle)  # Always author against the real owner.
        if entries is None:
            bundle = self.bundle
        else:
            # Private, test-only table: never a customer setting or production evidence override.
            folder = tempfile.TemporaryDirectory()
            self.addCleanup(folder.cleanup)
            table = Path(folder.name) / 'test-only-capabilities.json'
            table.write_text(json.dumps({'entries': entries}))
            bundle = replace(self.bundle, capabilities=table)
        return validated, connection_contract.check_named_capabilities(config, validated, bundle)

    def rejected(self, config, entries=None):
        with self.assertRaises(ContractError) as caught:
            self.check(config, entries)
        self.assertEqual(caught.exception.code, 'connection_capability_unsupported')
        self.assertEqual(caught.exception.path, '/llm/connections')

    def test_all_five_canonical_capability_vectors(self):
        self.assertEqual(len(self.vectors), 5)
        for vector in self.vectors:
            with self.subTest(vector=vector['id']):
                self.assertEqual(vector['kind'], 'capability')
                self.assertEqual(vector['expected']['structural'], True)
                self.assertEqual(vector['expected']['semantic'], True)
                config = copy.deepcopy(self.semantic[vector['baseId']])
                if vector['expected']['capability'] == 'admitted':
                    validated, outcome = self.check(config, vector['capabilityEntries'])
                    self.assertTrue(validated.required_capabilities)
                    self.assertIs(outcome, connection_contract.NamedCapability.ADMITTED)
                else:
                    self.rejected(config, vector['capabilityEntries'])

    def test_shipped_27_blocked_even_though_authoring_succeeds(self):
        entries = json.loads(self.bundle.capabilities.read_text())['entries']
        self.assertEqual(len(entries), 27)
        self.assertEqual({entry['status'] for entry in entries}, {'blocked'})
        config = copy.deepcopy(self.semantic[self.vectors[0]['baseId']])
        self.assertTrue(validate_connections(config, self.bundle).required_capabilities)
        self.rejected(config)

    def test_omitted_api_considers_all_route_auth_rows(self):
        config = copy.deepcopy(self.semantic['valid/direct-anthropic/anthropic-messages/api-key'])
        config['llm']['connections']['example'].pop('API')
        selected = {'route': 'direct-anthropic', 'api': 'anthropic-messages',
                    'authMode': 'api-key', 'status': 'offline-proven'}
        foreign = {**selected, 'api': 'openai-responses'}
        self.assertIs(self.check(config, [selected])[1], connection_contract.NamedCapability.ADMITTED)
        self.rejected(config, [selected, foreign])
        # A singleton from the wrong API cannot impersonate the owner-selected native API.
        self.rejected(config, [foreign])
        config['llm']['connections']['example']['API'] = 'anthropic-messages'
        self.assertIs(self.check(config, [selected, foreign])[1], connection_contract.NamedCapability.ADMITTED)

    def test_explicit_api_filters_exact_row_without_weakening_authoring(self):
        config = copy.deepcopy(self.semantic[self.vectors[0]['baseId']])
        selected = self.vectors[0]['capabilityEntries'][0]
        foreign = {**selected, 'api': 'openai-responses'}
        self.assertIs(self.check(config, [selected, foreign])[1], connection_contract.NamedCapability.ADMITTED)
        self.rejected(config, [foreign])
        config['llm']['connections']['example']['API'] = 'openai-responses'
        self.assertIs(self.check(config, [selected, foreign])[1], connection_contract.NamedCapability.ADMITTED)

    def test_generic_and_empty_are_not_applicable_not_install_permission(self):
        for config in ({}, self.semantic['generic_only']):
            with self.subTest(config=config):
                self.assertIs(self.check(config)[1], connection_contract.NamedCapability.NOT_APPLICABLE)
                self.assertIsNot(self.check(config)[1], connection_contract.NamedCapability.ADMITTED)

    def test_every_named_connection_needs_its_own_owner_row(self):
        config = copy.deepcopy(self.semantic[self.vectors[0]['baseId']])
        second = copy.deepcopy(self.semantic['valid/direct-anthropic/anthropic-messages/api-key'])
        config['llm']['connections']['second'] = second['llm']['connections']['example']
        config['llm'].setdefault('secretEnv', {}).update(second['llm'].get('secretEnv', {}))
        config['llm'].setdefault('env', {}).update(second['llm'].get('env', {}))
        first = self.vectors[0]['capabilityEntries'][0]
        other = {'route': 'direct-anthropic', 'api': 'anthropic-messages',
                 'authMode': 'api-key', 'status': 'offline-proven'}
        self.rejected(config, [first])
        self.assertIs(self.check(config, [first, other])[1], connection_contract.NamedCapability.ADMITTED)

    def test_customer_capability_claim_is_not_an_authoring_field(self):
        config = copy.deepcopy(self.semantic[self.vectors[0]['baseId']])
        config['capabilities'] = {'entries': self.vectors[0]['capabilityEntries']}
        with self.assertRaises(ContractError) as caught:
            validate_connections(config, self.bundle)
        self.assertEqual(caught.exception.code, 'connection_schema_invalid')

    def test_missing_unknown_and_duplicate_rows_fail_closed(self):
        config = copy.deepcopy(self.semantic[self.vectors[0]['baseId']])
        row = self.vectors[0]['capabilityEntries'][0]
        for entries in ([], [{**row, 'status': 'unknown'}], [row, row]):
            with self.subTest(entries=entries):
                self.rejected(config, entries)


if __name__ == '__main__':
    unittest.main()
