"""Offline named-authoring conformance against the immutable producer vectors."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from connection_contract import ContractError, load_contract


class ConnectionValuesTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.bundle = load_contract(ROOT)
        cls.vectors = json.loads(cls.bundle.vectors.read_text())
        cls.capabilities = json.loads(cls.bundle.capabilities.read_text())['entries']
        from connection_contract import validate_connections, _schema_helm
        cls.validate = staticmethod(validate_connections)
        cls.helm_schema = staticmethod(_schema_helm)

    def valid(self, value):
        return self.validate(value, self.bundle)

    def invalid(self, value, code=None):
        with self.assertRaises(ContractError) as caught:
            self.valid(value)
        if code:
            self.assertEqual(caught.exception.code, code)
        self.assertTrue(caught.exception.path.startswith('/'))
        self.assertNotIn('hostile', caught.exception.path)
        return caught.exception

    def base(self):
        return copy.deepcopy(self.vectors[0]['input'])

    def test_all_canonical_vectors(self):
        self.assertEqual(len(self.vectors), 74)
        self.assertEqual(len(self.capabilities), 27)
        self.assertEqual(sum(v['expected']['structural'] and v['expected']['semantic'] for v in self.vectors), 34)
        self.assertEqual(sum(not v['expected']['structural'] for v in self.vectors), 31)
        self.assertEqual(sum(v['expected']['structural'] and not v['expected']['semantic'] for v in self.vectors), 9)
        self.assertEqual({r['status'] for r in self.capabilities}, {'blocked'})
        self.assertEqual({v['kind'] for v in self.vectors}, {'values'})
        for vector in self.vectors:
            with self.subTest(vector=vector['id']):
                expected = vector['expected']
                try:
                    self.helm_schema(vector['input'], self.bundle)
                    structural = True
                except ContractError as error:
                    self.assertEqual(error.code, 'connection_schema_invalid')
                    structural = False
                self.assertEqual(structural, expected['structural'])
                if expected['semantic']:
                    result = self.valid(vector['input'])
                    self.assertEqual(expected['structural'], True)
                    self.assertEqual(expected['capability'], 'blocked')
                    self.assertTrue(all(cap in {(r['route'], r['api'], r['authMode']) for r in self.capabilities}
                                        for cap in result.required_capabilities))
                else:
                    error = self.invalid(vector['input'])
                    if expected['structural']:
                        self.assertNotEqual(error.code, 'connection_schema_invalid')
                    else:
                        self.assertIn(error.code, ('connection_schema_invalid', 'llm_authoring_required',
                                                       'reserved_destination'))

    def test_absent_not_falsey_llm(self):
        self.assertFalse(self.valid({}).enabled)
        for value in ({}, None, [], 0, False):
            self.invalid({'llm': value})
        for value in (1, True, None):
            config = self.base()
            config['llm']['CONFIG_VERSION'] = value
            self.invalid(config)
        for value in (None, {}, [], 0):
            self.invalid({'agentInputDelivery': value})
        self.invalid({'agentInputDelivery': {'enabled': 'false'}})
        self.invalid({'agentInputDelivery': {'enabled': False, 'env': {'FOO': 'x'}}})
        self.invalid({'agentInputDelivery': {'enabled': True, 'allowedEnterpriseIds': ['00000000-0000-4000-8000-000000000001'], 'env': {'FOO': 1}}})
        self.invalid({'unknown': 1})
        self.invalid({'agentInputDelivery': {'enabled': True, 'allowedEnterpriseIds': ['00000000-0000-4000-8000-000000000001'], 'secretEnv': {'FOO': 1}}})
        scope = ['00000000-0000-4000-8000-000000000001']
        self.assertEqual(self.valid({'agentInputDelivery': {'enabled': True, 'allowedEnterpriseIds': scope}}).plain_env, {})
        secret_only = self.valid({'agentInputDelivery': {'enabled': True, 'allowedEnterpriseIds': scope,
                            'secretEnv': {'KEY': {'name': 'synthetic-provider-secret', 'key': 'api-key'}}}})
        self.assertEqual(secret_only.plain_env, {})
        self.assertEqual(secret_only.secret_refs['KEY'].key, 'api-key')

    def test_config_version_must_be_string(self):
        config = self.base()
        config['llm']['CONFIG_VERSION'] = 1
        self.invalid(config, 'connection_schema_invalid')

    def test_typed_json_objects_not_double_encoded(self):
        config = self.base()
        config['llm']['connections']['zeta'] = config['llm']['connections'].pop('example')
        config['llm']['connections']['alpha'] = copy.deepcopy(config['llm']['connections']['zeta'])
        result = self.valid(config)
        self.assertEqual(result.plain_env['PHOENIX_LLM_CONNECTIONS'], 'alpha,zeta')
        self.assertEqual(result.plain_env['PHOENIX_LLM_CONFIG_VERSION'], '1')
        self.assertEqual(json.loads(result.plain_env['PHOENIX_LLM_ALPHA_NATIVE_ENV_REFS_JSON']), {'AWS_REGION': 'AWS_REGION'})
        self.assertIsInstance(json.loads(result.plain_env['PHOENIX_LLM_ALPHA_NATIVE_ENV_REFS_JSON']), dict)

    def test_route_api_auth_rules(self):
        for vector in self.vectors[:27]:
            with self.subTest(vector=vector['id']):
                conn = next(iter(vector['input']['llm']['connections'].values()))
                result = self.valid(vector['input'])
                route = vector['id'].split('/')[1]
                self.assertIn((route, result.plain_env['PHOENIX_LLM_EXAMPLE_API'], conn['AUTH_MODE']), result.required_capabilities)
        for name in ('ambiguous_direct_api', 'ambiguous_azure_api', 'subscription_auth_rejected', 'oauth_auth_rejected', 'aws_role_pair_required'):
            self.invalid(next(v['input'] for v in self.vectors if v['id'] == name))

    def test_reference_sources_and_collisions(self):
        for name in ('generic_secret_collision', 'generic_plain_secret_collision', 'api_key_reference_not_secret',
                     'missing_api_key_source', 'missing_aws_region_source', 'missing_aws_token_source',
                     'missing_vertex_region_source', 'missing_azure_token_source'):
            with self.subTest(name=name):
                self.invalid(next(v['input'] for v in self.vectors if v['id'] == name))
        config = self.base()
        config['llm']['platformEnv'] = ['AWS_REGION']
        self.invalid(config, 'destination_collision')
        config = self.base()
        config['agentInputDelivery']['env'] = {'AWS_REGION': config['llm']['env']['AWS_REGION']}
        self.invalid(config, 'destination_collision')
        config = self.base()
        config['llm']['connections']['example']['API_KEY_ENV'] = 'AWS_REGION'
        self.invalid(config, 'secret_reference_required')

    def test_no_model_management_fields(self):
        for name in ('removed_model_source', 'removed_target', 'removed_models', 'removed_discovery_mode',
                     'removed_auth_store', 'removed_login_command', 'removed_refresh_command'):
            self.invalid(next(v['input'] for v in self.vectors if v['id'] == name))
        config = self.base()
        config['agentInputDelivery']['env'] = {'PHOENIX_LLM_EXAMPLE_MODELS': 'x'}
        self.invalid(config, 'llm_authoring_required')
        config = self.base()
        config['agentInputDelivery']['secretEnv'] = {'PHOENIX_LLM_EXAMPLE_MODELS': {'name': 'synthetic-provider-secret', 'key': 'key'}}
        self.invalid(config, 'llm_authoring_required')
        for block, field, value in (('llm', 'env', {'AWS_REGION': 1}),
                                    ('llm', 'env', {'AWS_REGION': True}),
                                    ('llm', 'secretEnv', {'EXAMPLE_KEY': {'name': 'synthetic-provider-secret', 'key': None}})):
            config = self.base()
            config[block][field] = value
            self.invalid(config)

    def test_header_url_errors_are_value_free(self):
        config = self.base()
        conn = config['llm']['connections']['example']
        for headers in ({'Authorization': 'hostile'}, {'x-ok': 'bad\rhostile'},
                        {'x-ok': 'a$HOSTILE'}, {'x-ok': '$(hostile)'},
                        {'x-ok': '`hostile`'},
                        {'x-ok': '$MISSING'}, {'x-ok': '$AWS_REGION', 'X-OK': 'v'}):
            with self.subTest(headers=headers):
                conn['HEADERS_JSON'] = headers
                self.invalid(config)
        config = next(v['input'] for v in self.vectors if v['id'].startswith('valid/portkey-anthropic/'))
        for url in ('http://hostile.test', 'https://user@hostile.test', 'https://hostile.test/?x=1', 'https://hostile.test/#x'):
            with self.subTest(url=url):
                altered = copy.deepcopy(config)
                altered['llm']['connections']['example']['BASE_URL'] = url
                self.invalid(altered)
        config = self.base()
        config['llm']['env']['AWS_REGION'] = 'bad\rhostile'
        config['llm']['connections']['example']['HEADERS_JSON'] = {'x-region': '$AWS_REGION'}
        self.invalid(config)

    def test_transport_bounds(self):
        config = self.base()
        config['agentInputDelivery']['env'] = {'PAD': 'é' * 33000}
        self.invalid(config, 'env_size_limit')
        config = self.base()
        config['llm']['env']['AWS_REGION'] = 'é' * 33000
        self.invalid(config, 'env_size_limit')
        config = self.base()
        config['agentInputDelivery']['env'] = {'X_%03d' % i: 'x' for i in range(250)}
        self.invalid(config, 'env_count_limit')
        config = self.base()
        config['agentInputDelivery']['secretEnv'] = {
            'KEY_%03d' % i: {'name': 'synthetic-provider-secret', 'key': 'api-key'} for i in range(128)}
        self.invalid(config, 'secret_count_limit')

    def test_legacy_provider_names_are_not_runner_controls(self):
        config = self.base()
        config['agentInputDelivery']['env'] = {'ANTHROPIC_VERTEX_PROJECT_ID': 'project', 'CLOUD_ML_REGION': 'global'}
        self.valid(config)
        for marker in ('PHOENIX_AGENT_INPUTS_DIR', 'PHOENIX_AGENT_SECRET_NAMES_JSON'):
            invalid = copy.deepcopy(config)
            invalid['agentInputDelivery']['env'][marker] = 'x'
            self.invalid(invalid)
        config = self.base()
        config['llm']['secretEnv']['ANTHROPIC_API_KEY'] = {'name': 'synthetic-provider-secret', 'key': 'key'}
        self.valid(config)

    def test_byoc_named_subscription_auth_rejected(self):
        for name in ('subscription_auth_rejected', 'oauth_auth_rejected', 'removed_auth_store', 'removed_login_command', 'removed_refresh_command'):
            with self.subTest(name=name):
                self.invalid(next(v['input'] for v in self.vectors if v['id'] == name))
        # No installer integration in Task2: CLI must reject before performing any mutation.
        input_json = json.dumps(next(v['input'] for v in self.vectors if v['id'] == 'subscription_auth_rejected'))
        completed = subprocess.run([sys.executable, str(ROOT / 'scripts/connection-config.py'), 'check'], input=input_json, text=True, capture_output=True, cwd=ROOT)
        self.assertNotEqual(completed.returncode, 0)
        self.assertNotIn('subscription', completed.stderr)

    def test_cli_references_and_safe_errors(self):
        config = self.base()
        config['agentInputDelivery']['secretEnv'] = {'OTHER_KEY': {'name': 'synthetic-provider-secret', 'key': 'api-key'}}
        for command in ('check', 'references'):
            result = subprocess.run([sys.executable, str(ROOT / 'scripts/connection-config.py'), command],
                                    input=json.dumps(config), text=True, capture_output=True, cwd=ROOT)
            self.assertEqual(result.returncode, 0, result.stderr)
            if command == 'references':
                self.assertEqual(json.loads(result.stdout), [{'name': 'synthetic-provider-secret', 'key': 'api-key'}])
        nonce = 'hostile_' + secrets.token_hex(12)
        hostile_connection = self.base()
        hostile_connection['llm']['connections'][nonce + '\nprivate'] = hostile_connection['llm']['connections'].pop('example')
        payloads = ('{hostile', json.dumps({'llm': {'hostile\n': 'private'}}),
                    json.dumps(hostile_connection),
                    json.dumps({'agentInputDelivery': {'enabled': False, 'env': {'hostile\n': 'secret'}}}))
        for command in ('check', 'references'):
            for payload in payloads:
                result = subprocess.run([sys.executable, str(ROOT / 'scripts/connection-config.py'), command],
                                        input=payload, text=True, capture_output=True, cwd=ROOT)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, '')
                self.assertNotIn('hostile', result.stderr)
                self.assertNotIn(nonce, result.stderr)
                self.assertNotIn('secret', result.stderr)
                self.assertNotIn('Traceback', result.stderr)
