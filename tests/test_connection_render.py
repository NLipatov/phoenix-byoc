"""Offline conformance through the real BYOC Helmfile and hash-verified Engine charts."""
import copy
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import yaml
from connection_render_fixture import copy_source_files, digest, extract

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / 'tests/fixtures/connection-render'
CANDIDATE_SHA = 'd0f49a00daaca6ed875ecf1d7c5cec870043d97635b833c1248988b552f8b0af'
LEGACY_TEMPLATE_SHA = '268711a0f6978513874453e801bf64cbf3b21a09f9b302db695e93caee145d8c'
LOCK_SHA = 'd5c5406aff1a9b9d8a4166373da86e618eadcda72b287a14d3de0aa8df38291b'
ENTERPRISE = '12345678-1234-4234-8234-123456789abc'  # synthetic, not a customer identity


class ConnectionRenderTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scratch = tempfile.TemporaryDirectory(prefix='byoc-connection-render-')
        cls.addClassCleanup(cls.scratch.cleanup)
        cls.work = Path(cls.scratch.name)
        cls.isolation = cls.work / 'isolation'
        for part in ('bin', 'home', 'cache', 'config', 'data', 'plugins', 'helmfile-cache'):
            (cls.isolation / part).mkdir(parents=True, mode=0o700)
        for name in ('kubectl', 'curl', 'wget'):
            spy = cls.isolation / 'bin' / name
            spy.write_text('#!/bin/sh\necho "blocked tool invoked" >&2\nexit 97\n')
            spy.chmod(0o700)
        (cls.isolation / 'no-kubeconfig').touch()
        cls.helm = cls.pinned_tool('PHOENIX_TEST_HELM', 'helm', r'^v3\.18\.6(?:\+|$)', ('version', '--short'))
        cls.helmfile = cls.pinned_tool('PHOENIX_TEST_HELMFILE', 'helmfile', r'^helmfile version 0\.171\.0\s*$', ('--version',))
        manifest = json.loads((FIXTURES / 'manifest.json').read_text())
        release = yaml.safe_load((ROOT / 'release.yaml').read_text())
        if (manifest['releaseYamlSha256'] != 'db5815cc4e14a77d70a6c3fd6804fe55058f8b5adfb62308aacc8926ce057a8d'
                or digest(ROOT / 'release.yaml') != manifest['releaseYamlSha256'] or release['release'] != manifest['release']
                or len(manifest['charts']) != 10 or len(manifest['sourceFiles']) != 42):
            raise RuntimeError('pinned release inventory mismatch')
        cls.source = cls.work / 'source'
        cls.source.mkdir(mode=0o700)
        copy_source_files(ROOT, cls.source, manifest['sourceFiles'])
        cls.charts = cls.work / 'charts'
        cls.charts.mkdir(mode=0o700)
        pins = {'fuse-device-plugin': 'fuseDevicePlugin', 'cortex-postgresql': 'cortexPostgresql',
                'opensandbox-controller': 'opensandboxController', 'phoenix-web': 'phoenixWeb',
                'phoenix-web-frontend': 'phoenixWebFrontend', 'phoenix-gateway': 'phoenixGateway',
                'phoenix-workflow-engine': 'phoenixWorkflowEngine', 'postgresql': 'postgresql',
                'redis': 'redis', 'ingress-nginx': 'ingressNginx'}
        if {chart['name'] for chart in manifest['charts']} != set(pins):
            raise RuntimeError('published chart inventory mismatch')
        for chart in manifest['charts']:
            name, version = chart['name'], str(chart['version'])
            archive = FIXTURES / chart['archive']
            if (chart['releasePin'] != pins[name] or chart['dependencies']
                    or str(release['versions'][pins[name]]) != version or digest(archive) != chart['sha256']):
                raise RuntimeError(f'pinned archive mismatch: {name}')
            if name != 'phoenix-workflow-engine':
                extract(archive.read_bytes(), cls.charts, name)
            else:
                cls.old_archive = archive
        candidate = manifest['unreleasedEngine']
        candidate_archive = FIXTURES / candidate['archive']
        if (candidate['sourceCommit'] != '8fa3ecba678acd8599fd90aa2f0e9e4d7e0ca38d'
                or candidate['status'] != 'unreleased Git-source candidate; fixture only, not a published release'
                or candidate['sha256'] != CANDIDATE_SHA or digest(candidate_archive) != CANDIDATE_SHA):
            raise RuntimeError('unreleased chart candidate provenance mismatch')
        extract(candidate_archive.read_bytes(), cls.charts, 'phoenix-workflow-engine')
        lock = cls.charts / 'phoenix-workflow-engine/contracts/native-provider-inputs.lock.json'
        if (candidate['lockSha256'] != LOCK_SHA or digest(lock) != LOCK_SHA
                or digest(ROOT / 'contracts/native-provider-inputs.lock.json') != LOCK_SHA):
            raise RuntimeError('candidate owner lock mismatch')
        for chart in manifest['charts']:
            meta = yaml.safe_load((cls.charts / chart['name'] / 'Chart.yaml').read_text())
            version = candidate['chartVersion'] if chart['name'] == 'phoenix-workflow-engine' else str(chart['version'])
            if meta['name'] != chart['name'] or str(meta['version']) != version or meta.get('dependencies'):
                raise RuntimeError(f'chart metadata mismatch: {chart["name"]}')
        cls.legacy_template = FIXTURES / manifest['legacyTemplate']['path']
        if (manifest['legacyTemplate']['sourceCommit'] != '686b2bf3e8b41037a9fc9a7ed21bcb5dac6d7761'
                or manifest['legacyTemplate']['sha256'] != LEGACY_TEMPLATE_SHA
                or digest(cls.legacy_template) != LEGACY_TEMPLATE_SHA):
            raise RuntimeError('frozen legacy template mismatch')
        helmfile = cls.source / 'helmfile.yaml.gotmpl'
        text = helmfile.read_text()
        mappings = {
            'repositories:\n  - name: ingress-nginx\n    url: https://kubernetes.github.io/ingress-nginx': 'repositories: []',
            'chart: ingress-nginx/ingress-nginx': f'chart: "{cls.charts / "ingress-nginx"}"',
            'chart: oci://ghcr.io/helmforgedev/helm/postgresql': f'chart: "{cls.charts / "postgresql"}"',
            'chart: oci://ghcr.io/helmforgedev/helm/redis': f'chart: "{cls.charts / "redis"}"',
        }
        for name in pins.keys() - {'postgresql', 'redis', 'ingress-nginx'}:
            mappings[f'chart: {{{{ printf "%s/{name}" $chartRegistry | quote }}}}'] = f'chart: "{cls.charts / name}"'
        for old, new in mappings.items():
            if text.count(old) != 1:
                raise RuntimeError('Helmfile offline reference mismatch')
            text = text.replace(old, new)
        helmfile.write_text(text)
        cls.values = yaml.safe_load((cls.source / 'examples/values.yaml').read_text())
        cls.values['application'].update(tenantId='phoenix_test', appHost='phoenix.test.invalid',
                                         spaHost='phoenix.test.invalid', allowedHosts='phoenix.test.invalid,localhost',
                                         actionCableAllowedOrigins='https://phoenix.test.invalid')
        cls.values['application']['mailer']['deliveryMethod'] = 'test'
        cls.values['ingress']['className'] = 'nginx'
        cls.values['ingress']['frontend']['host'] = 'phoenix.test.invalid'
        cls.secrets = yaml.safe_load((cls.source / 'tests/fixtures/values.secrets.yaml').read_text())
        cls.secrets['secrets']['registry'] = {'ecr': {'accessKeyId': 'test-only-ecr-id',
                                                      'secretAccessKey': 'test-only-ecr-key', 'sessionToken': ''}}
        cls.secrets['secrets']['application']['mailgunApiKey'] = ''

    @classmethod
    def pinned_tool(cls, override, command, version_pattern, version_args):
        executable = os.environ.get(override) or shutil.which(command)
        if not executable or not Path(executable).is_file() or not os.access(executable, os.X_OK):
            raise RuntimeError(f'missing pinned {command}; set {override} to its executable')
        executable = str(Path(executable).resolve())
        environment = {'PATH': f'{cls.isolation / "bin"}:/usr/bin:/bin', 'HOME': str(cls.isolation / 'home'),
                       'KUBECONFIG': str(cls.isolation / 'no-kubeconfig'),
                       'HTTPS_PROXY': 'http://127.0.0.1:9', 'HTTP_PROXY': 'http://127.0.0.1:9',
                       'NO_PROXY': '', 'HELM_CONFIG_HOME': str(cls.isolation / 'config')}
        version = subprocess.run([executable, *version_args], env=environment, text=True,
                                 capture_output=True, timeout=10)
        if version.returncode or not re.search(version_pattern, version.stdout):
            raise RuntimeError(f'{command} must be pinned to {"3.18.6" if command == "helm" else "0.171.0"}')
        return executable

    def render(self, overlay=None, *, old=False, baseline=False, synthetic_capability=False, all_releases=False, forwarded=False):
        values = copy.deepcopy(self.values)
        if overlay:
            for key, value in overlay.items():
                if value == '__ABSENT__':
                    values.pop(key, None)
                else:
                    values[key] = value
        with tempfile.TemporaryDirectory(dir=self.work) as run:
            directory = Path(run)
            values_path = directory / 'values.json'
            secrets_path = directory / 'secrets.json'
            values_path.write_text(json.dumps(values))
            secrets_path.write_text(json.dumps(self.secrets))
            if synthetic_capability:
                # Private copy only. The shipped 27 blocked rows are never modified.
                capabilities = self.charts / 'phoenix-workflow-engine/contracts/llm-connections/v1/capabilities.json'
                original_capabilities = capabilities.read_bytes()
                table = json.loads(original_capabilities)
                match = [row for row in table['entries'] if (row['route'], row['api'], row['authMode']) ==
                         ('portkey-anthropic', 'openai-responses', 'api-key')]
                if len(match) != 1 or match[0]['status'] != 'blocked':
                    raise RuntimeError('synthetic capability fixture row mismatch')
                match[0]['status'] = 'offline-proven'
                capabilities.write_text(json.dumps(table))
            if baseline:
                template = self.source / 'values/phoenix-workflow-engine.yaml.gotmpl'
                original_template = template.read_bytes()
                template.write_bytes(self.legacy_template.read_bytes())
            if old:
                # Published >=0.2.8 chart, switched only in isolated scratch.
                chart = self.charts / 'phoenix-workflow-engine'
                replacement = directory / 'charts'
                replacement.mkdir()
                extract(self.old_archive.read_bytes(), replacement, 'phoenix-workflow-engine')
                path = self.source / 'helmfile.yaml.gotmpl'
                text = path.read_text().replace(str(chart), str(replacement / 'phoenix-workflow-engine'))
                # Keep the offline chart substitution in the isolated source tree.
                local_helmfile = self.source / 'helmfile.yaml.gotmpl'
                original = local_helmfile.read_text()
                local_helmfile.write_text(text)
            env = {'PATH': f'{self.isolation / "bin"}:/usr/bin:/bin', 'HOME': str(self.isolation / 'home'),
                   'KUBECONFIG': str(self.isolation / 'no-kubeconfig'), 'HELM_CACHE_HOME': str(self.isolation / 'cache'),
                   'HELM_CONFIG_HOME': str(self.isolation / 'config'), 'HELM_DATA_HOME': str(self.isolation / 'data'),
                   'HELM_PLUGINS': str(self.isolation / 'plugins'), 'HELMFILE_CACHE_HOME': str(self.isolation / 'helmfile-cache'),
                   'HELMFILE_DISABLE_RUNNER_UNIQUE_ID': 'true', 'PHOENIX_BYOC_NAMESPACE': 'phoenix',
                   'PHOENIX_BYOC_VALUES_FILE': str(values_path), 'PHOENIX_BYOC_SECRETS_FILE': str(secrets_path),
                   'PHOENIX_AGENTFS_RETAINED_IMAGES_JSON': '[]',
                   'HTTPS_PROXY': 'http://127.0.0.1:9', 'HTTP_PROXY': 'http://127.0.0.1:9', 'NO_PROXY': ''}
            try:
                command = [self.helmfile, '--helm-binary', self.helm, '--file', 'helmfile.yaml.gotmpl', '--skip-deps']
                if not all_releases:
                    command.extend(('-l', 'name=phoenix-workflow-engine'))
                if forwarded:
                    command.extend(('write-values', '--output-file-template', str(directory / '{{ .Release.Name }}.yaml')))
                else:
                    command.extend(('template', '--quiet'))
                result = subprocess.run(command, cwd=self.source, env=env,
                                        capture_output=True, text=True, timeout=90)
                if forwarded and result.returncode == 0:
                    projected_values = yaml.safe_load((directory / 'phoenix-workflow-engine.yaml').read_text())
            finally:
                if old:
                    local_helmfile.write_text(original)
                if baseline:
                    template.write_bytes(original_template)
                if synthetic_capability:
                    capabilities.write_bytes(original_capabilities)
            return result, ([projected_values] if forwarded else list(yaml.safe_load_all(result.stdout))) if result.returncode == 0 else []

    def objects(self, docs, kind):
        return [doc for doc in docs if isinstance(doc, dict) and doc.get('kind') == kind]

    def test_legacy_render_unchanged_and_old_chart_feature_off(self):
        current, _ = self.render()
        baseline, _ = self.render(baseline=True)
        old, old_docs = self.render(old=True)
        self.assertEqual(current.returncode, 0, current.stderr[:300])
        self.assertEqual(baseline.returncode, 0, baseline.stderr[:300])
        self.assertEqual(old.returncode, 0, old.stderr[:300])
        self.assertEqual(current.stdout, baseline.stdout)
        self.assertTrue(self.objects(old_docs, 'Deployment'))

    def test_all_release_off_render_unchanged(self):
        ingress = copy.deepcopy(self.values['ingressNginx'])
        ingress['enabled'] = True
        current, docs = self.render({'ingressNginx': ingress}, all_releases=True)
        baseline, _ = self.render({'ingressNginx': ingress}, baseline=True, all_releases=True)
        self.assertEqual(current.returncode, 0, current.stderr[:300])
        self.assertEqual(baseline.returncode, 0, baseline.stderr[:300])
        self.assertEqual(current.stdout, baseline.stdout)
        self.assertEqual(len(docs), 94)
        self.assertEqual(sum(isinstance(doc, dict) and 'kind' in doc for doc in docs), 93)
        self.assertEqual(len(set(re.findall(r'^# Source: ([^/]+)/', current.stdout, re.M))), 14)

    def test_legacy_vertex_and_agent_secrets_preserved(self):
        vertex = copy.deepcopy(self.values['vertex'])
        vertex['enabled'] = True
        vertex['projectId'] = 'test-only-project'
        vertex['serviceAccount']['gcpServiceAccount'] = 'test-only@project.invalid'
        off, off_docs = self.render({'vertex': vertex})
        on, on_docs = self.render({'vertex': vertex, 'agentInputDelivery':
                                   {'enabled': True, 'allowedEnterpriseIds': [ENTERPRISE]}})
        self.assertEqual(off.returncode, 0, off.stderr[:300])
        self.assertEqual(on.returncode, 0, on.stderr[:300])
        self.assertEqual(self.objects(off_docs, 'Secret'), self.objects(on_docs, 'Secret'))
        accounts = lambda docs: [d for d in self.objects(docs, 'ServiceAccount') if 'vertex' in d['metadata']['name']]
        self.assertTrue(accounts(off_docs))
        self.assertEqual(accounts(off_docs), accounts(on_docs))
        self.assertFalse(any('agent-inputs' in doc['metadata']['name'] for doc in off_docs
                             if isinstance(doc, dict) and 'metadata' in doc))

    def test_generic_only_projection_and_enabled_empty_env_json(self):
        for env in ({}, {'EXAMPLE_DATA': 'test-only-value'}):
            with self.subTest(env=bool(env)):
                result, docs = self.render({'agentInputDelivery': {'enabled': True, 'allowedEnterpriseIds': [ENTERPRISE], 'env': env}})
                self.assertEqual(result.returncode, 0, result.stderr[:400])
                config = next(d for d in self.objects(docs, 'ConfigMap') if d['metadata']['name'].endswith('agent-inputs'))
                self.assertEqual(json.loads(config['data']['env.json']), env)
                self.assertEqual(json.loads(config['data']['delivery-policy.json']), {'version': 1, 'allowedEnterpriseIds': [ENTERPRISE]})
                operators = [d for d in self.objects(docs, 'Deployment') if d['metadata']['name'].endswith('operator')]
                self.assertEqual(len(operators), 1)
                pod = operators[0]['spec']['template']['spec']
                # With no runAsUser/fsGroup override, the chart's root operator can read 0440.
                self.assertNotIn('securityContext', pod)
                self.assertNotIn('securityContext', pod['containers'][0])
                volumes = [v for v in pod['volumes'] if v['name'] == 'agent-inputs']
                self.assertEqual(len(volumes), 1)
                self.assertEqual(volumes[0]['projected']['defaultMode'], 0o440)
                mounts = [m for m in pod['containers'][0]['volumeMounts'] if m['name'] == 'agent-inputs']
                self.assertEqual(len(mounts), 1)
                self.assertEqual(mounts[0]['mountPath'], '/var/run/phoenix/agent-inputs')
                self.assertTrue(mounts[0]['readOnly'])
                self.assertEqual([source['configMap']['items'] for source in volumes[0]['projected']['sources'] if 'configMap' in source],
                                 [[{'key': 'env.json', 'path': 'env.json'}, {'key': 'delivery-policy.json', 'path': 'delivery-policy.json'}]])
                self.assertFalse(any('agent-inputs' in json.dumps(d) for d in self.objects(docs, 'Deployment') if d is not operators[0]))

    def test_invalid_present_blocks_not_discarded(self):
        sys.path.insert(0, str(ROOT / 'scripts'))
        from connection_contract import ContractError, load_contract, validate_connections
        bundle = load_contract(ROOT)
        for key, invalid in (('llm', None), ('llm', {}), ('llm', []), ('llm', 'wrong'),
                             ('agentInputDelivery', None), ('agentInputDelivery', {}), ('agentInputDelivery', []),
                             ('agentInputDelivery', {'enabled': True, 'unknownField': 'test'})):
            with self.subTest(key=key, invalid=invalid):
                forwarded, values = self.render({key: invalid}, forwarded=True)
                self.assertEqual(forwarded.returncode, 0, forwarded.stderr[:300])
                self.assertIn(key, values[0])
                self.assertEqual(values[0][key], invalid)
                schema_env = {'PATH': f'{Path(self.helm).parent}:/usr/bin:/bin',
                              'HOME': str(self.isolation / 'home'),
                              'KUBECONFIG': str(self.isolation / 'no-kubeconfig'),
                              'HELM_CACHE_HOME': str(self.isolation / 'cache'),
                              'HELM_CONFIG_HOME': str(self.isolation / 'config'),
                              'HELM_DATA_HOME': str(self.isolation / 'data'),
                              'HELM_PLUGINS': str(self.isolation / 'plugins'),
                              'HTTPS_PROXY': 'http://127.0.0.1:9', 'HTTP_PROXY': 'http://127.0.0.1:9',
                              'NO_PROXY': ''}
                with patch.dict(os.environ, schema_env, clear=True):
                    with self.assertRaises(ContractError) as rejected:
                        validate_connections({key: invalid}, bundle)
                self.assertNotEqual(rejected.exception.code, 'connection_validation_unavailable')
                result, _ = self.render({key: invalid})
                self.assertNotEqual(result.returncode, 0)

    def test_portkey_typed_env_and_selected_keys(self):
        vector = next(v for v in json.loads((self.charts / 'phoenix-workflow-engine/contracts/llm-connections/v1/semantic-vectors.json').read_text())
                      if v['id'] == 'valid/portkey-anthropic/openai-responses/api-key')
        overlay = copy.deepcopy(vector['input'])
        overlay['llm']['connections']['zeta'] = overlay['llm']['connections'].pop('example')
        overlay['llm']['connections']['alpha'] = copy.deepcopy(overlay['llm']['connections']['zeta'])
        overlay['llm']['connections']['alpha']['HEADERS_JSON'] = {'x-test': '$EXAMPLE_KEY'}
        blocked, _ = self.render(overlay)
        self.assertNotEqual(blocked.returncode, 0, 'production capability table must remain blocked')
        self.assertIn('native_capability_blocked', blocked.stderr)
        # Unknown fields must survive forwarding and fail chart schema, not be filtered.
        overlay['llm']['connections']['alpha']['EXTRA_MODEL_KNOB'] = 'keep-this-unknown-field'
        invalid, _ = self.render(overlay, synthetic_capability=True)
        self.assertNotEqual(invalid.returncode, 0)
        self.assertIn('EXTRA_MODEL_KNOB', invalid.stderr)
        overlay['llm']['connections']['alpha'].pop('EXTRA_MODEL_KNOB')
        accepted, docs = self.render(overlay, synthetic_capability=True)
        self.assertEqual(accepted.returncode, 0, accepted.stderr[:400])
        config = next(d for d in self.objects(docs, 'ConfigMap') if d['metadata']['name'].endswith('agent-inputs'))
        env = json.loads(config['data']['env.json'])
        self.assertEqual(env['PHOENIX_LLM_CONNECTIONS'], 'alpha,zeta')
        self.assertEqual(env['PHOENIX_LLM_ALPHA_API'], 'openai-responses')
        self.assertEqual(env['PHOENIX_LLM_ALPHA_HEADERS_JSON'], '{"x-test":"$EXAMPLE_KEY"}')
        self.assertEqual(json.loads(config['data']['delivery-policy.json'])['allowedEnterpriseIds'],
                         ['00000000-0000-4000-8000-000000000001'])
        operator = next(d for d in self.objects(docs, 'Deployment') if d['metadata']['name'].endswith('operator'))
        volume = next(v for v in operator['spec']['template']['spec']['volumes'] if v['name'] == 'agent-inputs')
        selected = [source for source in volume['projected']['sources'] if 'secret' in source]
        self.assertEqual(selected, [{'secret': {'name': 'synthetic-provider-secret', 'optional': False, 'items':
                                                [{'key': 'api-key', 'path': 'PHOENIX_AGENT_SECRET_EXAMPLE_KEY'}]}}])
        self.assertFalse(any('synthetic-provider-secret' in json.dumps(d) for d in self.objects(docs, 'Secret')))

    def test_projection_does_not_modify_legacy_checksum(self):
        off, off_docs = self.render()
        on, on_docs = self.render({'agentInputDelivery': {'enabled': True, 'allowedEnterpriseIds': [ENTERPRISE],
                                                          'secretEnv': {'EXAMPLE_KEY': {'name': 'synthetic-provider-secret', 'key': 'api-key'}}}})
        self.assertEqual(off.returncode, 0, off.stderr[:300])
        self.assertEqual(on.returncode, 0, on.stderr[:300])
        for kind in ('Secret',):
            self.assertEqual(self.objects(off_docs, kind), self.objects(on_docs, kind))
        old_operator = next(d for d in self.objects(off_docs, 'Deployment') if d['metadata']['name'].endswith('operator'))
        new_operator = next(d for d in self.objects(on_docs, 'Deployment') if d['metadata']['name'].endswith('operator'))
        self.assertEqual(old_operator['spec']['template']['metadata']['annotations'],
                         new_operator['spec']['template']['metadata']['annotations'])
        self.assertNotIn('test-only-value', json.dumps(on_docs))
        self.assertFalse(any('synthetic-provider-secret' in json.dumps(d) for d in self.objects(on_docs, 'ConfigMap')))

    def test_explicit_disabled_and_absent_off_equivalent(self):
        absent, _ = self.render()
        explicit, _ = self.render({'agentInputDelivery': {'enabled': False, 'allowedEnterpriseIds': [],
                                                           'env': {}, 'secretEnv': {}}})
        self.assertEqual(absent.returncode, 0, absent.stderr[:300])
        self.assertEqual(explicit.returncode, 0, explicit.stderr[:300])
        self.assertEqual(absent.stdout, explicit.stdout)
        forwarded, values = self.render(forwarded=True)
        self.assertEqual(forwarded.returncode, 0, forwarded.stderr[:300])
        self.assertNotIn('llm', values[0])
        self.assertNotIn('agentInputDelivery', values[0])

    def test_retention_chart_floor_preserved_feature_off(self):
        result, _ = self.render({'versions': {'phoenixWorkflowEngine': '0.2.7'}})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Run retention controls require phoenixWorkflowEngine chart >=0.2.8', result.stderr)

    def test_off_image_bytes_unchanged(self):
        for mirror in ('', 'registry.test.invalid/byoc'):
            with self.subTest(mirror=mirror):
                current, _ = self.render({'imageRegistry': mirror})
                baseline, _ = self.render({'imageRegistry': mirror}, baseline=True)
                old, old_docs = self.render({'imageRegistry': mirror}, old=True)
                self.assertEqual(current.returncode, 0, current.stderr[:300])
                self.assertEqual(old.returncode, 0, old.stderr[:300])
                self.assertEqual(current.stdout, baseline.stdout)
                _, current_docs = self.render({'imageRegistry': mirror})
                for current_doc, old_doc in zip(self.objects(current_docs, 'Deployment'), self.objects(old_docs, 'Deployment')):
                    self.assertEqual([c['image'] for c in current_doc['spec']['template']['spec']['containers']],
                                     [c['image'] for c in old_doc['spec']['template']['spec']['containers']])
