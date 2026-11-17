"""Offline integrity loader for the immutable owner exports; not configuration admission."""

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
from typing import Dict
from urllib.parse import urlsplit

LOCK_SHA256 = 'e5db4a3529d6a8d917f7f340e4e72ad0be5135c66894ececa2edbbdafaf35525'
MAX_LOCK_BYTES = 65536
MAX_FILE_BYTES = 1024 * 1024
MAX_TOTAL_BYTES = 4 * MAX_FILE_BYTES
MAX_FILES = 64
DIGEST = re.compile(r'[0-9a-f]{64}\Z')


class ContractError(Exception):
    def __init__(self, code: str, path: str):
        self.code = code
        self.path = path
        super().__init__(code + ': ' + path)


@dataclass(frozen=True)
class ContractBundle:
    schema: Path
    vectors: Path
    transport_vectors: Path
    transport: Path
    engine_vectors: Path
    capabilities: Path
    manifests: Dict[str, Path]
    digests: Dict[str, Dict[str, str]]


def _member_name(name, label):
    if (not isinstance(name, str) or not name or len(name) > 128 or
            PurePosixPath(name).is_absolute() or
            any(part in ('', '.', '..') for part in name.split('/')) or
            '\\' in name or '\x00' in name or ':' in name or '/' in name):
        raise ContractError('unsafe_path', label)


def _read(root, relative, limit):
    """Reject links at every component, and read bounded regular files only."""
    label = str(relative)
    current = root
    try:
        if not stat.S_ISDIR(current.lstat().st_mode):
            raise ContractError('unsafe_path', label)
        for part in relative.parts[:-1]:
            _member_name(part, label)
            current = current / part
            if not stat.S_ISDIR(current.lstat().st_mode):
                raise ContractError('unsafe_path', label)
        _member_name(relative.name, label)
        current = current / relative.name
        mode = current.lstat().st_mode
        if not stat.S_ISREG(mode):
            raise ContractError('unsafe_path', label)
        fd = os.open(current, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                raise ContractError('unsafe_path', label)
            if info.st_size > limit:
                raise ContractError('size_limit', label)
            with os.fdopen(fd, 'rb', closefd=False) as stream:
                data = stream.read(limit + 1)
            if len(data) > limit:
                raise ContractError('size_limit', label)
            return data
        finally:
            os.close(fd)
    except (FileNotFoundError, NotADirectoryError):
        raise ContractError('missing_member', label) from None
    except OSError:
        raise ContractError('unsafe_path', label) from None


def _json(data, label):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('duplicate key')
            result[key] = value
        return result
    try:
        return json.loads(data, object_pairs_hook=unique)
    except (ValueError, UnicodeError, RecursionError):
        raise ContractError('invalid_json', label) from None


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _schema_refs(schema, label):
    pending = [schema]
    count = 0
    while pending:
        node = pending.pop()
        count += 1
        if count > 100000:
            raise ContractError('size_limit', label)
        if isinstance(node, dict):
            if '$ref' in node:
                ref = node['$ref']
                if not isinstance(ref, str) or not ref.startswith('#/'):
                    raise ContractError('external_ref', label)
                target = schema
                for part in ref[2:].split('/'):
                    if re.search(r'~(?![01])', part):
                        raise ContractError('external_ref', label)
                    part = part.replace('~1', '/').replace('~0', '~')
                    if not isinstance(target, dict) or part not in target:
                        raise ContractError('external_ref', label)
                    target = target[part]
            pending.extend(node.values())
        elif isinstance(node, list):
            pending.extend(node)


def load_contract(root: Path) -> ContractBundle:
    root = Path(root)
    lock_path = Path('contracts/native-provider-inputs.lock.json')
    lock_bytes = _read(root, lock_path, MAX_LOCK_BYTES)
    if _sha(lock_bytes) != LOCK_SHA256:
        raise ContractError('lock_mismatch', str(lock_path))
    lock = _json(lock_bytes, str(lock_path))
    if lock.get('formatVersion') != 1 or set(lock.get('owners', {})) != {'agents', 'engine'}:
        raise ContractError('invalid_lock', str(lock_path))
    manifests = {}
    manifest_data = {}
    digests = {}
    paths = {}
    total = len(lock_bytes)
    schema_bytes = None
    for owner_name, directory in (('agents', 'contracts/llm-connections/v1'),
                                  ('engine', 'contracts/agent-input-delivery/v1')):
        owner = lock['owners'][owner_name]
        label = directory + '/manifest.json'
        if owner.get('path') != directory:
            raise ContractError('unsafe_path', str(lock_path))
        expected = owner.get('files')
        if not isinstance(expected, dict) or not 1 <= len(expected) <= MAX_FILES:
            raise ContractError('invalid_manifest', label)
        for name, digest in expected.items():
            _member_name(name, label)
            if not isinstance(digest, str) or not DIGEST.fullmatch(digest):
                raise ContractError('invalid_manifest', label)
        manifest_path = Path(directory) / 'manifest.json'
        manifest_bytes = _read(root, manifest_path, MAX_LOCK_BYTES)
        total += len(manifest_bytes)
        if _sha(manifest_bytes) != owner.get('manifestSha256'):
            raise ContractError('manifest_mismatch', label)
        manifest = _json(manifest_bytes, label)
        if manifest != owner.get('manifest') or manifest.get('files') != expected:
            raise ContractError('manifest_mismatch', label)
        if (manifest.get('formatVersion') != 1 or manifest.get('contractVersion') != '1' or
                manifest.get('deliveryVersion') != '1'):
            raise ContractError('version_mismatch', label)
        folder = root / directory
        expected_names = set(expected) | {'manifest.json'}
        seen = set()
        try:
            with os.scandir(folder) as entries:
                for entry in entries:
                    if entry.name not in expected_names:
                        raise ContractError('extra_member', label)
                    seen.add(entry.name)
        except OSError:
            raise ContractError('unsafe_path', label) from None
        if expected_names - seen:
            raise ContractError('missing_member', label)
        digests[owner_name] = {}
        paths[owner_name] = {}
        for name, expected_digest in expected.items():
            relative = Path(directory) / name
            content = _read(root, relative, MAX_FILE_BYTES)
            total += len(content)
            if total > MAX_TOTAL_BYTES:
                raise ContractError('size_limit', label)
            if _sha(content) != expected_digest:
                raise ContractError('digest_mismatch', str(relative))
            digests[owner_name][name] = expected_digest
            paths[owner_name][name] = root / relative
            if owner_name == 'agents' and name == 'values.schema.json':
                schema_bytes = content
        for role, name in owner['roles'].items():
            if name not in expected:
                raise ContractError('invalid_lock', str(lock_path))
        manifests[owner_name] = root / manifest_path
        manifest_data[owner_name] = manifest
    agents = paths['agents']
    engine = paths['engine']
    schema_path = agents['values.schema.json']
    _schema_refs(_json(schema_bytes, 'contracts/llm-connections/v1/values.schema.json'),
                 'contracts/llm-connections/v1/values.schema.json')
    agents_manifest = manifest_data['agents']
    engine_manifest = manifest_data['engine']
    if agents_manifest['contractVersion'] != engine_manifest['contractVersion'] or agents_manifest['deliveryVersion'] != engine_manifest['deliveryVersion']:
        raise ContractError('version_mismatch', 'contracts/native-provider-inputs.lock.json')
    return ContractBundle(schema_path, agents['semantic-vectors.json'], agents['transport-vectors.json'],
                          engine['contract.json'], engine['fixtures.json'], agents['capabilities.json'],
                          manifests, digests)


def verify_contract_files(root: Path) -> None:
    load_contract(root)


@dataclass(frozen=True)
class SecretKeyRef:
    name: str
    key: str


@dataclass(frozen=True)
class ValidatedInputs:
    enabled: bool
    plain_env: Dict[str, str]
    secret_refs: Dict[str, SecretKeyRef]
    platform_names: tuple[str, ...]
    required_capabilities: tuple[tuple[str, str, str], ...]


# Route identity is read from the pinned producer's fixed discriminators;
# APIs and required capability tuples come from its pinned capability records.
# This is not another route catalog or a schema validation interpreter.
_HEADER_TOKEN = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+\Z")
_HEADER_REF = re.compile(r'\$([A-Z][A-Z0-9_]*)\Z')
# Seven native keys require an actual sandbox platform source at runtime;
# a declaration here does not certify that source or its identity.
_PLATFORM_NATIVE_KEYS = frozenset((
    'AWS_ROLE_ARN', 'AWS_WEB_IDENTITY_TOKEN_FILE', 'AWS_ROLE_SESSION_NAME',
    'AWS_CONTAINER_CREDENTIALS_FULL_URI', 'AWS_CONTAINER_CREDENTIALS_RELATIVE_URI',
    'AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE', 'AZURE_FEDERATED_TOKEN_FILE',
))
_FORBIDDEN_MEMBER_NAMES = frozenset(('__proto__', 'constructor', 'prototype'))
_PROTECTED_HEADERS = frozenset((
    'authorization', 'proxy-authorization', 'x-api-key', 'api-key',
    'x-portkey-api-key', 'host', 'cookie', 'anthropic-version',
    'anthropic-beta', 'api-version',
))


def _schema_helm(config, bundle):
    """Use Helm's real schema validation in a dependency-free private chart.

    Neither user-controlled keys nor Helm diagnostics leave this function.
    """
    import subprocess
    import tempfile
    import shutil
    with tempfile.TemporaryDirectory(prefix='connection-validation-') as folder:
        os.chmod(folder, 0o700)
        base = Path(folder)
        chart = base / 'chart'
        (chart / 'templates').mkdir(mode=0o700, parents=True)
        def private_file(path, data):
            with os.fdopen(os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600), 'wb') as stream:
                stream.write(data)
        private_file(chart / 'Chart.yaml', b'apiVersion: v2\nname: connection-validation\nversion: 0.1.0\n')
        private_file(chart / 'templates' / 'noop.yaml', b'{{- /* validation only: no resources */ -}}\n')
        # The owner schema is copied byte-for-byte, with no local adapter.
        shutil.copyfile(bundle.schema, chart / 'values.schema.json')
        os.chmod(chart / 'values.schema.json', 0o600)
        # Escaped Unicode is the same JSON value; avoid YAML's raw C1 parser
        # rejection so Helm schema and semantic checks retain distinct outcomes.
        private_file(base / 'input.json', json.dumps(config, ensure_ascii=True,
                                                      separators=(',', ':'), allow_nan=False).encode('utf-8'))
        env = {'PATH': os.environ.get('PATH', '/usr/bin:/bin'), 'HOME': folder,
               'KUBECONFIG': '/dev/null', 'HELM_CONFIG_HOME': folder,
               'HELM_CACHE_HOME': folder, 'HELM_DATA_HOME': folder}
        try:
            process = subprocess.run(
                ['helm', 'template', 'connection-validation', str(chart), '--values', str(base / 'input.json')],
                env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=False)
        except (OSError, subprocess.TimeoutExpired):
            raise ContractError('connection_validation_unavailable', '/llm') from None
        if process.returncode:
            raise ContractError('connection_schema_invalid', '/llm' if 'llm' in config else '/agentInputDelivery')


def _transport_json(values):
    # Exact deterministic UTF-8 representation of the non-secret authoring env.
    return json.dumps(values, ensure_ascii=False, sort_keys=True,
                      separators=(',', ':'), allow_nan=False).encode('utf-8')


def validate_connections(config: dict, bundle: ContractBundle) -> ValidatedInputs:
    """Validate authoring, not deployment identity, Secret bytes or native capability."""
    if not isinstance(config, dict) or any(not isinstance(key, str) for key in config):
        raise ContractError('connection_schema_invalid', '/llm')
    if set(config) - {'llm', 'agentInputDelivery'}:
        raise ContractError('connection_schema_invalid', '/llm')
    generic = config.get('agentInputDelivery')
    # The generic PHOENIX_LLM_* error is explicitly distinct from schema errors.
    if isinstance(generic, dict):
        for origin in ('env', 'secretEnv'):
            mapping = generic.get(origin)
            if isinstance(mapping, dict) and any(isinstance(k, str) and k.startswith('PHOENIX_LLM_') for k in mapping):
                raise ContractError('llm_authoring_required', '/agentInputDelivery/' + origin)
    if config:
        try:
            _schema_helm(config, bundle)
        except (ValueError, TypeError, UnicodeError, RecursionError):
            raise ContractError('connection_schema_invalid', '/llm') from None
    if not config:
        return ValidatedInputs(False, {}, {}, (), ())
    # Helm 3.18's gojsonschema treats a numeric 1 as equal to the string const
    # "1". Enforce the one explicitly typed protocol version after real Helm.
    if 'llm' in config and (not isinstance(config['llm'], dict) or
                            type(config['llm'].get('CONFIG_VERSION')) is not str or
                            config['llm']['CONFIG_VERSION'] != '1'):
        raise ContractError('connection_schema_invalid', '/llm')
    llm = config.get('llm', {})
    generic = generic if generic is not None else {}
    # Schema was checked above: no defaults for malformed supplied null/empty objects.
    enabled = generic.get('enabled', False)
    llm_env = llm.get('env', {})
    llm_secrets = llm.get('secretEnv', {})
    generic_env = generic.get('env', {})
    generic_secrets = generic.get('secretEnv', {})
    platform = tuple(llm.get('platformEnv', ()))
    for left, right, path in (
        (llm_env, llm_secrets, '/llm/secretEnv'),
        (generic_env, generic_secrets, '/agentInputDelivery/secretEnv'),
        (llm_env, generic_env, '/agentInputDelivery/env'),
        (llm_secrets, generic_secrets, '/agentInputDelivery/secretEnv'),
        (llm_env, generic_secrets, '/agentInputDelivery/secretEnv'),
        (generic_env, llm_secrets, '/llm/secretEnv'),
    ):
        if left.keys() & right.keys():
            raise ContractError('destination_collision', path)
    destinations = set(llm_env) | set(llm_secrets) | set(generic_env) | set(generic_secrets)
    if destinations.intersection(platform):
        raise ContractError('destination_collision', '/llm/platformEnv')
    # The Engine transport forbids NUL even in unused known plain values.
    # Do not reject empty generic strings or inspect unknown Secret bytes.
    if any('\x00' in value for value in tuple(llm_env.values()) + tuple(generic_env.values())):
        raise ContractError('source_required', '/agentInputDelivery/env')
    plain = dict(generic_env)
    plain.update(llm_env)
    secrets = {name: SecretKeyRef(**ref) for name, ref in generic_secrets.items()}
    secrets.update({name: SecretKeyRef(**ref) for name, ref in llm_secrets.items()})
    capabilities = json.loads(bundle.capabilities.read_bytes())['entries']
    allowed_tuples = {(entry['route'], entry['api'], entry['authMode']) for entry in capabilities}
    schema = json.loads(bundle.schema.read_bytes())
    families = {}
    for route in {entry['route'] for entry in capabilities}:
        discriminators = schema['definitions']['llmConnectionsV1_' + route]['allOf'][1]['properties']
        key = (discriminators['PLATFORM']['const'], discriminators['PUBLISHER']['const'])
        if key in families:
            raise ContractError('connection_contract_invalid', '/llm')
        families[key] = route
    required = set()
    if 'llm' in config:
        plain['PHOENIX_LLM_CONFIG_VERSION'] = '1'
        connections = llm['connections']
        plain['PHOENIX_LLM_CONNECTIONS'] = ','.join(sorted(connections))
        for name, connection in sorted(connections.items()):
            if name in _FORBIDDEN_MEMBER_NAMES:
                raise ContractError('invalid_authoring', '/llm/connections')
            route = families.get((connection['PLATFORM'], connection['PUBLISHER']))
            if route is None:
                raise ContractError('connection_schema_invalid', '/llm/connections')
            candidate_apis = {api for family, api, auth in allowed_tuples
                              if family == route and auth == connection['AUTH_MODE']}
            if 'API' in connection:
                api = connection['API']
            elif len(candidate_apis) == 1:
                api = next(iter(candidate_apis))
            else:
                raise ContractError('connection_schema_invalid', '/llm/connections')
            capability = (route, api, connection['AUTH_MODE'])
            if capability not in allowed_tuples:
                raise ContractError('connection_schema_invalid', '/llm/connections')
            required.add(capability)
            path = '/llm/connections'  # Never reflect attacker-chosen property names.
            if 'API_KEY_ENV' in connection and connection['API_KEY_ENV'] not in llm_secrets:
                raise ContractError('secret_reference_required', path + '/API_KEY_ENV')
            refs = connection.get('NATIVE_ENV_REFS_JSON', {})
            for native_key, destination in refs.items():
                if native_key in _FORBIDDEN_MEMBER_NAMES:
                    raise ContractError('invalid_authoring', path + '/NATIVE_ENV_REFS_JSON')
                if native_key in _PLATFORM_NATIVE_KEYS:
                    if destination not in platform:
                        raise ContractError('source_required', path + '/NATIVE_ENV_REFS_JSON')
                elif destination not in plain or not plain[destination] or _has_control(plain[destination]):
                    raise ContractError('source_required', path + '/NATIVE_ENV_REFS_JSON')
            if 'BASE_URL' in connection and not _valid_url(connection['BASE_URL']):
                raise ContractError('invalid_authoring', path + '/BASE_URL')
            headers = connection.get('HEADERS_JSON', {})
            seen = set()
            for header, value in headers.items():
                lower = header.lower()
                if lower in seen:
                    raise ContractError('header_case_duplicate', path + '/HEADERS_JSON')
                seen.add(lower)
                if (header in _FORBIDDEN_MEMBER_NAMES or not _HEADER_TOKEN.fullmatch(header)
                        or lower in _PROTECTED_HEADERS):
                    raise ContractError('header_invalid', path + '/HEADERS_JSON')
                ref = _HEADER_REF.fullmatch(value)
                if ref:
                    destination = ref.group(1)
                    if destination not in plain and destination not in secrets and destination not in platform:
                        raise ContractError('source_required', path + '/HEADERS_JSON')
                    if destination in plain and not _header_value(plain[destination]):
                        raise ContractError('header_invalid', path + '/HEADERS_JSON')
                elif not _header_literal(value):
                    raise ContractError('header_invalid', path + '/HEADERS_JSON')
            prefix = 'PHOENIX_LLM_' + name.upper() + '_'
            for field, value in connection.items():
                if field in ('NATIVE_ENV_REFS_JSON', 'HEADERS_JSON'):
                    plain[prefix + field] = _transport_json(value).decode('utf-8')
                else:
                    plain[prefix + field] = value
            plain[prefix + 'API'] = api
    if len(plain) > 256:
        raise ContractError('env_count_limit', '/agentInputDelivery/env')
    if len(secrets) > 128:
        raise ContractError('secret_count_limit', '/agentInputDelivery/secretEnv')
    if any(len(value.encode('utf-8')) > 65536 for value in plain.values()) or len(_transport_json(plain)) > 65536:
        raise ContractError('env_size_limit', '/agentInputDelivery/env')
    return ValidatedInputs(enabled, plain, secrets, tuple(sorted(platform)), tuple(sorted(required)))


def _has_control(value):
    return any(ord(ch) < 32 or 127 <= ord(ch) <= 159 for ch in value)


def _valid_url(value):
    if _has_control(value) or '\\' in value or '?' in value or '#' in value:
        return False
    try:
        url = urlsplit(value)
        port = url.port  # Invalid numeric ports raise ValueError.
        return (url.scheme == 'https' and bool(url.hostname) and
                not url.username and not url.password and
                not url.query and not url.fragment)
    except ValueError:
        return False


def _header_value(value):
    return bool(value) and not _has_control(value) and len(value.encode('utf-8')) <= 65536


def _header_literal(value):
    return _header_value(value) and '$' not in value and not value.startswith('!') and '`' not in value
