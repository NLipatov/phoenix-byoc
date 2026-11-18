"""Offline integrity loader for the immutable owner exports; not configuration admission."""

from dataclasses import dataclass
from enum import Enum
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
from typing import Dict
from urllib.parse import urlsplit

LOCK_SHA256 = '668e9af8ce04afdc7807248b43a4ca58eebed603d9d0fa7e09cec9ff9f144c98'
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
    semantic_rules: Path
    authoring_vectors: Path
    capability_vectors: Path
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
                          agents['semantic-rules.json'], agents['authoring-vectors.json'],
                          agents['capability-vectors.json'], manifests, digests)


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


class NamedCapability(Enum):
    NOT_APPLICABLE = 'not-applicable'
    ADMITTED = 'admitted'


# Route identity is read from the pinned producer's fixed discriminators;
# APIs and required capability tuples come from its pinned capability records.
# This is not another route catalog or a schema validation interpreter.
_HEADER_TOKEN = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+\Z")
_HEADER_REF = re.compile(r'\$([A-Z][A-Z0-9_]*)\Z')


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
    # Match Helm toJson / Go encoding/json for both nested and outer JSON.
    # Escape literal characters only: an authored backslash-u remains unchanged.
    text = json.dumps(values, ensure_ascii=False, sort_keys=True,
                      separators=(',', ':'), allow_nan=False)
    for character, escaped in (('&', r'\u0026'), ('<', r'\u003c'), ('>', r'\u003e'),
                               ('\u2028', r'\u2028'), ('\u2029', r'\u2029')):
        text = text.replace(character, escaped)
    return text.encode('utf-8')


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
    rules = json.loads(bundle.semantic_rules.read_bytes())
    control_ranges = rules['controls']['disallowedCodePointRanges']
    forbidden_connections = frozenset(rules['forbidden']['connectionNames'])
    forbidden_members = frozenset(rules['forbidden']['jsonMemberNames'])
    platform_native_keys = frozenset(rules['references']['nativePlatformKeys'])
    protected_headers = frozenset(rules['headers']['protectedNamesCaseInsensitive'])
    header_sources = frozenset(rules['references']['headerSources'])
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
    declared_plain = dict(generic_env)
    declared_plain.update(llm_env)
    plain = dict(declared_plain)
    secrets = {name: SecretKeyRef(**ref) for name, ref in generic_secrets.items()}
    secrets.update({name: SecretKeyRef(**ref) for name, ref in llm_secrets.items()})
    capabilities = json.loads(bundle.capabilities.read_bytes())['entries']
    allowed_tuples = {(entry['route'], entry['api'], entry['authMode']) for entry in capabilities}
    families = _route_families(bundle, capabilities)
    required = set()
    if 'llm' in config:
        plain['PHOENIX_LLM_CONFIG_VERSION'] = '1'
        connections = llm['connections']
        plain['PHOENIX_LLM_CONNECTIONS'] = ','.join(sorted(connections))
        for name, connection in sorted(connections.items()):
            if name in forbidden_connections:
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
                if native_key in forbidden_members:
                    raise ContractError('invalid_authoring', path + '/NATIVE_ENV_REFS_JSON')
                if native_key in platform_native_keys:
                    if destination not in platform:
                        raise ContractError('source_required', path + '/NATIVE_ENV_REFS_JSON')
                elif destination not in declared_plain or not declared_plain[destination] or _has_control(declared_plain[destination], control_ranges):
                    raise ContractError('source_required', path + '/NATIVE_ENV_REFS_JSON')
            if 'BASE_URL' in connection and not _valid_url(connection['BASE_URL'], rules['urls']['scheme'], control_ranges):
                raise ContractError('invalid_authoring', path + '/BASE_URL')
            headers = connection.get('HEADERS_JSON', {})
            seen = set()
            for header, value in headers.items():
                lower = header.lower()
                if lower in seen:
                    raise ContractError('header_case_duplicate', path + '/HEADERS_JSON')
                seen.add(lower)
                if (header in forbidden_members or not _HEADER_TOKEN.fullmatch(header)
                        or lower in protected_headers):
                    raise ContractError('header_invalid', path + '/HEADERS_JSON')
                ref = _HEADER_REF.fullmatch(value)
                if ref:
                    destination = ref.group(1)
                    sources = {'plain': destination in declared_plain, 'secrets': destination in secrets,
                               'platform': destination in platform}
                    if sum(sources.values()) != 1 or not any(sources[source] for source in header_sources):
                        raise ContractError('source_required', path + '/HEADERS_JSON')
                    if destination in declared_plain and not _header_value(declared_plain[destination], control_ranges):
                        raise ContractError('header_invalid', path + '/HEADERS_JSON')
                elif not _header_literal(value, control_ranges):
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


def _route_families(bundle, capabilities):
    schema = json.loads(bundle.schema.read_bytes())
    families = {}
    for route in {entry['route'] for entry in capabilities}:
        discriminators = schema['definitions']['llmConnectionsV1_' + route]['allOf'][1]['properties']
        key = (discriminators['PLATFORM']['const'], discriminators['PUBLISHER']['const'])
        if key in families:
            raise ContractError('connection_contract_invalid', '/llm')
        families[key] = route
    return families


def check_named_capabilities(config: dict, validated: ValidatedInputs,
                             bundle: ContractBundle) -> NamedCapability:
    """Check only named route/API/auth evidence after authoring validation.

    NOT_APPLICABLE (empty or generic-only) is never generic/release/install permission.
    The production bundle comes from load_contract; private tables are test fixtures only.
    """
    connections = config.get('llm', {}).get('connections', {})
    if not connections:
        return NamedCapability.NOT_APPLICABLE
    entries = json.loads(bundle.capabilities.read_bytes())['entries']
    # Read identity from the owner's schema, not the test candidate table.
    schema = json.loads(bundle.schema.read_bytes())
    owner_routes = (key.removeprefix('llmConnectionsV1_') for key, definition in schema['definitions'].items()
                    if key.startswith('llmConnectionsV1_') and 'allOf' in definition and
                    len(definition['allOf']) > 1 and
                    'PLATFORM' in definition['allOf'][1].get('properties', {}))
    families = _route_families(bundle, ({'route': route} for route in owner_routes))
    for name, connection in connections.items():
        route = families.get((connection['PLATFORM'], connection['PUBLISHER']))
        auth = connection['AUTH_MODE']
        candidates = [entry for entry in entries if entry.get('route') == route and
                      entry.get('authMode') == auth and
                      ('API' not in connection or entry.get('api') == connection['API'])]
        # Omitted API must count every route/auth row before comparing with the
        # native API selected by the real owner authoring rules.
        if len(candidates) != 1 or candidates[0].get('status') != 'offline-proven':
            raise ContractError('connection_capability_unsupported', '/llm/connections')
        selected = candidates[0].get('api')
        native_api = validated.plain_env.get('PHOENIX_LLM_' + name.upper() + '_API')
        if selected != native_api or (route, selected, auth) not in validated.required_capabilities:
            raise ContractError('connection_capability_unsupported', '/llm/connections')
    return NamedCapability.ADMITTED


def _has_control(value, ranges):
    return any(low <= ord(ch) <= high for ch in value for low, high in ranges)


def _valid_url(value, scheme, ranges):
    if _has_control(value, ranges) or '?' in value or '#' in value:
        return False
    try:
        url = urlsplit(value)
        _ = url.port  # Invalid numeric ports raise ValueError.
        return (url.scheme == scheme and bool(url.hostname) and
                not url.username and not url.password and
                not url.query and not url.fragment)
    except ValueError:
        return False


def _header_value(value, ranges):
    return bool(value) and not _has_control(value, ranges) and len(value.encode('utf-8')) <= 65536


def _header_literal(value, ranges):
    return (_header_value(value, ranges) and '$' not in value
            and not value.startswith('!') and '`' not in value)
