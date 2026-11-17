"""Offline integrity loader for the immutable owner exports; not configuration admission."""

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
from typing import Dict

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
        try:
            actual = {p.name for p in folder.iterdir()}
        except OSError:
            raise ContractError('unsafe_path', label) from None
        if actual - (set(expected) | {'manifest.json'}):
            raise ContractError('extra_member', label)
        if (set(expected) | {'manifest.json'}) - actual:
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
