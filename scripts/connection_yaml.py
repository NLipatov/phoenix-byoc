"""Bounded raw-YAML adapter for authoring only; not release/capability admission."""
import json
import os
from pathlib import Path
import selectors
import shutil
import stat
import subprocess
import tempfile
import time

from connection_contract import ContractError, load_contract, validate_connections

BLOCKS = ('llm', 'agentInputDelivery')
MAX_FILE_BYTES = 4 * 1024 * 1024
MAX_OUTPUT_BYTES = 32 * 1024 * 1024
PROCESS_TIMEOUT = 10
YQ_VERSION = b'yq (https://github.com/mikefarah/yq/) version v4.49.2'
RAW_NODES = ('{"data": ., "entries": (to_entries | map('
             '{"key": .key, "tag": (.key | tag), "kind": (.key | kind), "value": .value})), '
             '"mappings": [... | select(kind == "map") | {"path": path, '
             '"entries": (to_entries | map({"key": .key, "tag": (.key | tag), "kind": (.key | kind)}))}], '
             '"nodes": [... | {"path": path, "kind": kind, "tag": tag, "key": is_key}]}')


class _Pairs(list):
    """Distinguish JSON objects (including duplicate members) from arrays."""


def _plain(node, path):
    if isinstance(node, _Pairs):
        result = {}
        for key, value in node:
            if key in result:
                raise ContractError('yaml_duplicate_authoring_key', path)
            result[key] = _plain(value, path)
        return result
    if isinstance(node, list):
        return [_plain(value, path) for value in node]
    return node


def _contains_blocks(node):
    # A root merge can be a mapping or a sequence of mappings. Do not inspect
    # arbitrary legacy descendants: only members that could become root blocks.
    if isinstance(node, _Pairs):
        return any(key in BLOCKS for key, _ in node)
    if isinstance(node, list):
        return any(_contains_blocks(value) for value in node)
    return False


def _projection(document):
    envelope = dict(document)
    data = envelope['data']
    if not isinstance(data, _Pairs):
        raise ContractError('yaml_representation_unsupported', '/')
    config = {}
    # Inspect preserved pairs BEFORE node traversal: yq's recursive descent
    # reports only the last occurrence of a duplicate mapping key.
    for key, value in data:
        if key in BLOCKS:
            if key in config:
                raise ContractError('yaml_duplicate_authoring_key', '/' + key)
            config[key] = _plain(value, '/' + key)
    nodes = _plain(envelope['nodes'], '/')
    if len(nodes) > 100000:
        raise ContractError('yaml_process_limit', '/')
    # Inspect every protected mapping's raw entries, not just the descendant
    # nodes: descent can hide an earlier merge/alias behind a quoted << key,
    # while JSON encoding removes even an ordinary string << entry entirely.
    entry_count = 0
    for mapping in envelope['mappings']:
        mapping = dict(mapping)
        entries = mapping['entries']
        entry_count += 1 + len(entries)
        if entry_count > 100000:
            raise ContractError('yaml_process_limit', '/')
        path = mapping['path']
        if not path or path[0] not in BLOCKS:
            continue
        seen = set()
        for entry in entries:
            entry = dict(entry)
            if entry['kind'] != 'scalar' or entry['tag'] != '!!str' or entry['key'] == '<<':
                raise ContractError('yaml_representation_unsupported', '/' + path[0])
            if entry['key'] in seen:
                raise ContractError('yaml_duplicate_authoring_key', '/' + path[0])
            seen.add(entry['key'])
    # to_entries preserves individual root keys and their tags even when a
    # later duplicate key would hide a merge node from recursive descent.
    for entry in envelope['entries']:
        entry = dict(entry)
        if entry['tag'] == '!!merge' and _contains_blocks(entry['value']):
            raise ContractError('yaml_representation_unsupported', '/')
        if entry['key'] in BLOCKS and (entry['tag'] != '!!str' or entry['kind'] != 'scalar'):
            raise ContractError('yaml_representation_unsupported', '/')
    for row in nodes:
        path = row['path']
        protected = bool(path) and path[0] in BLOCKS
        if not protected and not (config and not path):
            continue
        label = '/' + path[0] if protected else '/'
        expected = {'map': {'!!map'}, 'seq': {'!!seq'},
                    'scalar': {'!!str', '!!null', '!!bool', '!!int', '!!float'}}
        if (row['tag'] not in expected.get(row['kind'], set()) or
                (row['key'] and (row['kind'] != 'scalar' or row['tag'] != '!!str'))):
            raise ContractError('yaml_representation_unsupported', label)
    return config


def _invalid_constant(_):
    raise ValueError('nonfinite')


def _decode(payload):
    return json.loads(payload, object_pairs_hook=_Pairs, parse_constant=_invalid_constant)


def _read(path):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | getattr(os, 'O_NOFOLLOW', 0))
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                raise ContractError('yaml_input_invalid', '/')
            if info.st_size > MAX_FILE_BYTES:
                raise ContractError('input_size_limit', '/')
            with os.fdopen(fd, 'rb', closefd=False) as stream:
                content = stream.read(MAX_FILE_BYTES + 1)
            if len(content) > MAX_FILE_BYTES:
                raise ContractError('input_size_limit', '/')
            return content
        finally:
            os.close(fd)
    except (OSError, ValueError):
        raise ContractError('yaml_input_invalid', '/') from None


def _run(yq, arguments, payload=b''):
    """Drain both pipes within one byte/time budget; never expose child diagnostics."""
    with tempfile.TemporaryFile() as source:
        source.write(payload)
        source.seek(0)
        try:
            child = subprocess.Popen([yq, *arguments], stdin=source,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                     env={'PATH': os.environ.get('PATH', '/usr/bin:/bin'),
                                          'HOME': tempfile.gettempdir()})
        except OSError:
            raise ContractError('yaml_tool_unavailable', '/') from None
        output = bytearray()
        size = 0
        deadline = time.monotonic() + PROCESS_TIMEOUT
        try:
            with selectors.DefaultSelector() as selector:
                for pipe in (child.stdout, child.stderr):
                    os.set_blocking(pipe.fileno(), False)
                    selector.register(pipe, selectors.EVENT_READ)
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise ContractError('yaml_process_limit', '/')
                    for key, _ in selector.select(remaining):
                        chunk = os.read(key.fileobj.fileno(), 65536)
                        if not chunk:
                            selector.unregister(key.fileobj)
                            continue
                        size += len(chunk)
                        if size > MAX_OUTPUT_BYTES:
                            raise ContractError('yaml_process_limit', '/')
                        if key.fileobj is child.stdout:
                            output.extend(chunk)
                child.wait(timeout=max(0.001, deadline - time.monotonic()))
            if child.returncode:
                raise ContractError('yaml_parse_invalid', '/')
            return bytes(output)
        except subprocess.TimeoutExpired:
            raise ContractError('yaml_process_limit', '/') from None
        except OSError:
            raise ContractError('yaml_tool_unavailable', '/') from None
        finally:
            if child.poll() is None:
                child.kill()
            child.wait()
            child.stdout.close()
            child.stderr.close()


def load_yaml_authoring(release, defaults, values, secrets, bundle=None):
    """Read release/defaults/values/secrets and return the effective projection.

    Unsupported aliases, merges, tags and complex keys affecting authoring fail
    closed; unrelated legacy YAML is not subject to those restrictions. Callers
    must pass the result to validate_connections for complete final validation.
    """
    layers = []
    try:
        yq = shutil.which('yq')
        if not yq:
            raise ContractError('yaml_tool_unavailable', '/')
        if _run(yq, ['--version']).strip() != YQ_VERSION:
            raise ContractError('yaml_tool_version', '/')
        for path in (release, defaults, values, secrets):
            output = _run(yq, ['eval', '-o=json', '-I=0', RAW_NODES, '-'], _read(path))
            documents = [_projection(_decode(line)) for line in output.splitlines()]
            if not documents or (len(documents) != 1 and any(documents)):
                raise ContractError('yaml_representation_unsupported', '/')
            for config in documents:
                for key, value in config.items():
                    # Do not let yq's deep merge erase malformed presence. Let
                    # the owner validator decide; partial nonempty maps may be
                    # completed by other layers and are checked only at the end.
                    if not isinstance(value, dict) or not value:
                        if bundle is None:
                            bundle = load_contract(Path(__file__).resolve().parents[1])
                        validate_connections({key: value}, bundle)
                layers.append(config)
        merged = _run(yq, ['eval', '-o=json', '-I=0',
                          '.[] as $item ireduce ({}; . * $item)', '-'],
                      json.dumps(layers).encode('utf-8'))
        return _plain(_decode(merged), '/')
    except OSError:
        raise ContractError('yaml_io_unavailable', '/') from None
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError):
        raise ContractError('yaml_representation_unsupported', '/') from None
