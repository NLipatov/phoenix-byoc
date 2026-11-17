#!/usr/bin/env python3
"""Standalone named Secret key-presence check, not install or capability admission.

The fixed template exposes only key names locally, though kubectl receives the
Secret object from Kubernetes. This cannot authorize a secret-free API read.
Present empty values pass; Engine/Agent runtime validates blank, UTF-8, NUL,
size and header bytes. Future integration must gate release and authoring first.
"""
import json
import re
import subprocess
import sys
from typing import Callable

from connection_contract import ContractError, SecretKeyRef

MAX_INPUT = 4 * 1024 * 1024
MAX_REFS = 128
MAX_OUTPUT = 1024 * 1024
KEYS_TEMPLATE = '{{range $key, $value := .data}}{{printf "%s\\n" $key}}{{end}}'
_SECRET_NAME = re.compile(r'[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*\Z')
_SECRET_KEY = re.compile(r'[-._a-zA-Z0-9]+\Z')
_NAMESPACE = re.compile(r'[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\Z')
_CONTEXT = re.compile(r'[A-Za-z0-9][A-Za-z0-9._:@/+\-]*\Z')


def _valid_key(value):
    return (isinstance(value, str) and len(value) <= 253 and
            _SECRET_KEY.fullmatch(value) is not None and value != '.' and
            not value.startswith('..'))


def _valid_name(value):
    return (isinstance(value, str) and len(value) <= 253 and
            _SECRET_NAME.fullmatch(value) is not None)


def check_secret_references(refs: tuple[SecretKeyRef, ...], namespace: str,
                            context: str, run: Callable) -> None:
    """Check selected key existence; validate the entire request before any GET."""
    if not isinstance(namespace, str) or len(namespace) > 63 or not _NAMESPACE.fullmatch(namespace):
        raise ContractError('connection_secret_invalid', '/namespace')
    if not isinstance(context, str) or len(context) > 253 or not _CONTEXT.fullmatch(context):
        raise ContractError('connection_secret_invalid', '/context')
    if not isinstance(refs, (tuple, list)) or len(refs) > MAX_REFS:
        raise ContractError('secret_count_limit', '/references')
    grouped = {}
    for ref in refs:
        if not isinstance(ref, SecretKeyRef) or not _valid_name(ref.name) or not _valid_key(ref.key):
            raise ContractError('connection_secret_invalid', '/references')
        grouped.setdefault(ref.name, set()).add(ref.key)

    for name, keys in sorted(grouped.items()):
        argv = ['kubectl', '--context=' + context, '--namespace=' + namespace,
                '--request-timeout=30s', 'get', 'secret', '-o',
                'go-template=' + KEYS_TEMPLATE, name]
        try:
            result = run(argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                         timeout=35, check=False)
            if result.returncode != 0 or not isinstance(result.stdout, bytes) or len(result.stdout) > MAX_OUTPUT:
                raise ContractError('connection_secret_unreadable', '/references')
            output = result.stdout.decode('ascii')
            if output and not output.endswith('\n'):
                raise ContractError('connection_secret_unreadable', '/references')
            lines = output[:-1].split('\n') if output else []
            if any(not _valid_key(key) for key in lines) or len(lines) != len(set(lines)):
                raise ContractError('connection_secret_unreadable', '/references')
        except (OSError, UnicodeError, subprocess.SubprocessError, ValueError, TypeError) as error:
            raise ContractError('connection_secret_unreadable', '/references') from None
        if not keys.issubset(lines):
            raise ContractError('connection_secret_key_missing', '/references')


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate')
        result[key] = value
    return result


def main():
    if len(sys.argv) != 5 or sys.argv[1] != '--namespace' or sys.argv[3] != '--context':
        print('connection_secret_invalid: /arguments', file=sys.stderr)
        return 1
    try:
        payload = sys.stdin.buffer.read(MAX_INPUT + 1)
        if len(payload) > MAX_INPUT:
            raise ContractError('input_size_limit', '/references')
        raw = json.loads(payload, object_pairs_hook=_unique)
        if not isinstance(raw, list) or len(raw) > MAX_REFS:
            raise ContractError('secret_count_limit', '/references')
        refs = []
        for entry in raw:
            if not isinstance(entry, dict) or set(entry) != {'name', 'key'}:
                raise ContractError('connection_secret_invalid', '/references')
            refs.append(SecretKeyRef(entry['name'], entry['key']))
        check_secret_references(tuple(refs), sys.argv[2], sys.argv[4], subprocess.run)
    except ContractError as error:
        print(error.code + ': ' + error.path, file=sys.stderr)
        return 1
    except (ValueError, UnicodeError, RecursionError):
        print('invalid_json: /references', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
