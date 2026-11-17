#!/usr/bin/env python3
"""Offline, safe stdin-JSON authoring check; never reads Kubernetes Secret values."""
import json
from pathlib import Path
import sys

from connection_contract import ContractError, load_contract, validate_connections

MAX_INPUT = 4 * 1024 * 1024


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate')
        result[key] = value
    return result


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in ('check', 'references'):
        print('invalid_command: /', file=sys.stderr)
        return 1
    try:
        payload = sys.stdin.buffer.read(MAX_INPUT + 1)
        if len(payload) > MAX_INPUT:
            raise ContractError('input_size_limit', '/')
        config = json.loads(payload, object_pairs_hook=_unique)
    except (ValueError, UnicodeError, RecursionError):
        print('invalid_json: /', file=sys.stderr)
        return 1
    try:
        bundle = load_contract(Path(__file__).resolve().parents[1])
        validated = validate_connections(config, bundle)
    except ContractError as error:
        print(error.code + ': ' + error.path, file=sys.stderr)
        return 1
    if sys.argv[1] == 'references':
        refs = sorted({(ref.name, ref.key) for ref in validated.secret_refs.values()})
        print(json.dumps([{'name': name, 'key': key} for name, key in refs]))
    return 0


if __name__ == '__main__':
    sys.exit(main())
