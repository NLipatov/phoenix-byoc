#!/usr/bin/env python3
"""Offline authoring checks; YAML files are local inputs, not Kubernetes Secrets.

check-yaml RELEASE DEFAULTS VALUES SECRETS checks raw layers then effective authoring.
gate-yaml uses the same layers but also enforces current installation support.
Existing check/references commands continue to consume stdin JSON only.
"""
import json
from pathlib import Path
import sys

from connection_contract import (ContractError, check_named_capabilities, load_contract,
                                 validate_connections)

MAX_INPUT = 4 * 1024 * 1024


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate')
        result[key] = value
    return result


def main():
    if len(sys.argv) == 6 and sys.argv[1] in ('check-yaml', 'gate-yaml'):
        from connection_yaml import load_yaml_authoring
        try:
            gate = sys.argv[1] == 'gate-yaml'
            root = Path(__file__).resolve().parents[1]
            # Absent legacy authoring needs no capability/contract assets.
            # Supplied objects, including disabled ones, still get validation.
            bundle = None if gate else load_contract(root)
            config = load_yaml_authoring(*sys.argv[2:], bundle=bundle)
            if gate and not config:
                return 0
            if bundle is None:
                bundle = load_contract(root)
            validated = validate_connections(config, bundle)
            if gate:
                check_named_capabilities(config, validated, bundle)
                # NOT_APPLICABLE is not generic delivery permission. No shipped
                # release authority supports enabled delivery yet, even generic.
                if validated.enabled:
                    raise ContractError('connection_release_unsupported', '/agentInputDelivery')
        except ContractError as error:
            print(error.code + ': ' + error.path, file=sys.stderr)
            return 1
        return 0
    if len(sys.argv) != 2 or sys.argv[1] not in ('check', 'references'):
        print('invalid_command: /', file=sys.stderr)
        return 1
    try:
        payload = sys.stdin.buffer.read(MAX_INPUT + 1)
        if len(payload) > MAX_INPUT:
            raise ContractError('input_size_limit', '/')
        config = json.loads(payload, object_pairs_hook=_unique)
    except ContractError as error:
        print(error.code + ': ' + error.path, file=sys.stderr)
        return 1
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
