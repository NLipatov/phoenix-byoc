#!/usr/bin/env python3
"""Check the models list that Phoenix Web gets from merged BYOC values.

That is `models`, or, when it is unset or empty, `defaultModels.vertex` or
`defaultModels.anthropic` (selected by `vertex.enabled`).

Reads the merged values as JSON on stdin. Prints one line per error on stderr
and never prints anything but the offending id, profile or key names. A value
that is not a printable scalar is shown as JSON, or by its type for a mapping or
a list, so that an error stays on one line and never echoes nested values.
"""
import argparse
import json
import re
import sys

ID = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}/[\x21-\x7e]{1,255}")
PROFILE = re.compile(r"[a-z][a-z0-9_]{0,63}")
KEYS = ("id", "profile")
PATTERNS = {"id": ID, "profile": PROFILE}


def shown(value):
    if isinstance(value, (dict, list)):
        return f"({type(value).__name__})"
    if isinstance(value, str) and value and value.isprintable():
        return value
    return json.dumps(value)


def effective(config):
    """The list that Phoenix Web gets, and its name: `models`, or the provider default."""
    models = config.get("models")
    if models is not None and models != []:
        return models, "models"
    vertex = config.get("vertex")
    key = "vertex" if isinstance(vertex, dict) and vertex.get("enabled") is True else "anthropic"
    defaults = config.get("defaultModels")
    return (defaults.get(key) if isinstance(defaults, dict) else None), f"defaultModels.{key}"


def check(config):
    models, name = effective(config if isinstance(config, dict) else {})
    if models is not None and not isinstance(models, list):
        return [f"{name}: must be a list of {{id, profile}}"]
    if not models:
        return [f"{name}: at least 1 model is required"]
    errors = []
    seen = {key: set() for key in KEYS}
    for index, entry in enumerate(models):
        where = f"{name}[{index}]"
        if not isinstance(entry, dict):
            errors.append(f"{where}: must be a mapping with id and profile")
            continue
        for key in sorted(set(entry) - set(KEYS)):
            errors.append(f"{where}: unknown key {shown(key)}")
        for key in KEYS:
            value = entry.get(key)
            if value is None:
                errors.append(f"{where}: {key} is required")
            elif not isinstance(value, str) or not PATTERNS[key].fullmatch(value):
                errors.append(f"{where}: invalid {key} {shown(value)}")
            elif value in seen[key]:
                errors.append(f"{where}: duplicate {key} {shown(value)}")
            else:
                seen[key].add(value)
    return errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["check"])
    parser.parse_args()
    try:
        config = json.load(sys.stdin)
    except ValueError:
        print("models: input is not valid JSON", file=sys.stderr)
        return 1
    errors = check(config)
    for error in errors:
        print(error, file=sys.stderr)
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
