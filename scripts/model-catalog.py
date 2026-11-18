#!/usr/bin/env python3
"""Check the models list (top-level `models`) in merged BYOC values.

Reads the merged values as JSON on stdin. Prints one line per error on stderr
and never prints anything but the offending id, profile or key names.
"""
import argparse
import json
import re
import sys

ID = re.compile(r"[a-z0-9][a-z0-9_-]*/\S+")
PROFILE = re.compile(r"[a-z][a-z0-9_]{0,63}")
KEYS = ("id", "profile")


def check(config):
    models = config.get("models") if isinstance(config, dict) else None
    if not isinstance(models, list) or not models:
        return ["models: at least 1 model is required"]
    errors = []
    seen = {key: set() for key in KEYS}
    patterns = {"id": ID, "profile": PROFILE}
    for index, entry in enumerate(models):
        where = f"models[{index}]"
        if not isinstance(entry, dict):
            errors.append(f"{where}: must be a mapping with id and profile")
            continue
        for key in sorted(set(entry) - set(KEYS)):
            errors.append(f"{where}: unknown key {key}")
        for key in KEYS:
            value = entry.get(key)
            if value is None:
                errors.append(f"{where}: {key} is required")
            elif not isinstance(value, str) or not patterns[key].fullmatch(value):
                errors.append(f"{where}: invalid {key} {value}")
            elif value in seen[key]:
                errors.append(f"{where}: duplicate {key} {value}")
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
