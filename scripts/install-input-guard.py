#!/usr/bin/env python3
"""Installer-private byte snapshots, not remote artifact or same-UID attestation.

Only installer-owned cache chart trees are inspected. External cache roots are
bound by environment/path, not copied: they may contain unrelated private data.
Limits keep local input snapshots bounded (16 MiB/file, 128 MiB, 8192 entries).
"""
import json
import os
from pathlib import Path
import stat
import sys

MAX_FILE = 16 * 1024 * 1024
MAX_TOTAL = 128 * 1024 * 1024
MAX_ENTRIES = 8192
LOCAL_CHARTS = (
    'fuse-device-plugin', 'cortex-postgresql', 'opensandbox-controller',
    'phoenix-web', 'phoenix-web-frontend', 'phoenix-gateway',
    'phoenix-workflow-engine',
)
ENVIRONMENT = (
    'PHOENIX_BYOC_NAMESPACE', 'PHOENIX_BYOC_VALUES_FILE',
    'PHOENIX_BYOC_SECRETS_FILE', 'PHOENIX_BYOC_LOCAL_CHARTS',
    'PHOENIX_AGENTFS_CONTEXT', 'HELMFILE_CACHE_HOME', 'HELM_CACHE_HOME',
    'HELM_DATA_HOME', 'HELM_CONFIG_HOME', 'HELM_REPOSITORY_CACHE',
    'HELM_REPOSITORY_CONFIG', 'HELM_REGISTRY_CONFIG',
)
RETAINED = 'PHOENIX_AGENTFS_RETAINED_IMAGES_JSON'


class InputChanged(Exception):
    pass


class InputLimitExceeded(InputChanged):
    pass


def require(condition, error=InputChanged):
    if not condition:
        raise error()


def environment(repo):
    state = {name: os.environ.get(name) for name in ENVIRONMENT}
    # Bind symlink retargeting as well as the configured cache-root spelling.
    cache = os.environ.get('HELMFILE_CACHE_HOME') or '.tmp/helmfile-cache'
    state['resolved_helmfile_cache'] = str((repo / cache).resolve())
    return state


def collect(roots, confinement=None):
    """Read only declared input trees; never follow special files or unbound walks."""
    entries = {}
    total = 0

    def visit(path, depth=0):
        nonlocal total
        path = Path(os.path.abspath(path))
        key = str(path)
        if key in entries:
            return
        require(depth <= 32 and len(entries) < MAX_ENTRIES, InputLimitExceeded)
        resolved = str(path.resolve())
        if confinement is not None:
            require(Path(resolved).is_relative_to(confinement))
        if not path.exists():
            require(not path.is_symlink())
            entries[key] = (resolved, None)
            return
        mode = path.stat().st_mode
        if stat.S_ISDIR(mode):
            entries[key] = (resolved, None)
            for child in path.iterdir():
                visit(child, depth + 1)
        else:
            require(stat.S_ISREG(mode))
            require(path.stat().st_size <= MAX_FILE, InputLimitExceeded)
            with path.open('rb') as stream:
                data = stream.read(MAX_FILE + 1)
            total += len(data)
            require(len(data) <= MAX_FILE and total <= MAX_TOTAL, InputLimitExceeded)
            entries[key] = (resolved, data)
    for root in roots:
        visit(root)
    return entries


def source_roots(repo):
    roots = [repo / name for name in (
        'release.yaml', 'defaults/values.yaml', 'helmfile.yaml.gotmpl',
        'contracts', 'charts', 'values',
    )]
    roots.extend(Path(os.environ[name]) for name in (
        'PHOENIX_BYOC_VALUES_FILE', 'PHOENIX_BYOC_SECRETS_FILE',
    ))
    local = os.environ.get('PHOENIX_BYOC_LOCAL_CHARTS')
    if local:
        # Helmfile executes from the repository, including for relative roots.
        local_root = repo / local
        roots.extend(local_root / name for name in LOCAL_CHARTS)
    return roots


def cache_inputs(repo):
    # Explicit external cache directories are NOT enumerated. No auth/config
    # homes are read, even when their paths are present in the bound environment.
    cache = repo / '.tmp/helmfile-cache'
    configured = Path(os.environ.get('HELMFILE_CACHE_HOME') or cache)
    if not configured.is_absolute():
        configured = repo / configured
    if configured.resolve() != cache.resolve() or not cache.exists():
        return {}
    require(not cache.is_symlink() and not cache.parent.is_symlink())
    roots = []
    pending = [cache]
    visited = 0
    while pending:
        directory = pending.pop()
        children = []
        for child in directory.iterdir():
            visited += 1
            require(visited <= MAX_ENTRIES, InputLimitExceeded)
            require(not child.is_symlink())
            children.append(child)
        if any(child.name == 'Chart.yaml' and child.is_file() for child in children):
            roots.append(directory)
        else:
            pending.extend(child for child in children if child.is_dir())
    return collect(roots, confinement=cache.resolve())


def write_snapshot(folder, name, entries):
    destination = folder / name
    destination.mkdir(mode=0o700)
    index = {}
    for number, (path, (resolved, data)) in enumerate(entries.items()):
        filename = str(number) if data is not None else None
        if filename is not None:
            (destination / filename).write_bytes(data)
        index[path] = [resolved, filename]
    (destination / 'index.json').write_text(json.dumps(index))


def read_snapshot(folder, name):
    destination = folder / name
    index = json.loads((destination / 'index.json').read_text())
    return {path: (resolved, (destination / filename).read_bytes()
                   if filename is not None else None)
            for path, (resolved, filename) in index.items()}


def main():
    os.umask(0o077)
    action, folder_arg, repo_arg = sys.argv[1:]
    folder = Path(folder_arg)
    repo = Path(repo_arg)
    require(folder.is_dir() and not folder.is_symlink())
    sources = collect(source_roots(repo))
    cache = cache_inputs(repo)
    if action == 'capture':
        write_snapshot(folder, 'sources', sources)
        write_snapshot(folder, 'cache-before', cache)
        (folder / 'environment.json').write_text(json.dumps(environment(repo)))
        return
    require(environment(repo) == json.loads((folder / 'environment.json').read_text()))
    require(sources == read_snapshot(folder, 'sources'))
    if action in ('retained', 'seal'):
        before = read_snapshot(folder, 'cache-before')
        require(all(cache.get(path) == entry for path, entry in before.items()))
        if action == 'retained':
            (folder / 'retained.json').write_text(json.dumps(os.environ.get(RETAINED)))
        else:
            require(os.environ.get(RETAINED) == json.loads((folder / 'retained.json').read_text()))
            write_snapshot(folder, 'cache-after', cache)
            write_snapshot(folder, 'rendered', collect([repo / '.rendered/all.yaml']))
            require((repo / '.rendered/all.yaml').is_file())
    elif action == 'check':
        require(os.environ.get(RETAINED) == json.loads((folder / 'retained.json').read_text()))
        require(cache == read_snapshot(folder, 'cache-after'))
        require(collect([repo / '.rendered/all.yaml']) == read_snapshot(folder, 'rendered'))
    else:
        raise InputChanged()


if __name__ == '__main__':
    try:
        main()
    except InputLimitExceeded:
        print('ERROR: install_inputs_limit_exceeded; reduce selected inputs or installer-owned cache before rerunning.',
              file=sys.stderr)
        sys.exit(1)
    except (OSError, ValueError, KeyError, RuntimeError, InputChanged):
        # No paths, parser diagnostics, secret bytes or secret-derived hashes.
        print('ERROR: install_inputs_changed_or_unavailable; rerun validation and render.', file=sys.stderr)
        sys.exit(1)
