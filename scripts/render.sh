#!/usr/bin/env bash
set -euo pipefail
umask 077

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." 2>/dev/null && pwd) || {
  echo 'ERROR: render_source_unavailable' >&2
  exit 1
}
render_dir="$repo_root/.rendered"
output="$render_dir/all.yaml"
cache_dir="${HELMFILE_CACHE_HOME:-$repo_root/.tmp/helmfile-cache}"
staging=""

fail() {
  echo "ERROR: $1" >&2
  exit 1
}

cleanup() {
  if [[ -n "$staging" && -d "$staging" && ! -L "$staging" ]]; then
    rm -f -- "$staging/all.yaml" "$staging/helmfile.log" "$staging/kubeconform.log" 2>/dev/null || :
    rmdir -- "$staging" 2>/dev/null || :
  fi
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

# Do not follow a linked output directory or replace a linked/special manifest.
if [[ -L "$render_dir" || ( -e "$render_dir" && ! -d "$render_dir" ) ]]; then
  fail render_output_unavailable
fi
if [[ ! -d "$render_dir" ]]; then
  mkdir -m 700 -- "$render_dir" 2>/dev/null || fail render_output_unavailable
fi
chmod 700 "$render_dir" 2>/dev/null || fail render_output_unavailable
if [[ -L "$output" || ( -e "$output" && ! -f "$output" ) ]]; then
  fail render_output_unavailable
fi
# Invalidate an older successful manifest before any new attempt can fail.
rm -f -- "$output" 2>/dev/null || fail render_output_unavailable
mkdir -p -- "$cache_dir" 2>/dev/null || fail render_cache_unavailable
staging=$(mktemp -d "$render_dir/.render.XXXXXXXX" 2>/dev/null) || fail render_output_unavailable
chmod 700 "$staging" 2>/dev/null || fail render_output_unavailable
if ! {
  : >"$staging/all.yaml" &&
    : >"$staging/helmfile.log" &&
    : >"$staging/kubeconform.log"
} 2>/dev/null; then
  fail render_output_unavailable
fi

# Standalone rendering has the same raw/final gate as preflight, but no GETs.
# Keep failures private and invalidate the prior output before running the gate.
values_file=${PHOENIX_BYOC_VALUES_FILE:-}
secrets_file=${PHOENIX_BYOC_SECRETS_FILE:-}
[[ -n "$values_file" && -n "$secrets_file" ]] || fail render_connection_gate_failed
[[ "$values_file" == /* ]] || values_file="$repo_root/$values_file"
[[ "$secrets_file" == /* ]] || secrets_file="$repo_root/$secrets_file"
if ! python3 "$repo_root/scripts/connection-config.py" gate-yaml \
    "$repo_root/release.yaml" "$repo_root/defaults/values.yaml" \
    "$values_file" "$secrets_file" >/dev/null 2>&1; then
  fail render_connection_gate_failed
fi

# Protect Bash's own redirection-open diagnostics as well as tool stderr.
if ! {
  (
    cd "$repo_root"
    HELMFILE_CACHE_HOME="$cache_dir" helmfile template --skip-deps --quiet
  ) >"$staging/all.yaml" 2>"$staging/helmfile.log"
} 2>/dev/null; then
  fail render_helmfile_failed
fi

if command -v kubeconform >/dev/null 2>&1; then
  if ! {
    kubeconform -kubernetes-version 1.32.0 -strict -summary \
      -ignore-missing-schemas "$staging/all.yaml" \
      >"$staging/kubeconform.log" 2>&1
  } 2>/dev/null; then
    fail render_kubeconform_failed
  fi
fi

mv -- "$staging/all.yaml" "$output" 2>/dev/null || fail render_publish_failed
# All diagnostic files remain private and are removed by the EXIT trap.
echo "Rendered manifests: $output"
