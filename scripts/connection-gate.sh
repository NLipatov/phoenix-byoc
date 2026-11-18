#!/usr/bin/env bash
# Shared raw gate. Only fixed codes/paths may cross the subprocess boundary.
connection_gate() (
  set -o pipefail
  local root=$1 diagnostic code location line
  shift
  # Ignore stdout; retain at most one bounded stderr line. Interpreter/import
  # failures and arbitrary child diagnostics are never forwarded verbatim.
  if diagnostic=$(
    python3 -I -B -c '
import runpy, sys
from pathlib import Path
script = sys.argv.pop(1)
sys.path.insert(0, str(Path(script).resolve().parent))
runpy.run_path(script, run_name="__main__")
' "$root/scripts/connection-config.py" gate-yaml "$@" 2>&1 >/dev/null |
      { IFS= read -r -n 256 line || :; printf '%s' "$line"; }
  ); then
    return 0
  fi
  code=${diagnostic%%: *}
  location=${diagnostic#*: }
  case "$code" in
    yaml_template_unsupported|yaml_path_pattern_unsupported|yaml_tool_unavailable|yaml_tool_version|yaml_parse_invalid|\
    yaml_duplicate_authoring_key|yaml_representation_unsupported|yaml_process_limit|\
    yaml_input_invalid|yaml_io_unavailable|input_size_limit|\
    connection_validation_unavailable|connection_schema_invalid|connection_contract_invalid|\
    connection_capability_unsupported|connection_release_unsupported|llm_authoring_required|\
    destination_collision|source_required|secret_reference_required|invalid_authoring|\
    header_case_duplicate|header_invalid|env_count_limit|secret_count_limit|env_size_limit)
      case "$location" in
        /|/llm|/agentInputDelivery|/agentInputDelivery/env|/agentInputDelivery/secretEnv|\
        /llm/env|/llm/secretEnv|/llm/platformEnv|/llm/connections|\
        /llm/connections/API_KEY_ENV|/llm/connections/NATIVE_ENV_REFS_JSON|\
        /llm/connections/HEADERS_JSON|/llm/connections/BASE_URL)
          printf 'ERROR: %s: %s\n' "$code" "$location" >&2
          return 1
          ;;
      esac
      ;;
  esac
  echo 'ERROR: connection_gate_failed' >&2
  return 1
)
