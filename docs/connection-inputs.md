# Agent connection inputs

## Status and boundary

This guide describes unreleased **feature-branch** authoring, preflight/render
and changed-input protections. This document is not evidence that an
installation succeeded.

The shipped release is **0.2.6**, channel `stable`, source environment `preview`.
It has **no verified enabled-delivery authority**. On this feature branch,
preflight and standalone render reject **all enabled new delivery**, including
generic-only, secret-only and enabled empty inputs. Valid absent or disabled
legacy paths remain usable. There is no customer override, capability allowlist
or compatibility manifest that makes these examples installable.

The [canonical capabilities](../contracts/llm-connections/v1/capabilities.json)
contain **all 27 rows blocked**, with no live acceptance. Source implementation
and offline tests do not promote them. The unconditional Workflow Engine chart
floor remains **0.2.8**, including when delivery is off; an unpublished **0.2.9**
fixture is not release acceptance. Do not change `release.yaml` to enable this.
A future rollout needs the chart templates, a compatible Engine reader/lifecycle
image and compatible Agents—not merely a version-shaped value. The operator uses
`Recreate` and projected Secrets use `optional: false`: a missing Secret or key can
stop **all workflow execution** while the replacement pod waits. Provision and
authorize the required Secrets before any separately approved rollout.

## Authoring checks, not installation approval

The existing `scripts/connection-config.py` interface
`check-yaml RELEASE DEFAULTS VALUES SECRETS` is **authoring-only**. Supply the
repository `release.yaml`, `defaults/values.yaml` and the same selected local
values/secrets files, in that order. It uses existing **Helm 3.18.6**, **yq
4.49.2** and **Python 3.9+ standard library**; no additional customer packages,
provider login, credentials discovery or network calls are required for this
check. Success has empty output and is not installation approval. The JSON
`check` and `references` interfaces also do not authorize installation.

The adapter checks raw explicit blocks and duplicate keys before normalization
can hide them, then checks the effective merged authoring. An explicit malformed
`llm` or `agentInputDelivery` block (empty, null or wrong type) cannot be repaired
by a later layer. Partial nonempty maps overlay in release → defaults → values
→ secrets order; final references, types and collisions must still validate.
Unsupported aliases, merge keys and tags affecting these blocks reject rather
than silently losing authoring data. This does not ban unrelated legacy YAML.
The raw adapter ignores genuinely empty/null documents (including a trailing
separator), but not an explicit null protected block. Selected `.gotmpl` values
or secrets paths are rejected before generation or rendering: raw YAML cannot
validate configuration that Helmfile will subsequently template. Glob/escape
syntax (`*`, `?`, `[`, or backslash) in selected paths also rejects: Helmfile can
expand a readable literal filename to a different file. Use literal plain-YAML
paths. Selected symlinks may point to bounded regular files; the installer still binds
the selected path, resolved target and exact bytes and aborts on retargeting.

Omit `llm` completely when unused; `llm: {}` is not an off switch.
`CONFIG_VERSION` is the string `"1"`, `enabled` is a boolean, env values are
strings, and `HEADERS_JSON` / `NATIVE_ENV_REFS_JSON` are typed objects, not
JSON-encoded strings. Disabled delivery cannot carry `llm` or nonempty input
maps. Unknown model/discovery/login/refresh fields reject. Named-v1 OAuth and
subscription authentication are not supported; existing explicit legacy OAuth
credentials are unchanged.

Use the [owner authoring contract](../contracts/llm-connections/v1/README.md)
and its [canonical examples](../contracts/llm-connections/v1/semantic-vectors.json),
not a second schema. Generic `PHOENIX_LLM_*` entries cannot bypass typed `llm`
authoring. API keys must reference `llm.secretEnv`; they cannot come from plain
values, ambient environment or a platform declaration. Each destination must be
unique across derived/plain/secret/platform sources, even when values are equal.
URLs require HTTPS without userinfo, query or fragment; protected authentication
headers and command/interpolation forms reject. Native-specific fixed endpoints
cannot be replaced with arbitrary URLs.

Plain native and header references resolve from the immutable declared union of
`agentInputDelivery.env` and `llm.env`; header secrets may also come from either
secret map. Platform references still require `llm.platformEnv`. Header-only and
unused platform declarations are valid authoring. Generated transport keys never
become sources, and API keys remain `llm.secretEnv`-only. Collisions are rejected
before combining sources. Outer and nested JSON byte limits use the same compact,
key-sorted UTF-8 Go/Helm encoding, including HTML and U+2028/U+2029 escapes; literal
backslash-u text and delivered secret bytes are preserved.

## Non-installable authoring examples

These are independent, synthetic **authoring examples only**, not installation
inputs or capability claims. Each passes the existing authoring helper; the
named example fails the shipped capability predicate. Generic predicate
`not-applicable` means no named connection to check, **not** generic admission.
All enabled examples remain blocked by the feature-branch installation/render gate.
The example UUID is a fixture, not a customer enterprise identity. No Secret is
created and no credential is supplied by these snippets.

### Generic plain and selected Secret input

<!-- example: generic -->
```yaml
agentInputDelivery:
  enabled: true
  allowedEnterpriseIds: ["00000000-0000-4000-8000-000000000001"]
  env:
    EXAMPLE_PLAIN: "non-secret value"
  secretEnv:
    EXAMPLE_TOKEN:
      name: existing-agent-secret
      key: token
```

### Secret-only input

No `llm` or plain env is required for this authoring shape.

<!-- example: secret-only -->
```yaml
agentInputDelivery:
  enabled: true
  allowedEnterpriseIds: ["00000000-0000-4000-8000-000000000001"]
  secretEnv:
    EXAMPLE_TOKEN:
      name: existing-agent-secret
      key: token
```

### Shared Portkey connection

The endpoint and config ID below are non-secret fixtures. The actual API key is
only a selected Secret reference; do not add an inline authentication header.
`portkey_internal` selects a connection, not a model catalog or a provider router.

<!-- example: portkey -->
```yaml
agentInputDelivery:
  enabled: true
  allowedEnterpriseIds: ["00000000-0000-4000-8000-000000000001"]
llm:
  CONFIG_VERSION: "1"
  connections:
    portkey_internal:
      PLATFORM: portkey
      PUBLISHER: anthropic
      AUTH_MODE: api-key
      API: openai-completions
      BASE_URL: https://gateway.example.invalid/v1
      API_KEY_ENV: PORTKEY_API_KEY
      HEADERS_JSON:
        x-portkey-config: $PORTKEY_CONFIG_ID
  env:
    PORTKEY_CONFIG_ID: "example-config"
  secretEnv:
    PORTKEY_API_KEY:
      name: existing-portkey-secret
      key: api-key
```

Existing host **profiles** and **modelIds** still supply model selection and
trusted catalog/target metadata. Neither is a new BYOC field. **Pi 1.4.0** owns
the native catalog, serialization, dispatch, streaming, tools, usage and
supported authentication. Engine transports generic inputs; it does not
interpret providers or models. Helm never calls provider/model APIs. Native
source tests, capability records and separately authorized live acceptance are
different evidence; no live inference is established by these examples.

## Enterprise and workload identity

`allowedEnterpriseIds` uses the existing installation allowlist: 1–128 unique
canonical lowercase UUIDs when enabled, no wildcard or default-to-all. Admission
uses the existing trusted, persisted `ExecutionEnterpriseID` and assignment
path, not a new identity claim or an env-supplied tenant. A first installation
stays off; create the real Enterprise through the existing, separately approved
[administrator procedure](installation.md#create-the-initial-administrator).
Only a future supported release could enable delivery for its real enterprise
UUID. Do not substitute `application.tenantId` or invent a customer ID.

The selected inputs are scoped to the installation namespace/operator pool;
this is **not cross-tenant isolation**. The source transport targets Linux
OpenSandbox agents, not Windows, external-host or lab targets; none is enabled
by this release. Reusing one Secret key for distinct explicit destinations does
not isolate accounts. Agent bundle PIN validation,
scope/hash checks, resume/retry replay and conflict rejection remain unchanged.
A container image is **not an agent bundle PIN**. No new container-image
allowlist, image identity persistence or attestation framework is introduced.
Existing release image pinning and AgentFS retained-image requirements remain.

`llm.platformEnv` declares a source; it cannot prove sandbox injection or grant
cloud permissions. Operator GCP VM identity is not sandbox Vertex identity.
Named workload routes, AWS/Azure projection and Azure **Entra** refresh/audience
handling remain unproven; an ARM token is not inference audience evidence.
There is no developer ADC, static AWS profile, token-copy or cloud-discovery
workaround here. Do not infer support from a schema enum or a KSA annotation.
Preserve the existing [legacy Vertex setup](configuration.md#claude-code-through-google-vertex-ai)
and its [prerequisites](prerequisites.md#optional-google-vertex-ai-prerequisites).
Existing `secrets.agents.*` → chart `agentSecrets` delivery remains separate;
this guide neither replaces those credentials nor changes legacy `vertex` rules.

## Secret checks, runtime bytes and rotation

The existing named Secret/key checker is a bounded **key-presence** check, not
a positive enabled-install path in this release. It performs one named GET per
selected Secret in the chosen namespace/context, using a fixed key-output
template; no list-all, creation, value decoding or fallback identity. Denied GET
or missing object/key fails. Kubernetes still returns the Secret object to
kubectl internally: this is **not secret-free API authorization**. Granting GET
permits object access, not just key access. Referenced Secrets must already
exist; provider keys are external and **never generated** by the installer.

A present empty key passes existence checking. Engine/Agent must validate actual
nonblank UTF-8 secret bytes, NUL, per-file/aggregate bounds, header content,
readability, target authorization and identity at use time. Authoring bounds
cover the final generated/plain union (256 plain destinations, 128 secret
destinations, 64 KiB serialized `env.json`); unknown Secret bytes are not read or
estimated. The transport bounds are 64 KiB per selected file and 1 MiB total.
New/legacy explicit destination overlap fails at runtime even if equal; new
inputs do not silently replace existing credentials.

The source transport contract specifies one pinned projected generation and a
fresh snapshot **per delivery**. A newly delivered agent can receive a rotated
Secret after projection refresh; an already-running agent keeps its delivered
snapshot, not a live credential update. Do not promise immediate propagation or
rotate keys to repair admission. Legacy checksum/envFrom behavior is unchanged;
new delivery is not a secret-content checksum rollout mechanism. These are
source-contract semantics, not proof that release 0.2.6 delivers the feature.

## Rendering, changed inputs and privacy

On this feature branch, preflight validates raw/final local authoring before
cluster resource reads; standalone rendering applies the same local gate
without a Secret GET. Full rendering must finish before any cluster
mutation, including cache cutover. The installer automatically detects changes
to selected/local inputs and aborts rather than applying unchecked edits. The
operator must rerun validation and rendering; the installer does not
revalidate automatically. It uses **private snapshots** and comparisons, binds
selected values/secrets, release/defaults/contracts, relevant local
charts/templates and configured
roots/environment, and cleans private state on exit/signals. No public guard
protocol or bypass command is needed. A byte-identical cache rewrite is not an
input change; changed or new sealed chart inputs still abort even after sync,
preventing later unchecked mutations. `install_inputs_limit_exceeded` means the
selected inputs or installer-owned cache must be reduced before rerunning;
repeating the same oversized input does not repair the failure.

Gate diagnostics expose only allowlisted error codes and fixed authoring paths
(for example `yaml_tool_version: /` or `yaml_duplicate_authoring_key:
/agentInputDelivery`). Unknown interpreter/import/tool output remains suppressed
behind `connection_gate_failed`; renderer logs are not made public. The exact
yq 4.49.2 prerequisite applies to the local gate even when delivery is absent.
Normal exit and catchable signals clean private snapshots; SIGKILL or machine
failure can leave private plaintext residue in the installer's temporary
storage. Protect that storage and remove abandoned installer-owned temporary
directories through the operator's local recovery procedure.

External cache roots are bound, but arbitrary external cache contents and
**remote artifacts are not attested**. Normal render cache population is not
itself an unauthorized source edit. These checks do not promise race-proof
same-UID confinement or replace existing immutable release selection.

Keep selected secrets, snapshots, rendered manifests and raw tool logs private.
Private directories use mode `0700`, files `0600`; successful complete rendering
publishes `.rendered/all.yaml` atomically, while failures invalidate stale output
and clean staging. The manifest contains Secrets; do not attach it or raw logs
to public evidence. Safe diagnostics and redaction are defense in depth, not
complete confidentiality against short secrets, transformations or same-UID
access. Runtime/publication checks must keep secret-bearing **canonical output**
from publication without rewriting accepted bytes, receipts or bundle PINs;
clean canonical bytes must remain exact. Diagnostic masking does not rewrite
native provider frames or accepted results. Do not treat it as permission to
persist secrets, proof that all canonical data is secret-free, or proof that
arbitrary encodings are covered.

## Safe disable and rollback

1. **Pause admission** and workflow starts; drain active work or explicitly
   handle incompatible named sessions and resume requirements before downgrade.
2. In every selected overlay that supplies it, remove `llm`, empty the generic
   maps and disable delivery. An empty overlay map does not erase entries from
   an earlier layer: remove those entries at their source too. Inspect the final
   merged authoring; the following is the intended disabled state.

<!-- example: disabled -->
```yaml
agentInputDelivery:
  enabled: false
  allowedEnterpriseIds: []
  env: {}
  secretEnv: {}
```

3. Revalidate and render the same inputs before an explicitly authorized apply.
   Keep valid legacy credentials/profiles and AgentFS **retained images**. Do not
   silently fall back to legacy routing while new delivery remains enabled.
4. Follow [rollback guidance](rollback.md), including **Web-before-Engine**
   downgrade coordination, and the existing [upgrade procedure](../UPGRADE.md)
   and [AgentFS cautions](agentfs.md). Verify afterward with the existing
   verification procedure; no success is claimed here.

Off mode preserves the legacy compatibility path for supported old/new
chart/binary combinations; it does not waive the chart floor or other existing
compatibility checks. Enabled delivery with old/unknown support rejects.
Disabling does not undo retention deletion or authorize database down-migrations.
Do not delete PVCs, namespaces, CRDs or databases, alter IAM, or perform secret
rotation to “fix” rollback. Database recovery remains the customer's procedure.
