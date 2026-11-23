# Upgrade from Phoenix BYOC 0.2.6 to 0.2.7

This release updates all four application service groups from Preview and moves
the Agents runtime to Pi. It uses Web chart 0.2.7 and Engine chart 0.2.9. Existing
PostgreSQL, Valkey, Cortex, ClickHouse and storage remain in place.

## Before updating

Use published 0.2.6 as the starting point. Let active workflows and pending agent
or repository publications finish, and pause new starts and definition-seeding
jobs until the installer finishes. Keep existing `values.yaml`,
`values.secrets.yaml`, namespace, PVCs, GCP VM-pool settings and Workload Identity
bindings. Do not replace configuration with the examples.

An optional backup of databases, artifacts/snapshots and configuration provides
an additional recovery point. This installer does not take backups.

History cleanup remains disabled by default through
`services.workflowEngine.runRetention.enabled: false`. Keep it disabled until
there is a separate retention decision. The obsolete
`services.opensandbox.agentSandboxIdleTTL` setting is ignored and may be removed;
removing it does not enable cleanup.

## Review existing configuration

### Archive file limit

The new default is 200000 files, matching the updated multi-stage workflow
configuration. An explicit value in the customer's file still takes precedence.
If the file contains the old `outputArchiveMaxFiles: "1000"`, change that entry
(or remove it to inherit the new default) before using Maestro workflows that
produce more than 1000 files:

```yaml
services:
  opensandbox:
    outputArchiveMaxFiles: "200000"
```

Merge this setting into the existing `services` section; do not replace the
section. The byte limits are unchanged. Keep an intentionally lower custom
limit if required by your deployment, understanding that larger outputs fail.

### Models and provider credentials

Keep the existing Vertex project, region, ServiceAccount and Workload Identity
configuration. Pi supports the existing Vertex credential path and the existing
Anthropic API/OAuth credential fields. No new secret is required for those routes.

Web now exposes a deployment model catalog. When `models` is unset, the shipped
catalog selects Vertex IDs if `vertex.enabled=true`, otherwise Anthropic IDs.
Check that those model IDs are enabled for your account. To keep a particular
set of provider-approved models, set the top-level `models` list using the exact
IDs documented in [configuration.md](docs/configuration.md#allowed-models).
Do not rely on `vertex.models.*`: those old Claude CLI options are ignored by Pi.
Already sealed agent versions retain their model IDs.

`secrets.agents.llmEnv` is optional and defaults to an empty map. It is only
needed when configuring an additional provider or LLM gateway. Values must be
quoted strings; put credentials in the secrets file, never in `values.yaml`.
Existing custom agent bundles must satisfy the new runtime's numeric
`schema_version: 1` manifest/output-contract format and portable asset layout.
Do not silently rewrite or delete a customer's custom bundle to make it pass.

## Select and apply the release

From the existing BYOC checkout:

```bash
git fetch origin --tags
git checkout v0.2.7
kubectl config current-context
```

Preserve and resolve any local tracked changes before continuing; do not force
checkout. Confirm the context is the intended customer cluster.
Alternatively, download the archive and checksum from the
[published release](https://github.com/canonix-engineering/phoenix-byoc/releases/tag/v0.2.7),
verify them and extract into a new directory:

```bash
sha256sum -c phoenix-byoc-0.2.7.tar.gz.sha256
tar -xzf phoenix-byoc-0.2.7.tar.gz
cd phoenix-byoc-0.2.7
sha256sum -c SHA256SUMS
```

Use the existing customer configuration paths. For the bundled topology and
namespace `phoenix`:

```bash
./scripts/install.sh \
  --namespace phoenix \
  --values ./values.yaml \
  --secrets ./values.secrets.yaml \
  --generate-secrets
```

Existing populated credentials are preserved; missing new internal fields are
synchronized. External dependency deployments retain their existing explicit
secret contract and must not enable bundled services just to use this flag.
Valkey is unchanged; do not use `--discard-redis-state`.

The existing hooks apply the 15 incoming Web migrations before the Engine
migration, which also reconciles shipped default workflow definitions. Customer
edits are preserved by the service-owned seeding rules; higher shipped versions
may become the default ahead of older app overrides. Deployments with database
hooks disabled must apply the service-owned migrations in that order before
updating Engine. Concurrent index creation may extend the installation time.

Wait for a successful installer exit and verification before starting work.
Standalone verification uses the same inputs:

```bash
./scripts/verify.sh \
  --namespace phoenix \
  --values ./values.yaml \
  --secrets ./values.secrets.yaml
```

Sign in with an existing account, check the offered model list and run a new
workflow using an available model. If a migration fails, stop and report its
name and sanitized error; do not reset catalog markers or delete definitions.

## Retained work and recovery

New AgentFS sessions have a new storage-layout marker. Retained old sessions
must keep their original Agent image; there is no automatic database-layout
conversion on upgrade or rollback. The installer preserves the retained-image
permissions. Do not force the new image onto an old session.

Finish old-format repository publications before upgrading. A retry under the
new publisher can create a separate `canonix/` branch rather than reuse the old
`phoenix/` branch.

Do not run database down-migrations or the old installer as a generic rollback.
The new canonical agent-publication migration explicitly refuses rollback once
publishing/canonical publication data exists. Old images cannot undo new sealed
publication records. Coordinate recovery using the exact migration state and,
when needed, the pre-upgrade backup. History deletion remains disabled.
