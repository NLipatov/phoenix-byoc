# Deploy-Time Model Catalog: phoenix-byoc Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A BYOC customer sets the allowed models in one top-level `models` value. The installer checks the shape of the list, and phoenix-web gets it through the `phoenix-web` chart.

**Architecture:** `models` passes to the chart value `web.models` (devops plan). A preflight script checks the shape. The customer is responsible for IDs that their provider accepts. A separate release plan pins the new chart and images and proves them with a smoke install.

**Tech Stack:** helmfile, yq, Python `unittest`, bash, GitHub Actions.

**Spec:** `phoenix-agents/docs/superpowers/specs/2026-11-18-deploy-model-catalog-design.md` (sections 6.4 and 6.7).

**Repo:** `~/Canonix/phoenix-byoc`. This plan is step 4 of the rollout. Tasks 1 and 2 can merge before the release. The release itself is `2026-11-18-deploy-model-catalog-byoc-release.md`. It needs a published `phoenix-web` chart `0.2.7` (devops plan), an agents image that accepts `route/id` models, and a web image with the web plan.

## Global Constraints

- Value: top-level `models`, a list of `{id, profile}`. Patterns: `id` `^[a-z0-9][a-z0-9_-]*/\S+$`, `profile` `^[a-z][a-z0-9_]{0,63}$`. Python uses `re.fullmatch`, so that a trailing newline fails. Each `id` and each `profile` is unique. The list has at least 1 model.
- Default (`defaults/values.yaml`): the `anthropic/...` list from the devops plan, Task 2 table, because `vertex.enabled` is `false` by default. A customer list replaces the default list (`yq *` replaces arrays).
- No check of routes against credentials. The customer who sets `models` is responsible for IDs that their provider accepts.
- The check reads JSON on stdin, as `scripts/eval-config.py` does. It never prints a secret value.
- An undated Vertex 4.5 ID (for example `claude-haiku-4-5`) cannot run on Vertex. The docs tell customers to use the dated ID (`claude-haiku-4-5@20251001`).
- Every new test runs in CI (`.github/workflows/compliance-tests.yml`).
- Conventional Commits.

## Review Focus

1. A customer `models` list replaces the default list. It does not add to it. Test: Task 1, step 1.
2. An error message names the bad entry by index and value. Test: Task 2, step 1.
3. `models: []` fails with a message that the list must have at least 1 model. Test: Task 2, step 1.
4. `task test` still passes: its generator test expects preflight to stop on the ECR credential, and the default list must pass the new check. Test: Task 2, step 4.
5. The release pins an agents image that accepts `route/id` models. A smoke install proves it. Test: `2026-11-18-deploy-model-catalog-byoc-release.md`, step 2.

---

### Task 1: Pass `models` to phoenix-web, and document it

**Files:**
- Modify: `defaults/values.yaml` (add `models:` with the default list and a comment)
- Modify: `examples/values.yaml` (add a Vertex example with `anthropic-vertex/...` IDs, beside the `vertex` block)
- Modify: `values/phoenix-web.yaml.gotmpl` (under `web:`, add `models: {{ toJson .Values.models }}`)
- Modify: `docs/configuration.md` (new section "Allowed models": shape, the customer's responsibility for IDs, the dated Vertex 4.5 IDs, what a change does, that sealed agent versions keep their model)
- Modify: `UPGRADE.md` (customers with `vertex.enabled: true` must set `models` with `anthropic-vertex/...` IDs)
- Modify: `docs/superpowers/specs/2026-11-16-native-provider-connections-spec.md:155` (state that `models` is a phoenix-web catalog, not a connection field, and does not go to the agents)
- Modify: `.github/workflows/compliance-tests.yml` (add `python3 -m unittest discover -s tests -p 'test_model_catalog.py' -v` after the yq install step)
- Test: `tests/test_model_catalog.py` (create)

**Interfaces:**
- Consumes: chart value `web.models` (devops plan, Task 1).

- [ ] **Step 1: Write the failing tests**

Follow `tests/test_evals.py` (skip when `yq` is not Mike Farah yq). Render the phoenix-web values with the helper that `test_evals.py` uses.
- `test_default_list_reaches_web`: the rendered `web.models` equals the default list.
- `test_customer_list_replaces_default`: a values file with 1 `anthropic-vertex/...` model gives a rendered `web.models` with exactly that 1 model.

- [ ] **Step 2: Run the tests and see them fail**

Run: `python3 -m unittest discover -s tests -p 'test_model_catalog.py' -v`
Expected: FAIL.

- [ ] **Step 3: Implement the value, the pass-through, the docs and the CI step**

- [ ] **Step 4: Run the tests and see them pass**

Run: `python3 -m unittest discover -s tests -p 'test_model_catalog.py' -v`, then `task test`.
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add defaults/values.yaml examples/values.yaml values/phoenix-web.yaml.gotmpl docs UPGRADE.md .github/workflows/compliance-tests.yml tests/test_model_catalog.py
git commit -m "feat(byoc): configure the allowed models for phoenix-web"
```

---

### Task 2: Check the shape of the list in preflight

**Files:**
- Create: `scripts/model-catalog.py` (subcommand `check`, JSON on stdin)
- Modify: `scripts/preflight.sh` (call it directly after the `eval-config.py check` call, in the same way)
- Test: `tests/test_model_catalog.py`

**Interfaces:**
- Produces: `python3 scripts/model-catalog.py check` reads the merged values as JSON on stdin. Exit 0 when valid. Otherwise exit 1 with one line on stderr for each error, in the form `models[<index>]: <reason>`, or `models: <reason>` for the whole list.

- [ ] **Step 1: Write the failing tests**

Import the script with `importlib`, as `test_evals.py` does with `eval-config.py`. Call its check function with a dict. Cases:
- The default list: valid.
- `models: []`: error `models: at least 1 model is required`.
- `models` missing: the same error.
- `id: Anthropic/x`: error `models[0]: invalid id Anthropic/x`.
- An `id` with a trailing newline: invalid.
- A duplicate `id` and a duplicate `profile`: one error each, with the index and the value.
- A missing `profile` and an extra key: one error each, with the index.

- [ ] **Step 2: Run the tests and see them fail**

Run: `python3 -m unittest discover -s tests -p 'test_model_catalog.py' -v`
Expected: FAIL.

- [ ] **Step 3: Implement `scripts/model-catalog.py` and the preflight call**

- [ ] **Step 4: Run the tests and see them pass**

Run: `python3 -m unittest discover -s tests -p 'test_model_catalog.py' -v`, then `task test`.
Expected: PASS. The generator test in `scripts/test.sh` still sees the `secrets.registry.ecr.accessKeyId` failure, because the default list passes the new check.

- [ ] **Step 5: Commit**

```bash
git add scripts/model-catalog.py scripts/preflight.sh tests/test_model_catalog.py
git commit -m "feat(byoc): check the allowed models before install"
```
