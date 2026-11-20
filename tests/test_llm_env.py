import base64
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
CHARTS = os.environ.get("PHOENIX_BYOC_LOCAL_CHARTS", str(ROOT.parent / "phoenix-devops" / "charts"))
REQUIRED_IN_CI = bool(os.environ.get("CI"))
# helmfile runs `helm version` before it renders anything.
TOOLS = all(shutil.which(tool) for tool in ("yq", "helmfile", "helm"))
# `helmfile template` needs the DevOps chart. The CI job checks out only BYOC.
ENGINE_CHART = Path(CHARTS, "phoenix-workflow-engine").is_dir()

# Values that a careless `toYaml | nindent` would change: a multi-line string
# with `$` and `@`, and a quoted number.
STRESS_ENV = {
    "LLM_GATEWAY_HEADERS": "x-portkey-api-key: $LLM_GATEWAY_API_KEY\nx-portkey-provider: @bedrock-prod",
    "AWS_MAX_ATTEMPTS": "1",
}
STRESS_EXPECTED = {"LLM_GATEWAY_API": "anthropic-messages", **STRESS_ENV}


class LlmEnvCheckTests(unittest.TestCase):
    def test_tools_present_in_ci(self):
        if REQUIRED_IN_CI:
            self.assertTrue(TOOLS, "CI must provide yq, helmfile and helm; refusing to skip silently")

    def test_gateway_model_id_passes_model_check(self):
        spec = importlib.util.spec_from_file_location("model_catalog", ROOT / "scripts/model-catalog.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        doc = {"models": [{"id": "gateway/@bedrock-prod/us.anthropic.claude-sonnet-5-v1:0", "profile": "standard"}]}
        self.assertEqual(mod.check(doc), [])


@unittest.skipUnless(TOOLS, "requires Mike Farah yq, helmfile and helm")
class LlmEnvRenderTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)

    def secrets_copy(self, fixture, yq_edit=None):
        secrets = self.directory / "values.secrets.yaml"
        secrets.write_text((ROOT / "tests/fixtures" / fixture).read_text())
        if yq_edit:
            subprocess.run(["yq", "-i", yq_edit, str(secrets)], check=True)
        return secrets

    def env(self, values_fixture, secrets):
        values = self.directory / "values.yaml"
        values.write_text((ROOT / "tests/fixtures" / values_fixture).read_text())
        return dict(os.environ, PHOENIX_BYOC_LOCAL_CHARTS=CHARTS,
                    PHOENIX_BYOC_VALUES_FILE=str(values), PHOENIX_BYOC_SECRETS_FILE=str(secrets),
                    PHOENIX_BYOC_NAMESPACE="phoenix-llm-env-test",
                    HELMFILE_CACHE_HOME=os.environ.get("HELMFILE_CACHE_HOME", str(ROOT / ".tmp/helmfile-cache")))

    def secrets_with_raw_entries(self, lines):
        """The fixture with `lines` (raw YAML, so unquoted scalars keep their YAML type) in llmEnv."""
        secrets = self.directory / "values.secrets.yaml"
        text = (ROOT / "tests/fixtures/values.secrets.yaml").read_text()
        entries = "".join(f"      {line}\n" for line in lines)
        secrets.write_text(text.replace("    llmEnv:\n", f"    llmEnv:\n{entries}", 1))
        return secrets

    def run_helmfile(self, args, values_fixture, secrets):
        return subprocess.run(["helmfile", "--selector", "name=phoenix-workflow-engine", *args],
                              cwd=ROOT, env=self.env(values_fixture, secrets), capture_output=True, text=True)

    def helmfile(self, args, values_fixture, secrets):
        result = self.run_helmfile(args, values_fixture, secrets)
        self.assertEqual(result.returncode, 0, f"helmfile {args[0]} failed:\n{result.stderr}")
        return result.stdout

    def write_values_args(self):
        return ["write-values", "--skip-deps",
                "--output-file-template", str(self.directory / "{{ .Release.Name }}.yaml")]

    def render_llm_env(self, secrets, values_fixture="values.yaml"):
        self.helmfile(self.write_values_args(), values_fixture, secrets)
        rendered = subprocess.check_output(
            ["yq", "-o=json", ".agentSecrets.llmEnv", str(self.directory / "phoenix-workflow-engine.yaml")],
            text=True)
        return json.loads(rendered)

    def render_engine_secret(self, secrets, values_fixture="values.yaml"):
        manifests = self.helmfile(["template", "--skip-deps", "--quiet"], values_fixture, secrets)
        path = self.directory / "engine.yaml"
        path.write_text(manifests)
        data = subprocess.check_output(
            ["yq", "-o=json", 'select(.kind == "Secret" and .data.PHOENIX_AGENT_HARNESS_TOKEN != null) | .data',
             str(path)], text=True)
        return {name: base64.b64decode(value).decode() for name, value in json.loads(data).items()}

    def test_default_renders_empty_map(self):
        secrets = self.secrets_copy("values.secrets.yaml", "del(.secrets.agents.llmEnv)")
        self.assertEqual(self.render_llm_env(secrets), {})

    def stress_secrets(self):
        return self.secrets_copy("values.secrets.yaml", f".secrets.agents.llmEnv += {json.dumps(STRESS_ENV)}")

    def test_entries_pass_through_unchanged(self):
        self.assertEqual(self.render_llm_env(self.stress_secrets()), STRESS_EXPECTED)

    def test_unquoted_non_string_values_fail_naming_the_key(self):
        cases = {
            "AZURE_OPENAI_API_VERSION": "2024-10-21",
            "AWS_MAX_ATTEMPTS": "31337",
            "SENTINEL_FLAG": "true",
            "SENTINEL_EMPTY": "",
        }
        for name, raw in cases.items():
            with self.subTest(name=name):
                secrets = self.secrets_with_raw_entries([f"{name}: {raw}"])
                tag = subprocess.check_output(["yq", f".secrets.agents.llmEnv.{name} | tag", str(secrets)],
                                              text=True).strip()
                self.assertNotEqual(tag, "!!str", f"fixture must hold an unquoted {name}")
                result = self.run_helmfile(self.write_values_args(), "values.yaml", secrets)
                self.assertNotEqual(result.returncode, 0, f"{name}: {raw} was accepted")
                self.assertIn(f"secrets.agents.llmEnv.{name}", result.stderr)
                self.assertIn("quote", result.stderr)
                if raw:
                    self.assertNotIn(raw, result.stderr)
                self.assertNotIn("2024-10-21T00:00:00Z", result.stderr)

    def test_quoted_values_pass_unchanged(self):
        quoted = {"AZURE_OPENAI_API_VERSION": "2024-10-21", "AWS_MAX_ATTEMPTS": "1", "SENTINEL_FLAG": "true"}
        secrets = self.secrets_with_raw_entries([f'{name}: "{value}"' for name, value in quoted.items()])
        self.assertEqual(self.render_llm_env(secrets), {"LLM_GATEWAY_API": "anthropic-messages", **quoted})

    def test_entries_reach_the_engine_secret(self):
        if not ENGINE_CHART:
            self.skipTest(f"needs the DevOps phoenix-workflow-engine chart in {CHARTS}; "
                          "set PHOENIX_BYOC_LOCAL_CHARTS")
        chart_values = Path(CHARTS, "phoenix-workflow-engine", "values.yaml")
        supported = subprocess.run(["yq", "-e", '.agentSecrets | has("llmEnv")', str(chart_values)],
                                   capture_output=True, text=True)
        if supported.returncode != 0:
            self.skipTest(f"the DevOps chart {chart_values.parent} has no agentSecrets.llmEnv "
                          "(it predates llmEnv); point PHOENIX_BYOC_LOCAL_CHARTS at a chart that has it")
        secret = self.render_engine_secret(self.stress_secrets())
        for name, value in STRESS_EXPECTED.items():
            key = f"PHOENIX_LLM_ENV__{name}"
            self.assertIn(key, secret, f"the engine Secret from {chart_values.parent} has no {key}")
            self.assertEqual(secret[key], value)

    def test_external_secrets_mode_passes_through(self):
        secrets = self.secrets_copy("values.secrets-external.yaml")
        self.assertEqual(self.render_llm_env(secrets, "values-external.yaml"), {"AWS_REGION": "us-east-1"})


if __name__ == "__main__":
    unittest.main()
