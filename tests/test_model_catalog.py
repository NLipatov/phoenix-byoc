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
PREFLIGHT_TOOLS = TOOLS and bool(shutil.which("kubectl"))


def default_models():
    """The shipped default list, read from defaults/values.yaml (not a copy)."""
    return json.loads(subprocess.check_output(
        ["yq", "-o=json", ".models", str(ROOT / "defaults/values.yaml")], text=True))


def models(*entries):
    return {"models": list(entries)}


OK = {"id": "anthropic/claude-sonnet-5-5", "profile": "standard_latest"}


class ModelCatalogCheckTests(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location("model_catalog", ROOT / "scripts/model-catalog.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        self.check = mod.check

    def test_tools_present_in_ci(self):
        if REQUIRED_IN_CI:
            self.assertTrue(PREFLIGHT_TOOLS,
                            "CI must provide yq, helmfile, helm and kubectl; refusing to skip silently")

    @unittest.skipUnless(shutil.which("yq"), "requires Mike Farah yq")
    def test_defaults_file_is_valid(self):
        doc = json.loads(subprocess.check_output(
            ["yq", "-o=json", ".", str(ROOT / "defaults/values.yaml")], text=True))
        self.assertEqual(self.check(doc), [])

    def test_empty_and_missing_list(self):
        want = ["models: at least 1 model is required"]
        self.assertEqual(self.check(models()), want)
        self.assertEqual(self.check({}), want)

    def test_invalid_id(self):
        self.assertEqual(self.check(models({"id": "Anthropic/x", "profile": "fast"})),
                         ["models[0]: invalid id Anthropic/x"])

    def test_trailing_newline_is_invalid(self):
        self.assertEqual(self.check(models({"id": "anthropic/x\n", "profile": "fast"})),
                         ['models[0]: invalid id "anthropic/x\\n"'])
        self.assertEqual(self.check(models({"id": "anthropic/x", "profile": "fast\n"})),
                         ['models[0]: invalid profile "fast\\n"'])

    def test_non_string_and_empty_values_are_not_echoed_raw(self):
        self.assertEqual(self.check(models({"id": {"token": "secret"}, "profile": ""})),
                         ["models[0]: invalid id (dict)", 'models[0]: invalid profile ""'])
        self.assertEqual(self.check(models({"id": "anthropic/x", "profile": 5})),
                         ["models[0]: invalid profile 5"])

    def test_models_that_is_not_a_list(self):
        self.assertEqual(self.check({"models": {"id": "anthropic/x"}}),
                         ["models: must be a list of {id, profile}"])

    def test_duplicates(self):
        errors = self.check(models(
            {"id": "anthropic/a", "profile": "one"},
            {"id": "anthropic/a", "profile": "two"},
            {"id": "anthropic/b", "profile": "two"}))
        self.assertEqual(errors, ["models[1]: duplicate id anthropic/a",
                                  "models[2]: duplicate profile two"])

    def test_missing_profile_and_extra_key(self):
        self.assertEqual(self.check(models({"id": "anthropic/a"})), ["models[0]: profile is required"])
        self.assertEqual(self.check(models({**OK, "note": "x"})), ["models[0]: unknown key note"])

    def test_cli_reads_stdin_and_reports_on_stderr(self):
        def run(doc):
            return subprocess.run(
                ["python3", str(ROOT / "scripts/model-catalog.py"), "check"],
                input=json.dumps(doc), text=True, capture_output=True)

        self.assertEqual(run(models(OK)).returncode, 0)
        bad = run(models())
        self.assertEqual((bad.returncode, bad.stderr), (1, "models: at least 1 model is required\n"))


@unittest.skipUnless(TOOLS, "requires Mike Farah yq, helmfile and helm")
class ModelCatalogTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)

    def render_web_models(self, customer_values):
        values = self.directory / "values.yaml"
        secrets = self.directory / "values.secrets.yaml"
        values.write_text((ROOT / "tests/fixtures/values.yaml").read_text() + customer_values)
        secrets.write_text((ROOT / "tests/fixtures/values.secrets.yaml").read_text())
        env = dict(os.environ, PHOENIX_BYOC_LOCAL_CHARTS=CHARTS,
                   PHOENIX_BYOC_VALUES_FILE=str(values), PHOENIX_BYOC_SECRETS_FILE=str(secrets),
                   PHOENIX_BYOC_NAMESPACE="phoenix-model-catalog-test",
                   HELMFILE_CACHE_HOME=os.environ.get("HELMFILE_CACHE_HOME", str(ROOT / ".tmp/helmfile-cache")))
        subprocess.run(
            ["helmfile", "--selector", "name=phoenix-web", "write-values", "--skip-deps",
             "--output-file-template", str(self.directory / "{{ .Release.Name }}.yaml")],
            cwd=ROOT, env=env, check=True, capture_output=True, text=True)
        rendered = subprocess.check_output(
            ["yq", "-o=json", ".web.models", str(self.directory / "phoenix-web.yaml")], text=True)
        return json.loads(rendered)

    def test_default_list_reaches_web(self):
        self.assertEqual(self.render_web_models(""), default_models())

    def test_customer_list_replaces_default(self):
        models = [{"id": "anthropic-vertex/claude-haiku-4-5@20251001", "profile": "fast"}]
        customer = "\nmodels:\n  - id: anthropic-vertex/claude-haiku-4-5@20251001\n    profile: fast\n"
        self.assertEqual(self.render_web_models(customer), models)


@unittest.skipUnless(PREFLIGHT_TOOLS, "requires yq, helmfile, helm and kubectl")
class PreflightModelCatalogTests(unittest.TestCase):
    def test_preflight_rejects_bad_models(self):
        with tempfile.TemporaryDirectory() as temp:
            values = Path(temp) / "values.yaml"
            secrets = Path(temp) / "values.secrets.yaml"
            values.write_text((ROOT / "tests/fixtures/values.yaml").read_text()
                              + "\nmodels:\n  - {id: Anthropic/x, profile: fast}\n")
            secrets.write_text((ROOT / "tests/fixtures/values.secrets.yaml").read_text())
            env = dict(os.environ, PHOENIX_BYOC_LOCAL_CHARTS=CHARTS,
                       PHOENIX_BYOC_VALUES_FILE=str(values), PHOENIX_BYOC_SECRETS_FILE=str(secrets),
                       PHOENIX_BYOC_NAMESPACE="phoenix-model-catalog-test")
            result = subprocess.run([str(ROOT / "scripts/preflight.sh")], cwd=ROOT, env=env,
                                    text=True, capture_output=True)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("models[0]: invalid id Anthropic/x", result.stderr)


if __name__ == "__main__":
    unittest.main()
