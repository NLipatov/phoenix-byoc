"""The installer gates must have a credential-free, pinned-tool CI job."""
from pathlib import Path
import unittest
import yaml

ROOT = Path(__file__).resolve().parents[1]

class ConnectionCITest(unittest.TestCase):
    def test_offline_connection_job_selects_every_boundary(self):
        jobs = yaml.safe_load((ROOT / '.github/workflows/compliance-tests.yml').read_text())['jobs']
        self.assertIn('connections', jobs)
        job = jobs['connections']
        self.assertNotIn('needs', job)
        commands = '\n'.join(step.get('run', '') for step in job['steps'])
        for required in ('helm-v3.18.6-linux-amd64.tar.gz', 'helmfile_0.171.0_linux_amd64.tar.gz', 'v4.49.2/yq_linux_amd64', 'PyYAML==6.0.3'):
            self.assertIn(required, commands)
        for module in ('test_connection_ci', 'test_connection_contract', 'test_connection_docs',
                       'test_connection_gates', 'test_connection_install', 'test_connection_release',
                       'test_connection_render', 'test_connection_secrets', 'test_connection_values',
                       'test_connection_yaml', 'test_install_input_guard', 'test_render_privacy'):
            self.assertIn(module, commands)
            self.assertTrue((ROOT / 'tests' / (module + '.py')).is_file())

if __name__ == '__main__':
    unittest.main()
