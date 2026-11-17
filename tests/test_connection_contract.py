import hashlib
import importlib.util
import json
import shutil
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('connection_contract', ROOT / 'scripts/connection_contract.py')
contract = importlib.util.module_from_spec(spec)
if spec.loader is not None:
    spec.loader.exec_module(contract)


class ConnectionContractTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        shutil.copytree(ROOT / 'contracts', self.root / 'contracts')
        self.agents = self.root / 'contracts/llm-connections/v1'
        self.engine = self.root / 'contracts/agent-input-delivery/v1'

    def repin_synthetic_lock(self, owner=None, member=None):
        lock_path = self.root / 'contracts/native-provider-inputs.lock.json'
        lock = json.loads(lock_path.read_text())
        if owner and member:
            location = self.root / lock['owners'][owner]['path'] / member
            digest = hashlib.sha256(location.read_bytes()).hexdigest()
            lock['owners'][owner]['files'][member] = digest
            manifest_path = location.parent / 'manifest.json'
            manifest = json.loads(manifest_path.read_text())
            manifest['files'][member] = digest
            manifest_path.write_text(json.dumps(manifest))
        if owner:
            manifest_path = self.root / lock['owners'][owner]['path'] / 'manifest.json'
            lock['owners'][owner]['manifest'] = json.loads(manifest_path.read_text())
            lock['owners'][owner]['manifestSha256'] = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
        lock_path.write_text(json.dumps(lock))
        return patch.object(contract, 'LOCK_SHA256', hashlib.sha256(lock_path.read_bytes()).hexdigest())

    def rejects(self, code):
        with self.assertRaises(contract.ContractError) as caught:
            contract.load_contract(self.root)
        self.assertEqual(caught.exception.code, code)
        self.assertNotIn(self.temp.name, str(caught.exception))

    def test_current_blocked_native_capability_is_valid_integrity_not_admission(self):
        bundle = contract.load_contract(self.root)
        capabilities = json.loads(bundle.capabilities.read_text())
        self.assertTrue(any(entry['status'] == 'blocked' for entry in capabilities['entries']))
        self.assertEqual(bundle.digests['agents']['values.schema.json'],
                         '0556b9bc85894f2984a4428afe61000b2707c183ef0a1e3ab55d77191ef16b93')

    def test_seed_is_not_production_admission(self):
        (self.agents / 'capabilities.json').write_text('{"entries":[],"liveAcceptance":true}')
        self.rejects('digest_mismatch')

    def test_contract_digest_mismatch(self):
        (self.engine / 'contract.json').write_text('{}')
        self.rejects('digest_mismatch')

    def test_missing_and_extra_member(self):
        (self.agents / 'README.md').unlink()
        self.rejects('missing_member')
        (self.agents / 'README.md').write_text('synthetic')
        (self.agents / 'unexpected.json').write_text('{}')
        self.rejects('extra_member')

    def test_manifest_path_escape(self):
        lock = self.root / 'contracts/native-provider-inputs.lock.json'
        data = json.loads(lock.read_text())
        data['owners']['agents']['files']['../outside'] = '0' * 64
        lock.write_text(json.dumps(data))
        with self.repin_synthetic_lock():
            self.rejects('unsafe_path')

    def test_symlink_escape_and_dangling_link(self):
        member = self.agents / 'README.md'
        member.unlink()
        member.symlink_to('/etc/passwd')
        self.rejects('unsafe_path')
        member.unlink()
        member.symlink_to(self.root / 'missing')
        self.rejects('unsafe_path')

    def test_parent_directory_symlink_rejected(self):
        original = self.root / 'contracts/llm-connections'
        moved = self.root / 'contracts/llm-connections-real'
        original.rename(moved)
        original.symlink_to(moved, target_is_directory=True)
        self.rejects('unsafe_path')

    def test_bounded_file_rejected(self):
        (self.engine / 'fixtures.json').write_bytes(b'x' * (contract.MAX_FILE_BYTES + 1))
        self.rejects('size_limit')

    def test_external_schema_ref_rejected(self):
        schema = self.agents / 'values.schema.json'
        schema.write_text(schema.read_text().replace('#/definitions/llmConnectionsV1_bedrock-anthropic',
                                                      'https://example.invalid/schema', 1))
        with self.repin_synthetic_lock('agents', 'values.schema.json'):
            self.rejects('external_ref')

    def test_contract_versions_disagree(self):
        manifest = self.engine / 'manifest.json'
        data = json.loads(manifest.read_text())
        data['deliveryVersion'] = '2'
        manifest.write_text(json.dumps(data))
        with self.repin_synthetic_lock('engine'):
            self.rejects('version_mismatch')

    def test_disabled_legacy_needs_no_capability_import(self):
        # No import of this module is required on the disabled legacy path.
        self.assertFalse((ROOT / 'scripts/preflight.sh').read_text().find('connection_contract') >= 0)
        self.assertFalse((ROOT / 'scripts/render.sh').read_text().find('connection_contract') >= 0)


if __name__ == '__main__':
    unittest.main()
