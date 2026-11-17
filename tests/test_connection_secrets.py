"""Offline key-presence tests: fake runner and isolated fail-closed kubectl only."""
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'scripts/connection-secrets.py'
sys.path.insert(0, str(ROOT / 'scripts'))
spec = importlib.util.spec_from_file_location('connection_secrets', SCRIPT)
checker = importlib.util.module_from_spec(spec)
if spec.loader is not None:
    spec.loader.exec_module(checker)
from connection_contract import ContractError, SecretKeyRef  # noqa: E402


class ConnectionSecretsTest(unittest.TestCase):
    def setUp(self):
        self.calls = []
        self.responses = {}

    def fake_run(self, argv, **kwargs):
        self.calls.append((argv, kwargs))
        return self.responses.get(argv[-1], subprocess.CompletedProcess(argv, 0, b'api-key\n', b''))

    def check(self, refs, namespace='phoenix', context='cluster-1'):
        return checker.check_secret_references(refs, namespace, context, self.fake_run)

    def test_selected_secret_keys_only(self):
        self.responses['second'] = subprocess.CompletedProcess([], 0, b'other\n.env\n', b'')
        self.check((SecretKeyRef('second', '.env'), SecretKeyRef('first', 'api-key'),
                    SecretKeyRef('first', 'api-key'), SecretKeyRef('second', 'other')))
        self.assertEqual([call[-1] for call, _ in self.calls], ['first', 'second'])
        for argv, kwargs in self.calls:
            self.assertEqual(argv[:6], ['kubectl', '--context=cluster-1', '--namespace=phoenix',
                                         '--request-timeout=30s', 'get', 'secret'])
            self.assertEqual(argv[6], '-o')
            self.assertEqual(argv[7], 'go-template=' + checker.KEYS_TEMPLATE)
            self.assertNotIn('api-key', argv[7])
            self.assertFalse(any(token in argv for token in ('list', '-A', '--all-namespaces', 'decode')))
            self.assertFalse(kwargs.get('shell', False))

    def test_secret_get_denied_is_not_missing_fallback(self):
        self.responses['first'] = subprocess.CompletedProcess([], 1, b'canary-output', b'canary-secret-stderr')
        with self.assertRaises(ContractError) as caught:
            self.check((SecretKeyRef('first', 'api-key'), SecretKeyRef('second', 'api-key')))
        self.assertEqual(caught.exception.code, 'connection_secret_unreadable')
        self.assertNotIn('canary', str(caught.exception))
        self.assertEqual(len(self.calls), 1)

    def test_missing_key(self):
        self.responses['first'] = subprocess.CompletedProcess([], 0, b'other\n', b'')
        with self.assertRaises(ContractError) as caught:
            self.check((SecretKeyRef('first', 'api-key'),))
        self.assertEqual(caught.exception.code, 'connection_secret_key_missing')

    def test_missing_object_and_unreadable_result(self):
        for result in (subprocess.CompletedProcess([], 1, b'', b'not found: canary'),
                       subprocess.CompletedProcess([], 0, 'api-key\n', b'')):
            self.responses['first'] = result
            with self.assertRaises(ContractError) as caught:
                self.check((SecretKeyRef('first', 'api-key'),))
            self.assertEqual(caught.exception.code, 'connection_secret_unreadable')
            self.assertNotIn('canary', str(caught.exception))

    def test_key_with_dot_dash_underscore(self):
        self.responses['first'] = subprocess.CompletedProcess([], 0, b'.env\na-b_c.d\n', b'')
        self.check((SecretKeyRef('first', '.env'), SecretKeyRef('first', 'a-b_c.d')))

    def test_invalid_resource_name_no_subprocess(self):
        for name in ('-secret', 'a/b', 'UPPER', 'a..b', 'a.' , 'a' * 254, '', 'a\ncanary'):
            with self.subTest(name=name), self.assertRaises(ContractError):
                self.check((SecretKeyRef(name, 'key'),))
        self.assertEqual(self.calls, [])
        self.check((SecretKeyRef('a' * 253, 'api-key'),))
        self.assertEqual(len(self.calls), 1)  # subdomain total length, not 63-label limit

    def test_all_local_validation_before_any_call(self):
        for refs, namespace, context in (
            ((SecretKeyRef('ok', 'key'), SecretKeyRef('bad/name', 'key')), 'phoenix', 'ctx'),
            ((SecretKeyRef('ok', 'key'), SecretKeyRef('ok', '..bad')), 'phoenix', 'ctx'),
            ((SecretKeyRef('ok', 'key'),), '-bad', 'ctx'),
            ((SecretKeyRef('ok', 'key'),), 'phoenix', '\nctx'),
            (tuple(SecretKeyRef('ok', 'key') for _ in range(129)), 'phoenix', 'ctx'),
        ):
            with self.subTest(refs=len(refs), namespace=namespace, context=context):
                with self.assertRaises(ContractError):
                    self.check(refs, namespace, context)
        self.assertEqual(self.calls, [])

    def test_namespace_context_and_argument_safety(self):
        for namespace in ('a' * 64, 'Upper', 'a.b', 'a/b', '--other'):
            with self.subTest(namespace=namespace), self.assertRaises(ContractError):
                self.check((SecretKeyRef('ok', 'api-key'),), namespace=namespace)
        for context in ('--other', 'x\ncanary', '', 'x' * 254):
            with self.subTest(context=context), self.assertRaises(ContractError):
                self.check((SecretKeyRef('ok', 'api-key'),), context=context)
        self.assertEqual(self.calls, [])
        self.check((SecretKeyRef('ok', 'api-key'),), context='gke_project/zone:cluster@id')
        self.assertEqual(self.calls[0][0][1], '--context=gke_project/zone:cluster@id')

    def test_invalid_key_edges(self):
        for key in ('', '.', '..', '..env', '..a', 'a/b', 'a\n', 'é', 'x' * 254):
            with self.subTest(key=key), self.assertRaises(ContractError):
                self.check((SecretKeyRef('ok', key),))
        self.assertEqual(self.calls, [])
        self.responses['ok'] = subprocess.CompletedProcess([], 0, ('.env\na..b\n' + 'x' * 253 + '\n').encode(), b'')
        self.check((SecretKeyRef('ok', '.env'), SecretKeyRef('ok', 'a..b'), SecretKeyRef('ok', 'x' * 253)))

    def test_no_list_decode_or_value_output(self):
        self.responses['ok'] = subprocess.CompletedProcess([], 0, b'{"data":{"api-key":"canary"}}', b'')
        with self.assertRaises(ContractError) as caught:
            self.check((SecretKeyRef('ok', 'api-key'),))
        self.assertEqual(caught.exception.code, 'connection_secret_unreadable')
        self.assertNotIn('canary', str(caught.exception))

    def test_empty_value_key_presence_not_runtime_validation(self):
        # A fixed template prints the key even when its corresponding value is empty.
        self.responses['ok'] = subprocess.CompletedProcess([], 0, b'api-key\n', b'')
        self.check((SecretKeyRef('ok', 'api-key'),))

    def test_timeout_and_malformed_output_fail_closed(self):
        def timeout(argv, **kwargs):
            self.calls.append((argv, kwargs))
            raise subprocess.TimeoutExpired(argv, 35, output=b'canary', stderr=b'canary')
        with self.assertRaises(ContractError) as caught:
            checker.check_secret_references((SecretKeyRef('ok', 'key'),), 'ns', 'ctx', timeout)
        self.assertEqual(caught.exception.code, 'connection_secret_unreadable')
        self.assertNotIn('canary', str(caught.exception))
        for output in (b'key\nother/invalid\n', b'key\x00\n', b'key\n' + b'x' * 1048576,
                       b'key\n\xff', b'key\n\n'):
            self.responses['ok'] = subprocess.CompletedProcess([], 0, output, b'')
            with self.subTest(output=output[:20]), self.assertRaises(ContractError):
                self.check((SecretKeyRef('ok', 'key'),))


class ConnectionSecretsCliTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.log = root / 'calls'
        fake = root / 'kubectl'
        fake.write_text('#!' + sys.executable + '\nimport os, sys\n'
                        'with open(os.environ["FAKE_KUBECTL_LOG"], "a") as out:\n'
                        '    out.write("called\\n")\n'
                        'sys.stderr.write("canary-secret-stderr")\n'
                        'if os.environ.get("FAKE_DENY"):\n    sys.exit(1)\n'
                        'sys.stdout.write("api-key\\n")\n')
        fake.chmod(fake.stat().st_mode | stat.S_IXUSR)
        self.env = dict(os.environ, PATH=str(root), FAKE_KUBECTL_LOG=str(self.log))

    def install_fake(self, body):
        fake = Path(self.temp.name) / 'kubectl'
        fake.write_text('#!' + sys.executable + '\n' + body)
        fake.chmod(fake.stat().st_mode | stat.S_IXUSR)

    def cli(self, payload, args=('--namespace', 'phoenix', '--context', 'ctx'), env=None):
        return subprocess.run([sys.executable, '-B', str(SCRIPT), *args], input=payload,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              env=env or self.env, timeout=10)

    def test_cli_isolated_fake_success_and_denial(self):
        payload = b'[{"name":"ok","key":"api-key"}]'
        success = self.cli(payload)
        self.assertEqual((success.returncode, success.stdout, success.stderr), (0, b'', b''))
        self.assertEqual(self.log.read_text(), 'called\n')
        env = dict(self.env, FAKE_DENY='1')
        denied = self.cli(payload, env=env)
        self.assertNotEqual(denied.returncode, 0)
        self.assertEqual(denied.stdout, b'')
        self.assertNotIn(b'canary', denied.stderr)
        self.assertEqual(self.log.read_text(), 'called\ncalled\n')

    def test_cli_oversize_output_terminates_and_reaps_before_completion(self):
        marker = Path(self.temp.name) / 'finished'
        pidfile = Path(self.temp.name) / 'pid'
        self.install_fake('import os, pathlib, sys\n'
                          'pathlib.Path(os.environ["FAKE_PID"]).write_text(str(os.getpid()))\n'
                          'sys.stderr.write("canary-secret-stderr")\n'
                          'for _ in range(128):\n'
                          '    sys.stdout.buffer.write(b"api-key\\n" + b"x" * 65528)\n'
                          '    sys.stdout.buffer.flush()\n'
                          'pathlib.Path(os.environ["FAKE_FINISHED"]).write_text("finished")\n')
        env = dict(self.env, FAKE_PID=str(pidfile), FAKE_FINISHED=str(marker))
        result = self.cli(b'[{"name":"ok","key":"api-key"}]', env=env)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b'')
        self.assertEqual(result.stderr, b'connection_secret_unreadable: /references\n')
        self.assertTrue(pidfile.is_file())
        self.assertFalse(marker.exists(), 'child must stop before finishing 8 MiB of stdout')
        with self.assertRaises(ProcessLookupError):
            os.kill(int(pidfile.read_text()), 0)  # child reaped, not left alive/zombie

    def test_bounded_adapter_timeout_terminates_and_reaps(self):
        pidfile = Path(self.temp.name) / 'pid'
        marker = Path(self.temp.name) / 'finished'
        self.install_fake('import os, pathlib, time\n'
                          'pathlib.Path(os.environ["FAKE_PID"]).write_text(str(os.getpid()))\n'
                          'time.sleep(3)\n'
                          'pathlib.Path(os.environ["FAKE_FINISHED"]).write_text("finished")\n')
        env = dict(self.env, FAKE_PID=str(pidfile), FAKE_FINISHED=str(marker))
        with patch.dict(os.environ, env, clear=True):
            with self.assertRaises(subprocess.TimeoutExpired):
                checker._run_bounded(['kubectl', '--context=ctx', '--namespace=phoenix',
                                      '--request-timeout=30s', 'get', 'secret', '-o',
                                      'go-template=' + checker.KEYS_TEMPLATE, 'ok'],
                                     stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                     timeout=0.4, check=False)
        self.assertTrue(pidfile.is_file())
        self.assertFalse(marker.exists())
        with self.assertRaises(ProcessLookupError):
            os.kill(int(pidfile.read_text()), 0)

    def test_cli_invalid_input_never_executes_fake(self):
        for payload in (b'[{"name":"ok","key":"key"},{"name":"bad/name","key":"x"}]',
                        b'{"name":"ok","name":"other"}', b'[' + b' ' * (4 * 1024 * 1024) + b']',
                        b'\xff', b'[{"name":"ok","key":"..x"}]'):
            with self.subTest(payload=payload[:30]):
                result = self.cli(payload)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, b'')
                self.assertFalse(self.log.exists())
        self.assertNotEqual(self.cli(json.dumps([{'name': 'ok', 'key': 'key'}]).encode(),
                                     args=('--namespace', 'bad/name', '--context', 'ctx')).returncode, 0)
        self.assertFalse(self.log.exists())


if __name__ == '__main__':
    unittest.main()
