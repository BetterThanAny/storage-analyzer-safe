import http.client
import importlib.util
import json
import os
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SERVER = ROOT / "scripts" / "server.py"


def load_server_module(home):
    old_home = os.environ.get("HOME")
    os.environ["HOME"] = str(home)
    try:
        spec = importlib.util.spec_from_file_location(
            f"server_under_test_{id(home)}", SERVER
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    finally:
        if old_home is None:
            os.environ.pop("HOME", None)
        else:
            os.environ["HOME"] = old_home


class ServerHarness:
    def __init__(self, module):
        self.module = module
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), module.Handler)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, exc_type, exc, tb):
        self.httpd.shutdown()
        self.thread.join(timeout=3)
        self.httpd.server_close()

    def request(self, method, path, body=None, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=3)
        try:
            conn.request(method, path, body=body, headers=headers or {})
            response = conn.getresponse()
            return response.status, response.read().decode("utf-8", "replace")
        finally:
            conn.close()


class ServerSecurityTests(unittest.TestCase):
    def write_analysis(self, payload):
        fd, path = tempfile.mkstemp(suffix=".json")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(payload, f)
        self.addCleanup(lambda: os.path.exists(path) and os.unlink(path))
        return path

    def prepare_module(self, home, payload=None):
        module = load_server_module(home)
        src = self.write_analysis(payload or {"system": {"os": "macOS test"}})
        module.DATA, module.TPL, module.TRASH_ALLOW, module.OPEN_ALLOW = module.load(src)
        return module

    def test_get_report_rejects_untrusted_host_before_exposing_token(self):
        with tempfile.TemporaryDirectory() as tmp:
            module = self.prepare_module(Path(tmp))
            with ServerHarness(module) as server:
                status, body = server.request("GET", "/", headers={"Host": "evil.example"})

        self.assertEqual(status, 403)
        self.assertNotIn(module.TOKEN, body)

    def test_post_rejects_cross_origin_even_with_valid_token(self):
        with tempfile.TemporaryDirectory() as tmp:
            module = self.prepare_module(Path(tmp))
            body = json.dumps({"token": module.TOKEN, "mode": "open", "paths": []})
            with ServerHarness(module) as server:
                status, _ = server.request(
                    "POST",
                    "/action",
                    body=body,
                    headers={
                        "Host": "127.0.0.1",
                        "Origin": "http://evil.example",
                        "Content-Type": "application/json",
                        "Content-Length": str(len(body)),
                    },
                )

        self.assertEqual(status, 403)

    def test_post_rejects_non_json_content_type_even_with_valid_token(self):
        with tempfile.TemporaryDirectory() as tmp:
            module = self.prepare_module(Path(tmp))
            body = json.dumps({"token": module.TOKEN, "mode": "open", "paths": []})
            with ServerHarness(module) as server:
                status, _ = server.request(
                    "POST",
                    "/action",
                    body=body,
                    headers={
                        "Host": "127.0.0.1",
                        "Content-Type": "text/plain",
                        "Content-Length": str(len(body)),
                    },
                )

        self.assertEqual(status, 415)

    def test_trash_allowlist_rejects_sensitive_roots_and_allows_cache_children(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp).resolve()
            unsafe = [
                ".ssh",
                ".aws",
                ".gnupg",
                ".kube",
                ".config",
                "Library/Keychains",
                "Library/Application Support",
                "Documents/project-cache",
            ]
            safe = ["Library/Caches/pip"]
            for rel in unsafe + safe:
                (home / rel).mkdir(parents=True)
            payload = {
                "system": {"os": "macOS test"},
                "green": [
                    {
                        "name": "candidate paths",
                        "trash_paths": [str(home / rel) for rel in unsafe + safe],
                    }
                ],
            }
            module = load_server_module(home)
            src = self.write_analysis(payload)
            _, _, trash_allow, _ = module.load(src)

        for rel in unsafe:
            self.assertNotIn(str(home / rel), trash_allow, rel)
        self.assertIn(str(home / "Library/Caches/pip"), trash_allow)


if __name__ == "__main__":
    unittest.main()
