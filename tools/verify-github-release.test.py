"""Offline regression tests for the release publication gate."""

import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from urllib.error import HTTPError


spec = importlib.util.spec_from_file_location("release_gate", Path(__file__).with_name("verify-github-release.py"))
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


class ReleaseGateTests(unittest.TestCase):
    def setUp(self):
        self.expected = {name: (index + 1, "sha256:" + str(index) * 64) for index, name in enumerate(gate.ASSET_NAMES)}
        self.assets = [
            {"name": name, "state": "uploaded", "size": size, "digest": digest}
            for name, (size, digest) in self.expected.items()
        ]
        self.release = {"id": 42, "tag_name": "v0.44.1", "draft": False, "prerelease": False, "assets": self.assets}

    def test_only_http_404_permits_missing_release(self):
        for status in (404, 401, 403, 429, 500):
            with self.subTest(status=status), patch.dict(gate.os.environ, {"GH_TOKEN": "test-secret"}), patch.object(
                gate, "urlopen", side_effect=HTTPError("https://api.github.com/test", status, "failure", {}, None)
            ):
                if status == 404:
                    gate.preflight("agentpitch/prox", "v0.44.1")
                else:
                    with self.assertRaisesRegex(gate.GateError, f"HTTP {status}"):
                        gate.preflight("agentpitch/prox", "v0.44.1")

    def test_preflight_refuses_public_or_invalid_metadata(self):
        for value in (self.release, None, {}, {"tag_name": "wrong", "draft": True}):
            with self.subTest(value=value), patch.object(gate, "api_json", return_value=value):
                with self.assertRaises(gate.GateError):
                    gate.preflight("agentpitch/prox", "v0.44.1")
        with patch.object(gate, "api_json", return_value={**self.release, "draft": True}):
            gate.preflight("agentpitch/prox", "v0.44.1")

    def test_asset_gate_rejects_partial_or_changed_uploads(self):
        gate.verify_assets(self.assets, self.expected)
        bad_sets = [self.assets[:-1], self.assets + [self.assets[0]], [self.assets[0]] * 4]
        for key, value in (("name", "unexpected"), ("state", "starter"), ("size", 0), ("size", True), ("digest", None), ("digest", "sha256:" + "f" * 64)):
            assets = copy.deepcopy(self.assets)
            assets[0][key] = value
            bad_sets.append(assets)
        for assets in bad_sets:
            with self.subTest(assets=assets), self.assertRaises(gate.GateError):
                gate.verify_assets(assets, self.expected)

    def test_prepare_uses_numeric_asset_endpoint_and_structured_body(self):
        draft = {**self.release, "draft": True}
        with tempfile.TemporaryDirectory() as directory, patch.object(gate, "api_json", side_effect=[draft, self.assets]) as api:
            body = Path(directory) / "publish.json"
            gate.prepare_publish("agentpitch/prox", "v0.44.1", 42, self.expected, body)
            self.assertEqual(json.loads(body.read_text()), {"draft": False})
            self.assertEqual(api.call_args_list[1].args[0], "repos/agentpitch/prox/releases/42/assets?per_page=100")
            self.assertTrue(all(call.kwargs["authenticated"] for call in api.call_args_list))

    def test_prepare_does_not_create_publish_body_on_mismatch(self):
        for release in (self.release, {**self.release, "draft": True, "id": 43}, {**self.release, "draft": True, "prerelease": True}):
            with self.subTest(release=release), tempfile.TemporaryDirectory() as directory, patch.object(gate, "api_json", return_value=release):
                body = Path(directory) / "publish.json"
                with self.assertRaises(gate.GateError):
                    gate.prepare_publish("agentpitch/prox", "v0.44.1", 42, self.expected, body)
                self.assertFalse(body.exists())

    def test_public_checks_both_views_without_authentication(self):
        with patch.object(gate, "api_json", side_effect=[[self.release], self.release]) as api:
            gate.verify_public("agentpitch/prox", "v0.44.1", 42, self.expected)
        self.assertEqual([call.args[0] for call in api.call_args_list], [
            "repos/agentpitch/prox/releases?per_page=20&page=1",
            "repos/agentpitch/prox/releases/tags/v0.44.1",
        ])
        self.assertTrue(all(call.kwargs["authenticated"] is False for call in api.call_args_list))

    def test_public_stale_assets_retry_until_the_deadline(self):
        now = [0]

        def advance(seconds):
            now[0] += seconds

        with patch.object(gate.time, "monotonic", side_effect=lambda: now[0]), patch.object(gate.time, "sleep", side_effect=advance), patch.object(
            gate, "api_json", return_value=[{**self.release, "assets": []}]
        ) as api:
            with self.assertRaisesRegex(gate.GateError, "older updater compatibility was not confirmed"):
                gate.verify_public("agentpitch/prox", "v0.44.1", 42, self.expected, wait_seconds=11)
        self.assertEqual(now[0], 11)
        self.assertEqual(api.call_count, 3)

    def test_public_headers_never_include_token(self):
        class Response:
            def __enter__(self):
                return self

            def __exit__(self, *unused):
                pass

            def read(self, unused):
                return b"[]"

        with patch.dict(gate.os.environ, {"GH_TOKEN": "test-secret"}), patch.object(gate, "urlopen", return_value=Response()) as open_request:
            gate.api_json("repos/agentpitch/prox/releases", authenticated=False)
        self.assertIsNone(open_request.call_args.args[0].get_header("Authorization"))


if __name__ == "__main__":
    unittest.main()
