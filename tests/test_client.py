"""MCP contract and defensive transport checks; every response is synthetic."""

from __future__ import annotations

from email.message import Message
import importlib.util
import io
import json
from pathlib import Path
import unittest
from unittest.mock import MagicMock
from urllib.error import HTTPError, URLError
from urllib.request import Request


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("penny_client_test_module", ROOT / "penny_client.py")
client_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(client_module)


class Response:
    def __init__(self, payload, content_type="application/json", session=None):
        self.raw = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
        self.headers = Message()
        self.headers["Content-Type"] = content_type
        if session:
            self.headers["Mcp-Session-Id"] = session
        self.limit = None

    def read(self, size):
        self.limit = size
        return self.raw[:size]

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


class ClientTests(unittest.TestCase):
    def setUp(self):
        self.opener = MagicMock()
        self.client = client_module.PennyClient(lambda: "synthetic-access-token", opener=self.opener)

    def rpc_response(self, result, request_id=1):
        return Response({"jsonrpc": "2.0", "id": request_id, "result": result})

    def prime(self, result=None):
        self.client._initialized = True
        self.opener.open.return_value = self.rpc_response(result or {"structuredContent": {"value": {"ok": True}}})

    def test_handshake_notification_and_call_use_fixed_origin_and_session(self):
        responses = [self.rpc_response({"protocolVersion": "2025-03-26"}), Response(b"", session="synthetic-session"), self.rpc_response({"structuredContent": {"value": {"ok": True}}}, 2)]
        self.opener.open.side_effect = responses
        self.assertEqual(self.client.call("penny_read", {"target": "profile"}), {"ok": True})
        calls = self.opener.open.call_args_list
        payloads = [json.loads(call.args[0].data) for call in calls]
        self.assertEqual([payload["method"] for payload in payloads], ["initialize", "notifications/initialized", "tools/call"])
        self.assertNotIn("id", payloads[1])
        self.assertEqual(payloads[2]["params"], {"name": "penny_read", "arguments": {"target": "profile"}})
        for call in calls:
            request = call.args[0]
            self.assertEqual(request.full_url, "https://app.mypenny.ai/mcp")
            self.assertEqual(request.get_method(), "POST")
            self.assertEqual(request.get_header("Authorization"), "Bearer synthetic-access-token")
            self.assertEqual(call.kwargs["timeout"], 8)
        self.assertEqual(calls[2].args[0].get_header("Mcp-session-id"), "synthetic-session")

    def test_second_call_reuses_initialization(self):
        self.opener.open.side_effect = [self.rpc_response({"protocolVersion": "2025-03-26"}), Response(b""), self.rpc_response({"structuredContent": {"value": 1}}, 2), self.rpc_response({"structuredContent": {"value": 2}}, 3)]
        self.assertEqual(self.client.call("first", {}), 1)
        self.assertEqual(self.client.call("second", {}), 2)
        self.assertEqual(self.opener.open.call_count, 4)

    def test_sse_ignores_notifications_and_matches_request_id(self):
        self.client._initialized = True
        raw = b': keepalive\n\nevent: message\ndata: {"jsonrpc":"2.0","method":"notice"}\n\ndata: {"jsonrpc":"2.0",\ndata: "id":1,"result":{"content":[{"type":"text","text":"{\\"ok\\":true}"}]}}\n\n'
        self.opener.open.return_value = Response(raw, "text/event-stream; charset=utf-8")
        self.assertEqual(self.client.call("penny_read", {}), {"ok": True})

    def test_structured_result_precedes_json_text_fallback(self):
        result = {"structuredContent": {"value": ["synthetic structured result"]}, "content": [{"type": "text", "text": '["synthetic text result"]'}]}
        self.assertEqual(client_module.unpack_result(result), ["synthetic structured result"])
        self.assertEqual(client_module.unpack_result({"content": [{"type": "image"}, {"type": "text", "text": "Not JSON"}, {"type": "text", "text": '{"ok":true}'}]}), {"ok": True})

    def test_unsupported_protocol_and_malformed_handshake_fail_cleanly(self):
        for result in ({"protocolVersion": "unsupported"}, None, [], "bad shape"):
            with self.subTest(result=result):
                self.client = client_module.PennyClient(lambda: "synthetic-access-token", opener=self.opener)
                self.opener.open.return_value = self.rpc_response(result)
                with self.assertRaises(client_module.PennyError):
                    self.client.call("penny_read", {})

    def test_malformed_envelopes_are_safe_errors(self):
        for payload in (b"not json", b"\xff", {"jsonrpc": "2.0", "id": 999, "result": {}}, {"id": 1, "result": {}}, {"jsonrpc": "2.0", "id": 1}, [], None):
            with self.subTest(payload=payload):
                self.client = client_module.PennyClient(lambda: "synthetic-access-token", opener=self.opener)
                self.client._initialized = True
                self.opener.open.return_value = Response(payload)
                with self.assertRaises(client_module.PennyError):
                    self.client.call("penny_read", {})

    def test_malformed_tool_content_is_safe_error(self):
        for result in ({"content": [None]}, {"content": ["bad shape"]}, {"content": "bad shape"}, {"content": []}, {"isError": True, "content": [{"text": "Synthetic private failure"}]}):
            with self.subTest(result=result):
                with self.assertRaises(client_module.PennyError):
                    client_module.unpack_result(result)

    def test_response_size_is_bounded(self):
        self.client._initialized = True
        response = Response(b"x" * (client_module.MAX_RESPONSE_BYTES + 2))
        self.opener.open.return_value = response
        with self.assertRaisesRegex(client_module.PennyError, "more data"):
            self.client.call("penny_read", {})
        self.assertEqual(response.limit, client_module.MAX_RESPONSE_BYTES + 1)

    def test_http_and_network_errors_do_not_expose_server_body_or_credentials(self):
        sentinel = "Synthetic private content and synthetic credential"
        for error in (HTTPError("https://app.mypenny.ai/mcp", 401, sentinel, {}, io.BytesIO(sentinel.encode())), HTTPError("https://app.mypenny.ai/mcp", 500, sentinel, {}, io.BytesIO(sentinel.encode())), URLError(sentinel), TimeoutError(sentinel), OSError(sentinel)):
            with self.subTest(error=type(error).__name__):
                if isinstance(error, HTTPError):
                    self.addCleanup(error.close)
                self.client._initialized = True
                self.opener.open.side_effect = error
                with self.assertRaises(client_module.PennyError) as caught:
                    self.client.call("penny_read", {})
                self.assertNotIn(sentinel, str(caught.exception))

    def test_json_rpc_error_body_is_not_exposed(self):
        self.client._initialized = True
        self.opener.open.return_value = Response({"jsonrpc": "2.0", "id": 1, "error": {"code": -1, "message": "Synthetic private failure"}})
        with self.assertRaises(client_module.PennyError) as caught:
            self.client.call("penny_read", {})
        self.assertNotIn("Synthetic private failure", str(caught.exception))

    def test_redirect_handler_refuses_other_origins(self):
        handler = client_module.NoRedirect()
        request = Request("https://app.mypenny.ai/mcp", headers={"Authorization": "Bearer synthetic-access-token"})
        with self.assertRaises(client_module.PennyError):
            handler.redirect_request(request, None, 302, "redirect", {}, "https://another.example/mcp")

    def test_missing_or_mcp_key_token_is_rejected_before_network(self):
        for token in (None, "", "mpt_synthetic_key", 123):
            with self.subTest(token=token):
                client = client_module.PennyClient(lambda: token, opener=self.opener)
                with self.assertRaises(client_module.PennyError):
                    client.call("penny_read", {})
        self.opener.open.assert_not_called()


if __name__ == "__main__":
    unittest.main()
