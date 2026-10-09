"""Bounded, credential-redacting MCP transport for Penny's public endpoint."""

from __future__ import annotations

import json
import threading
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener

MCP_URL = "https://app.mypenny.ai/mcp"
MAX_RESPONSE_BYTES = 2 * 1024 * 1024


class PennyError(RuntimeError):
    """Safe to display: never carries a token, server body, or memory content."""


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if fp is not None:
            fp.close()
        raise PennyError("Penny redirected the request; reconnect before retrying.")


def unpack_result(result):
    """Prefer the structured result, otherwise parse the first JSON text block."""
    if not isinstance(result, dict) or result.get("isError"):
        raise PennyError("Penny rejected the memory request.")
    if "structuredContent" in result:
        value = result["structuredContent"]
        return value.get("value", value) if isinstance(value, dict) else value
    blocks = result.get("content", [])
    if not isinstance(blocks, list):
        raise PennyError("Penny returned an unsupported memory response.")
    for block in blocks:
        if not isinstance(block, dict):
            continue
        if block.get("type") == "text":
            try:
                return json.loads(block.get("text", ""))
            except (ValueError, TypeError):
                continue
    raise PennyError("Penny returned an unsupported memory response.")


class PennyClient:
    def __init__(self, token_source, *, opener=None, timeout=8):
        self._token_source = token_source
        self._opener = opener or build_opener(NoRedirect())
        self._timeout = timeout
        self._lock = threading.Lock()
        self._next_id = 0
        self._initialized = False
        self._session = None

    def _rpc(self, method, params, *, notification=False):
        token = self._token_source()
        if not isinstance(token, str) or not token or token.startswith("mpt_"):
            raise PennyError("Connect Penny using this plugin's OAuth login.")
        headers = {
            "Authorization": "Bearer " + token,
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "MCP-Protocol-Version": "2025-03-26",
            "User-Agent": "penny-hermes/0.1.0",
        }
        if self._session:
            headers["Mcp-Session-Id"] = self._session
        payload = {"jsonrpc": "2.0", "method": method, "params": params}
        if not notification:
            self._next_id += 1
            payload["id"] = self._next_id
        request = Request(MCP_URL, data=json.dumps(payload).encode(), headers=headers, method="POST")
        try:
            with self._opener.open(request, timeout=self._timeout) as response:
                self._session = response.headers.get("Mcp-Session-Id", self._session)
                raw = response.read(MAX_RESPONSE_BYTES + 1)
                content_type = response.headers.get("Content-Type", "")
        except HTTPError as exc:
            code = exc.code
            exc.close()
            if code in (401, 403):
                raise PennyError("Penny authorization failed. Run this plugin's login again.") from None
            raise PennyError(f"Penny request failed (HTTP {code}).") from None
        except (URLError, OSError, TimeoutError):
            raise PennyError("Penny could not be reached. Retry when connected.") from None
        if len(raw) > MAX_RESPONSE_BYTES:
            raise PennyError("Penny returned more data than this plugin can accept.")
        if notification:
            return None
        try:
            if "text/event-stream" in content_type:
                replies = []
                # SSE data lines join within an event. Comments/notifications have no matching id.
                data_lines = []
                for line in raw.decode("utf-8").splitlines() + [""]:
                    if line.startswith("data:"):
                        data_lines.append(line[5:].lstrip(" "))
                    elif not line and data_lines:
                        replies.append(json.loads("\n".join(data_lines)))
                        data_lines = []
                body = next(item for item in replies if item.get("id") == payload["id"])
            else:
                body = json.loads(raw)
            if body.get("id") != payload["id"] or body.get("jsonrpc") != "2.0":
                raise ValueError("invalid envelope")
            if "error" in body:
                raise PennyError("Penny rejected the memory request.")
            return body["result"]
        except (ValueError, KeyError, TypeError, AttributeError, StopIteration, UnicodeError):
            raise PennyError("Penny returned an invalid MCP response.") from None

    def call(self, name, arguments):
        with self._lock:
            if not self._initialized:
                result = self._rpc("initialize", {
                    "protocolVersion": "2025-03-26", "capabilities": {},
                    "clientInfo": {"name": "penny-hermes", "version": "0.1.0"},
                })
                if not isinstance(result, dict) or result.get("protocolVersion") != "2025-03-26":
                    raise PennyError("Penny negotiated an unsupported MCP version.")
                self._rpc("notifications/initialized", {}, notification=True)
                self._initialized = True
            return unpack_result(self._rpc("tools/call", {"name": name, "arguments": arguments}))
