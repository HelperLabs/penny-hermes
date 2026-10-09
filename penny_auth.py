"""Independent public-client OAuth credentials for Penny's Hermes integration.

Run ``python penny_auth.py login --home ~/.hermes`` yourself to connect a
profile. Hermes tools only read or refresh this integration's own credentials;
they never start an interactive login or borrow another client's token.
"""

from __future__ import annotations

import argparse
import base64
from contextlib import contextmanager
import fcntl
import hashlib
import hmac
import json
import math
import os
from pathlib import Path
import secrets
import stat
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Callable
from urllib import error, parse, request


RESOURCE_URL = "https://app.mypenny.ai/mcp"
RESOURCE_METADATA_URL = "https://app.mypenny.ai/.well-known/oauth-protected-resource"
TRUSTED_ISSUERS = frozenset({"https://clerk.mypenny.ai"})
CLIENT_NAME = "Penny for Hermes"
SCOPES = "openid profile email offline_access"
HTTP_TIMEOUT = 10.0
MAX_LOGIN_SECONDS = 180.0
MAX_JSON_BYTES = 262_144
EXPIRY_MARGIN_SECONDS = 30.0


class AuthError(RuntimeError):
    """An actionable authentication error whose message contains no credentials."""


class _NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # Never forward a token, authorization code, or refresh token elsewhere.
        return None


def _request_json(
    url: str,
    *,
    form: dict[str, str] | None = None,
    document: dict[str, Any] | None = None,
    timeout: float = HTTP_TIMEOUT,
) -> dict[str, Any]:
    if form is not None and document is not None:
        raise AuthError("Invalid Penny authorization request.")
    headers = {"Accept": "application/json", "User-Agent": "penny-hermes/0.1.0"}
    body = None
    if form is not None:
        body = parse.urlencode(form).encode("ascii")
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    elif document is not None:
        body = json.dumps(document, separators=(",", ":")).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = request.Request(url, data=body, headers=headers)
    try:
        with request.build_opener(_NoRedirect()).open(req, timeout=timeout) as response:
            payload = response.read(MAX_JSON_BYTES + 1)
    except error.HTTPError as exc:
        status = exc.code
        exc.close()
        raise AuthError(f"Penny authorization request failed (HTTP {status}).") from None
    except (error.URLError, TimeoutError, OSError):
        raise AuthError("Penny authorization could not be reached. Try again later.") from None
    if len(payload) > MAX_JSON_BYTES:
        raise AuthError("Penny returned an oversized authorization response.")
    try:
        result = json.loads(payload)
    except (ValueError, UnicodeDecodeError):
        raise AuthError("Penny returned an invalid authorization response.") from None
    if not isinstance(result, dict):
        raise AuthError("Penny returned an invalid authorization response.")
    return result


def _issuer(value: Any) -> str:
    if not isinstance(value, str) or value not in TRUSTED_ISSUERS:
        raise AuthError("Penny advertised an untrusted authorization server.")
    return value


def _endpoint(value: Any, issuer: str) -> str:
    if not isinstance(value, str):
        raise AuthError("Penny authorization metadata is incomplete.")
    try:
        parsed = parse.urlsplit(value)
    except ValueError:
        raise AuthError("Penny advertised an invalid authorization endpoint.") from None
    if (
        parsed.scheme != "https"
        or parsed.netloc != parse.urlsplit(_issuer(issuer)).netloc
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or not parsed.path.startswith("/")
    ):
        raise AuthError("Penny advertised an untrusted authorization endpoint.")
    return value


def _text(value: Any, maximum: int = 65_536) -> bool:
    return isinstance(value, str) and 0 < len(value) <= maximum and "\x00" not in value


def _finite_number(value: Any) -> bool:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    try:
        return math.isfinite(value)
    except OverflowError:
        return False


def _check_owner_mode(info: os.stat_result, mode: int, *, directory: bool) -> None:
    expected_type = stat.S_ISDIR if directory else stat.S_ISREG
    if (
        not expected_type(info.st_mode)
        or stat.S_IMODE(info.st_mode) != mode
        or (hasattr(os, "getuid") and info.st_uid != os.getuid())
        or (not directory and info.st_nlink != 1)
    ):
        raise AuthError("Penny credential storage has unsafe ownership or permissions.")


def _token_record(response: dict[str, Any], previous: dict[str, Any]) -> dict[str, Any]:
    access_token = response.get("access_token")
    expires_in = response.get("expires_in")
    refresh_token = response.get("refresh_token", previous.get("refresh_token"))
    token_type = response.get("token_type")
    if (
        not _text(access_token)
        or access_token.startswith("mpt_")
        or not isinstance(token_type, str)
        or token_type.lower() != "bearer"
        or not _finite_number(expires_in)
        or expires_in <= 0
        or (refresh_token is not None and not _text(refresh_token))
    ):
        raise AuthError("Penny returned an invalid token response. Reconnect this profile.")
    scope = response.get("scope", previous.get("scope", SCOPES))
    if not isinstance(scope, str) or not set(scope.split()).issubset(SCOPES.split()):
        raise AuthError("Penny returned unexpected authorization scopes.")
    return {
        **previous,
        "access_token": access_token,
        "refresh_token": refresh_token,
        "scope": scope,
        "expires_at": time.time() + expires_in,
    }


class AuthStore:
    """Credentials scoped to ``hermes_home/penny/auth.json``.

    Construction and ``has_credentials`` do not perform network requests or
    create files. ``token`` has one bounded refresh request when necessary.
    """

    def __init__(self, hermes_home: str | os.PathLike[str]):
        self.home = Path(hermes_home).expanduser().absolute()
        self.directory = self.home / "penny"
        self.path = self.directory / "auth.json"
        self._lock = threading.RLock()
        self._storage_fd: int | None = None

    def _check_home(self) -> bool:
        try:
            info = self.home.lstat()
        except FileNotFoundError:
            return False
        if (
            not stat.S_ISDIR(info.st_mode)
            or stat.S_IMODE(info.st_mode) & 0o022
            or (hasattr(os, "getuid") and info.st_uid != os.getuid())
        ):
            raise AuthError("The Hermes profile directory has unsafe ownership or permissions.")
        return True

    def _directory_fd(self, *, create: bool = False) -> int | None:
        if not self._check_home():
            if create:
                raise AuthError("Create the Hermes profile directory before connecting Penny.")
            return None
        try:
            home_fd = os.open(self.home, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        except OSError:
            raise AuthError("The Hermes profile directory could not be opened safely.") from None
        try:
            home_info = os.fstat(home_fd)
            if (
                not stat.S_ISDIR(home_info.st_mode)
                or stat.S_IMODE(home_info.st_mode) & 0o022
                or (hasattr(os, "getuid") and home_info.st_uid != os.getuid())
            ):
                raise AuthError("The Hermes profile directory has unsafe ownership or permissions.")
            if create:
                try:
                    os.mkdir("penny", mode=0o700, dir_fd=home_fd)
                except FileExistsError:
                    pass
            try:
                info = os.stat("penny", dir_fd=home_fd, follow_symlinks=False)
            except FileNotFoundError:
                return None
            _check_owner_mode(info, 0o700, directory=True)
            fd = os.open("penny", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=home_fd)
            try:
                _check_owner_mode(os.fstat(fd), 0o700, directory=True)
            except Exception:
                os.close(fd)
                raise
        except OSError:
            raise AuthError("Penny credential storage could not be opened safely.") from None
        finally:
            os.close(home_fd)
        return fd

    def _load(self) -> dict[str, Any] | None:
        fd = self._directory_fd()
        if fd is None:
            return None
        try:
            try:
                auth_fd = os.open("auth.json", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
            except FileNotFoundError:
                return None
            except OSError:
                raise AuthError("Penny credentials could not be opened safely.") from None
            with os.fdopen(auth_fd, "rb") as auth_file:
                _check_owner_mode(os.fstat(auth_file.fileno()), 0o600, directory=False)
                payload = auth_file.read(MAX_JSON_BYTES + 1)
            if len(payload) > MAX_JSON_BYTES:
                raise AuthError("Penny credentials are invalid. Reconnect this profile.")
            try:
                record = json.loads(payload)
            except (ValueError, UnicodeDecodeError):
                raise AuthError("Penny credentials are invalid. Reconnect this profile.") from None
            self._validate(record)
            return record
        finally:
            os.close(fd)

    @contextmanager
    def _storage_guard(self, *, create: bool = False):
        # The directory inode survives atomic auth.json replacements. Locking
        # it prevents another Hermes process from refreshing over login/logout.
        # A nonblocking lock keeps tool calls bounded and makes contention clear.
        with self._lock:
            if self._storage_fd is not None:
                yield
                return
            fd = self._directory_fd(create=create)
            if fd is None:
                yield
                return
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                os.close(fd)
                raise AuthError("Penny credentials are in use by another request. Try again after it finishes.") from None
            self._storage_fd = fd
            try:
                yield
            finally:
                self._storage_fd = None
                os.close(fd)

    @staticmethod
    def _validate(record: Any) -> None:
        if not isinstance(record, dict):
            raise AuthError("Penny credentials are invalid. Reconnect this profile.")
        expires_at = record.get("expires_at")
        if (
            type(record.get("version")) is not int
            or record.get("version") != 1
            or record.get("resource") != RESOURCE_URL
            or record.get("token_endpoint_auth_method") != "none"
            or "client_secret" in record
            or not _text(record.get("client_id"), 4096)
            or not _text(record.get("access_token"))
            or record["access_token"].startswith("mpt_")
            or not _finite_number(expires_at)
            or (record.get("refresh_token") is not None and not _text(record["refresh_token"]))
            or not isinstance(record.get("scope"), str)
            or not set(record["scope"].split()).issubset(SCOPES.split())
        ):
            raise AuthError("Penny credentials are invalid. Reconnect this profile.")
        _endpoint(record.get("token_endpoint"), _issuer(record.get("issuer")))

    def _save(self, record: dict[str, Any]) -> None:
        self._validate(record)
        with self._storage_guard(create=True):
            self._save_locked(record)

    def _save_locked(self, record: dict[str, Any]) -> None:
        self._validate(record)
        payload = json.dumps(record, separators=(",", ":")).encode("utf-8")
        if len(payload) > MAX_JSON_BYTES:
            raise AuthError("Penny credentials are too large to store.")
        fd = self._directory_fd(create=True)
        assert fd is not None
        temp_name = f".auth-{secrets.token_hex(16)}.tmp"
        temp_created = False
        try:
            try:
                existing = os.stat("auth.json", dir_fd=fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                _check_owner_mode(existing, 0o600, directory=False)
            auth_fd = os.open(
                temp_name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
                dir_fd=fd,
            )
            temp_created = True
            with os.fdopen(auth_fd, "wb") as auth_file:
                os.fchmod(auth_file.fileno(), 0o600)
                auth_file.write(payload)
                auth_file.flush()
                os.fsync(auth_file.fileno())
            os.replace(temp_name, "auth.json", src_dir_fd=fd, dst_dir_fd=fd)
            temp_created = False
            os.fsync(fd)
        except OSError:
            raise AuthError("Penny credentials could not be saved safely.") from None
        finally:
            if temp_created:
                try:
                    os.unlink(temp_name, dir_fd=fd)
                except OSError:
                    pass
            os.close(fd)

    def has_credentials(self) -> bool:
        """Return whether this profile can authenticate, without contacting Penny."""
        with self._lock:
            record = self._load()
            return record is not None and (
                record["expires_at"] > time.time() + EXPIRY_MARGIN_SECONDS
                or bool(record.get("refresh_token"))
            )

    def identity(self) -> tuple[str, str] | None:
        """Return this profile's issuer/client identity without exposing tokens.

        Refresh keeps this identity stable; a fresh login's dedicated client
        changes it, and local logout returns ``None``. No network or writes.
        """
        with self._lock:
            record = self._load()
            if record is None:
                return None
            return record["issuer"], record["client_id"]

    def token(self, *, expected_identity: tuple[str, str] | None = None) -> str:
        """Return this client's token, refreshing once if it is near expiry.

        Callers carrying account-specific data can pin ``expected_identity``.
        The identity check and token lookup share the credential-storage lock,
        so a changed login fails before any account's token is returned.
        """
        with self._storage_guard():
            record = self._load()
            if record is None:
                raise AuthError("Connect Penny first with the Penny login command for this Hermes profile.")
            if expected_identity is not None and (record["issuer"], record["client_id"]) != expected_identity:
                raise AuthError("Penny login changed. Retry with the current Hermes profile.")
            if record["expires_at"] > time.time() + EXPIRY_MARGIN_SECONDS:
                return record["access_token"]
            if not record.get("refresh_token"):
                raise AuthError("Penny authorization expired. Reconnect this Hermes profile.")
            response = _request_json(
                record["token_endpoint"],
                form={
                    "grant_type": "refresh_token",
                    "client_id": record["client_id"],
                    "refresh_token": record["refresh_token"],
                    "resource": RESOURCE_URL,
                },
            )
            updated = _token_record(response, record)
            self._save(updated)
            return updated["access_token"]

    def clear(self) -> bool:
        """Remove this profile's local credentials without touching other clients."""
        with self._storage_guard():
            if self._load() is None:
                return False
            fd = self._directory_fd()
            assert fd is not None
            try:
                os.unlink("auth.json", dir_fd=fd)
                os.fsync(fd)
            except OSError:
                raise AuthError("Penny credentials could not be removed safely.") from None
            finally:
                os.close(fd)
            return True


class _LoopbackServer(HTTPServer):
    def get_request(self):
        connection, address = super().get_request()
        connection.settimeout(min(5.0, max(0.001, self.deadline - time.monotonic())))
        return connection, address


def login(
    store: AuthStore,
    *,
    timeout: float = MAX_LOGIN_SECONDS,
    output: Callable[[str], None] = print,
) -> None:
    """Register a separate public client and wait for human-approved PKCE login.

    This function only belongs in the human-invoked command. It prints the
    authorization URL without opening a browser and finishes within 180 seconds.
    """
    if not _finite_number(timeout) or not 0 < timeout <= MAX_LOGIN_SECONDS:
        raise AuthError("Penny login timeout must be greater than zero and at most 180 seconds.")
    # Reject an unsafe existing store before starting a remote registration.
    store._load()
    if not store._check_home():
        raise AuthError("Create the Hermes profile directory before connecting Penny.")
    deadline = time.monotonic() + timeout

    def remaining() -> float:
        duration = deadline - time.monotonic()
        if duration <= 0:
            raise AuthError("Penny login timed out. Run the login command again.")
        return min(duration, HTTP_TIMEOUT)

    resource = _request_json(RESOURCE_METADATA_URL, timeout=remaining())
    servers = resource.get("authorization_servers")
    if resource.get("resource") != RESOURCE_URL or not isinstance(servers, list):
        raise AuthError("Penny protected-resource metadata is invalid.")
    issuer = next((value for value in servers if isinstance(value, str) and value in TRUSTED_ISSUERS), None)
    issuer = _issuer(issuer)
    metadata = _request_json(f"{issuer}/.well-known/oauth-authorization-server", timeout=remaining())
    challenges = metadata.get("code_challenge_methods_supported")
    if metadata.get("issuer") != issuer or not isinstance(challenges, list) or "S256" not in challenges:
        raise AuthError("Penny authorization server does not support the required PKCE flow.")
    methods = metadata.get("token_endpoint_auth_methods_supported", [])
    if not isinstance(methods, list) or "none" not in methods:
        raise AuthError("Penny authorization server does not support a public client.")
    authorize_endpoint = _endpoint(metadata.get("authorization_endpoint"), issuer)
    token_endpoint = _endpoint(metadata.get("token_endpoint"), issuer)
    registration_endpoint = _endpoint(metadata.get("registration_endpoint"), issuer)
    require_issuer = metadata.get("authorization_response_iss_parameter_supported") is True
    state = secrets.token_urlsafe(32)
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).rstrip(b"=").decode("ascii")
    outcome: dict[str, str] = {}

    class Callback(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            # Default HTTP logs would expose the authorization code in the URL.
            pass

        def reply(self, status: int, message: str) -> None:
            payload = message.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(payload)

        def do_GET(self):
            try:
                callback = parse.urlsplit(self.path)
            except ValueError:
                self.reply(400, "Invalid authorization callback.")
                return
            if callback.path != "/callback":
                self.reply(404, "Not found.")
                return
            try:
                values = parse.parse_qs(callback.query, keep_blank_values=True, max_num_fields=20)
            except ValueError:
                self.reply(400, "Invalid authorization callback.")
                return
            returned_state = values.get("state", [])
            if len(returned_state) != 1 or not hmac.compare_digest(returned_state[0].encode("utf-8"), state.encode("ascii")):
                self.reply(400, "Invalid authorization state.")
                return
            returned_issuer = values.get("iss", [])
            if (require_issuer or returned_issuer) and returned_issuer != [issuer]:
                outcome["error"] = "Penny returned an invalid authorization issuer. Run login again."
                self.reply(400, "Invalid authorization issuer.")
                return
            if "error" in values:
                outcome["error"] = "Penny authorization was declined. Run login again when ready."
                self.reply(400, "Authorization was declined. You can close this tab.")
                return
            code = values.get("code", [])
            if len(code) != 1 or not _text(code[0], 16_384):
                outcome["error"] = "Penny returned an invalid authorization callback. Run login again."
                self.reply(400, "Invalid authorization callback.")
                return
            outcome["code"] = code[0]
            self.reply(200, "Penny sign-in received. Return to your terminal. You can close this tab.")

    try:
        server = _LoopbackServer(("127.0.0.1", 0), Callback)
    except OSError:
        raise AuthError("Penny could not open a local sign-in callback.") from None
    server.deadline = deadline
    try:
        redirect_uri = f"http://127.0.0.1:{server.server_port}/callback"
        registered = _request_json(
            registration_endpoint,
            document={
                "client_name": CLIENT_NAME,
                "redirect_uris": [redirect_uri],
                "grant_types": ["authorization_code", "refresh_token"],
                "response_types": ["code"],
                "token_endpoint_auth_method": "none",
                "scope": SCOPES,
            },
            timeout=remaining(),
        )
        client_id = registered.get("client_id")
        if not _text(client_id, 4096) or registered.get("token_endpoint_auth_method") != "none":
            raise AuthError("Penny did not register the required independent public client.")
        authorization_url = authorize_endpoint + "?" + parse.urlencode({
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scope": SCOPES,
            "resource": RESOURCE_URL,
            "state": state,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        })
        output("Open this URL in your browser to connect Penny to this Hermes profile:\n" + authorization_url)
        while not outcome:
            server.timeout = min(0.25, remaining())
            server.handle_request()
        if "error" in outcome:
            raise AuthError(outcome["error"])
        response = _request_json(
            token_endpoint,
            form={
                "grant_type": "authorization_code",
                "client_id": client_id,
                "code": outcome["code"],
                "code_verifier": verifier,
                "redirect_uri": redirect_uri,
                "resource": RESOURCE_URL,
            },
            timeout=remaining(),
        )
        record = _token_record(response, {
            "version": 1,
            "resource": RESOURCE_URL,
            "issuer": issuer,
            "client_id": client_id,
            "token_endpoint": token_endpoint,
            "token_endpoint_auth_method": "none",
            "scope": SCOPES,
        })
        store._save(record)
    finally:
        server.server_close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Connect a Hermes profile to Penny using its own OAuth client.")
    parser.add_argument("command", choices=("login", "logout", "status"))
    parser.add_argument("--home", default=os.environ.get("HERMES_HOME", str(Path.home() / ".hermes")), help="Hermes profile directory")
    args = parser.parse_args(argv)
    store = AuthStore(args.home)
    try:
        if args.command == "login":
            login(store)
            print("Penny is connected to this Hermes profile.")
        elif args.command == "logout":
            store.clear()
            print("This Hermes profile's local Penny credentials have been removed.")
        else:
            print("Penny is connected." if store.has_credentials() else "Penny is not connected.")
    except AuthError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
