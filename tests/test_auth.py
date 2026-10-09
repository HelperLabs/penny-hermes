"""Offline checks for the Penny public client's OAuth and credential boundary."""

import base64
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest import mock
from urllib import error, parse, request

import penny_auth


ISSUER = "https://clerk.mypenny.ai"
TOKEN_ENDPOINT = ISSUER + "/oauth/token"


def record(**changes):
    return {
        "version": 1,
        "resource": penny_auth.RESOURCE_URL,
        "issuer": ISSUER,
        "client_id": "hermes-public-client",
        "token_endpoint": TOKEN_ENDPOINT,
        "token_endpoint_auth_method": "none",
        "access_token": "test-access-token",
        "refresh_token": "test-refresh-token",
        "scope": penny_auth.SCOPES,
        "expires_at": time.time() + 3600,
        **changes,
    }


def metadata():
    return {
        "issuer": ISSUER,
        "authorization_endpoint": ISSUER + "/oauth/authorize",
        "token_endpoint": TOKEN_ENDPOINT,
        "registration_endpoint": ISSUER + "/oauth/register",
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "none"],
        "code_challenge_methods_supported": ["S256"],
        "authorization_response_iss_parameter_supported": True,
    }


def discovery():
    return {
        "resource": penny_auth.RESOURCE_URL,
        "authorization_servers": [ISSUER],
        "bearer_methods_supported": ["header"],
    }


def token_response(**changes):
    return {
        "access_token": "new-test-access-token",
        "refresh_token": "new-test-refresh-token",
        "token_type": "Bearer",
        "expires_in": 3600,
        "scope": penny_auth.SCOPES,
        **changes,
    }


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name)
        self.store = penny_auth.AuthStore(self.home)

    def put(self, value=None):
        self.store.directory.mkdir(mode=0o700, exist_ok=True)
        self.store.path.write_text(json.dumps(record() if value is None else value))
        self.store.path.chmod(0o600)

    def test_missing_credentials_do_not_create_files_or_contact_penny(self):
        with mock.patch.object(penny_auth, "_request_json") as http:
            self.assertFalse(self.store.has_credentials())
            self.assertIsNone(self.store.identity())
            with self.assertRaisesRegex(penny_auth.AuthError, "Connect Penny first"):
                self.store.token()
            http.assert_not_called()
        self.assertFalse(self.store.directory.exists())

    def test_active_token_is_read_without_network_or_writes(self):
        self.put()
        before = self.store.path.read_bytes()
        with mock.patch.object(penny_auth, "_request_json") as http:
            self.assertTrue(self.store.has_credentials())
            self.assertEqual(self.store.token(), "test-access-token")
            http.assert_not_called()
        self.assertEqual(self.store.path.read_bytes(), before)

    def test_refresh_uses_only_registered_profile_client_and_fixed_resource(self):
        self.put(record(expires_at=time.time() - 1))
        identity = self.store.identity()
        self.assertEqual(identity, (ISSUER, "hermes-public-client"))
        with mock.patch.object(penny_auth, "_request_json", return_value=token_response()) as http:
            self.assertTrue(self.store.has_credentials())
            http.assert_not_called()
            self.assertEqual(self.store.token(expected_identity=identity), "new-test-access-token")
            http.assert_called_once_with(TOKEN_ENDPOINT, form={
                "grant_type": "refresh_token",
                "client_id": "hermes-public-client",
                "refresh_token": "test-refresh-token",
                "resource": penny_auth.RESOURCE_URL,
            })
        stored = json.loads(self.store.path.read_text())
        self.assertEqual(stored["refresh_token"], "new-test-refresh-token")
        self.assertEqual(self.store.identity(), identity)
        self.assertEqual(os.stat(self.store.path).st_mode & 0o777, 0o600)
        self.assertEqual(os.stat(self.store.directory).st_mode & 0o777, 0o700)
        self.assertEqual(list(self.store.directory.iterdir()), [self.store.path])

    def test_refresh_preserves_old_refresh_token_when_response_omits_it(self):
        self.put(record(expires_at=0))
        response = token_response()
        del response["refresh_token"]
        with mock.patch.object(penny_auth, "_request_json", return_value=response):
            self.store.token()
        self.assertEqual(json.loads(self.store.path.read_text())["refresh_token"], "test-refresh-token")

    def test_expired_token_without_refresh_requires_human_login(self):
        self.put(record(expires_at=0, refresh_token=None))
        with mock.patch.object(penny_auth, "_request_json") as http:
            self.assertFalse(self.store.has_credentials())
            with self.assertRaisesRegex(penny_auth.AuthError, "expired"):
                self.store.token()
            http.assert_not_called()

    def test_failed_refresh_preserves_credentials_and_redacts_response(self):
        self.put(record(expires_at=0))
        before = self.store.path.read_bytes()
        with mock.patch.object(penny_auth, "_request_json", side_effect=penny_auth.AuthError("Request failed.")):
            with self.assertRaisesRegex(penny_auth.AuthError, "Request failed"):
                self.store.token()
        self.assertEqual(self.store.path.read_bytes(), before)

    def test_malformed_refresh_response_keeps_original_credentials(self):
        self.put(record(expires_at=0))
        before = self.store.path.read_bytes()
        with mock.patch.object(penny_auth, "_request_json", return_value=token_response(expires_in=10 ** 400)):
            with self.assertRaisesRegex(penny_auth.AuthError, "invalid token response"):
                self.store.token()
        self.assertEqual(self.store.path.read_bytes(), before)

    def test_malformed_or_foreign_credentials_are_rejected_without_network(self):
        bad_records = [
            record(version=True),
            record(resource="https://other.example/mcp"),
            record(issuer="https://other.example"),
            record(token_endpoint="https://other.example/token"),
            record(token_endpoint=ISSUER + "/token?secret=hidden"),
            record(client_secret="never-import-this-secret"),
            record(token_endpoint_auth_method="client_secret_basic"),
            record(access_token="mpt_manual-token"),
            record(expires_at=float("nan")),
            record(scope="openid profile email public_metadata"),
            ["not", "a", "record"],
        ]
        with mock.patch.object(penny_auth, "_request_json") as http:
            for value in bad_records:
                with self.subTest(value_type=type(value).__name__):
                    self.put(value)
                    with self.assertRaises(penny_auth.AuthError) as raised:
                        self.store.has_credentials()
                    self.assertNotIn("never-import", str(raised.exception))
                    self.assertNotIn("hidden", str(raised.exception))
            http.assert_not_called()

    def test_invalid_json_does_not_expose_file_contents(self):
        self.put()
        self.store.path.write_text("{secret-content")
        with self.assertRaises(penny_auth.AuthError) as raised:
            self.store.has_credentials()
        self.assertNotIn("secret-content", str(raised.exception))

    def test_symlink_file_is_rejected_for_read_save_and_clear(self):
        self.store.directory.mkdir(mode=0o700)
        outside = self.home / "outside.json"
        outside.write_text("unchanged")
        self.store.path.symlink_to(outside)
        for operation in (self.store.has_credentials, lambda: self.store._save(record()), self.store.clear):
            with self.subTest(operation=operation):
                with self.assertRaises(penny_auth.AuthError):
                    operation()
        self.assertEqual(outside.read_text(), "unchanged")

    def test_symlink_directory_and_profile_are_rejected(self):
        outside = self.home / "outside"
        outside.mkdir(mode=0o700)
        self.store.directory.symlink_to(outside, target_is_directory=True)
        with self.assertRaises(penny_auth.AuthError):
            self.store.has_credentials()
        profile_link = self.home / "profile-link"
        profile_link.symlink_to(outside, target_is_directory=True)
        with self.assertRaises(penny_auth.AuthError):
            penny_auth.AuthStore(profile_link).has_credentials()

    def test_unsafe_permissions_are_rejected(self):
        self.put()
        self.store.path.chmod(0o644)
        with self.assertRaises(penny_auth.AuthError):
            self.store.has_credentials()
        self.store.path.chmod(0o600)
        self.store.directory.chmod(0o755)
        with self.assertRaises(penny_auth.AuthError):
            self.store.has_credentials()
        self.store.directory.chmod(0o700)
        self.home.chmod(0o777)
        try:
            with self.assertRaises(penny_auth.AuthError):
                self.store.has_credentials()
        finally:
            self.home.chmod(0o700)

    def test_hardlink_and_nonregular_auth_files_are_rejected(self):
        self.put()
        os.link(self.store.path, self.home / "copied-auth")
        with self.assertRaises(penny_auth.AuthError):
            self.store.has_credentials()
        self.store.path.unlink()
        os.mkfifo(self.store.path, mode=0o600)
        with self.assertRaises(penny_auth.AuthError):
            self.store.has_credentials()

    def test_failed_atomic_replace_keeps_original_and_removes_temporary_file(self):
        self.put()
        before = self.store.path.read_bytes()
        with mock.patch.object(penny_auth.os, "replace", side_effect=OSError("filesystem error")):
            with self.assertRaisesRegex(penny_auth.AuthError, "could not be saved"):
                self.store._save(record(access_token="replacement"))
        self.assertEqual(self.store.path.read_bytes(), before)
        self.assertEqual(list(self.store.directory.iterdir()), [self.store.path])

    def test_clear_removes_only_local_credentials_without_network(self):
        self.put()
        other = self.home / "another-client.json"
        other.write_text("other client data")
        with mock.patch.object(penny_auth, "_request_json") as http:
            self.assertTrue(self.store.clear())
            self.assertFalse(self.store.clear())
            self.assertIsNone(self.store.identity())
            http.assert_not_called()
        self.assertEqual(other.read_text(), "other client data")

    def test_identity_reads_only_issuer_and_client_without_network_or_writes(self):
        self.put()
        before = self.store.path.read_bytes()
        with mock.patch.object(penny_auth, "_request_json") as http:
            self.assertEqual(self.store.identity(), (ISSUER, "hermes-public-client"))
            http.assert_not_called()
        self.assertEqual(self.store.path.read_bytes(), before)

    def test_changed_client_rejects_pinned_token_before_refresh_or_egress(self):
        self.put(record(expires_at=0))
        previous_identity = self.store.identity()
        self.store._save(record(client_id="new-login-client", expires_at=0))
        before = self.store.path.read_bytes()
        with mock.patch.object(penny_auth, "_request_json") as http:
            with self.assertRaisesRegex(penny_auth.AuthError, "login changed"):
                self.store.token(expected_identity=previous_identity)
            http.assert_not_called()
        self.assertEqual(self.store.path.read_bytes(), before)

    def test_matching_identity_reads_active_token_and_missing_identity_rejects(self):
        self.put()
        identity = self.store.identity()
        with mock.patch.object(penny_auth, "_request_json") as http:
            self.assertEqual(self.store.token(expected_identity=identity), "test-access-token")
            self.store.clear()
            with self.assertRaises(penny_auth.AuthError):
                self.store.token(expected_identity=identity)
            http.assert_not_called()

    def test_separate_client_cannot_logout_or_overwrite_during_refresh(self):
        self.put(record(expires_at=0))
        other_store = penny_auth.AuthStore(self.home)
        before = self.store.path.read_bytes()

        def refresh(url, **kwargs):
            started = time.monotonic()
            with self.assertRaisesRegex(penny_auth.AuthError, "in use"):
                other_store.clear()
            with self.assertRaisesRegex(penny_auth.AuthError, "in use"):
                other_store._save(record(client_id="different-login"))
            self.assertLess(time.monotonic() - started, 0.5)
            self.assertEqual(self.store.path.read_bytes(), before)
            return token_response()

        with mock.patch.object(penny_auth, "_request_json", side_effect=refresh):
            self.assertEqual(self.store.token(), "new-test-access-token")
        self.assertTrue(other_store.clear())
        self.assertFalse(self.store.has_credentials())

    def test_storage_lock_is_released_after_refresh_failure(self):
        self.put(record(expires_at=0))
        with mock.patch.object(penny_auth, "_request_json", side_effect=penny_auth.AuthError("failed refresh")):
            with self.assertRaises(penny_auth.AuthError):
                self.store.token()
        self.assertTrue(penny_auth.AuthStore(self.home).clear())


class LoginTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = penny_auth.AuthStore(self.temp.name)
        self.workers = []
        self.worker_errors = []
        self.addCleanup(self.join_workers)

    def join_workers(self):
        for worker in self.workers:
            worker.join(timeout=2)
            self.assertFalse(worker.is_alive())
        self.assertEqual(self.worker_errors, [])

    def callback_output(self, *, bad_state_first=False, duplicate_state_first=False, issuer=ISSUER, oauth_error=None):
        def output(message):
            self.authorization = parse.parse_qs(parse.urlsplit(message.splitlines()[-1]).query)
            params = {
                "state": self.authorization["state"][0],
                "code": "human-approved-test-code",
            }
            if issuer is not None:
                params["iss"] = issuer
            if oauth_error:
                params["error"] = oauth_error

            def send():
                try:
                    callback = self.authorization["redirect_uri"][0]
                    if bad_state_first or duplicate_state_first:
                        bad = {**params, "state": [params["state"], params["state"]] if duplicate_state_first else "wrong-state"}
                        try:
                            request.urlopen(callback + "?" + parse.urlencode(bad, doseq=True), timeout=2)
                        except error.HTTPError as exc:
                            try:
                                self.assertEqual(exc.code, 400)
                            finally:
                                exc.close()
                    try:
                        with request.urlopen(callback + "?" + parse.urlencode(params, doseq=True), timeout=2) as response:
                            self.assertNotIn("human-approved-test-code", response.read().decode())
                    except error.HTTPError as exc:
                        try:
                            if issuer == ISSUER and not oauth_error:
                                raise
                            self.assertEqual(exc.code, 400)
                        finally:
                            exc.close()
                except Exception as exc:
                    self.worker_errors.append(exc)

            worker = threading.Thread(target=send, daemon=True)
            self.workers.append(worker)
            worker.start()
        return output

    def responses(self):
        return [
            discovery(), metadata(),
            {"client_id": "fresh-hermes-client", "token_endpoint_auth_method": "none", "client_secret": "ignored-should-not-be-stored"},
            token_response(),
        ]

    def test_human_login_registers_own_public_client_and_validates_pkce(self):
        self.store._save(record(client_id="previous-dedicated-client"))
        previous_identity = self.store.identity()
        with mock.patch.object(penny_auth, "_request_json", side_effect=self.responses()) as http:
            penny_auth.login(self.store, timeout=3, output=self.callback_output(bad_state_first=True))
        registration = http.call_args_list[2]
        self.assertEqual(registration.args, (ISSUER + "/oauth/register",))
        document = registration.kwargs["document"]
        self.assertEqual(document["client_name"], "Penny for Hermes")
        self.assertEqual(document["token_endpoint_auth_method"], "none")
        self.assertEqual(document["grant_types"], ["authorization_code", "refresh_token"])
        self.assertEqual(document["scope"], "openid profile email offline_access")
        redirect = self.authorization["redirect_uri"][0]
        self.assertEqual(parse.urlsplit(redirect).hostname, "127.0.0.1")
        self.assertGreater(parse.urlsplit(redirect).port, 0)
        self.assertEqual(document["redirect_uris"], [redirect])
        exchange = http.call_args_list[3].kwargs["form"]
        self.assertEqual(exchange["resource"], penny_auth.RESOURCE_URL)
        self.assertEqual(exchange["client_id"], "fresh-hermes-client")
        self.assertEqual(exchange["code"], "human-approved-test-code")
        expected_challenge = base64.urlsafe_b64encode(hashlib.sha256(exchange["code_verifier"].encode()).digest()).rstrip(b"=").decode()
        self.assertEqual(self.authorization["code_challenge"], [expected_challenge])
        self.assertEqual(self.authorization["code_challenge_method"], ["S256"])
        self.assertEqual(self.authorization["resource"], [penny_auth.RESOURCE_URL])
        self.assertNotIn("code_verifier", self.authorization)
        self.assertNotIn("access_token", self.authorization)
        stored = json.loads(self.store.path.read_text())
        self.assertEqual(stored["client_id"], "fresh-hermes-client")
        self.assertEqual(self.store.identity(), (ISSUER, "fresh-hermes-client"))
        self.assertNotEqual(self.store.identity(), previous_identity)
        self.assertNotIn("client_secret", stored)
        self.assertNotIn("ignored-should-not-be-stored", self.store.path.read_text())
        self.assertTrue(self.store.has_credentials())
        for call in http.call_args_list:
            self.assertLessEqual(call.kwargs["timeout"], 3)

    def test_callback_missing_or_wrong_issuer_does_not_exchange_or_store_token(self):
        for issuer in (None, "https://other.example", [ISSUER, ISSUER]):
            with self.subTest(issuer=issuer):
                with mock.patch.object(penny_auth, "_request_json", side_effect=self.responses()) as http:
                    with self.assertRaisesRegex(penny_auth.AuthError, "invalid authorization issuer"):
                        penny_auth.login(self.store, timeout=3, output=self.callback_output(issuer=issuer))
                    self.assertEqual(http.call_count, 3)
                self.assertFalse(self.store.path.exists())

    def test_duplicate_state_is_ignored_before_valid_callback(self):
        with mock.patch.object(penny_auth, "_request_json", side_effect=self.responses()):
            penny_auth.login(self.store, timeout=3, output=self.callback_output(duplicate_state_first=True))
        self.assertTrue(self.store.has_credentials())

    def test_malformed_registration_is_rejected_without_authorization_or_store(self):
        for registration in (
            {},
            {"client_id": "valid", "token_endpoint_auth_method": "client_secret_basic"},
            {"client_id": [], "token_endpoint_auth_method": "none"},
            {"client_id": "valid"},
        ):
            with self.subTest(registration=registration):
                output = mock.Mock()
                with mock.patch.object(penny_auth, "_request_json", side_effect=[discovery(), metadata(), registration]) as http:
                    with self.assertRaisesRegex(penny_auth.AuthError, "independent public client"):
                        penny_auth.login(self.store, timeout=1, output=output)
                    self.assertEqual(http.call_count, 3)
                    output.assert_not_called()
                self.assertFalse(self.store.path.exists())

    def test_declined_authorization_redacts_provider_error(self):
        with mock.patch.object(penny_auth, "_request_json", side_effect=self.responses()) as http:
            with self.assertRaises(penny_auth.AuthError) as raised:
                penny_auth.login(self.store, timeout=3, output=self.callback_output(oauth_error="sensitive-provider-error"))
            self.assertNotIn("sensitive-provider-error", str(raised.exception))
            self.assertEqual(http.call_count, 3)
        self.assertFalse(self.store.path.exists())

    def test_timeout_does_not_start_browser_or_create_credentials(self):
        started = time.monotonic()
        with mock.patch.object(penny_auth, "_request_json", side_effect=self.responses()):
            with self.assertRaisesRegex(penny_auth.AuthError, "timed out"):
                penny_auth.login(self.store, timeout=0.05, output=lambda message: None)
        self.assertLess(time.monotonic() - started, 0.5)
        self.assertFalse(self.store.path.exists())

    def test_timeout_above_limit_is_rejected_before_network(self):
        with mock.patch.object(penny_auth, "_request_json") as http:
            with self.assertRaises(penny_auth.AuthError):
                penny_auth.login(self.store, timeout=181)
            http.assert_not_called()

    def test_untrusted_or_malformed_discovery_is_rejected_before_registration(self):
        for resource in (
            {**discovery(), "authorization_servers": ["https://other.example"]},
            {**discovery(), "authorization_servers": [{"issuer": ISSUER}]},
            {**discovery(), "resource": "https://other.example/mcp"},
        ):
            with self.subTest(resource=resource):
                with mock.patch.object(penny_auth, "_request_json", return_value=resource) as http:
                    with self.assertRaises(penny_auth.AuthError):
                        penny_auth.login(self.store, timeout=1, output=lambda message: None)
                    self.assertEqual(http.call_count, 1)

    def test_foreign_endpoint_or_missing_pkce_is_rejected(self):
        for server in (
            {**metadata(), "token_endpoint": "https://other.example/token"},
            {**metadata(), "authorization_endpoint": ISSUER + "/authorize?token=private"},
            {**metadata(), "code_challenge_methods_supported": None},
            {**metadata(), "token_endpoint_auth_methods_supported": ["client_secret_basic"]},
        ):
            with self.subTest(server=server):
                with mock.patch.object(penny_auth, "_request_json", side_effect=[discovery(), server]) as http:
                    with self.assertRaises(penny_auth.AuthError):
                        penny_auth.login(self.store, timeout=1, output=lambda message: None)
                    self.assertEqual(http.call_count, 2)


class HttpTests(unittest.TestCase):
    def test_oauth_requests_identify_plugin_for_server_admission(self):
        for options in ({}, {"document": {"client_name": "Penny for Hermes"}}, {"form": {"grant_type": "refresh_token"}}):
            with self.subTest(request_type=next(iter(options), "discovery")):
                response = mock.MagicMock()
                response.__enter__.return_value = response
                response.read.return_value = b'{"ok":true}'
                opener = mock.Mock()
                opener.open.return_value = response
                with mock.patch.object(penny_auth.request, "build_opener", return_value=opener):
                    penny_auth._request_json(TOKEN_ENDPOINT, **options)
                sent_request = opener.open.call_args.args[0]
                self.assertEqual(sent_request.get_header("User-agent"), "penny-hermes/0.1.0")

    def test_http_error_is_redacted_and_redirects_are_disabled(self):
        opener = mock.Mock()
        body = io.BytesIO(b"raw secret response")
        opener.open.side_effect = error.HTTPError(TOKEN_ENDPOINT, 400, "raw secret", {}, body)
        with mock.patch.object(penny_auth.request, "build_opener", return_value=opener) as build:
            with self.assertRaises(penny_auth.AuthError) as raised:
                penny_auth._request_json(TOKEN_ENDPOINT, form={"refresh_token": "test-secret"})
        self.assertEqual(str(raised.exception), "Penny authorization request failed (HTTP 400).")
        self.assertTrue(body.closed)
        self.assertIsInstance(build.call_args.args[0], penny_auth._NoRedirect)
        self.assertIsNone(build.call_args.args[0].redirect_request(None, None, 302, "", {}, "https://other.example"))
        self.assertEqual(opener.open.call_args.kwargs["timeout"], penny_auth.HTTP_TIMEOUT)

    def test_oversized_invalid_and_nonobject_json_are_rejected(self):
        for payload in (b"x" * (penny_auth.MAX_JSON_BYTES + 1), b"secret-invalid", b"[]"):
            response = mock.MagicMock()
            response.__enter__.return_value = response
            response.read.return_value = payload
            opener = mock.Mock()
            opener.open.return_value = response
            with mock.patch.object(penny_auth.request, "build_opener", return_value=opener):
                with self.assertRaises(penny_auth.AuthError) as raised:
                    penny_auth._request_json(TOKEN_ENDPOINT)
                self.assertNotIn("secret-invalid", str(raised.exception))

    def test_bad_token_response_never_exposes_or_persists_secrets(self):
        for response in (
            token_response(token_type="MAC"),
            token_response(expires_in=-1),
            token_response(expires_in=float("inf")),
            token_response(expires_in=True),
            token_response(access_token="mpt_private-secret"),
            token_response(scope="private_metadata"),
        ):
            with self.subTest(response_type=response.get("token_type")):
                with self.assertRaises(penny_auth.AuthError) as raised:
                    penny_auth._token_record(response, record())
                self.assertNotIn("private-secret", str(raised.exception))


if __name__ == "__main__":
    unittest.main()
