"""Provider integration checks using Hermes's actual memory ABC and manager."""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import MagicMock, patch

from agent.memory_manager import MemoryManager
from agent.memory_provider import MemoryProvider, spawn_context_thread


ROOT = Path(__file__).resolve().parents[1]
PACKAGE = "penny_hermes_provider_tests"
spec = importlib.util.spec_from_file_location(
    PACKAGE, ROOT / "__init__.py", submodule_search_locations=[str(ROOT)]
)
plugin = importlib.util.module_from_spec(spec)
sys.modules[PACKAGE] = plugin
spec.loader.exec_module(plugin)


class ProviderTests(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.TemporaryDirectory(prefix="penny-provider-test-")
        self.addCleanup(self.home.cleanup)
        self.auth = MagicMock()
        self.auth.has_credentials.return_value = True
        self.auth.identity.return_value = ("https://clerk.mypenny.ai", "synthetic-client-a")
        self.client = MagicMock()
        self.client.call.return_value = {"global": []}
        self.auth_patch = patch.object(plugin, "AuthStore", return_value=self.auth)
        self.client_patch = patch.object(plugin, "PennyClient", return_value=self.client)
        self.home_patch = patch.object(plugin, "get_hermes_home", return_value=Path(self.home.name))
        for item in (self.auth_patch, self.client_patch, self.home_patch):
            item.start()
            self.addCleanup(item.stop)
        self.provider = plugin.PennyMemoryProvider()
        self.addCleanup(self.provider.shutdown)

    def initialize(self, **kwargs):
        options = {"hermes_home": self.home.name, "platform": "cli", "agent_context": "primary"}
        options.update(kwargs)
        with patch.object(plugin, "spawn_context_thread") as spawn:
            self.provider.initialize("session-a", **options)
        return spawn

    def result(self, name, args=None):
        return json.loads(self.provider.handle_tool_call(name, args or {}))

    def test_real_hermes_abc_and_manager_register_tools_before_initialization(self):
        self.assertIsInstance(self.provider, MemoryProvider)
        manager = MemoryManager()
        manager.add_provider(self.provider)
        self.initialize()
        self.assertEqual(manager.get_all_tool_names(), {"penny_profile", "penny_search", "penny_remember"})
        self.client.call.return_value = {"coreMemory": "Synthetic preference"}
        result = json.loads(manager.handle_tool_call("penny_profile", {}))
        self.assertIn("result", result)

    def test_uninitialized_provider_cannot_send_private_memory_requests(self):
        self.assertEqual(self.provider.prefetch("previous decision"), "")
        self.assertEqual(self.provider.system_prompt_block(), "")
        self.assertIn("error", self.result("penny_profile"))
        self.client.call.assert_not_called()

    def test_availability_is_local_and_rebinds_auth_to_active_home(self):
        self.assertTrue(self.provider.is_available())
        self.client.call.assert_not_called()
        other_home = Path(self.home.name) / "other-profile"
        self.initialize(hermes_home=str(other_home))
        plugin.AuthStore.assert_called_with(other_home)

    def test_nonprimary_and_gateway_contexts_fail_closed(self):
        for context in ("subagent", "cron", "flush"):
            with self.subTest(context=context):
                spawn = self.initialize(agent_context=context)
                self.assertEqual(self.provider.prefetch("private decision"), "")
                self.assertEqual(self.provider.system_prompt_block(), "")
                self.assertIn("error", self.result("penny_profile"))
                spawn.assert_not_called()
        for platform in ("telegram", "discord", "slack", "feishu", "unknown"):
            with self.subTest(platform=platform):
                spawn = self.initialize(platform=platform)
                self.assertIn("error", self.result("penny_search", {"query": "private decision"}))
                spawn.assert_not_called()
        self.client.call.assert_not_called()

    def test_sync_and_session_end_never_upload_transcripts(self):
        self.initialize()
        self.provider.sync_turn("Synthetic sensitive user text", "Synthetic assistant text", messages=[{"role": "tool", "content": "Synthetic workspace output"}])
        self.provider.on_session_end([{"role": "user", "content": "Synthetic transcript"}])
        self.client.call.assert_not_called()

    def test_labeled_search_uses_public_arguments_and_never_reads_scope_metadata(self):
        self.initialize()
        private = {"content": "Synthetic private note", "scope": {"kind": "private"}}
        self.client.call.return_value = [private, {"scope": "private"}, {"scope": {"kind": "space"}}, {"scope": {}}, None]
        self.assertEqual(self.result("penny_search", {"query": "past decision", "limit": 3}), {"result": [private]})
        self.client.call.assert_called_once_with("penny_read", {"target": "search", "query": "past decision", "limit": 3})

    def test_unlabeled_private_notes_are_retained_only_with_complete_no_space_proof(self):
        self.initialize()
        note = {"content": "Synthetic legacy private note"}
        self.client.call.side_effect = [[note], {"scopes": [], "coverage": "complete", "nextCursor": None}]
        self.assertEqual(self.result("penny_search", {"query": "legacy decision"}), {"result": [note]})
        self.assertEqual(self.client.call.call_args_list[1].args, ("penny_read", {"target": "projects", "view": "scopes", "limit": 1}))
        self.assertEqual(self.client.call.call_count, 2)

    def test_unlabeled_notes_fail_closed_for_nonempty_partial_missing_or_failed_proof(self):
        self.initialize()
        private = {"content": "Synthetic labeled private note", "scope": {"kind": "private"}}
        unlabeled = {"content": "Synthetic unlabeled note"}
        proofs = [
            {"scopes": [{"kind": "space", "workspaceId": "synthetic-space"}], "coverage": "complete", "nextCursor": None},
            {"scopes": [], "coverage": "partial", "nextCursor": None},
            {"scopes": [], "coverage": "complete"},
            {"scopes": [], "coverage": "complete", "nextCursor": "synthetic-next-page"},
            {"scopes": [], "nextCursor": None},
            {"coverage": "complete", "nextCursor": None},
            None,
            [],
            plugin.PennyError("Synthetic scope lookup failure"),
        ]
        for proof in proofs:
            with self.subTest(proof=proof):
                self.client.call.reset_mock()
                self.client.call.side_effect = [[private, unlabeled], proof]
                self.assertEqual(self.result("penny_search", {"query": "legacy decision"}), {"result": [private]})
                self.assertEqual(self.client.call.call_count, 2)

    def test_no_space_proof_never_admits_shared_markers_or_contradictory_labels(self):
        self.initialize()
        private = {"content": "Synthetic labeled private note", "scope": {"kind": "private"}}
        unlabeled = {"content": "Synthetic legacy private note"}
        rows = [private, unlabeled,
            {"content": "Synthetic workspace note", "workspaceId": "synthetic-space"},
            {"content": "Synthetic attributed shared note", "author": "synthetic-author"},
            {"content": "Synthetic shared note", "sharedVia": "synthetic-space"},
            {"content": "Synthetic empty workspace marker", "workspaceId": None},
            {"content": "Synthetic space scope", "scope": {"kind": "space"}},
            {"content": "Synthetic malformed scope", "scope": None}]
        self.client.call.side_effect = [rows, {"scopes": [], "coverage": "complete", "nextCursor": None}]
        self.assertEqual(self.result("penny_search", {"query": "mixed decision"}), {"result": [private, unlabeled]})

    def test_private_filter_rejects_missing_or_malformed_scope_labels(self):
        for value in (None, "content", {"results": []}, [{"content": "Synthetic unlabeled note"}], [{"scope": {"kind": "Private"}}]):
            with self.subTest(value=value):
                self.assertEqual(plugin._private_notes(value), [])

    def test_remember_uses_note_objects_and_cannot_share_to_spaces(self):
        self.initialize()
        args = {"content": "Synthetic durable decision", "sample_questions": ["What decision was made?", "Why was it made?", "Which choice won?"], "confidence": 0.8, "tags": ["decision"]}
        self.client.call.return_value = {"ok": ["synthetic-note-id"], "failed": []}
        self.assertIn("result", self.result("penny_remember", args))
        name, payload = self.client.call.call_args.args
        self.assertEqual(name, "penny_write")
        self.assertEqual(payload["entityType"], "note")
        self.assertIsInstance(payload["notes"][0], dict)
        self.assertEqual(payload["notes"][0]["sampleQuestions"], args["sample_questions"])
        self.assertNotIn("spaceId", payload)

    def test_remember_requires_an_explicit_success_receipt(self):
        self.initialize()
        args = {"content": "Synthetic durable decision", "sample_questions": ["One?", "Two?", "Three?"], "confidence": 0.8}
        for receipt in (None, {}, {"ok": []}, {"ok": False}, {"ok": True, "failed": []}, {"ok": "synthetic-note-id", "failed": []}, {"ok": [None], "failed": []}, {"ok": [""], "failed": []}, {"ok": ["id-a", "id-b"], "failed": []}, {"ok": ["synthetic-note-id"]}, {"ok": ["synthetic-note-id"], "failed": None}, {"ok": ["synthetic-note-id"], "failed": ["synthetic failure"]}, {"ok": ["synthetic-note-id"], "failed": [], "receipts": {"synthetic-space": "synthetic-receipt"}}, {"ok": ["synthetic-note-id"], "failed": [], "receipts": None}, {"ids": ["synthetic-note-id"]}):
            with self.subTest(receipt=receipt):
                self.client.call.return_value = receipt
                value = self.result("penny_remember", args)
                self.assertIn("error", value)
                self.assertNotIn("result", value)

    def test_bad_or_unknown_tool_arguments_never_reach_penny(self):
        self.initialize()
        valid_note = {"content": "Synthetic note", "sample_questions": ["One?", "Two?", "Three?"], "confidence": 0.5}
        cases = [
            ("penny_profile", {"scope": "space"}),
            ("penny_search", {"query": "x", "scope": "space"}),
            ("penny_search", {"query": "x", "spaceId": "synthetic-space"}),
            ("penny_search", {"query": ""}),
            ("penny_search", {"query": "x", "limit": True}),
            ("penny_search", {"query": "x", "limit": 11}),
            ("penny_search", {"query": "x" * 4001}),
            ("penny_remember", {**valid_note, "spaceId": "synthetic-space"}),
            ("penny_remember", {**valid_note, "content": ""}),
            ("penny_remember", {**valid_note, "confidence": True}),
            ("penny_remember", {**valid_note, "confidence": float("nan")}),
            ("penny_remember", {**valid_note, "sample_questions": ["Only one?"]}),
            ("penny_remember", {**valid_note, "tags": [None]}),
            ("unknown_tool", {}),
        ]
        for name, args in cases:
            with self.subTest(name=name, args=args):
                self.assertIn("error", self.result(name, args))
        self.client.call.assert_not_called()

    def test_upstream_exception_details_never_appear_in_tool_responses(self):
        self.initialize()
        sentinel = "Synthetic private content and synthetic credential"
        for error in (RuntimeError(sentinel), plugin.PennyError(sentinel), plugin.AuthError(sentinel)):
            with self.subTest(error=type(error).__name__):
                self.client.call.side_effect = error
                value = self.result("penny_profile")
                self.assertIn("error", value)
                self.assertNotIn(sentinel, json.dumps(value))

    def test_queue_is_nonblocking_bounded_and_deduplicated(self):
        self.initialize()
        started = time.monotonic()
        for _ in range(1000):
            self.provider.queue_prefetch("synthetic query", session_id="session-a")
        elapsed = time.monotonic() - started
        self.assertLess(elapsed, 0.5)
        self.assertLessEqual(self.provider._jobs.qsize(), 2)
        self.assertEqual(len([item for item in self.provider._pending if item == (self.provider._generation, "search", "session-a", "synthetic query")]), 1)
        self.client.call.assert_not_called()

    def test_trivial_prompts_do_not_queue_search(self):
        self.initialize()
        before = set(self.provider._pending)
        for query in ("", "hi!", "thanks", "/help", "continue"):
            self.provider.queue_prefetch(query)
        self.assertEqual(self.provider._pending, before)

    def test_prefetch_preserves_session_boundaries_and_clears_recall_status(self):
        self.initialize()
        self.provider._profile = []
        note = {"content": "Synthetic note for session A", "scope": {"kind": "private"}}
        self.provider._recall[("session-a", "decision")] = [note]
        self.assertEqual(self.provider.prefetch("decision", session_id="session-b"), "")
        self.assertIsNone(self.provider.recall_status())
        recalled = self.provider.prefetch("decision", session_id="session-a")
        self.assertIn(note["content"], recalled)
        value = json.loads(recalled.split("\n", 1)[1])
        self.assertEqual(value["recall_query"], "decision")
        self.assertFalse(value["recall_for_previous_prompt"])
        self.assertEqual(self.provider.recall_status().count, 1)
        self.assertEqual(self.provider.prefetch("decision", session_id="session-a"), "")
        self.assertIsNone(self.provider.recall_status())

    def test_preceding_query_recall_is_honestly_annotated_and_stays_in_session(self):
        self.initialize()
        self.provider._profile = []
        old = {"content": "Synthetic older same-session note", "scope": {"kind": "private"}}
        latest = {"content": "Synthetic latest same-session note", "scope": {"kind": "private"}}
        other = {"content": "Synthetic other-session note", "scope": {"kind": "private"}}
        self.provider._recall[("session-a", "older query")] = [old]
        self.provider._recall[("session-a", "previous query")] = [latest]
        self.provider._recall[("session-b", "other session query")] = [other]
        value = json.loads(self.provider.prefetch("new query", session_id="session-a").split("\n", 1)[1])
        self.assertEqual(value["private_notes"], [latest])
        self.assertEqual(value["recall_query"], "previous query")
        self.assertTrue(value["recall_for_previous_prompt"])
        self.assertEqual(self.provider._recall[("session-b", "other session query")], [other])

    def test_trivial_prompts_do_not_consume_previous_query_recall(self):
        self.initialize()
        self.provider._profile = []
        note = {"content": "Synthetic prior prompt note", "scope": {"kind": "private"}}
        self.provider._recall[("session-a", "previous query")] = [note]
        self.assertEqual(self.provider.prefetch("thanks", session_id="session-a"), "")
        self.assertEqual(self.provider._recall[("session-a", "previous query")], [note])
        self.assertIsNone(self.provider.recall_status())

    def test_fresh_login_invalidates_all_cached_account_memory(self):
        self.initialize()
        old_generation = self.provider._generation
        self.provider._profile = ["Synthetic old-account profile"]
        self.provider._recall[("session-a", "query")] = [{"content": "Synthetic old-account note"}]
        self.auth.identity.return_value = ("https://clerk.mypenny.ai", "synthetic-client-b")
        self.assertEqual(self.provider.prefetch("query"), "")
        self.assertGreater(self.provider._generation, old_generation)
        self.assertIsNone(self.provider._profile)
        self.assertEqual(self.provider._recall, {})
        self.assertIsNone(self.provider.recall_status())
        self.client.call.assert_not_called()

    def test_logout_or_identity_failure_invalidates_caches_and_blocks_requests(self):
        self.initialize()
        self.provider._profile = ["Synthetic logged-out profile"]
        self.provider._recall[("session-a", "query")] = [{"content": "Synthetic logged-out note"}]
        self.auth.identity.return_value = None
        self.assertEqual(self.provider.prefetch("query"), "")
        self.assertIsNone(self.provider._profile)
        self.assertEqual(self.provider._recall, {})
        self.assertIn("error", self.result("penny_profile"))
        self.auth.identity.side_effect = plugin.AuthError("Synthetic identity failure")
        self.assertIn("error", self.result("penny_profile"))
        self.client.call.assert_not_called()

    def test_identity_change_during_explicit_call_never_returns_old_account_content(self):
        self.initialize()

        def call(name, args):
            self.auth.identity.return_value = ("https://clerk.mypenny.ai", "synthetic-client-b")
            return {"coreMemory": "Synthetic prior-account content"}

        self.client.call.side_effect = call
        value = self.result("penny_profile")
        self.assertIn("error", value)
        self.assertNotIn("Synthetic prior-account content", json.dumps(value))

    def test_inflight_search_is_discarded_when_session_generation_changes(self):
        self.initialize()
        # Discard the synthetic initial profile job so only a search is in flight.
        while not self.provider._jobs.empty():
            key = self.provider._jobs.get_nowait()
            self.provider._pending.discard(key)
            self.provider._jobs.task_done()
        started = threading.Event()
        release = threading.Event()

        def call(name, args):
            if name == "penny_session_start":
                return {"global": []}
            started.set()
            release.wait(2)
            return [{"content": "Synthetic stale search", "scope": {"kind": "private"}}]

        self.client.call.side_effect = call
        self.provider._enqueue("search", "old session query", "session-a")
        worker = spawn_context_thread(self.provider._run, name="penny-generation-test")
        worker.start()
        try:
            self.assertTrue(started.wait(1))
            self.provider.on_session_switch("session-b")
            release.set()
            deadline = time.monotonic() + 2
            while self.provider._jobs.unfinished_tasks and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertEqual(self.provider._recall, {})
            self.assertEqual(self.provider._session_id, "session-b")
        finally:
            release.set()
            self.provider._stop.set()
            worker.join(timeout=2)

    def test_obsolete_queued_query_is_not_sent_after_a_new_login(self):
        self.initialize()
        while not self.provider._jobs.empty():
            key = self.provider._jobs.get_nowait()
            self.provider._pending.discard(key)
            self.provider._jobs.task_done()
        self.provider._enqueue("search", "Synthetic previous-account query", "session-a")
        self.auth.identity.return_value = ("https://clerk.mypenny.ai", "synthetic-client-b")
        worker = spawn_context_thread(self.provider._run, name="penny-obsolete-job-test")
        worker.start()
        try:
            deadline = time.monotonic() + 2
            while self.provider._jobs.unfinished_tasks and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertEqual(self.provider._jobs.unfinished_tasks, 0)
            self.client.call.assert_not_called()
            self.assertEqual(self.provider._recall, {})
        finally:
            self.provider._stop.set()
            worker.join(timeout=2)

    def test_client_token_source_passes_the_captured_identity_to_atomic_auth_lookup(self):
        self.initialize()
        source = plugin.PennyClient.call_args.args[0]
        self.auth.token.return_value = "synthetic-access-token"
        self.assertEqual(source(), "synthetic-access-token")
        self.auth.token.assert_called_once_with(expected_identity=("https://clerk.mypenny.ai", "synthetic-client-a"))

    def test_explicit_save_keeps_its_pinned_client_after_account_changes(self):
        self.initialize()
        source = plugin.PennyClient.call_args.args[0]
        current_client = self.client
        new_client = MagicMock()
        plugin.PennyClient.return_value = new_client

        def token(*, expected_identity=None):
            if expected_identity != self.auth.identity():
                raise plugin.AuthError("Synthetic account mismatch")
            return "synthetic-access-token"

        def call(name, args):
            self.auth.identity.return_value = ("https://clerk.mypenny.ai", "synthetic-client-b")
            self.provider._ensure_identity()
            # The client dispatching this save still owns the original identity.
            source()
            return {"ok": ["synthetic-note-id"], "failed": []}

        self.auth.token.side_effect = token
        current_client.call.side_effect = call
        args = {"content": "Synthetic account-specific note", "sample_questions": ["One?", "Two?", "Three?"], "confidence": 0.8}
        self.assertIn("error", self.result("penny_remember", args))
        current_client.call.assert_called_once()
        new_client.call.assert_not_called()
        # A mismatched account is rejected before any token is obtained.
        self.auth.token.assert_not_called()

    def test_background_worker_stores_only_private_results_in_matching_session(self):
        self.initialize()
        done = threading.Event()
        private = {"content": "Synthetic worker note", "scope": {"kind": "private"}}

        def call(name, args):
            if name == "penny_session_start":
                return {"global": []}
            done.set()
            return [private, {"content": "Synthetic shared note", "scope": {"kind": "space"}}]

        self.client.call.side_effect = call
        self.provider._enqueue("search", "worker query", "worker-session")
        self.provider._worker = spawn_context_thread(self.provider._run, name="penny-test-worker")
        self.provider._worker.start()
        self.assertTrue(done.wait(2))
        deadline = time.monotonic() + 2
        while self.provider._jobs.unfinished_tasks and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertEqual(self.provider._recall[("worker-session", "worker query")], [private])
        self.assertNotIn(("session-a", "worker query"), self.provider._recall)

    def test_session_switch_discards_recall_and_shutdown_clears_memory(self):
        self.initialize()
        self.provider._profile = ["Synthetic profile"]
        self.provider._recall[("session-a", "query")] = [{"content": "Synthetic note"}]
        self.provider.on_session_switch("session-b")
        self.assertEqual(self.provider._session_id, "session-b")
        self.assertEqual(self.provider._recall, {})
        self.provider.shutdown()
        self.assertIsNone(self.provider._profile)
        self.assertEqual(self.provider.prefetch("query"), "")

    def test_inflight_response_cannot_restore_caches_after_shutdown(self):
        self.initialize()
        started = threading.Event()
        release = threading.Event()

        def call(name, args):
            started.set()
            release.wait(2)
            return {"global": ["Synthetic profile after shutdown"]}

        self.client.call.side_effect = call
        worker = spawn_context_thread(self.provider._run, name="penny-shutdown-test")
        worker.start()
        self.assertTrue(started.wait(1))
        self.provider.shutdown()
        release.set()
        worker.join(timeout=2)
        self.assertFalse(worker.is_alive())
        self.assertIsNone(self.provider._profile)
        self.assertEqual(self.provider._recall, {})


class LoaderTests(unittest.TestCase):
    def test_actual_hermes_discovery_loader_and_declared_config_schema(self):
        from plugins.memory import discover_memory_providers, load_memory_provider
        from plugins.memory.config_schema import get_provider_config_schema

        with tempfile.TemporaryDirectory(prefix="penny-loader-test-") as home:
            plugin_dir = Path(home) / "plugins" / "penny"
            plugin_dir.mkdir(parents=True)
            for source in ROOT.glob("*.py"):
                shutil.copy2(source, plugin_dir / source.name)
            shutil.copy2(ROOT / "plugin.yaml", plugin_dir / "plugin.yaml")
            (Path(home) / "config.yaml").write_text("memory:\n  provider: penny\n", encoding="utf-8")
            with patch.dict(os.environ, {"HERMES_HOME": home}, clear=False):
                names = {name for name, _description, _installed in discover_memory_providers()}
                self.assertIn("penny", names)
                provider = load_memory_provider("penny")
                self.assertIsInstance(provider, MemoryProvider)
                self.assertEqual(provider.name, "penny")
                if (plugin_dir / "config_schema.py").exists():
                    schema = get_provider_config_schema("penny")
                    self.assertEqual(schema.name, "penny")
                    token_fields = [field for field in schema.fields if field.env_key == "PENNY_ACCESS_TOKEN"]
                    self.assertTrue(token_fields)
                    self.assertTrue(all(field.is_secret for field in token_fields))
                provider.shutdown()


if __name__ == "__main__":
    unittest.main()
