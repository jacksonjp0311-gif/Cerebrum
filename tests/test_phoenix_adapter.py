"""Tests for the Phoenix adapter boundary.

Verifies that private files are always denied and only explicitly
allowed file types under allowed paths pass through.
"""

import json
import tempfile
import unittest
from pathlib import Path

from phoenix_adapter import (
    PhoenixPolicy,
    audit_boundary,
    build_context_packet,
    classify,
    is_denied,
    is_allowed,
    walk_phoenix,
)


class DenyListTests(unittest.TestCase):
    """Every deny pattern must block its target, non-overridable."""

    def test_denies_soul_md(self):
        self.assertIsNotNone(is_denied("SOUL.md"))
        self.assertIsNotNone(is_denied("agents/lyra/SOUL.md"))
        self.assertIsNotNone(is_denied("deep/nested/path/SOUL.md"))

    def test_denies_journal_md(self):
        self.assertIsNotNone(is_denied("JOURNAL.md"))
        self.assertIsNotNone(is_denied("agents/lyra/JOURNAL.md"))

    def test_denies_memory_md(self):
        self.assertIsNotNone(is_denied("MEMORY.md"))
        self.assertIsNotNone(is_denied("agents/lyra/MEMORY.md"))

    def test_denies_memory_directory(self):
        self.assertIsNotNone(is_denied("memory/sessions/session_001.md"))
        self.assertIsNotNone(is_denied("agents/lyra/memory/something.md"))

    def test_denies_phone_sessions(self):
        self.assertIsNotNone(is_denied("phone_sessions/phone_001.md"))
        self.assertIsNotNone(is_denied("agents/lyra/memory/phone_sessions/phone_2026.md"))

    def test_denies_pre_compression_notes(self):
        self.assertIsNotNone(is_denied("PRE_COMPRESSION_20260712.md"))
        self.assertIsNotNone(is_denied("agents/lyra/memory/PRE_COMPRESSION_20260713.md"))

    def test_denies_env_files(self):
        self.assertIsNotNone(is_denied(".env"))
        self.assertIsNotNone(is_denied(".env.local"))
        self.assertIsNotNone(is_denied("project/.env.production"))

    def test_denies_credentials(self):
        self.assertIsNotNone(is_denied("api_key.txt"))
        self.assertIsNotNone(is_denied("config/credentials.json"))
        self.assertIsNotNone(is_denied("secret_token.py"))

    def test_denies_conversation_archives(self):
        self.assertIsNotNone(is_denied("conversations/2026-07-12.json"))
        self.assertIsNotNone(is_denied("chat_log.md"))
        self.assertIsNotNone(is_denied("session_transcript.txt"))

    def test_denies_personal_data(self):
        self.assertIsNotNone(is_denied("relationship_notes.md"))
        self.assertIsNotNone(is_denied("personal_journal.md"))

    def test_allows_source_code(self):
        allowed, reason = is_allowed("src/main.py", PhoenixPolicy(phoenix_root=Path("/tmp")))
        self.assertTrue(allowed)

    def test_allows_schema_files(self):
        allowed, _ = is_allowed("config/schema.json", PhoenixPolicy(phoenix_root=Path("/tmp")))
        self.assertTrue(allowed)

    def test_denies_markdown_outside_doc_paths(self):
        allowed, _ = is_allowed("random_notes.md", PhoenixPolicy(phoenix_root=Path("/tmp")))
        self.assertFalse(allowed)

    def test_allows_markdown_in_docs(self):
        allowed, _ = is_allowed("docs/architecture.md", PhoenixPolicy(phoenix_root=Path("/tmp")))
        self.assertTrue(allowed)

    def test_allows_readme_anywhere(self):
        allowed, _ = is_allowed("README.md", PhoenixPolicy(phoenix_root=Path("/tmp")))
        self.assertTrue(allowed)

    def test_allows_changelog(self):
        allowed, _ = is_allowed("CHANGELOG.md", PhoenixPolicy(phoenix_root=Path("/tmp")))
        self.assertTrue(allowed)

    def test_source_code_in_memory_dir_still_denied(self):
        """Even a .py file inside memory/ is denied."""
        allowed, _ = is_allowed("memory/tool.py", PhoenixPolicy(phoenix_root=Path("/tmp")))
        self.assertFalse(allowed)

    def test_env_extension_in_memory_dir_still_denied(self):
        """Deny takes priority over allow."""
        allowed, _ = is_allowed("memory/.env", PhoenixPolicy(phoenix_root=Path("/tmp")))
        self.assertFalse(allowed)


class WalkAndCollectTests(unittest.TestCase):
    """End-to-end boundary test with a real temp directory tree."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)

        # ALLOWED files
        (root / "src").mkdir()
        (root / "src" / "main.py").write_text("# entry point\n")
        (root / "src" / "utils.rs").write_text("fn main() {}\n")

        (root / "docs").mkdir()
        (root / "docs" / "architecture.md").write_text("# Architecture\n")
        (root / "docs" / "api.md").write_text("# API Reference\n")

        (root / "README.md").write_text("# Project\n")
        (root / "schema.json").write_text('{"type": "object"}\n')

        # DENIED files
        (root / "SOUL.md").write_text("# private identity\n")
        (root / "JOURNAL.md").write_text("# private thoughts\n")
        (root / "MEMORY.md").write_text("# private memory\n")

        (root / "memory").mkdir()
        (root / "memory" / "session_001.md").write_text("# session\n")
        (root / "memory" / "tool.py").write_text("# private tool\n")

        (root / "phone_sessions").mkdir()
        (root / "phone_sessions" / "phone_001.md").write_text("# phone\n")

        (root / ".env").write_text("SECRET=abc123\n")
        (root / "config_api_key.json").write_text('{"key": "leaked"}\n')

        # Markdown outside docs/ — should be denied
        (root / "notes.md").write_text("# random notes\n")

        self.policy = PhoenixPolicy(phoenix_root=root)

    def tearDown(self):
        self.tmp.cleanup()

    def test_audit_separates_allowed_and_denied(self):
        report = audit_boundary(self.policy)
        allowed_paths = {e["path"] for e in report["allowed"]}
        denied_paths = {e["path"] for e in report["denied"]}

        # Allowed
        self.assertIn("src/main.py", allowed_paths)
        self.assertIn("src/utils.rs", allowed_paths)
        self.assertIn("docs/architecture.md", allowed_paths)
        self.assertIn("docs/api.md", allowed_paths)
        self.assertIn("README.md", allowed_paths)
        self.assertIn("schema.json", allowed_paths)

        # Denied
        self.assertIn("SOUL.md", denied_paths)
        self.assertIn("JOURNAL.md", denied_paths)
        self.assertIn("MEMORY.md", denied_paths)
        self.assertIn("memory/session_001.md", denied_paths)
        self.assertIn("memory/tool.py", denied_paths)
        self.assertIn("phone_sessions/phone_001.md", denied_paths)
        self.assertIn(".env", denied_paths)
        self.assertIn("config_api_key.json", denied_paths)
        self.assertIn("notes.md", denied_paths)

    def test_context_packet_excludes_denied_content(self):
        packet = build_context_packet(self.policy)

        # Check allowed files have content
        content_paths = {f["path"] for f in packet["files"]}
        self.assertIn("src/main.py", content_paths)
        self.assertIn("docs/architecture.md", content_paths)

        # Check denied files are NOT in the packet
        self.assertNotIn("SOUL.md", content_paths)
        self.assertNotIn("JOURNAL.md", content_paths)
        self.assertNotIn("MEMORY.md", content_paths)
        self.assertNotIn("memory/session_001.md", content_paths)
        self.assertNotIn("memory/tool.py", content_paths)
        self.assertNotIn("phone_sessions/phone_001.md", content_paths)
        self.assertNotIn(".env", content_paths)

        # Verify denied count
        self.assertGreater(packet["denied_count"], 0)

        # Verify no leaked secrets in any file content
        for f in packet["files"]:
            self.assertNotIn("SECRET=abc123", f["content"])
            self.assertNotIn("private identity", f["content"])
            self.assertNotIn("private memory", f["content"])

    def test_denied_files_count_matches_audit(self):
        audit = audit_boundary(self.policy)
        packet = build_context_packet(self.policy)
        self.assertEqual(audit["denied_count"], packet["denied_count"])


class LogFileTests(unittest.TestCase):
    """Log files require explicit opt-in."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        (root / "app.log").write_text("2026-07-13 INFO startup\n")
        self.root = root

    def tearDown(self):
        self.tmp.cleanup()

    def test_logs_denied_by_default(self):
        policy = PhoenixPolicy(phoenix_root=self.root, allow_log_files=False)
        packet = build_context_packet(policy)
        paths = {f["path"] for f in packet["files"]}
        self.assertNotIn("app.log", paths)

    def test_logs_allowed_when_opted_in(self):
        policy = PhoenixPolicy(phoenix_root=self.root, allow_log_files=True)
        packet = build_context_packet(policy)
        paths = {f["path"] for f in packet["files"]}
        self.assertIn("app.log", paths)


class RelayPhoenixIntegrationTests(unittest.TestCase):
    """Verify the relay correctly routes Phoenix tools."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.policy_path = Path(self.tmp.name) / "policy.json"

    def tearDown(self):
        self.tmp.cleanup()

    def test_phoenix_tools_denied_without_config(self):
        import cerebrum_relay as relay
        self.policy_path.write_text(
            json.dumps({
                "allowed_repositories": [],
                "phoenix_root": None,
            }),
            encoding="utf-8",
        )
        policy = relay.load_policy(self.policy_path)
        with self.assertRaises(PermissionError):
            relay.handle_tool_call("cerebrum_phoenix_audit", {}, policy)

    def test_phoenix_audit_works_with_config(self):
        import cerebrum_relay as relay

        phoenix_dir = Path(self.tmp.name) / "phoenix"
        phoenix_dir.mkdir()
        (phoenix_dir / "src").mkdir()
        (phoenix_dir / "src" / "main.py").write_text("# ok\n")
        (phoenix_dir / "SOUL.md").write_text("# private\n")

        self.policy_path.write_text(
            json.dumps({
                "allowed_repositories": [],
                "phoenix_root": str(phoenix_dir),
            }),
            encoding="utf-8",
        )
        policy = relay.load_policy(self.policy_path)
        result = relay.handle_tool_call("cerebrum_phoenix_audit", {}, policy)
        self.assertIn("allowed", result)
        self.assertIn("denied", result)
        allowed_paths = {e["path"] for e in result["allowed"]}
        denied_paths = {e["path"] for e in result["denied"]}
        self.assertIn("src/main.py", allowed_paths)
        self.assertIn("SOUL.md", denied_paths)


if __name__ == "__main__":
    unittest.main()
