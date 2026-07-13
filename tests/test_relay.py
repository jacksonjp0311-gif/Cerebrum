import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import cerebrum_relay as relay


class RelayTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.policy_path = Path(self.directory.name) / "policy.json"
        self.policy_path.write_text(json.dumps({"allowed_repositories": ["Cortex"], "max_query_characters": 100, "max_results": 3, "command_timeout_seconds": 5}), encoding="utf-8")
        self.policy = relay.load_policy(self.policy_path)

    def tearDown(self):
        self.directory.cleanup()

    def test_denies_unallowlisted_repository(self):
        with self.assertRaises(PermissionError):
            relay.handle_tool_call("cerebrum_health", {"repo_name": "private"}, self.policy)

    def test_status_is_scoped_to_an_allowlisted_repository(self):
        with self.assertRaises(PermissionError):
            relay.handle_tool_call("cerebrum_status", {}, self.policy)

    def test_denies_mutating_or_unknown_tools(self):
        with self.assertRaises(PermissionError):
            relay.handle_tool_call("cortex_index", {}, self.policy)

    @patch("cerebrum_relay.execute_cortex", return_value={"status": "ok"})
    def test_query_is_bounded_and_allowlisted(self, execute):
        result = relay.handle_tool_call("cerebrum_query", {"repo_name": "Cortex", "query": "check policy", "limit": 3}, self.policy)
        self.assertEqual({"status": "ok"}, result)
        self.assertEqual(["query", "--repo", "Cortex", "check policy", "--limit", "3", "--json"], execute.call_args.args[0])

    def test_never_offers_network_or_maintenance_tools(self):
        names = {tool["name"] for tool in relay.tool_schemas()}
        self.assertEqual({"cerebrum_status", "cerebrum_health", "cerebrum_query", "cerebrum_context", "cerebrum_phoenix_audit", "cerebrum_phoenix_context"}, names)


if __name__ == "__main__":
    unittest.main()
