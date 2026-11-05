from pathlib import Path
import json
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "deploy"))
import panel


class ClientMonitorTests(unittest.TestCase):
    def test_counts_only_inbound_established_sockets_of_production_pid(self):
        output = '''LISTEN 0 4096 0.0.0.0:443 0.0.0.0:* users:(("sniproxy",pid=123,fd=7))
LISTEN 0 4096 [::]:8080 [::]:* users:(("sniproxy",pid=123,fd=8))
ESTAB 0 0 192.0.2.1:443 198.51.100.2:1001 users:(("sniproxy",pid=123,fd=9))
ESTAB 0 0 192.0.2.1:443 198.51.100.2:1002 users:(("sniproxy",pid=123,fd=10))
ESTAB 0 0 [2001:db8::1]:8080 [2001:db8::2]:1003 users:(("sniproxy",pid=123,fd=11))
ESTAB 0 0 [::ffff:192.0.2.1]:443 [::ffff:198.51.100.2]:1004 users:(("sniproxy",pid=123,fd=12))
ESTAB 0 0 192.0.2.1:50000 203.0.113.1:443 users:(("sniproxy",pid=123,fd=13))
SYN-SENT 0 1 192.0.2.1:50001 203.0.113.1:443 users:(("sniproxy",pid=123,fd=14))
ESTAB 0 0 127.0.0.1:443 127.0.0.1:1234 users:(("sniproxy",pid=1234,fd=15))
'''
        counts, listening = panel.client_connections(output, 123)
        self.assertTrue(listening)
        self.assertEqual(counts, {"198.51.100.2": 3, "2001:db8::2": 1})

    def test_no_listener_does_not_mislabel_upstreams_as_clients(self):
        counts, listening = panel.client_connections(
            'ESTAB 0 0 192.0.2.1:50000 203.0.113.1:443 users:(("sniproxy",pid=123,fd=9))', 123)
        self.assertEqual(counts, {})
        self.assertFalse(listening)

    def test_whitelist_persists_normalizes_and_does_not_restart(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(panel, "ROOT", Path(tmp)), \
                patch.object(panel, "restart") as restart, \
                patch.object(panel, "atomic_write", side_effect=lambda p, b, **kw: p.write_bytes(b)) as write:
            panel.update_client_whitelist("::ffff:198.51.100.2")
            panel.update_client_whitelist("198.51.100.2")
            panel.update_client_whitelist("2001:db8::2")
            self.assertEqual(panel.client_whitelist(), {"198.51.100.2", "2001:db8::2"})
            panel.update_client_whitelist("198.51.100.2", remove=True)
            self.assertEqual(panel.client_whitelist(), {"2001:db8::2"})
            self.assertEqual(write.call_args.kwargs["mode"], 0o600)
            restart.assert_not_called()
            before = (Path(tmp) / "client-whitelist.json").read_bytes()
            with self.assertRaises(ValueError):
                panel.update_client_whitelist("198.51.100.0/24")
            self.assertEqual((Path(tmp) / "client-whitelist.json").read_bytes(), before)

    def test_corrupt_whitelist_is_not_silently_overwritten(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(panel, "ROOT", Path(tmp)):
            path = Path(tmp) / "client-whitelist.json"
            path.write_text('{"not":"a list"}')
            with self.assertRaises(ValueError):
                panel.update_client_whitelist("198.51.100.2")
            self.assertEqual(json.loads(path.read_text()), {"not": "a list"})

    def test_all_and_exclude_whitelisted_views_and_search(self):
        with patch.object(panel, "client_whitelist", return_value={"198.51.100.2"}), \
                patch.object(panel, "current_clients", return_value=({"198.51.100.2": 4, "203.0.113.3": 2}, "")):
            def rows(mode, query=""):
                return panel.client_monitor_page(mode, query).split("<tbody>", 1)[1].split("</tbody>", 1)[0]
            self.assertIn("198.51.100.2", rows("all"))
            self.assertNotIn("198.51.100.2", rows("unknown"))
            self.assertIn("203.0.113.3", rows("unknown"))
            self.assertNotIn("203.0.113.3", rows("all", "198.51"))

    def test_inactive_service_does_not_query_unrelated_connections(self):
        with patch.object(panel, "command", return_value=subprocess.CompletedProcess([], 0, "0\n", "")) as run:
            self.assertEqual(panel.current_clients(), ({}, "代理未运行。"))
            self.assertEqual(run.call_count, 1)


if __name__ == "__main__":
    unittest.main()
