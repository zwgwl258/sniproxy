import importlib.util
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "deploy"))
spec = importlib.util.spec_from_file_location("health", Path(sys.path[0]) / "dns-health.py")
health = importlib.util.module_from_spec(spec)
spec.loader.exec_module(health)


class HealthTests(unittest.TestCase):
    def setUp(self):
        self.calls = []
        self.good = {"b"}
        def probe(server, domains):
            self.calls.append((server, domains))
            return dict(proxy=[10 if server in self.good else None for _ in domains])
        self.policy = health.Policy(probe)
        self.group = dict(preferred="a", standby=["b", "c"])
        self.bad = dict(started=60, connected=10, failed=40, cancelled=0,
                        pending=10, reset=0, connect_ms=10, upstreams=["192.0.2.1:443"])

    def check(self, stats=None, now=1000):
        return self.policy.check("login.example,video.example", self.group,
                                 stats or self.bad, ["video.example"], ["a", "b", "c"], now)

    def test_no_traffic_or_fast_challenger_does_not_switch(self):
        quiet = dict(connected=0, failed=0, pending=0, reset=0)
        for _ in range(4):
            self.assertFalse(self.check(quiet))
        self.assertEqual(self.group["preferred"], "a")
        self.assertEqual(self.calls, [])

    def test_two_windows_and_retest_then_whole_group_switch(self):
        self.assertFalse(self.check())
        self.assertTrue(self.check())
        self.assertEqual(self.group["preferred"], "b")
        self.assertEqual(self.group["cooldown"]["a"], 1600)
        text = health.route_text({"login.example,video.example": self.group}, 1000).decode()
        self.assertIn("login.example b !\nvideo.example b !\n", text)
        self.assertTrue(all("video.example" in domains for _, domains in self.calls))

    def test_original_passes_retest_or_all_backups_fail_keeps_current(self):
        self.good = {"a", "b"}
        self.check()
        self.assertFalse(self.check())
        self.assertEqual(self.group["preferred"], "a")
        self.good = set()
        self.check()
        self.assertFalse(self.check())
        self.assertEqual(self.group["preferred"], "a")

    def test_cooled_candidate_is_not_used(self):
        self.group["cooldown"] = {"b": 2000}
        self.check()
        self.assertFalse(self.check())
        self.assertNotIn("b", [server for server, _ in self.calls])

    def test_client_cancellation_not_counted_as_failure(self):
        events = [(0, "started", 0, "ip"), (1, "cancelled", 0, "ip")]
        stats = health.metrics(events)
        self.assertEqual(stats["failed"], 0)
        self.assertEqual(stats["pending"], 0)
        self.assertFalse(health.suspicious(stats))

    def test_different_dns_with_same_failing_upstream_is_not_a_backup(self):
        def probe(server, domains):
            return dict(proxy=[None if server == "a" else 10 for _ in domains],
                        addresses=[["192.0.2.99"] for _ in domains])
        self.policy = health.Policy(probe)
        self.check()
        self.assertFalse(self.check())
        self.assertEqual(self.group["preferred"], "a")

    def test_expected_api_http_errors_are_not_transport_outages(self):
        def probe(server, domains):
            return dict(proxy=[None for _ in domains],
                        status=[403 if server == "b" else 0 for _ in domains])
        self.policy = health.Policy(probe)
        self.check()
        self.assertTrue(self.check())
        self.assertEqual(self.group["preferred"], "b")


if __name__ == "__main__":
    unittest.main()
