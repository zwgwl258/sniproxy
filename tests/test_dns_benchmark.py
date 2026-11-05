import importlib.util
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

DEPLOY = Path(__file__).resolve().parents[1] / "deploy"
sys.path.insert(0, str(DEPLOY))
spec = importlib.util.spec_from_file_location("benchmark", DEPLOY / "dns-benchmark.py")
benchmark = importlib.util.module_from_spec(spec)
spec.loader.exec_module(benchmark)


class BenchmarkTests(unittest.TestCase):
    def test_targets_from_config(self):
        self.assertEqual(benchmark.targets(r"""
table {
    .*example\.com$ *
    .*example\.org$ *
    .*example\.net$ *
    .*example\.edu$ *
    ^host[0-9]+[.]example[.]net$ *
}
resolver {
    client fallback
    nameserver 192.0.2.1
    nameserver 192.0.2.2
    mode ipv4_only
}
"""), (["example.com", "example.org", "example.net", "example.edu"], ["192.0.2.1", "192.0.2.2"]))

    def test_rank_preserves_incumbent(self):
        round1 = {"a": {"proxy": [20, None], "dns": [1, 1]},
                  "b": {"proxy": [120, 130], "dns": [20, 20]}}
        scores = benchmark.summarize([round1], round1)
        self.assertEqual(benchmark.select(scores, "a", "", round1), ("a", ""))
        self.assertEqual(benchmark.select(scores, "a", "b", round1), ("a", ""))
        round2 = {**round1, "a": {"proxy": [None, None], "dns": [1, 1]}}
        self.assertEqual(benchmark.select(scores, "a", "", round2), ("a", ""))
        self.assertEqual(benchmark.select(scores, "removed", "", round2), ("b", ""))
        self.assertEqual(benchmark.standby_order(scores, round1, "a"), ["b"])

    def test_proxy_retains_domain_and_targets_loopback(self):
        with patch.object(benchmark, "command", return_value="200 0.120") as run:
            self.assertEqual(benchmark.proxy_ms(9876, "example.com"), 120)
            self.assertIn("example.com:443:127.0.0.1:9876", run.call_args.args)
            self.assertIn("https://example.com/", run.call_args.args)
        with patch.object(benchmark, "command", return_value="503 0.100"):
            self.assertIsNone(benchmark.proxy_ms(9876, "example.com"))

    def test_dns_requires_an_address(self):
        with patch.object(benchmark, "command", return_value="alias.example.com."):
            self.assertIsNone(benchmark.dns_ms("192.0.2.1", "example.com"))
        with patch.object(benchmark, "command", return_value="192.0.2.2"):
            self.assertIsNotNone(benchmark.dns_ms("192.0.2.1", "example.com"))

    def test_measure_skips_https_for_failed_dns_and_preserves_order(self):
        domains = ["ok.example", "failed.example", "other.example"]
        with patch.object(benchmark.subprocess, "Popen") as process, \
                patch.object(benchmark.socket, "create_connection"), \
                patch.object(benchmark, "dns_ms", side_effect=lambda server, domain:
                             None if domain == "failed.example" else 10), \
                patch.object(benchmark, "proxy_probe", return_value=(25, 200)) as probe:
            process.return_value.__enter__.return_value.poll.return_value = None
            result = benchmark.measure("192.0.2.1", domains)
        self.assertEqual(result, {"dns": [10, None, 10],
                                  "proxy": [25, None, 25],
                                  "status": [200, 0, 200]})
        self.assertEqual(probe.call_count, 2)


if __name__ == "__main__":
    unittest.main()
