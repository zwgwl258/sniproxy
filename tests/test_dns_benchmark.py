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
    ^host[0-9]+[.]example[.]net$ *
}
resolver {
    client fallback
    nameserver 192.0.2.1
    nameserver 192.0.2.2
    mode ipv4_only
}
"""), (["example.com", "example.org"], ["192.0.2.1", "192.0.2.2"]))

    def test_rank_and_hysteresis(self):
        round1 = {"a": {"proxy": [20, None], "dns": [1, 1]},
                  "b": {"proxy": [120, 130], "dns": [20, 20]}}
        scores = benchmark.summarize([round1], round1)
        self.assertEqual(benchmark.select(scores, "a", "", round1), ("a", "b"))
        self.assertEqual(benchmark.select(scores, "a", "b", round1), ("b", ""))
        round2 = {**round1, "a": {"proxy": [None, None], "dns": [1, 1]}}
        self.assertEqual(benchmark.select(scores, "a", "", round2), ("b", ""))

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


if __name__ == "__main__":
    unittest.main()
