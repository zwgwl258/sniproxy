from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "deploy"))
import panel


def snapshot(sequence=2, pid=123, epoch=1700000000000000):
    header = f"{sequence:020d} {pid:010d} {epoch:020d}\n".encode().ljust(64, b"\x00")
    return header + f"{time.time()} 5\n- {b'.*example.com$'.hex()} 1000000 2000000 500000 1000000\n".encode()


class TrafficTests(unittest.TestCase):
    def test_snapshot_and_epoch_are_preserved(self):
        with tempfile.TemporaryDirectory() as tmp:
            file = Path(tmp) / "snapshot"
            file.write_bytes(snapshot())
            data = panel.read_traffic_snapshot(file, 123)
            self.assertEqual(data["epoch"], 1700000000000000)
            self.assertEqual(data["records"], [("", ".*example.com$", [1000000, 2000000, 500000, 1000000])])
            with self.assertRaises(ValueError):
                panel.read_traffic_snapshot(file, 456)
            file.write_bytes(snapshot(sequence=3))
            with self.assertRaises(ValueError):
                panel.read_traffic_snapshot(file, 123)

    def test_native_pattern_follows_config_tokenizer(self):
        self.assertEqual(panel.native_pattern(r'.*example\.com$ *'), ".*example.com$")
        self.assertEqual(panel.native_pattern(r'"^host[0-9]+[.]example[.]com$" *'), "^host[0-9]+[.]example[.]com$")

    def test_group_rates_totals_and_unclassified_rules(self):
        config = r"""table {
    .*example\.com$ *

    ^host[0-9]+[.]other[.]net$ *
}
"""
        data = dict(epoch=1700000000000000, time=time.time(), interval=5,
                    records=[("", ".*example.com$", [1000000, 2000000, 500000, 1000000]),
                             ("", "^host[0-9]+[.]other[.]net$", [0, 1000000, 0, 500000]),
                             ("custom", "other", [0, 1000000, 0, 0])])
        with patch.object(panel, "command", return_value=subprocess.CompletedProcess([], 0, "123\n")), \
                patch.object(panel, "read_traffic_snapshot", return_value=data):
            html = panel.traffic_status(config)
            self.assertIn("<td>0.10</td><td>0.20</td>", html)
            self.assertIn("其他／未归组", html)
            self.assertIn("<td>5.00</td><td>100.0%</td>", html)
            self.assertIn("累计起点", html)

    def test_stale_snapshot_does_not_claim_current_speed(self):
        with patch.object(panel, "command", return_value=subprocess.CompletedProcess([], 0, "123")), \
                patch.object(panel, "read_traffic_snapshot", return_value=dict(
                    epoch=1700000000000000, time=time.time() - 60, interval=5,
                    records=[("", "other", [1, 2, 99999999, 99999999])])):
            self.assertIn("快照已过期", panel.traffic_status(""))


if __name__ == "__main__":
    unittest.main()
