import json
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ADAPTER = ROOT / "conformance/rvr-v0/adapter.py"


class RvrV0ConformanceTests(unittest.TestCase):
    def test_complete_gate(self):
        completed = subprocess.run(
            [sys.executable, str(ADAPTER), "--check"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        report = json.loads(completed.stdout)
        self.assertEqual(report["gate"], "RVR_V0_CONFORMANCE_PASS")
        self.assertEqual(report["cases"]["REPRODUCED"]["recomputationStatus"], "REPRODUCED")
        self.assertEqual(report["cases"]["DIVERGED"]["recomputationStatus"], "DIVERGED")
        self.assertEqual(
            report["cases"]["CANNOT_RECOMPUTE"]["recomputationStatus"],
            "CANNOT_RECOMPUTE",
        )


if __name__ == "__main__":
    unittest.main()
