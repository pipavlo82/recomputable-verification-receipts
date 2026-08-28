import json
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
ADAPTER = Path(__file__).with_name("adapter.py")


class Erc8281CommittedReceiptProfileTests(unittest.TestCase):
    def test_exact_gate(self) -> None:
        completed = subprocess.run(
            [sys.executable, str(ADAPTER), "--check"],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
        report = json.loads(completed.stdout)
        self.assertEqual(report["gate"], "RVR_ERC8281_COMMITTED_RECEIPT_SNAPSHOT_PASS")
        self.assertEqual(report["snapshotAssurance"], "COMMITTED_RECEIPT_SNAPSHOT")
        self.assertEqual(report["hashFunctionCases"]["passed"], 3)
        self.assertEqual(report["semanticFailures"]["passed"], 12)
        self.assertEqual(report["cases"]["REPRODUCED"]["recomputationStatus"], "REPRODUCED")
        self.assertEqual(report["cases"]["DIVERGED"]["recomputationStatus"], "DIVERGED")
        self.assertEqual(
            report["cases"]["CANNOT_RECOMPUTE"]["recomputationStatus"],
            "CANNOT_RECOMPUTE",
        )


if __name__ == "__main__":
    unittest.main()
