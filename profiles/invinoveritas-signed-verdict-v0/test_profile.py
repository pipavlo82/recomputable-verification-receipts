import json
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
ADAPTER = Path(__file__).with_name("adapter.py")


class InvinoveritasSignedVerdictProfileTests(unittest.TestCase):
    def test_exact_gate(self) -> None:
        completed = subprocess.run(
            [sys.executable, str(ADAPTER), "--check"],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
        report = json.loads(completed.stdout)
        self.assertEqual(report["gate"], "RVR_INVINO_SIGNED_VERDICT_PASS")
        self.assertEqual(report["cases"]["REPRODUCED"]["recomputationStatus"], "REPRODUCED")
        self.assertEqual(report["cases"]["DIVERGED"]["recomputationStatus"], "DIVERGED")
        self.assertEqual(report["cases"]["CANNOT_RECOMPUTE"]["recomputationStatus"], "CANNOT_RECOMPUTE")
        self.assertEqual(report["cases"]["JUDGMENT_BOUNDARY"]["producerVerdict"], "approve_with_concerns")
        self.assertFalse(report["cases"]["JUDGMENT_BOUNDARY"]["producerVerdictEqualsRvrOutcome"])
        self.assertEqual(report["semanticFailures"]["passed"], 6)


if __name__ == "__main__":
    unittest.main()
