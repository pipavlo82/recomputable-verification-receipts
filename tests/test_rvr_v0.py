import json
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PYTHON_ADAPTER = ROOT / "conformance/rvr-v0/adapter.py"
TYPESCRIPT_ADAPTER = ROOT / "conformance/rvr-v0/adapter.ts"


class RvrV0ConformanceTests(unittest.TestCase):
    def run_gate(self, command):
        completed = subprocess.run(
            command,
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        return json.loads(completed.stdout)

    def test_independent_implementations_agree(self):
        python_report = self.run_gate([sys.executable, str(PYTHON_ADAPTER), "--check"])
        typescript_report = self.run_gate(["bun", str(TYPESCRIPT_ADAPTER), "--check"])
        for report in (python_report, typescript_report):
            self.assertEqual(report["gate"], "RVR_V0_CONFORMANCE_PASS")
            self.assertEqual(report["cases"]["REPRODUCED"]["recomputationStatus"], "REPRODUCED")
            self.assertEqual(report["cases"]["DIVERGED"]["recomputationStatus"], "DIVERGED")
            self.assertEqual(
                report["cases"]["CANNOT_RECOMPUTE"]["recomputationStatus"],
                "CANNOT_RECOMPUTE",
            )
        self.assertNotEqual(python_report["implementation"], typescript_report["implementation"])
        self.assertEqual(
            python_report["verificationProfileDigest"],
            typescript_report["verificationProfileDigest"],
        )
        self.assertEqual(python_report["canonicalByteVectors"], typescript_report["canonicalByteVectors"])
        self.assertEqual(python_report["cases"], typescript_report["cases"])


if __name__ == "__main__":
    unittest.main()
