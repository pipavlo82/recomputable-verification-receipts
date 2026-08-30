import json
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PYTHON_ADAPTER = ROOT / "conformance/rvr-v0/adapter.py"
TYPESCRIPT_ADAPTER = ROOT / "conformance/rvr-v0/adapter.ts"


class RvrV0ConformanceTests(unittest.TestCase):
    def run_gate(self, command, cwd=ROOT):
        completed = subprocess.run(
            command,
            cwd=cwd,
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
            self.assertEqual(
                report["cases"]["REQUIRED_DEPENDENCY_IDENTITY_MISMATCH"]["recomputationStatus"],
                "CANNOT_RECOMPUTE",
            )
            self.assertEqual(
                report["cases"]["PRESENT_PAYLOAD_UNRESOLVED"]["recomputationStatus"],
                "CANNOT_RECOMPUTE",
            )
            self.assertEqual(
                report["cases"]["RESOLVED_PAYLOAD_IDENTITY_MISMATCH"]["gateStatus"],
                "REJECTED",
            )
            self.assertEqual(
                report["cases"]["OPTIONAL_DEPENDENCY_NONSEMANTIC"],
                report["cases"]["REPRODUCED"],
            )
        self.assertNotEqual(python_report["implementation"], typescript_report["implementation"])
        self.assertEqual(
            python_report["verificationProfileDigest"],
            typescript_report["verificationProfileDigest"],
        )
        self.assertEqual(python_report["canonicalByteVectors"], typescript_report["canonicalByteVectors"])
        self.assertEqual(python_report["canonicalByteVectors"]["passed"], 13)
        self.assertEqual(python_report["dependencyResolver"], typescript_report["dependencyResolver"])
        self.assertEqual(python_report["dependencyResolver"]["passed"], 7)
        self.assertEqual(python_report["profileSchemaBoundary"], typescript_report["profileSchemaBoundary"])
        self.assertTrue(python_report["profileSchemaBoundary"]["genericManifestAccepted"])
        self.assertFalse(
            python_report["profileSchemaBoundary"]["sha256EqualsConstraintsAccepted"]
        )
        self.assertTrue(
            python_report["profileSchemaBoundary"]["tamperedConstraintsPinRejected"]
        )
        self.assertEqual(python_report["cases"], typescript_report["cases"])
        self.assertEqual(
            python_report["adversarialSemanticMutants"],
            typescript_report["adversarialSemanticMutants"],
        )
        self.assertEqual(python_report["adversarialSemanticMutants"]["killed"], 6)
        self.assertEqual(
            python_report["adversarialSemanticMutants"]["killed"],
            python_report["adversarialSemanticMutants"]["total"],
        )

    def test_profile_package_root_is_not_process_cwd(self):
        commands = (
            [sys.executable, str(PYTHON_ADAPTER), "--check"],
            ["bun", str(TYPESCRIPT_ADAPTER), "--check"],
        )
        for command in commands:
            with self.subTest(command=command[0]):
                report = self.run_gate(command, cwd=ROOT.parent)
                self.assertEqual(report["gate"], "RVR_V0_CONFORMANCE_PASS")
                self.assertEqual(report["dependencyResolver"]["passed"], 7)


if __name__ == "__main__":
    unittest.main()
