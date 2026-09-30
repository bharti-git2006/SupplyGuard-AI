"""Unit tests for SupplyGuard AI data models."""

import unittest
from core.models import (
    SeverityLevel,
    FindingCategory,
    SecurityFinding,
    RiskChain,
    AIAnalysisResult,
    ScanReport,
)


class TestModels(unittest.TestCase):
    def test_security_finding_serialization(self):
        finding = SecurityFinding(
            id="SEC-001",
            category=FindingCategory.EXPOSED_SECRET,
            severity=SeverityLevel.HIGH,
            title="Potential secret detected: AWS Access Key",
            description="A pattern matching an AWS Access Key ID was identified.",
            file_path=".env",
            line_number=3,
            snippet="AKIAIOSFODNN7E******",
            explanation="Hardcoded credentials in config files can be exfiltrated.",
            remediation="Move secret to local secret store or environment variable.",
            metadata={"pattern_type": "aws_key"}
        )
        d = finding.to_dict()
        self.assertEqual(d["id"], "SEC-001")
        self.assertEqual(d["category"], "EXPOSED_SECRET")
        self.assertEqual(d["severity"], "HIGH")
        self.assertEqual(d["file_path"], ".env")
        self.assertEqual(d["line_number"], 3)
        self.assertEqual(d["snippet"], "AKIAIOSFODNN7E******")

    def test_risk_chain_linking(self):
        chain = RiskChain(
            id="CHAIN-01",
            rule_id="RULE_B",
            title="Potential credential exposure through installation behavior",
            composite_severity=SeverityLevel.CRITICAL,
            risk_priority_score=9.2,
            finding_ids=["HOOK-001", "EXEC-001", "SEC-001"],
            attack_vector="Lifecycle hook executes script accessing env vars while a secret is present.",
            rationale="Automated execution during npm install can read environment secrets.",
            remediation_order=[
                "Remove untrusted lifecycle hook",
                "Inspect script for outbound telemetry",
                "Rotate exposed credentials"
            ]
        )
        d = chain.to_dict()
        self.assertEqual(d["id"], "CHAIN-01")
        self.assertEqual(d["composite_severity"], "CRITICAL")
        self.assertEqual(len(d["finding_ids"]), 3)
        self.assertIn("HOOK-001", d["finding_ids"])

    def test_scan_report_severity_counts(self):
        f1 = SecurityFinding(
            id="F1",
            category=FindingCategory.EXPOSED_SECRET,
            severity=SeverityLevel.HIGH,
            title="Finding 1",
            description="Desc 1",
            file_path="config.json"
        )
        f2 = SecurityFinding(
            id="F2",
            category=FindingCategory.INSTALL_HOOK,
            severity=SeverityLevel.HIGH,
            title="Finding 2",
            description="Desc 2",
            file_path="package.json"
        )
        f3 = SecurityFinding(
            id="F3",
            category=FindingCategory.DEPENDENCY_REPRODUCIBILITY_RISK,
            severity=SeverityLevel.LOW,
            title="Finding 3",
            description="Desc 3",
            file_path="package.json"
        )

        report = ScanReport(
            project_name="demo_node_app",
            scanned_files_count=10,
            dependencies_count=5,
            raw_findings=[f1, f2, f3],
            risk_chains=[],
            overall_risk_score=7.4
        )

        counts = report.severity_counts
        self.assertEqual(counts["HIGH"], 2)
        self.assertEqual(counts["LOW"], 1)
        self.assertEqual(counts["CRITICAL"], 0)

        report_dict = report.to_dict()
        self.assertEqual(report_dict["project_name"], "demo_node_app")
        self.assertEqual(len(report_dict["raw_findings"]), 3)
        self.assertEqual(report_dict["overall_risk_score"], 7.4)


if __name__ == "__main__":
    unittest.main()
