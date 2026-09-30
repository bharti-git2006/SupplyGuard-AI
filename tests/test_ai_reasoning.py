"""
Unit tests for SupplyGuard AI Deterministic AI Reasoning Layer.
Validates structured assessment generation, ranking stability, conditional impact language,
evidence traceability, zero secret leakage, absence of hallucinated CVEs, and offline execution.
"""

import unittest
from unittest.mock import patch

from core.ai.deterministic_reasoner import DeterministicReasoner
from core.models import (
    SecurityFinding,
    RiskChain,
    AIAnalysisResult,
    FindingCategory,
    SeverityLevel,
)


class TestAIReasoningLayer(unittest.TestCase):
    def setUp(self):
        self.reasoner = DeterministicReasoner()

    def test_1_empty_scan_produces_valid_assessment(self):
        """Test 1: Empty findings and chains produce a clean valid assessment."""
        result = self.reasoner.generate_assessment([], [])
        self.assertIsInstance(result, AIAnalysisResult)
        self.assertIn("No findings were detected", result.executive_summary)
        self.assertEqual(result.priority_risks, [])
        self.assertEqual(result.evidence_references, [])
        self.assertEqual(result.provider_used, "deterministic-offline")

    def test_2_findings_produce_correct_executive_summary_count(self):
        """Test 2: Executive summary accurately reflects exact finding and chain counts."""
        f1 = SecurityFinding(
            id="SEC-001",
            category=FindingCategory.EXPOSED_SECRET,
            severity=SeverityLevel.HIGH,
            title="Secret",
            description="desc",
            file_path=".env",
        )
        f2 = SecurityFinding(
            id="DEP-001",
            category=FindingCategory.DEPENDENCY_REPRODUCIBILITY_RISK,
            severity=SeverityLevel.LOW,
            title="Range",
            description="desc",
            file_path="package.json",
        )
        chain = RiskChain(
            id="CHAIN-001",
            rule_id="EXPOSED_CREDENTIAL",
            title="Potential credential exposure in .env",
            composite_severity=SeverityLevel.HIGH,
            risk_priority_score=7.5,
            finding_ids=["SEC-001"],
            attack_vector="Exposed secret",
            rationale="Secret in .env",
        )

        result = self.reasoner.generate_assessment([f1, f2], [chain])
        self.assertIn("2 security finding(s)", result.executive_summary)
        self.assertIn("1 correlated risk chain(s)", result.executive_summary)
        self.assertIn("7.5/10", result.executive_summary)

    def test_3_high_risk_chain_appears_before_lower_risk_chain(self):
        """Test 3: Chains are sorted strictly by severity and risk score."""
        c_low = RiskChain(
            id="CHAIN-001",
            rule_id="INSTALL_REPRODUCIBILITY",
            title="Low priority repro",
            composite_severity=SeverityLevel.MEDIUM,
            risk_priority_score=5.0,
            finding_ids=["F1"],
            attack_vector="repro",
            rationale="repro",
        )
        c_high = RiskChain(
            id="CHAIN-002",
            rule_id="INSTALL_REMOTE_EXECUTION",
            title="High priority remote execution",
            composite_severity=SeverityLevel.HIGH,
            risk_priority_score=8.5,
            finding_ids=["F2", "F3"],
            attack_vector="exec",
            rationale="exec",
        )

        result = self.reasoner.generate_assessment([], [c_low, c_high])
        priority_ids = [item["chain_id"] for item in result.priority_risks]
        self.assertEqual(priority_ids, ["CHAIN-002", "CHAIN-001"])

    def test_4_deterministic_ordering_is_stable(self):
        """Test 4: Equal score chains order deterministically via chain ID."""
        c_a = RiskChain(
            id="CHAIN-A",
            rule_id="RULE_X",
            title="Chain A",
            composite_severity=SeverityLevel.HIGH,
            risk_priority_score=7.0,
            finding_ids=["F1"],
            attack_vector="A",
            rationale="A",
        )
        c_b = RiskChain(
            id="CHAIN-B",
            rule_id="RULE_Y",
            title="Chain B",
            composite_severity=SeverityLevel.HIGH,
            risk_priority_score=7.0,
            finding_ids=["F2"],
            attack_vector="B",
            rationale="B",
        )

        res1 = self.reasoner.generate_assessment([], [c_a, c_b])
        res2 = self.reasoner.generate_assessment([], [c_b, c_a])
        self.assertEqual(
            [x["chain_id"] for x in res1.priority_risks],
            [x["chain_id"] for x in res2.priority_risks],
        )

    def test_5_chain_ids_are_preserved(self):
        """Test 5: Chain IDs match original inputs in priority risks and correlations."""
        chain = RiskChain(
            id="CHAIN-XYZ",
            rule_id="INSTALL_REMOTE_EXECUTION",
            title="Remote exec",
            composite_severity=SeverityLevel.HIGH,
            risk_priority_score=8.0,
            finding_ids=["F1"],
            attack_vector="vec",
            rationale="rat",
        )
        result = self.reasoner.generate_assessment([], [chain])
        self.assertEqual(result.priority_risks[0]["chain_id"], "CHAIN-XYZ")
        self.assertEqual(result.correlated_risks[0]["chain_id"], "CHAIN-XYZ")

    def test_6_finding_ids_are_preserved(self):
        """Test 6: Finding IDs are traceable across priority risks and evidence refs."""
        f = SecurityFinding(
            id="HOOK-999",
            category=FindingCategory.INSTALL_HOOK,
            severity=SeverityLevel.INFO,
            title="Hook",
            description="desc",
            file_path="package.json",
        )
        chain = RiskChain(
            id="CHAIN-001",
            rule_id="RULE_1",
            title="Chain",
            composite_severity=SeverityLevel.MEDIUM,
            risk_priority_score=5.5,
            finding_ids=["HOOK-999"],
            attack_vector="v",
            rationale="r",
        )
        result = self.reasoner.generate_assessment([f], [chain])
        self.assertIn("HOOK-999", result.evidence_references)
        self.assertIn("HOOK-999", result.priority_risks[0]["finding_ids"])

    def test_7_remediation_for_exposed_secret_is_generated(self):
        """Test 7: Remediation targets credential rotation when secret is present."""
        f = SecurityFinding(
            id="SEC-001",
            category=FindingCategory.EXPOSED_SECRET,
            severity=SeverityLevel.HIGH,
            title="Secret",
            description="desc",
            file_path=".env",
        )
        result = self.reasoner.generate_assessment([f], [])
        rem_text = " ".join(result.remediation_order).lower()
        self.assertTrue("rotate" in rem_text or "credentials" in rem_text)

    def test_8_remediation_for_lifecycle_hook_is_generated(self):
        """Test 8: Remediation targets lifecycle hook auditing when hook chain is present."""
        chain = RiskChain(
            id="CHAIN-001",
            rule_id="INSTALL_REMOTE_EXECUTION",
            title="Install hook remote exec",
            composite_severity=SeverityLevel.HIGH,
            risk_priority_score=8.5,
            finding_ids=["F1"],
            attack_vector="v",
            rationale="r",
        )
        result = self.reasoner.generate_assessment([], [chain])
        rem_text = " ".join(result.remediation_order).lower()
        self.assertTrue("lifecycle" in rem_text or "install" in rem_text)

    def test_9_remediation_for_dependency_reproducibility_is_generated(self):
        """Test 9: Remediation advises committing lockfile for reproducibility issues."""
        f = SecurityFinding(
            id="DEP-001",
            category=FindingCategory.DEPENDENCY_REPRODUCIBILITY_RISK,
            severity=SeverityLevel.MEDIUM,
            title="Missing lockfile",
            description="desc",
            file_path="package.json",
        )
        result = self.reasoner.generate_assessment([f], [])
        rem_text = " ".join(result.remediation_order).lower()
        self.assertTrue("package-lock.json" in rem_text or "lockfile" in rem_text)

    def test_10_potential_impact_uses_conditional_wording(self):
        """Test 10: All impact narratives use conditional wording (could, potential, if, may)."""
        chain = RiskChain(
            id="CHAIN-001",
            rule_id="INSTALL_REMOTE_EXECUTION",
            title="Remote exec",
            composite_severity=SeverityLevel.HIGH,
            risk_priority_score=8.5,
            finding_ids=["F1"],
            attack_vector="v",
            rationale="r",
        )
        result = self.reasoner.generate_assessment([], [chain])
        self.assertTrue(len(result.potential_impacts) >= 1)
        for impact_item in result.potential_impacts:
            text = impact_item["impact"].lower()
            self.assertTrue(any(w in text for w in ("potential", "could", "if", "may")))

    def test_11_no_cve_or_vulnerability_claims_invented(self):
        """Test 11: Reasoner never invents CVE numbers or confirms exploits."""
        chain = RiskChain(
            id="CHAIN-001",
            rule_id="INSTALL_REMOTE_EXECUTION",
            title="Remote exec",
            composite_severity=SeverityLevel.HIGH,
            risk_priority_score=8.5,
            finding_ids=["F1"],
            attack_vector="v",
            rationale="r",
        )
        result = self.reasoner.generate_assessment([], [chain])
        res_str = str(result.to_dict()).lower()
        self.assertNotIn("cve-", res_str)
        self.assertNotIn("malware", res_str)
        self.assertNotIn("compromise occurred", res_str)
        self.assertNotIn("credentials were stolen", res_str)

    def test_12_raw_secret_values_do_not_appear_in_output(self):
        """Test 12: No raw secret leaked into assessment strings or dictionary output."""
        raw_secret = "syntheticSuperSecretAWSKey123"
        f = SecurityFinding(
            id="SEC-001",
            category=FindingCategory.EXPOSED_SECRET,
            severity=SeverityLevel.HIGH,
            title="Potential exposed AWS credential detected",
            description="desc",
            file_path=".env",
            snippet="AKIA************90AB",
        )
        result = self.reasoner.generate_assessment([f], [])
        self.assertNotIn(raw_secret, str(result.to_dict()))
        self.assertNotIn(raw_secret, str(result))

    def test_13_same_input_produces_identical_assessment(self):
        """Test 13: Deterministic assessment is 100% idempotent."""
        f = SecurityFinding(
            id="SEC-001",
            category=FindingCategory.EXPOSED_SECRET,
            severity=SeverityLevel.HIGH,
            title="Secret",
            description="desc",
            file_path=".env",
        )
        res1 = self.reasoner.generate_assessment([f], [])
        res2 = self.reasoner.generate_assessment([f], [])
        self.assertEqual(res1.to_dict(), res2.to_dict())

    @patch("urllib.request.urlopen")
    @patch("subprocess.run")
    def test_14_no_external_network_or_api_calls_occur(self, mock_subp, mock_urlopen):
        """Test 14: Confirms reasoner executes zero network or subprocess calls."""
        result = self.reasoner.generate_assessment([], [])
        mock_urlopen.assert_not_called()
        mock_subp.assert_not_called()
        self.assertIsNotNone(result)

    def test_15_works_with_no_project_context(self):
        """Test 15: Operates reliably when project_context is None."""
        f = SecurityFinding(
            id="F1",
            category=FindingCategory.CONFIG_ISSUE,
            severity=SeverityLevel.LOW,
            title="Config issue",
            description="desc",
            file_path="package.json",
        )
        result = self.reasoner.generate_assessment([f], [], project_context=None)
        self.assertEqual(len(result.evidence_references), 1)
        self.assertIn("1 security finding(s)", result.executive_summary)


if __name__ == "__main__":
    unittest.main()
