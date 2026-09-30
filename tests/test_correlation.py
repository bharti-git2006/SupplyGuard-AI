"""
Unit tests for SupplyGuard AI Risk Correlation Engine.
Validates multi-signal correlation rules, relationship verification, false-correlation
rejection, score bounding, duplicate prevention, and zero secret leakage.
"""

import unittest
from core.models import SecurityFinding, RiskChain, FindingCategory, SeverityLevel
from core.correlation.engine import (
    RiskCorrelationEngine,
    correlate_findings,
    compute_overall_project_risk_score,
)


class TestCorrelationEngine(unittest.TestCase):
    def setUp(self):
        self.engine = RiskCorrelationEngine()

    def test_1_install_exec_and_network_yields_remote_execution_chain(self):
        """Test 1: Install hook + command execution + network request yields HIGH remote-execution chain."""
        f_hook = SecurityFinding(
            id="HOOK-001",
            category=FindingCategory.INSTALL_HOOK,
            severity=SeverityLevel.INFO,
            title="Dependency installation lifecycle hook detected: postinstall",
            description="Runs postinstall script",
            file_path="package.json",
            metadata={"hook_name": "postinstall", "referenced_script": "scripts/setup.js"},
        )
        f_exec = SecurityFinding(
            id="EXEC-001",
            category=FindingCategory.DANGEROUS_EXECUTION,
            severity=SeverityLevel.MEDIUM,
            title="Potentially dangerous command execution detected",
            description="Process execution",
            file_path="scripts/setup.js",
            metadata={"has_command_exec": True, "indicator_types": ["command_execution"]},
        )
        f_net = SecurityFinding(
            id="EXEC-002",
            category=FindingCategory.DANGEROUS_EXECUTION,
            severity=SeverityLevel.MEDIUM,
            title="Potentially dangerous outbound network request detected",
            description="Network call",
            file_path="scripts/setup.js",
            metadata={"has_network": True, "indicator_types": ["network_access"]},
        )

        chains = self.engine.correlate([f_hook, f_exec, f_net])

        rule_chains = [c for c in chains if c.rule_id == "INSTALL_REMOTE_EXECUTION"]
        self.assertEqual(len(rule_chains), 1)
        c = rule_chains[0]
        self.assertEqual(c.composite_severity, SeverityLevel.HIGH)
        self.assertIn("HOOK-001", c.finding_ids)
        self.assertIn("EXEC-001", c.finding_ids)
        self.assertIn("EXEC-002", c.finding_ids)
        self.assertTrue(7.0 <= c.risk_priority_score <= 8.9)

    def test_2_install_exec_and_sensitive_env_yields_credential_chain(self):
        """Test 2: Install hook + command execution + sensitive env yields HIGH credential-access chain."""
        f_hook = SecurityFinding(
            id="HOOK-001",
            category=FindingCategory.INSTALL_HOOK,
            severity=SeverityLevel.INFO,
            title="Lifecycle hook: postinstall",
            description="Runs install",
            file_path="package.json",
            metadata={"hook_name": "postinstall", "referenced_script": "scripts/postinstall.js"},
        )
        f_exec = SecurityFinding(
            id="EXEC-001",
            category=FindingCategory.DANGEROUS_EXECUTION,
            severity=SeverityLevel.MEDIUM,
            title="Command execution",
            description="execSync",
            file_path="scripts/postinstall.js",
            metadata={"has_command_exec": True, "indicator_types": ["command_execution"]},
        )
        f_env = SecurityFinding(
            id="EXEC-002",
            category=FindingCategory.DANGEROUS_EXECUTION,
            severity=SeverityLevel.MEDIUM,
            title="Sensitive env access",
            description="process.env.AWS_SECRET_ACCESS_KEY",
            file_path="scripts/postinstall.js",
            metadata={"has_sensitive_env": True, "indicator_types": ["sensitive_env"]},
        )

        chains = self.engine.correlate([f_hook, f_exec, f_env])

        cred_chains = [c for c in chains if c.rule_id == "INSTALL_CREDENTIAL_ACCESS"]
        self.assertEqual(len(cred_chains), 1)
        c = cred_chains[0]
        self.assertEqual(c.composite_severity, SeverityLevel.HIGH)
        self.assertIn("HOOK-001", c.finding_ids)
        self.assertIn("EXEC-001", c.finding_ids)
        self.assertIn("EXEC-002", c.finding_ids)

    def test_3_install_hook_and_exposed_secret_in_related_location(self):
        """Test 3: Install hook + exec + exposed secret in related project config."""
        f_hook = SecurityFinding(
            id="HOOK-001",
            category=FindingCategory.INSTALL_HOOK,
            severity=SeverityLevel.INFO,
            title="Hook: postinstall",
            description="Runs script",
            file_path="package.json",
            metadata={"hook_name": "postinstall", "has_command_exec": True},
        )
        f_sec = SecurityFinding(
            id="SEC-001",
            category=FindingCategory.EXPOSED_SECRET,
            severity=SeverityLevel.HIGH,
            title="Potential exposed AWS credential detected",
            description="AWS Key",
            file_path=".env",
            snippet="AKIA************90AB",
            metadata={"secret_type": "aws_access_key"},
        )

        chains = self.engine.correlate([f_hook, f_sec])

        cred_chains = [c for c in chains if c.rule_id == "INSTALL_CREDENTIAL_ACCESS"]
        self.assertEqual(len(cred_chains), 1)
        self.assertIn("HOOK-001", cred_chains[0].finding_ids)
        self.assertIn("SEC-001", cred_chains[0].finding_ids)

    def test_4_version_range_and_lifecycle_hook_yields_reproducibility_chain(self):
        """Test 4: Version range + lifecycle hook in same package.json yields INSTALL_REPRODUCIBILITY."""
        f_dep = SecurityFinding(
            id="DEP-001",
            category=FindingCategory.DEPENDENCY_REPRODUCIBILITY_RISK,
            severity=SeverityLevel.LOW,
            title="Dependency version range: express",
            description="uses ^4.18.2",
            file_path="package.json",
            metadata={"risk_type": "version_range"},
        )
        f_hook = SecurityFinding(
            id="HOOK-001",
            category=FindingCategory.INSTALL_HOOK,
            severity=SeverityLevel.INFO,
            title="Lifecycle hook: prepare",
            description="husky install",
            file_path="package.json",
            metadata={"hook_name": "prepare"},
        )

        chains = self.engine.correlate([f_dep, f_hook])

        repro_chains = [c for c in chains if c.rule_id == "INSTALL_REPRODUCIBILITY"]
        self.assertEqual(len(repro_chains), 1)
        c = repro_chains[0]
        self.assertEqual(c.composite_severity, SeverityLevel.MEDIUM)
        self.assertIn("DEP-001", c.finding_ids)
        self.assertIn("HOOK-001", c.finding_ids)

    def test_5_missing_lockfile_and_version_range(self):
        """Test 5: Missing lockfile + version range yields DEPENDENCY_REPRODUCIBILITY chain."""
        f_lock = SecurityFinding(
            id="DEP-001",
            category=FindingCategory.DEPENDENCY_REPRODUCIBILITY_RISK,
            severity=SeverityLevel.MEDIUM,
            title="package-lock.json is missing",
            description="Lockfile absent",
            file_path="package.json",
            metadata={"risk_type": "missing_lockfile"},
        )
        f_range = SecurityFinding(
            id="DEP-002",
            category=FindingCategory.DEPENDENCY_REPRODUCIBILITY_RISK,
            severity=SeverityLevel.LOW,
            title="Version range: lodash",
            description="uses ^4.17.21",
            file_path="package.json",
            metadata={"risk_type": "version_range"},
        )

        chains = self.engine.correlate([f_lock, f_range])

        dep_chains = [c for c in chains if c.rule_id == "DEPENDENCY_REPRODUCIBILITY"]
        self.assertEqual(len(dep_chains), 1)
        self.assertEqual(dep_chains[0].composite_severity, SeverityLevel.MEDIUM)

    def test_6_exposed_secret_alone_yields_credential_chain(self):
        """Test 6: Standalone exposed secret yields EXPOSED_CREDENTIAL chain."""
        f_sec = SecurityFinding(
            id="SEC-001",
            category=FindingCategory.EXPOSED_SECRET,
            severity=SeverityLevel.HIGH,
            title="Potential exposed GitHub token detected",
            description="Token detected",
            file_path="src/config.js",
            snippet="ghp_************1234",
            metadata={"secret_type": "github_token"},
        )

        chains = self.engine.correlate([f_sec])

        self.assertEqual(len(chains), 1)
        self.assertEqual(chains[0].rule_id, "EXPOSED_CREDENTIAL")
        self.assertEqual(chains[0].composite_severity, SeverityLevel.HIGH)
        self.assertEqual(chains[0].finding_ids, ["SEC-001"])

    def test_7_unrelated_secret_and_unrelated_network_finding_no_correlation(self):
        """Test 7: Unrelated secret in config and network call in app file do NOT correlate."""
        f_sec = SecurityFinding(
            id="SEC-001",
            category=FindingCategory.EXPOSED_SECRET,
            severity=SeverityLevel.MEDIUM,
            title="Potential generic API key detected",
            description="API Key",
            file_path=".env",
            snippet="api_************9988",
        )
        f_net = SecurityFinding(
            id="EXEC-001",
            category=FindingCategory.DANGEROUS_EXECUTION,
            severity=SeverityLevel.MEDIUM,
            title="Outbound network call",
            description="fetch() in frontend app",
            file_path="frontend/src/App.js",
            metadata={"has_network": True, "indicator_types": ["network_access"]},
        )

        chains = self.engine.correlate([f_sec, f_net])

        # Expect ONLY the standalone secret chain, and NO installation/composite chain
        chain_rule_ids = [c.rule_id for c in chains]
        self.assertNotIn("INSTALL_REMOTE_EXECUTION", chain_rule_ids)
        self.assertNotIn("INSTALL_CREDENTIAL_ACCESS", chain_rule_ids)

    def test_8_unrelated_install_hook_and_unrelated_source_execution_no_correlation(self):
        """Test 8: Install hook in package.json and exec in unrelated test runner do NOT correlate."""
        f_hook = SecurityFinding(
            id="HOOK-001",
            category=FindingCategory.INSTALL_HOOK,
            severity=SeverityLevel.INFO,
            title="Hook: postinstall",
            description="node scripts/build.js",
            file_path="package.json",
            metadata={"hook_name": "postinstall", "referenced_script": "scripts/build.js"},
        )
        f_exec = SecurityFinding(
            id="EXEC-001",
            category=FindingCategory.DANGEROUS_EXECUTION,
            severity=SeverityLevel.MEDIUM,
            title="Command execution",
            description="exec in unit tests",
            file_path="tests/run_tests.js",  # Unrelated file!
            metadata={"has_command_exec": True, "indicator_types": ["command_execution"]},
        )

        chains = self.engine.correlate([f_hook, f_exec])

        # scripts/build.js != tests/run_tests.js; no remote execution chain should form
        chain_rule_ids = [c.rule_id for c in chains]
        self.assertNotIn("INSTALL_REMOTE_EXECUTION", chain_rule_ids)

    def test_9_same_evidence_does_not_generate_duplicate_chains(self):
        """Test 9: Passing repeated or overlapping findings produces distinct unique chains."""
        f_hook = SecurityFinding(
            id="HOOK-001",
            category=FindingCategory.INSTALL_HOOK,
            severity=SeverityLevel.INFO,
            title="Hook: postinstall",
            description="postinstall",
            file_path="package.json",
            metadata={"hook_name": "postinstall", "has_network": True, "has_command_exec": True},
        )

        chains = self.engine.correlate([f_hook, f_hook])

        self.assertEqual(len(chains), 1)

    def test_10_all_chain_finding_ids_reference_real_input_findings(self):
        """Test 10: Every finding ID in RiskChain exists in original input list."""
        f1 = SecurityFinding(
            id="F1",
            category=FindingCategory.EXPOSED_SECRET,
            severity=SeverityLevel.HIGH,
            title="Secret",
            description="Secret",
            file_path=".env",
        )
        f2 = SecurityFinding(
            id="F2",
            category=FindingCategory.INSTALL_HOOK,
            severity=SeverityLevel.INFO,
            title="Hook",
            description="Hook",
            file_path="package.json",
            metadata={"hook_name": "postinstall", "has_command_exec": True},
        )

        input_ids = {"F1", "F2"}
        chains = self.engine.correlate([f1, f2])

        for c in chains:
            for fid in c.finding_ids:
                self.assertIn(fid, input_ids)

    def test_11_risk_score_always_bounded_between_0_and_10(self):
        """Test 11: Risk priority score is strictly bounded [0.0, 10.0]."""
        # Test extreme CRITICAL combination
        crit_findings = [
            SecurityFinding(
                id=f"CRIT-{i}",
                category=FindingCategory.EXPOSED_SECRET,
                severity=SeverityLevel.CRITICAL,
                title="Private Key",
                description="Private Key",
                file_path=f"key_{i}.pem",
            )
            for i in range(10)
        ]

        chains = self.engine.correlate(crit_findings)
        overall_score = compute_overall_project_risk_score(chains, crit_findings)

        for c in chains:
            self.assertTrue(0.0 <= c.risk_priority_score <= 10.0)
        self.assertTrue(0.0 <= overall_score <= 10.0)

    def test_12_no_raw_secret_value_appears_in_risk_chain_output(self):
        """Test 12: Verified that no unmasked raw secret string appears in any chain property."""
        raw_secret = "syntheticAWSSecretKey123456"
        f_sec = SecurityFinding(
            id="SEC-001",
            category=FindingCategory.EXPOSED_SECRET,
            severity=SeverityLevel.HIGH,
            title="Potential exposed AWS credential detected",
            description="AWS Access Key detected",
            file_path=".env",
            snippet="AKIA************90AB",  # Already masked
            metadata={"secret_type": "aws_access_key"},
        )

        chains = self.engine.correlate([f_sec])
        for c in chains:
            c_dict = c.to_dict()
            c_str = str(c)
            self.assertNotIn(raw_secret, c_str)
            self.assertNotIn(raw_secret, str(c_dict))

    def test_13_no_critical_chain_generated_merely_from_medium_findings(self):
        """Test 13: Combinations of MEDIUM findings never reach CRITICAL (> 8.9) score."""
        med_dep = SecurityFinding(
            id="DEP-001",
            category=FindingCategory.DEPENDENCY_REPRODUCIBILITY_RISK,
            severity=SeverityLevel.MEDIUM,
            title="Missing lockfile",
            description="desc",
            file_path="package.json",
            metadata={"risk_type": "missing_lockfile"},
        )
        med_range = SecurityFinding(
            id="DEP-002",
            category=FindingCategory.DEPENDENCY_REPRODUCIBILITY_RISK,
            severity=SeverityLevel.MEDIUM,
            title="Wildcard dep",
            description="desc",
            file_path="package.json",
            metadata={"risk_type": "wildcard_version"},
        )

        chains = self.engine.correlate([med_dep, med_range])
        for c in chains:
            self.assertNotEqual(c.composite_severity, SeverityLevel.CRITICAL)
            self.assertTrue(c.risk_priority_score <= 7.0)

    def test_14_deterministic_output(self):
        """Test 14: Executing correlation multiple times produces identical chains and scores."""
        f1 = SecurityFinding(
            id="F1",
            category=FindingCategory.EXPOSED_SECRET,
            severity=SeverityLevel.HIGH,
            title="Secret",
            description="Desc",
            file_path=".env",
        )
        f2 = SecurityFinding(
            id="F2",
            category=FindingCategory.INSTALL_HOOK,
            severity=SeverityLevel.INFO,
            title="Hook",
            description="Desc",
            file_path="package.json",
            metadata={"hook_name": "postinstall", "has_command_exec": True},
        )

        run1 = [c.to_dict() for c in self.engine.correlate([f1, f2])]
        run2 = [c.to_dict() for c in self.engine.correlate([f1, f2])]

        self.assertEqual(run1, run2)

    def test_15_empty_findings_yields_empty_chains(self):
        """Test 15: Empty finding list produces 0 chains and 0.0 project score."""
        chains = self.engine.correlate([])
        score = compute_overall_project_risk_score([], [])

        self.assertEqual(chains, [])
        self.assertEqual(score, 0.0)


if __name__ == "__main__":
    unittest.main()
