"""
Deterministic Risk Correlation Engine for SupplyGuard AI.
Correlates individual SecurityFinding objects into contextual RiskChains.
Calculates the bounded heuristic 'SupplyGuard Risk Priority Score' (0.0 to 10.0).
Zero network calls, zero code execution, zero external databases.
"""

from pathlib import Path
from typing import Dict, Any, List, Optional, Set, Tuple

from core.models import SecurityFinding, RiskChain, FindingCategory, SeverityLevel


SEVERITY_BASE_SCORES: Dict[SeverityLevel, float] = {
    SeverityLevel.CRITICAL: 9.0,
    SeverityLevel.HIGH: 7.0,
    SeverityLevel.MEDIUM: 4.5,
    SeverityLevel.LOW: 2.5,
    SeverityLevel.INFO: 1.0,
}


def calculate_risk_priority_score(
    composite_severity: SeverityLevel,
    finding_count: int,
    has_network: bool = False,
    has_command_exec: bool = False,
    has_credential: bool = False,
    is_lifecycle_context: bool = False,
) -> float:
    """
    Computes the heuristic 'SupplyGuard Risk Priority Score' bounded between 0.0 and 10.0.
    Factors in severity tier, multi-stage correlation, and attack surface context.
    """
    base = SEVERITY_BASE_SCORES.get(composite_severity, 2.0)
    multiplier_boost = 0.0

    if is_lifecycle_context and has_command_exec and has_network:
        multiplier_boost += 1.2
    elif is_lifecycle_context and (has_command_exec or has_network):
        multiplier_boost += 0.6

    if has_credential and is_lifecycle_context:
        multiplier_boost += 0.8
    elif has_credential and composite_severity == SeverityLevel.HIGH:
        multiplier_boost += 0.5

    if finding_count >= 3:
        multiplier_boost += 0.4
    elif finding_count >= 2:
        multiplier_boost += 0.2

    # Ceiling caps to ensure MEDIUM findings never artificially reach CRITICAL scores (> 8.9)
    if composite_severity == SeverityLevel.MEDIUM:
        score = min(6.8, base + multiplier_boost)
    elif composite_severity == SeverityLevel.LOW:
        score = min(4.0, base + multiplier_boost)
    elif composite_severity == SeverityLevel.INFO:
        score = min(2.0, base + multiplier_boost)
    elif composite_severity == SeverityLevel.HIGH:
        score = min(8.9, base + multiplier_boost)
    else:  # CRITICAL
        score = min(9.9, base + multiplier_boost)

    return round(max(0.0, min(10.0, score)), 1)


class RiskCorrelationEngine:
    """
    Analyzes technical relationships between findings to produce correlated RiskChains.
    Enforces strict relationship checks to prevent false correlations across unrelated files.
    """

    def correlate(self, findings: List[SecurityFinding]) -> List[RiskChain]:
        if not findings:
            return []

        chains: List[RiskChain] = []
        seen_signatures: Set[Tuple[str, Tuple[str, ...]]] = set()
        chain_counter = 1

        # Index findings
        finding_map: Dict[str, SecurityFinding] = {f.id: f for f in findings}
        hooks = [f for f in findings if f.category == FindingCategory.INSTALL_HOOK]
        execs = [f for f in findings if f.category == FindingCategory.DANGEROUS_EXECUTION]
        secrets = [f for f in findings if f.category == FindingCategory.EXPOSED_SECRET]
        dep_risks = [f for f in findings if f.category == FindingCategory.DEPENDENCY_REPRODUCIBILITY_RISK]

        # Helper to register unique chains
        def add_chain(
            rule_id: str,
            title: str,
            description: str,
            composite_severity: SeverityLevel,
            involved_findings: List[SecurityFinding],
            attack_vector: str,
            rationale: str,
            remediation_order: List[str],
            has_net: bool = False,
            has_cmd: bool = False,
            has_cred: bool = False,
            is_lifecycle: bool = False,
        ) -> None:
            nonlocal chain_counter
            sorted_ids = tuple(sorted(set(f.id for f in involved_findings)))
            sig = (rule_id, sorted_ids)
            if sig in seen_signatures:
                return
            seen_signatures.add(sig)

            score = calculate_risk_priority_score(
                composite_severity=composite_severity,
                finding_count=len(sorted_ids),
                has_network=has_net,
                has_command_exec=has_cmd,
                has_credential=has_cred,
                is_lifecycle_context=is_lifecycle,
            )

            chains.append(
                RiskChain(
                    id=f"CHAIN-{chain_counter:03d}",
                    rule_id=rule_id,
                    title=title,
                    description=description,
                    composite_severity=composite_severity,
                    risk_priority_score=score,
                    finding_ids=list(sorted_ids),
                    attack_vector=attack_vector,
                    rationale=rationale,
                    remediation_order=remediation_order,
                )
            )
            chain_counter += 1

        # -----------------------------------------------------------------
        # RULE 1: INSTALLATION EXECUTION + NETWORK (HIGH)
        # -----------------------------------------------------------------
        self._correlate_install_execution_network(hooks, execs, add_chain)

        # -----------------------------------------------------------------
        # RULE 2: INSTALLATION EXECUTION + SENSITIVE CREDENTIAL ACCESS (HIGH)
        # -----------------------------------------------------------------
        self._correlate_install_credentials(hooks, execs, secrets, add_chain)

        # -----------------------------------------------------------------
        # RULE 3: DEPENDENCY REPRODUCIBILITY + INSTALL HOOK (MEDIUM)
        # -----------------------------------------------------------------
        self._correlate_install_reproducibility(hooks, dep_risks, add_chain)

        # -----------------------------------------------------------------
        # RULE 4: EXPOSED SECRET (CRITICAL / HIGH / MEDIUM)
        # -----------------------------------------------------------------
        self._correlate_exposed_secrets(secrets, add_chain)

        # -----------------------------------------------------------------
        # RULE 5: MISSING LOCKFILE + VERSION RANGES (MEDIUM / LOW)
        # -----------------------------------------------------------------
        self._correlate_dependency_reproducibility(dep_risks, add_chain)

        return chains

    def _correlate_install_execution_network(
        self,
        hooks: List[SecurityFinding],
        execs: List[SecurityFinding],
        add_chain_fn,
    ) -> None:
        """RULE 1: Lifecycle hook linked to command execution AND network download."""
        for hook in hooks:
            hook_file = hook.file_path
            hook_name = hook.metadata.get("hook_name", "")
            hook_ref = hook.metadata.get("referenced_script", "")

            # Findings technically connected to this hook:
            # 1. In the hook finding itself (e.g. hook command string has both net and exec)
            hook_has_net = hook.metadata.get("has_network", False)
            hook_has_exec = hook.metadata.get("has_command_exec", False)

            if hook_has_net and hook_has_exec:
                add_chain_fn(
                    rule_id="INSTALL_REMOTE_EXECUTION",
                    title="Potential remote execution during dependency installation",
                    description=(
                        "The project contains an installation lifecycle hook that reaches command execution "
                        "and outbound network behavior. If triggered during dependency installation, these behaviors "
                        "could allow downloaded or remotely supplied content to influence local execution."
                    ),
                    composite_severity=SeverityLevel.HIGH,
                    involved_findings=[hook],
                    attack_vector=f"Lifecycle hook '{hook_name}' in {hook_file} invokes shell download and execution commands.",
                    rationale=(
                        f"The '{hook_name}' hook automatically executes upon dependency installation. "
                        "Command-line inspection detected both network fetching and process execution syntax."
                    ),
                    remediation_order=[
                        "Inspect and remove unvetted commands from the lifecycle hook in package.json.",
                        "Verify why dependency installation requires network downloads or process execution.",
                        "Consider configuring npm with '--ignore-scripts' in CI/CD pipelines.",
                    ],
                    has_net=True,
                    has_cmd=True,
                    is_lifecycle=True,
                )
                continue

            # 2. In a referenced script or findings matching the hook's execution path
            # Look for related execution findings in the same referenced script
            related_execs = []
            for ex in execs:
                # Is ex in the referenced script or same file?
                if hook_ref and ex.file_path == hook_ref:
                    related_execs.append(ex)
                elif ex.file_path == hook_file and ex.line_number == hook.line_number:
                    related_execs.append(ex)

            if related_execs:
                has_net = hook_has_net or any(e.metadata.get("has_network", False) for e in related_execs)
                has_cmd = hook_has_exec or any(e.metadata.get("has_command_exec", False) for e in related_execs)

                if has_net and has_cmd:
                    involved = [hook] + related_execs
                    add_chain_fn(
                        rule_id="INSTALL_REMOTE_EXECUTION",
                        title="Potential remote execution during dependency installation",
                        description=(
                            "The project contains an installation lifecycle hook that reaches command execution "
                            "and outbound network behavior. If triggered during dependency installation, these behaviors "
                            "could allow downloaded or remotely supplied content to influence local execution."
                        ),
                        composite_severity=SeverityLevel.HIGH,
                        involved_findings=involved,
                        attack_vector=f"Lifecycle hook '{hook_name}' triggers {hook_ref or hook_file}, reaching both network requests and command execution.",
                        rationale=(
                            f"The hook '{hook_name}' executes automatically during 'npm install'. "
                            f"Referenced code in '{hook_ref or hook_file}' combines outbound network communication "
                            "with process execution."
                        ),
                        remediation_order=[
                            "Inspect and remove unvetted commands from the lifecycle hook in package.json.",
                            "Verify why dependency installation requires network downloads or process execution.",
                            "Consider configuring npm with '--ignore-scripts' in CI/CD pipelines.",
                        ],
                        has_net=True,
                        has_cmd=True,
                        is_lifecycle=True,
                    )

    def _correlate_install_credentials(
        self,
        hooks: List[SecurityFinding],
        execs: List[SecurityFinding],
        secrets: List[SecurityFinding],
        add_chain_fn,
    ) -> None:
        """RULE 2: Lifecycle hook + command execution + sensitive credential/env access."""
        for hook in hooks:
            hook_file = hook.file_path
            hook_name = hook.metadata.get("hook_name", "")
            hook_ref = hook.metadata.get("referenced_script", "")

            # Check if this hook connects to command execution AND credential access
            related_execs = [
                ex for ex in execs
                if (hook_ref and ex.file_path == hook_ref) or (ex.file_path == hook_file)
            ]

            has_cmd = hook.metadata.get("has_command_exec", False) or any(
                e.metadata.get("has_command_exec", False) for e in related_execs
            )

            has_env_access = hook.metadata.get("has_sensitive_env", False) or any(
                e.metadata.get("has_sensitive_env", False) for e in related_execs
            )

            # Check if an exposed secret exists in a related file or directory
            related_secrets = []
            for s in secrets:
                # Same directory as hook or same referenced script
                if hook_ref and (s.file_path == hook_ref or Path(s.file_path).parent == Path(hook_ref).parent):
                    related_secrets.append(s)
                elif Path(s.file_path).parent == Path(hook_file).parent:
                    # e.g., package.json and .env at project root
                    related_secrets.append(s)

            if has_cmd and (has_env_access or related_secrets):
                involved = [hook] + related_execs + related_secrets
                add_chain_fn(
                    rule_id="INSTALL_CREDENTIAL_ACCESS",
                    title="Potential credential exposure through installation behavior",
                    description=(
                        "An automatic installation lifecycle hook executes code that accesses sensitive credential "
                        "environment variables or references exposed secrets. Automated execution during package "
                        "installation could expose credentials to third-party or untrusted code."
                    ),
                    composite_severity=SeverityLevel.HIGH,
                    involved_findings=involved,
                    attack_vector=f"Lifecycle hook '{hook_name}' invokes execution code that accesses credential environment variables or exposed secret files.",
                    rationale=(
                        f"Execution triggered during 'npm install' via hook '{hook_name}' is connected to credential "
                        "access. Installation scripts should not require access to production credentials or secret stores."
                    ),
                    remediation_order=[
                        "Remove credential access from installation scripts.",
                        "Ensure install-time scripts do not read sensitive environment variables or secrets.",
                        "Rotate any credentials accessible in the installation environment.",
                    ],
                    has_cmd=True,
                    has_cred=True,
                    is_lifecycle=True,
                )

    def _correlate_install_reproducibility(
        self,
        hooks: List[SecurityFinding],
        dep_risks: List[SecurityFinding],
        add_chain_fn,
    ) -> None:
        """RULE 3: Dependency reproducibility risk + lifecycle hook in same package.json."""
        for hook in hooks:
            pkg_file = hook.file_path
            hook_name = hook.metadata.get("hook_name", "")

            # Find dependency risks in the exact same package.json
            related_deps = [d for d in dep_risks if d.file_path == pkg_file]
            if related_deps:
                involved = [hook] + related_deps
                add_chain_fn(
                    rule_id="INSTALL_REPRODUCIBILITY",
                    title="Reduced dependency installation reproducibility with lifecycle behavior",
                    description=(
                        "The project defines automatic installation lifecycle hooks while relying on flexible "
                        "dependency version ranges or missing a lockfile. Over time, dependency updates may introduce "
                        "unvetted lifecycle scripts during fresh installations."
                    ),
                    composite_severity=SeverityLevel.MEDIUM,
                    involved_findings=involved,
                    attack_vector=f"Automatic lifecycle script '{hook_name}' runs in conjunction with unpinned dependency resolution in {pkg_file}.",
                    rationale=(
                        "Flexible dependency ranges allow transitive dependencies to update automatically. "
                        "When combined with automatic lifecycle execution, installation behavior becomes non-deterministic."
                    ),
                    remediation_order=[
                        "Commit a package-lock.json to pin exact dependency versions and their lifecycle scripts.",
                        "Pin critical dependencies to exact semantic versions without flexible range specifiers.",
                        "Audit lifecycle scripts whenever updating dependencies.",
                    ],
                    is_lifecycle=True,
                )

    def _correlate_exposed_secrets(
        self,
        secrets: List[SecurityFinding],
        add_chain_fn,
    ) -> None:
        """RULE 4: Standalone exposed secret finding correlation."""
        # Group secrets by file to avoid repetitive identical chains
        secrets_by_file: Dict[str, List[SecurityFinding]] = {}
        for s in secrets:
            secrets_by_file.setdefault(s.file_path, []).append(s)

        for file_path, file_secrets in secrets_by_file.items():
            highest_sev = max(s.severity for s in file_secrets)
            secret_types = list(set(s.metadata.get("secret_type", "credential") for s in file_secrets))
            types_str = ", ".join(secret_types)

            add_chain_fn(
                rule_id="EXPOSED_CREDENTIAL",
                title=f"Potential credential exposure in {file_path}",
                description=(
                    f"Static pattern analysis detected potential {types_str} in '{file_path}'. "
                    "If these values are genuine, exposure in source control could grant unauthorized access to services."
                ),
                composite_severity=highest_sev,
                involved_findings=file_secrets,
                attack_vector=f"Exposed potential {types_str} found in {file_path}.",
                rationale=(
                    f"Credentials detected in '{file_path}'. Storing sensitive credentials in source-controlled "
                    "or application configuration files creates an immediate risk of credential leakage."
                ),
                remediation_order=[
                    "Immediately revoke and rotate the affected credential if valid.",
                    "Remove the credential from source control and add the file to .gitignore.",
                    "Store credentials using runtime environment variables or a dedicated secrets manager.",
                ],
                has_cred=True,
            )

    def _correlate_dependency_reproducibility(
        self,
        dep_risks: List[SecurityFinding],
        add_chain_fn,
    ) -> None:
        """RULE 5: Missing lockfile + version ranges in the same package.json."""
        # Group by package.json file
        by_file: Dict[str, List[SecurityFinding]] = {}
        for d in dep_risks:
            by_file.setdefault(d.file_path, []).append(d)

        for file_path, file_deps in by_file.items():
            has_lock_missing = any(d.metadata.get("risk_type") == "missing_lockfile" for d in file_deps)
            has_ranges = any(d.metadata.get("risk_type") in {"version_range", "wildcard_version"} for d in file_deps)

            if has_lock_missing and has_ranges:
                add_chain_fn(
                    rule_id="DEPENDENCY_REPRODUCIBILITY",
                    title="Reduced dependency reproducibility",
                    description=(
                        "The project uses flexible dependency version ranges and lacks a package-lock.json. "
                        "Dependency resolution may resolve differing package versions across installations, "
                        "creating drift and potential build instability."
                    ),
                    composite_severity=SeverityLevel.MEDIUM,
                    involved_findings=file_deps,
                    attack_vector=f"Non-deterministic dependency resolution in {file_path}.",
                    rationale=(
                        "Without a lockfile, npm resolves dependency ranges to the latest available matching versions, "
                        "which may lead to unreviewed code being pulled into builds."
                    ),
                    remediation_order=[
                        "Generate and commit a package-lock.json using 'npm install' in a trusted environment.",
                        "Pin key dependency versions to ensure deterministic installation across environments.",
                    ],
                )


def correlate_findings(findings: List[SecurityFinding]) -> List[RiskChain]:
    """Public helper function for executing the Risk Correlation Engine."""
    engine = RiskCorrelationEngine()
    return engine.correlate(findings)


def compute_overall_project_risk_score(
    chains: List[RiskChain],
    raw_findings: List[SecurityFinding],
) -> float:
    """
    Computes the composite 'SupplyGuard Risk Priority Score' (0.0 to 10.0) for the whole project.
    Anchored on the highest chain priority with diminishing increases for secondary chains.
    """
    if not chains and not raw_findings:
        return 0.0

    if chains:
        highest_chain_score = max(c.risk_priority_score for c in chains)
        # Diminishing factor for multiple independent risk chains
        additional_penalty = min(1.0, 0.25 * (len(chains) - 1))
        overall = highest_chain_score + additional_penalty
    else:
        # Fallback to max raw finding base score if no correlation rules triggered
        highest_sev = max(f.severity for f in raw_findings)
        overall = SEVERITY_BASE_SCORES.get(highest_sev, 1.0)

    return round(max(0.0, min(10.0, overall)), 1)
