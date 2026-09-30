"""
Static Node.js Dependency Scanner for SupplyGuard AI.
Analyzes package.json and package-lock.json for:
- Dependency reproducibility risks (version ranges, wildcards, missing lockfile)
- Direct external URLs and git repository references
- Automatic lifecycle installation hooks (preinstall, install, postinstall, prepare)
Strictly static analysis: zero network calls, zero npm commands, zero execution.
"""

import json
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple, Set

from core.models import ProjectContext, SecurityFinding, FindingCategory, SeverityLevel
from core.scanners.base import BaseScanner

# Standard lifecycle installation hooks in npm
LIFECYCLE_HOOKS: Set[str] = {
    "preinstall",
    "install",
    "postinstall",
    "prepare",
}

DEPENDENCY_SECTIONS: List[str] = [
    "dependencies",
    "devDependencies",
    "optionalDependencies",
    "peerDependencies",
]


def find_key_line_number(lines: List[str], key: str, parent_hint: Optional[str] = None) -> Optional[int]:
    """
    Heuristically locates the 1-indexed line number for a specific JSON key in lines of text.
    """
    search_target = f'"{key}"'
    for line_no, line in enumerate(lines, start=1):
        if search_target in line:
            return line_no
    return 1


def is_external_url_dependency(version_str: str) -> bool:
    """Checks whether a dependency version is pointing directly to a URL or git repo."""
    v = version_str.strip().lower()
    return (
        v.startswith(("git+", "git://", "http://", "https://", "ssh://", "git@"))
        or v.endswith((".git", ".tgz", ".tar.gz"))
    )


class DependencyScanner(BaseScanner):
    """Static Node.js dependency and lifecycle hook scanner."""

    def scan(self, context: ProjectContext) -> List[SecurityFinding]:
        findings: List[SecurityFinding] = []
        dep_finding_counter = 1
        hook_finding_counter = 1

        # Locate all package.json files in relevant_files
        pkg_json_rel_paths = [
            p for p in context.relevant_files if p.name.lower() == "package.json"
        ]

        if not pkg_json_rel_paths:
            return findings

        # Check for package-lock.json presence across project
        lockfile_rel_paths = {
            p.as_posix()
            for p in context.all_discovered_files
            if p.name.lower() == "package-lock.json"
        }

        for rel_path in pkg_json_rel_paths:
            full_path = context.root_path / rel_path
            try:
                raw_text = full_path.read_text(encoding="utf-8", errors="replace")
            except Exception as e:
                findings.append(
                    SecurityFinding(
                        id=f"DEP-ERR-{dep_finding_counter:03d}",
                        category=FindingCategory.CONFIG_ISSUE,
                        severity=SeverityLevel.MEDIUM,
                        title="Unable to read package.json",
                        description=f"Could not read package.json file: {e}",
                        file_path=str(rel_path.as_posix()),
                        line_number=1,
                    )
                )
                dep_finding_counter += 1
                continue

            lines = raw_text.splitlines()

            # Parse JSON
            try:
                data = json.loads(raw_text)
            except json.JSONDecodeError as err:
                findings.append(
                    SecurityFinding(
                        id=f"DEP-ERR-{dep_finding_counter:03d}",
                        category=FindingCategory.CONFIG_ISSUE,
                        severity=SeverityLevel.MEDIUM,
                        title="Malformed package.json configuration",
                        description=f"JSON syntax error encountered: {err.msg} at line {err.lineno}",
                        file_path=str(rel_path.as_posix()),
                        line_number=err.lineno,
                        snippet=lines[err.lineno - 1].strip() if 0 < err.lineno <= len(lines) else None,
                        explanation="Malformed package.json files prevent reliable dependency resolution and static security auditing.",
                        remediation="Correct JSON syntax errors in package.json.",
                    )
                )
                dep_finding_counter += 1
                continue

            if not isinstance(data, dict):
                continue

            total_declared_deps = 0

            # 1. Dependency Analysis
            for section in DEPENDENCY_SECTIONS:
                deps_dict = data.get(section)
                if not isinstance(deps_dict, dict):
                    continue

                for pkg_name, version_spec in deps_dict.items():
                    total_declared_deps += 1
                    line_no = find_key_line_number(lines, pkg_name)
                    v_str = str(version_spec).strip()
                    snippet = lines[line_no - 1].strip() if 0 < line_no <= len(lines) else f'"{pkg_name}": "{v_str}"'

                    # A. Direct External URL or Git Repository
                    if is_external_url_dependency(v_str):
                        findings.append(
                            SecurityFinding(
                                id=f"DEP-{dep_finding_counter:03d}",
                                category=FindingCategory.DEPENDENCY_REPRODUCIBILITY_RISK,
                                severity=SeverityLevel.INFO,
                                title=f"Dependency is sourced directly from an external URL: {pkg_name}",
                                description=f"Dependency '{pkg_name}' points directly to an external URL or git repository.",
                                file_path=str(rel_path.as_posix()),
                                line_number=line_no,
                                snippet=snippet,
                                explanation="Direct URL dependencies bypass public registry metadata, integrity checks, and version immutability.",
                                remediation="Pin dependencies to public registry releases with cryptographic integrity hashes where possible.",
                                metadata={
                                    "package_name": pkg_name,
                                    "declared_version": v_str,
                                    "dependency_section": section,
                                    "risk_type": "external_url_dependency",
                                },
                            )
                        )
                        dep_finding_counter += 1

                    # B. Wildcard Version Detection (*, latest, x)
                    elif v_str in {"*", "latest", "x", "X"}:
                        findings.append(
                            SecurityFinding(
                                id=f"DEP-{dep_finding_counter:03d}",
                                category=FindingCategory.DEPENDENCY_REPRODUCIBILITY_RISK,
                                severity=SeverityLevel.MEDIUM,
                                title=f"Wildcard dependency version reduces reproducibility: {pkg_name}",
                                description=f"Dependency '{pkg_name}' uses wildcard version '{v_str}'.",
                                file_path=str(rel_path.as_posix()),
                                line_number=line_no,
                                snippet=snippet,
                                explanation="Wildcard versions automatically pull untested new major releases upon install, creating build instability.",
                                remediation=f"Pin '{pkg_name}' to a specific semantic version (e.g., '1.2.3').",
                                metadata={
                                    "package_name": pkg_name,
                                    "declared_version": v_str,
                                    "dependency_section": section,
                                    "risk_type": "wildcard_version",
                                },
                            )
                        )
                        dep_finding_counter += 1

                    # C. Version Range Detection (^ or ~)
                    elif v_str.startswith("^") or v_str.startswith("~"):
                        findings.append(
                            SecurityFinding(
                                id=f"DEP-{dep_finding_counter:03d}",
                                category=FindingCategory.DEPENDENCY_REPRODUCIBILITY_RISK,
                                severity=SeverityLevel.LOW,
                                title=f"Dependency version range may reduce reproducibility: {pkg_name}",
                                description=f"Dependency '{pkg_name}' specifies a flexible version range '{v_str}'.",
                                file_path=str(rel_path.as_posix()),
                                line_number=line_no,
                                snippet=snippet,
                                explanation="Flexible ranges allow automatic minor/patch updates during fresh installs without lockfiles.",
                                remediation="Ensure a package-lock.json is committed to guarantee deterministic builds across environments.",
                                metadata={
                                    "package_name": pkg_name,
                                    "declared_version": v_str,
                                    "dependency_section": section,
                                    "risk_type": "version_range",
                                },
                            )
                        )
                        dep_finding_counter += 1

            # 2. Missing Lockfile Check
            # Check corresponding package-lock.json in same folder or project root
            pkg_dir = rel_path.parent.as_posix()
            expected_lockfile = (
                f"{pkg_dir}/package-lock.json" if pkg_dir != "." else "package-lock.json"
            )

            has_lockfile = expected_lockfile in lockfile_rel_paths or "package-lock.json" in lockfile_rel_paths

            if total_declared_deps > 0 and not has_lockfile:
                findings.append(
                    SecurityFinding(
                        id=f"DEP-{dep_finding_counter:03d}",
                        category=FindingCategory.DEPENDENCY_REPRODUCIBILITY_RISK,
                        severity=SeverityLevel.MEDIUM,
                        title="package-lock.json is missing; dependency resolution may not be reproducible",
                        description=f"Project declares {total_declared_deps} dependencies but contains no package-lock.json.",
                        file_path=str(rel_path.as_posix()),
                        line_number=1,
                        explanation="Without a lockfile, repeated installations resolve differing transitive packages, risking drift or unexpected upstream code changes.",
                        remediation="Generate a lockfile via 'npm install' or 'npm generate-lockfile' and commit it to version control.",
                        metadata={
                            "total_declared_dependencies": total_declared_deps,
                            "risk_type": "missing_lockfile",
                        },
                    )
                )
                dep_finding_counter += 1

            # 3. Lifecycle Scripts Detection
            scripts_dict = data.get("scripts")
            if isinstance(scripts_dict, dict):
                for hook_name in LIFECYCLE_HOOKS:
                    if hook_name in scripts_dict:
                        cmd = str(scripts_dict[hook_name]).strip()
                        line_no = find_key_line_number(lines, hook_name)
                        snippet = lines[line_no - 1].strip() if 0 < line_no <= len(lines) else f'"{hook_name}": "{cmd}"'

                        findings.append(
                            SecurityFinding(
                                id=f"HOOK-{hook_finding_counter:03d}",
                                category=FindingCategory.INSTALL_HOOK,
                                severity=SeverityLevel.INFO,
                                title=f"Dependency installation lifecycle hook detected: {hook_name}",
                                description=f"The package.json declares an automatic '{hook_name}' lifecycle script.",
                                file_path=str(rel_path.as_posix()),
                                line_number=line_no,
                                snippet=snippet,
                                explanation=f"The '{hook_name}' script executes automatically upon package installation. The installation script scanner will evaluate its commands.",
                                remediation=f"Inspect the '{hook_name}' script command to ensure it does not execute untrusted binaries or make unauthorized network calls.",
                                metadata={
                                    "hook_name": hook_name,
                                    "script_command": cmd,
                                },
                            )
                        )
                        hook_finding_counter += 1

        return findings


def scan_dependencies(context: ProjectContext) -> List[SecurityFinding]:
    """Public entry point for scanning Node.js dependencies."""
    scanner = DependencyScanner()
    return scanner.scan(context)


def count_declared_dependencies(context: ProjectContext) -> Dict[str, int]:
    """
    Helper function to tally dependencies across all package.json files in context.
    Returns a dictionary of counts per section and total.
    """
    counts = {
        "dependencies": 0,
        "devDependencies": 0,
        "optionalDependencies": 0,
        "peerDependencies": 0,
        "total": 0,
    }

    for rel_path in context.relevant_files:
        if rel_path.name.lower() == "package.json":
            full_path = context.root_path / rel_path
            try:
                data = json.loads(full_path.read_text(encoding="utf-8", errors="replace"))
                if isinstance(data, dict):
                    for sec in DEPENDENCY_SECTIONS:
                        d = data.get(sec)
                        if isinstance(d, dict):
                            counts[sec] += len(d)
                            counts["total"] += len(d)
            except Exception:
                pass

    return counts
