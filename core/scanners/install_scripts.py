"""
Lifecycle Installation Script Scanner for SupplyGuard AI.
Analyzes package.json lifecycle hooks (preinstall, install, postinstall, prepare):
- Inspects command strings for shell, network, process execution, and obfuscated patterns.
- Safely resolves referenced local scripts with strict path traversal protection.
- Evaluates referenced local scripts statically without execution.
"""

import json
import re
from pathlib import Path
from typing import Dict, Any, List, Optional, Set, Tuple

from core.models import ProjectContext, SecurityFinding, FindingCategory, SeverityLevel
from core.scanners.base import BaseScanner
from core.scanners.dangerous_patterns import check_line_indicators, compute_severity_and_title

LIFECYCLE_HOOKS: Set[str] = {
    "preinstall",
    "install",
    "postinstall",
    "prepare",
}

# Regex to detect command string indicators
RE_CMD_NETWORK = re.compile(r"\b(?:curl|wget|Invoke-WebRequest|fetch|http\.get|axios|requests)\b", re.IGNORECASE)
RE_CMD_SHELL = re.compile(r"\b(?:bash|sh|cmd(?:\.exe)?|powershell(?:\.exe)?|pwsh)\b", re.IGNORECASE)
RE_CMD_EXEC = re.compile(r"\b(?:child_process|execSync|exec|spawn)\b", re.IGNORECASE)
RE_CMD_OBFUSCATED = re.compile(r"(?:(?:^|\s)-(?:enc|encodedcommand)\b|\b(?:certutil|base64)\b)", re.IGNORECASE)
RE_CMD_ENV = re.compile(r"\b(?:process\.env|\.env|AWS_ACCESS_KEY|API_KEY|TOKEN)\b", re.IGNORECASE)

# Extract local script path from command string (e.g., 'node scripts/setup.js')
RE_REFERENCED_SCRIPT = re.compile(r"(?:node|bash|sh)\s+([^\s;&|]+\.[a-zA-Z0-9]+)")


def analyze_hook_command_string(command: str) -> List[str]:
    """Detects dangerous behavior categories inside a hook command string."""
    behaviors: List[str] = []
    if RE_CMD_NETWORK.search(command):
        behaviors.append("network_download")
    if RE_CMD_SHELL.search(command):
        behaviors.append("shell_execution")
    if RE_CMD_EXEC.search(command):
        behaviors.append("command_execution")
    if RE_CMD_OBFUSCATED.search(command):
        behaviors.append("obfuscated_command")
    if RE_CMD_ENV.search(command):
        behaviors.append("environment_access")
    return behaviors


class InstallScriptScanner(BaseScanner):
    """Static scanner for package.json lifecycle install scripts and referenced files."""

    def scan(self, context: ProjectContext) -> List[SecurityFinding]:
        findings: List[SecurityFinding] = []
        finding_id_counter = 1

        pkg_json_rel_paths = [
            p for p in context.relevant_files if p.name.lower() == "package.json"
        ]

        root_resolved = context.root_path.resolve()

        for pkg_rel in pkg_json_rel_paths:
            full_pkg_path = context.root_path / pkg_rel
            if not full_pkg_path.exists():
                continue

            try:
                pkg_data = json.loads(full_pkg_path.read_text(encoding="utf-8", errors="replace"))
            except Exception:
                continue

            scripts = pkg_data.get("scripts")
            if not isinstance(scripts, dict):
                continue

            for hook_name in LIFECYCLE_HOOKS:
                if hook_name not in scripts:
                    continue

                cmd_str = str(scripts[hook_name]).strip()
                behaviors = analyze_hook_command_string(cmd_str)

                # 1. Analyze the command string itself
                if behaviors:
                    has_net = "network_download" in behaviors
                    has_exec = "command_execution" in behaviors or "shell_execution" in behaviors
                    has_obf = "obfuscated_command" in behaviors
                    has_env = "environment_access" in behaviors

                    if (has_net and has_exec) or has_obf or (has_exec and has_env):
                        severity = SeverityLevel.HIGH
                    elif has_exec or has_net or has_env:
                        severity = SeverityLevel.MEDIUM
                    else:
                        severity = SeverityLevel.LOW

                    behavior_names = ", ".join(behaviors)
                    findings.append(
                        SecurityFinding(
                            id=f"HOOK-ACT-{finding_id_counter:03d}",
                            category=FindingCategory.INSTALL_HOOK,
                            severity=severity,
                            title=f"Potentially dangerous installation behavior detected in lifecycle hook: {hook_name}",
                            description=(
                                f"Lifecycle hook '{hook_name}' contains suspicious installation command patterns: "
                                f"{behavior_names}."
                            ),
                            file_path=str(pkg_rel.as_posix()),
                            line_number=1,
                            snippet=f'"{hook_name}": "{cmd_str}"',
                            explanation=(
                                f"The '{hook_name}' script executes automatically during package installation. "
                                "Automated network downloads or shell commands in lifecycle hooks can download "
                                "and execute secondary payloads without developer interaction."
                            ),
                            remediation=(
                                f"Remove or audit the '{hook_name}' script command. Ensure dependencies do not run "
                                "arbitrary shell or download commands on install."
                            ),
                            metadata={
                                "hook_name": hook_name,
                                "script_command": cmd_str,
                                "detected_behaviors": behaviors,
                                "has_network": has_net,
                                "has_command_exec": has_exec,
                                "has_sensitive_env": has_env,
                            },
                        )
                    )
                    finding_id_counter += 1

                # 2. Analyze Referenced Local Scripts safely
                ref_match = RE_REFERENCED_SCRIPT.search(cmd_str)
                if ref_match:
                    raw_script_target = ref_match.group(1)
                    pkg_dir = full_pkg_path.parent

                    # Safely resolve target relative to package.json
                    try:
                        resolved_script = (pkg_dir / raw_script_target).resolve()
                        is_within_root = resolved_script.is_relative_to(root_resolved)
                    except (ValueError, AttributeError):
                        is_within_root = str(resolved_script).startswith(str(root_resolved))

                    if not is_within_root:
                        findings.append(
                            SecurityFinding(
                                id=f"HOOK-ACT-{finding_id_counter:03d}",
                                category=FindingCategory.CONFIG_ISSUE,
                                severity=SeverityLevel.HIGH,
                                title=f"Lifecycle hook references path outside project root: {hook_name}",
                                description=(
                                    f"Lifecycle hook '{hook_name}' attempts to reference a script outside the project "
                                    f"boundary: '{raw_script_target}'."
                                ),
                                file_path=str(pkg_rel.as_posix()),
                                line_number=1,
                                snippet=f'"{hook_name}": "{cmd_str}"',
                                explanation="Path traversal in lifecycle scripts can allow execution of external system scripts.",
                                remediation="Ensure lifecycle script references are confined strictly to internal project directories.",
                                metadata={"hook_name": hook_name, "raw_target": raw_script_target},
                            )
                        )
                        finding_id_counter += 1
                        continue

                    # If file exists within project, inspect its contents for dangerous execution
                    if resolved_script.exists() and resolved_script.is_file():
                        try:
                            rel_to_root = resolved_script.relative_to(root_resolved)
                            script_content = resolved_script.read_text(encoding="utf-8", errors="replace")
                            lines = script_content.splitlines()

                            for line_no, line in enumerate(lines, start=1):
                                script_inds = check_line_indicators(line)
                                if script_inds:
                                    s_sev, s_title, s_desc = compute_severity_and_title(script_inds)
                                    findings.append(
                                        SecurityFinding(
                                            id=f"HOOK-ACT-{finding_id_counter:03d}",
                                            category=FindingCategory.INSTALL_HOOK,
                                            severity=s_sev,
                                            title=f"Lifecycle hook '{hook_name}' executes script containing dangerous pattern",
                                            description=(
                                                f"Referenced script '{rel_to_root.as_posix()}' on line {line_no} contains: {s_title}."
                                            ),
                                            file_path=str(rel_to_root.as_posix()),
                                            line_number=line_no,
                                            snippet=line.strip()[:120],
                                            explanation=(
                                                f"The script '{rel_to_root.as_posix()}' is invoked by the automatic '{hook_name}' hook. "
                                                "Its execution during 'npm install' can lead to automated supply-chain compromise."
                                            ),
                                            remediation="Refactor or remove the script from the lifecycle installation flow.",
                                            metadata={
                                                "hook_name": hook_name,
                                                "referenced_script": str(rel_to_root.as_posix()),
                                                "indicator_types": [ind[0] for ind in script_inds],
                                            },
                                        )
                                    )
                                    finding_id_counter += 1
                        except Exception:
                            pass

        return findings


def scan_install_scripts(context: ProjectContext) -> List[SecurityFinding]:
    """Public entry point for scanning lifecycle installation scripts."""
    scanner = InstallScriptScanner()
    return scanner.scan(context)
