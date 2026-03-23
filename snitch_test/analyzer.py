"""Analyze captured traffic and sandbox results for credential exfiltration."""

import json
import re
from dataclasses import dataclass
from enum import Enum
from typing import Optional

from snitch_test.canary import CanaryCredential
from snitch_test.monitor import MonitorResult, NetworkEvent


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Finding:
    """A security finding from the analysis."""
    severity: Severity
    title: str
    description: str
    credential: Optional[str]
    destination: Optional[str]
    evidence: str
    recommendation: str


@dataclass
class AnalysisReport:
    """Complete analysis of a sandbox run."""
    findings: list[Finding]
    risk_score: int  # 0-100
    risk_level: str  # "safe", "low", "medium", "high", "critical"
    total_events: int
    suspicious_events: int
    leaked_count: int
    scan_duration: float
    summary: str


# Known malicious IP ranges (sample - in production use threat intel feeds)
KNOWN_BAD_RANGES = [
    # These are example ranges for demonstration
    "185.220.",  # Known Tor exit nodes
    "45.33.",    # Known hosting used for C2
]

# Suspicious URL patterns in install scripts
SUSPICIOUS_PATTERNS = [
    re.compile(r"curl\s+.*\|.*sh", re.IGNORECASE),
    re.compile(r"wget\s+.*\|.*sh", re.IGNORECASE),
    re.compile(r"eval\s*\(.*base64", re.IGNORECASE),
    re.compile(r"exec\s*\(.*http", re.IGNORECASE),
    re.compile(r"os\.environ", re.IGNORECASE),
    re.compile(r"process\.env", re.IGNORECASE),
    re.compile(r"subprocess.*curl", re.IGNORECASE),
    re.compile(r"child_process.*exec", re.IGNORECASE),
    re.compile(r"\\x[0-9a-f]{2}\\x[0-9a-f]{2}", re.IGNORECASE),  # Hex-encoded strings
    re.compile(r"atob\s*\(", re.IGNORECASE),  # Base64 decode in JS
]


def check_suspicious_patterns(text: str) -> list[Finding]:
    """Check text for suspicious code patterns."""
    findings = []
    for pattern in SUSPICIOUS_PATTERNS:
        matches = pattern.findall(text)
        for match in matches[:3]:  # Limit to 3 matches per pattern
            findings.append(Finding(
                severity=Severity.MEDIUM,
                title="Suspicious code pattern in install script",
                description=f"Found potentially malicious pattern: {match[:100]}",
                credential=None,
                destination=None,
                evidence=match[:200],
                recommendation="Review the dependency's install scripts manually",
            ))
    return findings


def check_env_access(install_log: str) -> list[Finding]:
    """Check install log for signs of environment variable access."""
    findings = []

    # Look for Python os.environ access patterns
    env_patterns = [
        (r"os\.environ\[", "Direct environment variable access"),
        (r"os\.getenv\(", "Environment variable read via getenv"),
        (r"process\.env\.", "Node.js environment variable access"),
        (r"ENV\[", "Ruby ENV access"),
    ]

    for pattern, desc in env_patterns:
        if re.search(pattern, install_log):
            findings.append(Finding(
                severity=Severity.HIGH,
                title=f"Environment variable access during install",
                description=f"{desc} detected during package installation",
                credential=None,
                destination=None,
                evidence=f"Pattern: {pattern}",
                recommendation="Investigate which package is accessing environment variables during install",
            ))

    return findings


def analyze_network_events(
    events: list[NetworkEvent],
    canaries: list[CanaryCredential],
) -> list[Finding]:
    """Analyze network events for suspicious activity."""
    findings = []

    for event in events:
        # Check for canary leakage
        if event.contains_canary:
            for cred_name in event.contains_canary:
                cred = next((c for c in canaries if c.name == cred_name), None)
                findings.append(Finding(
                    severity=Severity.CRITICAL,
                    title=f"Credential exfiltration detected: {cred_name}",
                    description=(
                        f"The canary value for {cred_name} ({cred.category if cred else 'unknown'}) "
                        f"was found in network traffic to {event.destination}"
                    ),
                    credential=cred_name,
                    destination=event.destination,
                    evidence=event.payload_preview[:200],
                    recommendation="IMMEDIATELY remove this dependency. It is actively stealing credentials.",
                ))

        # Check for known bad IPs
        for bad_range in KNOWN_BAD_RANGES:
            if event.destination.startswith(bad_range):
                findings.append(Finding(
                    severity=Severity.HIGH,
                    title=f"Connection to known malicious IP range",
                    description=f"Network connection to {event.destination} which is in a known malicious range",
                    credential=None,
                    destination=event.destination,
                    evidence=event.raw[:200],
                    recommendation="Investigate this connection. Known malicious infrastructure.",
                ))

    return findings


def calculate_risk_score(findings: list[Finding]) -> tuple[int, str]:
    """Calculate overall risk score from findings."""
    score = 0
    has_critical = False
    severity_weights = {
        Severity.CRITICAL: 40,
        Severity.HIGH: 20,
        Severity.MEDIUM: 10,
        Severity.LOW: 3,
        Severity.INFO: 0,
    }

    for f in findings:
        score += severity_weights.get(f.severity, 0)
        if f.severity == Severity.CRITICAL:
            has_critical = True

    score = min(100, score)

    # Any CRITICAL finding guarantees at least "critical" level
    if has_critical:
        level = "critical"
        score = max(score, 80)
    elif score >= 50:
        level = "high"
    elif score >= 25:
        level = "medium"
    elif score > 0:
        level = "low"
    else:
        level = "safe"

    return score, level


def analyze_results(
    monitor_result: MonitorResult,
    canaries: list[CanaryCredential],
) -> AnalysisReport:
    """Run complete analysis on sandbox monitoring results."""
    findings: list[Finding] = []

    # Analyze network events
    findings.extend(analyze_network_events(monitor_result.events, canaries))

    # Check install log for suspicious patterns
    if monitor_result.install_log:
        findings.extend(check_suspicious_patterns(monitor_result.install_log))
        findings.extend(check_env_access(monitor_result.install_log))

    # Check container output
    if monitor_result.container_logs:
        findings.extend(check_suspicious_patterns(monitor_result.container_logs))

    # Check for leaked credentials from monitor
    for cred in monitor_result.leaked_credentials:
        # Avoid duplicate findings
        already_found = any(
            f.credential == cred.name and f.severity == Severity.CRITICAL
            for f in findings
        )
        if not already_found:
            findings.append(Finding(
                severity=Severity.CRITICAL,
                title=f"Credential leaked: {cred.name}",
                description=f"Canary value for {cred.name} ({cred.category}) was detected in container output",
                credential=cred.name,
                destination=None,
                evidence=f"Category: {cred.category}, Fingerprint: {cred.fingerprint}",
                recommendation="This dependency may be logging or transmitting credentials. Remove immediately.",
            ))

    # Sort by severity
    severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
    findings.sort(key=lambda f: severity_order.index(f.severity))

    risk_score, risk_level = calculate_risk_score(findings)

    suspicious_count = sum(
        1 for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH)
    )

    # Build summary
    if risk_level == "safe":
        summary = "No suspicious activity detected. Dependencies appear safe."
    elif risk_level == "low":
        summary = f"Minor concerns found ({len(findings)} findings). Review recommended."
    elif risk_level == "medium":
        summary = f"Suspicious activity detected ({len(findings)} findings). Manual review required."
    elif risk_level == "high":
        summary = f"High-risk activity detected! {suspicious_count} critical/high findings."
    else:
        summary = f"CRITICAL: Credential exfiltration detected! {len(monitor_result.leaked_credentials)} credentials leaked."

    return AnalysisReport(
        findings=findings,
        risk_score=risk_score,
        risk_level=risk_level,
        total_events=len(monitor_result.events),
        suspicious_events=suspicious_count,
        leaked_count=len(monitor_result.leaked_credentials),
        scan_duration=monitor_result.duration,
        summary=summary,
    )
