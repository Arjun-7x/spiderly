"""
SPIDERLY - Rule-based findings engine.

Every rule here is evidence-based: it fires only on something SPIDERLY
actually observed (an open port, a specific banner string, a specific
HTTP header). Nothing is labeled "vulnerable" without an observation
backing it up, and severities are deliberately conservative -- this is
an informational recon tool, not an automated exploit scanner.
"""
from dataclasses import dataclass
from typing import List, Optional

SEVERITY_INFO = "INFORMATIONAL"
SEVERITY_LOW = "LOW"
SEVERITY_MEDIUM = "MEDIUM"
SEVERITY_HIGH = "HIGH"

INSECURE_PLAINTEXT_SERVICES = {
    "Telnet": "Telnet transmits credentials and session data in plaintext.",
    "FTP": "Plain FTP transmits credentials and file contents in plaintext.",
    "SMTP-Submission": None,
}


@dataclass
class Finding:
    title: str
    severity: str
    description: str
    evidence: str
    affected_service: str
    recommendation: str


def evaluate_open_port(port: int, service: str, banner: Optional[str]) -> List[Finding]:
    """Findings for one open port. A port that triggers a specific rule
    (Telnet, FTP, ...) reports only that rule; every other open port gets a
    single informational finding, so the list isn't padded with duplicates."""
    findings = _specific_port_findings(port, service, banner)
    if findings:
        return findings
    return [_baseline_finding(port, service, banner)]


def _baseline_finding(port: int, service: str, banner: Optional[str]) -> Finding:
    return Finding(
        title=f"Open TCP port {port}",
        severity=SEVERITY_INFO,
        description=f"A TCP service is accessible on port {port} ({service}).",
        evidence=f"TCP connect succeeded on port {port}." + (f" Banner: {banner}" if banner else ""),
        affected_service=service,
        recommendation="Confirm this service is intended to be exposed. Restrict access with a "
                        "firewall or network segmentation if it is not required externally.",
    )


def _specific_port_findings(port: int, service: str, banner: Optional[str]) -> List[Finding]:
    findings: List[Finding] = []

    if service == "Telnet":
        findings.append(Finding(
            title="Telnet service detected",
            severity=SEVERITY_MEDIUM,
            description="Telnet is an insecure, unencrypted remote administration protocol. "
                        "Credentials and traffic are transmitted in plaintext.",
            evidence=f"Port {port} identified as Telnet." + (f" Banner: {banner}" if banner else ""),
            affected_service="Telnet",
            recommendation="Disable Telnet and replace it with SSH.",
        ))

    if service == "FTP":
        findings.append(Finding(
            title="Unencrypted FTP service detected",
            severity=SEVERITY_MEDIUM,
            description="Plain FTP transmits authentication credentials and file contents in "
                        "cleartext, making them vulnerable to interception.",
            evidence=f"Port {port} identified as FTP." + (f" Banner: {banner}" if banner else ""),
            affected_service="FTP",
            recommendation="Migrate to SFTP or FTPS. Disable anonymous access unless explicitly required.",
        ))

    if service in ("SMB",):
        findings.append(Finding(
            title="SMB service exposed",
            severity=SEVERITY_LOW,
            description="SMB file-sharing services are a common target for lateral movement and "
                        "have a history of critical remote-code-execution vulnerabilities "
                        "(e.g. EternalBlue). Exposure should be minimized, especially externally.",
            evidence=f"Port {port} identified as SMB.",
            affected_service="SMB",
            recommendation="Restrict SMB to trusted internal networks only. Ensure the host is "
                            "fully patched.",
        ))

    if service in ("Redis", "MongoDB", "Memcached", "Elasticsearch") :
        findings.append(Finding(
            title=f"{service} datastore exposed on the network",
            severity=SEVERITY_MEDIUM,
            description=f"{service} is reachable over the network. Many deployments of this "
                        "service have no authentication enabled by default, which can allow "
                        "unauthenticated data access.",
            evidence=f"Port {port} identified as {service}." + (f" Banner: {banner}" if banner else ""),
            affected_service=service,
            recommendation=f"Verify {service} requires authentication and is not reachable from "
                            "untrusted networks.",
        ))

    if service == "RDP":
        findings.append(Finding(
            title="RDP service exposed",
            severity=SEVERITY_LOW,
            description="Remote Desktop Protocol is exposed. RDP is a frequent target for "
                        "credential-stuffing and brute-force attacks when reachable from the "
                        "internet.",
            evidence=f"Port {port} identified as RDP.",
            affected_service="RDP",
            recommendation="Restrict RDP access to a VPN or bastion host, enable Network Level "
                            "Authentication, and enforce account lockout policies.",
        ))

    return findings


def evaluate_http(port: int, status_code: Optional[int], server_header: Optional[str],
                   tls: bool, title: Optional[str]) -> List[Finding]:
    findings = []

    if not tls:
        findings.append(Finding(
            title=f"Unencrypted HTTP service on port {port}",
            severity=SEVERITY_LOW,
            description="This web service was reached over plain HTTP rather than HTTPS. "
                        "Traffic to and from it is not encrypted in transit.",
            evidence=f"Successful plaintext HTTP GET on port {port} (status {status_code}).",
            affected_service="HTTP",
            recommendation="Enable TLS and redirect HTTP traffic to HTTPS.",
        ))

    if server_header:
        findings.append(Finding(
            title="Server identification header exposed",
            severity=SEVERITY_INFO,
            description="The web server discloses its identity via the Server response header, "
                        "which can aid an attacker in fingerprinting the software stack.",
            evidence=f"Server header on port {port}: \"{server_header}\"",
            affected_service="HTTP",
            recommendation="Consider suppressing or genericizing the Server header in production.",
        ))

    return findings
