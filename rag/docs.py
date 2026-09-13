"""Tiny curated knowledge base. Replace with your real runbooks later."""
from dataclasses import dataclass, field


@dataclass
class KnowledgeDoc:
    doc_id: str
    title: str
    text: str
    tags: list[str] = field(default_factory=list)
    signature: list[str] = field(default_factory=list)

    def indexed_text(self) -> str:
        return (
            f"{self.title}. {self.text} "
            f"Signature: {', '.join(self.signature)}. "
            f"Tags: {', '.join(self.tags)}"
        )


ATTACK_DOCS = [
    KnowledgeDoc(
        "KB-001", "TCP SYN Flood / Volumetric DoS",
        "A high-rate flood of TCP SYN packets that never completes the handshake, "
        "exhausting the server backlog. Connections are extremely short-lived and "
        "carry almost no payload, so the SYN-error rate approaches 1.0 while byte "
        "counts stay near zero.",
        tags=["dos", "tcp", "volumetric"],
        signature=["high serror_rate", "high count", "low duration",
                   "low src_bytes", "high dst_host_serror_rate"],
    ),
    KnowledgeDoc(
        "KB-002", "TCP Port Scan / Reconnaissance",
        "Sequential probing of many destination ports on one or few hosts. Most "
        "connection attempts are rejected, producing a very high RST-error rate and "
        "a high diversity of services touched relative to the number of flows.",
        tags=["recon", "scan", "tcp"],
        signature=["high rerror_rate", "high diff_srv_rate", "low same_srv_rate",
                   "high dst_host_count"],
    ),
    KnowledgeDoc(
        "KB-003", "Slowloris / Low-and-Slow Connection Exhaustion",
        "The client opens many connections and holds them open by trickling partial "
        "HTTP headers, never finishing the request. Flow duration is very long while "
        "bytes transferred per connection stay tiny.",
        tags=["dos", "http", "slow"],
        signature=["high duration", "low src_bytes", "high same_srv_rate",
                   "low dst_bytes"],
    ),
    KnowledgeDoc(
        "KB-004", "Data Exfiltration / Large Outbound Transfer",
        "An internal host uploads an unusually large volume to an external endpoint. "
        "The distinguishing signal is a very high destination-byte count over a long "
        "flow with very few concurrent connections.",
        tags=["exfiltration", "dlp", "data-loss"],
        signature=["high dst_bytes", "high duration", "low count", "high src_bytes"],
    ),
    KnowledgeDoc(
        "KB-005", "SSH / Credential Brute Force",
        "Repeated authentication attempts against a single service. Authentication "
        "failures drive the SYN-error rate up, and because the target service is the "
        "same every time, the same-service rate stays near 1.0.",
        tags=["bruteforce", "auth", "ssh"],
        signature=["high serror_rate", "high same_srv_rate",
                   "high dst_host_srv_count", "high count", "low dst_bytes"],
    ),
    KnowledgeDoc(
        "KB-006", "HTTP Flood / Application-Layer DDoS",
        "A large number of well-formed but useless HTTP requests hit the same web "
        "service. Unlike a SYN flood the handshakes succeed, so the error rate stays "
        "low-to-moderate while the connection count and destination host count spike.",
        tags=["ddos", "http", "layer7"],
        signature=["high count", "high dst_host_count", "high same_srv_rate",
                   "moderate serror_rate"],
    ),
]

MITIGATION_DOCS = [
    KnowledgeDoc(
        "KB-101", "Rate Limiting & SYN Cookies",
        "Enable SYN cookies on the target host and apply a per-source rate limit at "
        "the edge. Raise the listen backlog and shorten SYN-received timeouts. "
        "Escalate to upstream scrubbing if packets-per-second exceed 50k.",
        tags=["mitigation", "dos", "tcp"],
        signature=["rate limiting", "syn cookies", "tcp", "syn flood"],
    ),
    KnowledgeDoc(
        "KB-102", "Host Isolation Runbook",
        "If a host is confirmed compromised, quarantine it from the production VLAN, "
        "preserve volatile memory for forensics, and rotate any credentials that were "
        "present on the box. Notify the on-call security lead within 15 minutes.",
        tags=["mitigation", "containment", "ir"],
        signature=["host isolation", "quarantine", "containment", "incident response"],
    ),
    KnowledgeDoc(
        "KB-103", "Egress Filtering & DLP",
        "Block outbound traffic to unknown external destinations, enforce TLS "
        "inspection for data-loss prevention, and cap per-host egress volume. Alert "
        "on any single flow exceeding 50 MB outbound.",
        tags=["mitigation", "exfiltration", "dlp"],
        signature=["egress filtering", "data loss prevention", "exfiltration",
                   "outbound"],
    ),
    KnowledgeDoc(
        "KB-104", "WAF Rules & Connection Limits",
        "Deploy rate-based WAF rules, cap concurrent connections per source IP, and "
        "enable bot-detection challenges on the affected virtual host. Keep-alive "
        "timeouts should be reduced to below 10 seconds.",
        tags=["mitigation", "http", "waf"],
        signature=["waf", "connection limit", "http flood", "slowloris",
                   "rate limiting"],
    ),
    KnowledgeDoc(
        "KB-105", "Account Lockout & MFA Enforcement",
        "Apply progressive lockout after 5 failed logins, enforce MFA on the targeted "
        "service, and block the source IP range at the perimeter firewall. Review "
        "auth logs for any successful login from the attacking range.",
        tags=["mitigation", "bruteforce", "auth"],
        signature=["account lockout", "mfa", "brute force", "authentication"],
    ),
    KnowledgeDoc(
        "KB-106", "Upstream Scrubbing & Blackhole Routing",
        "For volumetric attacks that saturate the link, announce a more specific "
        "route to a scrubbing centre or blackhole the target /32 while the attack is "
        "in progress. Coordinate with the ISP NOC.",
        tags=["mitigation", "ddos", "volumetric"],
        signature=["scrubbing", "blackhole", "upstream", "ddos", "volumetric"],
    ),
]

ALL_DOCS = ATTACK_DOCS + MITIGATION_DOCS

ATTACK_TO_DOC = {
    "syn_flood": "KB-001",
    "port_scan": "KB-002",
    "slowloris": "KB-003",
    "exfiltration": "KB-004",
    "brute_force": "KB-005",
    "http_flood": "KB-006",
}