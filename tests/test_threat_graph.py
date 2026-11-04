from groundtrace.models import Finding
from groundtrace.threat_graph import build_threat_graph


def test_build_threat_graph_links_cve_to_actor_and_ioc():
    finding = Finding(
        cve_id="CVE-2024-1234",
        title="Remote code execution in web application",
        description="Critical remote code execution flaw in the management interface.",
        cwe_ids=["CWE-79"],
    )
    signals = [
        {
            "signal_type": "exploit_sale",
            "threat_actor": "APT36",
            "domains": ["evil.example"],
            "ip_addresses": ["203.0.113.10"],
            "malware_hashes": ["abc123"],
            "tags": ["RCE", "phishing"],
            "priority": "P1",
        }
    ]

    graph = build_threat_graph(finding, signals)

    assert graph.entities[0].kind == "cve"
    assert any(r.relation == "mentions" and r.target == "APT36" for r in graph.relationships)
    assert graph.keywords
    assert "T1190" in graph.attack_techniques or "T1059" in graph.attack_techniques
