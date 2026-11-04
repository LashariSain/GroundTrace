"""Lightweight threat-graph primitives for CVE + adversary + IOC correlation."""

from __future__ import annotations

from dataclasses import dataclass, field
import re
from typing import Any


@dataclass
class GraphEntity:
    name: str
    kind: str
    attributes: dict[str, Any] = field(default_factory=dict)


@dataclass
class GraphRelationship:
    source: str
    relation: str
    target: str
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class ThreatGraph:
    entities: list[GraphEntity] = field(default_factory=list)
    relationships: list[GraphRelationship] = field(default_factory=list)
    keywords: list[str] = field(default_factory=list)
    attack_techniques: list[str] = field(default_factory=list)


def _ensure_entity(graph: ThreatGraph, name: str, kind: str, attributes: dict[str, Any] | None = None) -> None:
    if not any(entity.name == name and entity.kind == kind for entity in graph.entities):
        graph.entities.append(GraphEntity(name=name, kind=kind, attributes=attributes or {}))


def _add_relationship(graph: ThreatGraph, source: str, relation: str, target: str, **metadata: Any) -> None:
    if not any(
        rel.source == source and rel.relation == relation and rel.target == target
        for rel in graph.relationships
    ):
        graph.relationships.append(GraphRelationship(source=source, relation=relation, target=target, metadata=metadata))


def _extract_keywords(*values: str | None) -> list[str]:
    keywords: list[str] = []
    seen: set[str] = set()
    for value in values:
        if not value:
            continue
        for token in re.findall(r"[A-Za-z0-9][A-Za-z0-9/.-]{1,}", value.lower()):
            if len(token) < 3:
                continue
            if token in {"the", "with", "from", "into", "that", "this", "have", "will", "your"}:
                continue
            if token not in seen:
                seen.add(token)
                keywords.append(token)
    return keywords


def _infer_attack_techniques(finding, signal: dict[str, Any] | None = None) -> list[str]:
    techniques: list[str] = []
    haystack = " ".join(
        [
            finding.title or "",
            finding.description or "",
            " ".join(finding.cwe_ids or []),
            " ".join((signal or {}).get("tags", []) or []),
        ]
    ).lower()

    if "rce" in haystack or "remote code execution" in haystack or "code execution" in haystack:
        techniques.append("T1190")
    if "phishing" in haystack or "spear" in haystack or "credential" in haystack:
        techniques.append("T1566")
    if "powershell" in haystack or "script" in haystack or "macro" in haystack:
        techniques.append("T1059")

    # De-duplicate while preserving order.
    seen: set[str] = set()
    ordered: list[str] = []
    for technique in techniques:
        if technique not in seen:
            seen.add(technique)
            ordered.append(technique)
    return ordered


def build_threat_graph(finding, signals: list[dict[str, Any]] | None = None) -> ThreatGraph:
    """Build a minimal graph linking a CVE to likely actors, infrastructure and ATT&CK techniques."""
    graph = ThreatGraph()
    graph.entities.append(GraphEntity(name=finding.cve_id, kind="cve", attributes={"title": finding.title}))
    graph.keywords = _extract_keywords(finding.title, finding.description, " ".join(finding.cwe_ids))
    graph.attack_techniques = []

    if not signals:
        signals = []

    for signal in signals:
        signal_tags = signal.get("tags", []) or []
        graph.keywords.extend(_extract_keywords(" ".join(signal_tags), signal.get("signal_type"), signal.get("threat_actor")))
        if signal.get("threat_actor"):
            actor_name = str(signal["threat_actor"])
            _ensure_entity(graph, actor_name, "actor")
            _add_relationship(graph, finding.cve_id, "mentions", actor_name)
            _add_relationship(graph, actor_name, "targets", finding.cve_id)
        for domain in signal.get("domains", []) or []:
            _ensure_entity(graph, str(domain), "domain")
            _add_relationship(graph, finding.cve_id, "mentions", str(domain))
        for ip in signal.get("ip_addresses", []) or []:
            _ensure_entity(graph, str(ip), "ip")
            _add_relationship(graph, finding.cve_id, "mentions", str(ip))
        for malware_hash in signal.get("malware_hashes", []) or []:
            _ensure_entity(graph, str(malware_hash), "hash")
            _add_relationship(graph, finding.cve_id, "linked_to", str(malware_hash))

        for technique in _infer_attack_techniques(finding, signal):
            graph.attack_techniques.append(technique)

    # Fill in a sensible default when there are no explicit signal matches.
    if not graph.attack_techniques:
        graph.attack_techniques = _infer_attack_techniques(finding)

    deduped_keywords: list[str] = []
    seen_keywords: set[str] = set()
    for keyword in graph.keywords:
        if keyword not in seen_keywords:
            seen_keywords.add(keyword)
            deduped_keywords.append(keyword)
    graph.keywords = deduped_keywords

    if not graph.attack_techniques:
        graph.attack_techniques = ["T1190"]

    return graph
