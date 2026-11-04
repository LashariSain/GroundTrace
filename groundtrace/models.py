"""
Core data model for the vulnerability intelligence framework.

Everything is a plain dataclass so it serializes cleanly to JSON and is easy to
extend. Enums keep the "discovery method" and "disclosure basis" fields
structured instead of free text, which is what makes the output usable for both
research and automated reporting.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import date
from enum import Enum
from typing import Optional


# --------------------------------------------------------------------------- #
# Controlled vocabularies (enums)
# --------------------------------------------------------------------------- #
class DiscoveryMethod(str, Enum):
    """HOW the flaw was technically found."""
    STATIC_ANALYSIS = "static_analysis"
    DYNAMIC_ANALYSIS = "dynamic_analysis"
    FUZZING = "fuzzing"
    PENTEST = "pentest"
    BUG_BOUNTY = "bug_bounty"
    INTERNAL_AUDIT = "internal_audit"
    EXPLOITED_IN_WILD = "exploited_in_wild"
    DEPENDENCY_SCAN = "dependency_scan"
    RESPONSIBLE_DISCLOSURE = "responsible_disclosure"
    UNKNOWN = "unknown"


class DisclosureBasis(str, Enum):
    """On what BASIS / through what channel it became public."""
    COORDINATED = "coordinated_disclosure"
    FULL_DISCLOSURE = "full_disclosure"
    VENDOR_ADVISORY = "vendor_advisory"
    ZERO_DAY_LEAK = "zero_day_leak"
    EXPLOIT_PUBLISHED = "exploit_published"
    ACCIDENTAL_LEAK = "accidental_leak"
    THREAT_INTEL = "threat_intel"
    UNKNOWN = "unknown"


class Confidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


# --------------------------------------------------------------------------- #
# Sub-structures
# --------------------------------------------------------------------------- #
@dataclass
class Discovery:
    method: DiscoveryMethod = DiscoveryMethod.UNKNOWN
    found_by: Optional[str] = None          # researcher / vendor / team
    detection_signal: Optional[str] = None  # e.g. "malformed HTTP header crash"
    confidence: Confidence = Confidence.LOW
    evidence: list[str] = field(default_factory=list)  # phrases that justified the label
    ai_found_by: Optional[str] = None       # e.g. "Google Big Sleep", "AI-assisted"
    ai_evidence: list[str] = field(default_factory=list)


@dataclass
class Disclosure:
    basis: DisclosureBasis = DisclosureBasis.UNKNOWN
    channel: Optional[str] = None           # NVD, GHSA, ExploitDB, vendor blog...
    disclosure_date: Optional[date] = None
    patch_date: Optional[date] = None
    exploit_public: bool = False
    in_kev: bool = False                    # CISA Known-Exploited-Vulnerabilities
    confidence: Confidence = Confidence.LOW
    evidence: list[str] = field(default_factory=list)

    # --- derived ---
    @property
    def patch_available_at_disclosure(self) -> Optional[bool]:
        if self.disclosure_date and self.patch_date:
            return self.patch_date <= self.disclosure_date
        return None

    @property
    def leaked_before_fix(self) -> Optional[bool]:
        pav = self.patch_available_at_disclosure
        return (pav is False) if pav is not None else None


@dataclass
class Scores:
    cvss: Optional[float] = None        # 0-10 severity
    cvss_severity: Optional[str] = None  # LOW/MEDIUM/HIGH/CRITICAL
    epss: Optional[float] = None        # 0-1 probability of exploitation
    asset_criticality: float = 1.0     # 0-1, set by the defender per environment
    in_kev: bool = False               # CISA KEV — confirmed exploited in the wild

    # EPSS only *predicts* exploitation; a KEV listing means it is *observed*.
    # So a KEV CVE's exploit-likelihood is effectively certain — floor it here
    # rather than let a low EPSS drag an actively-exploited CVE down to ~0.
    _KEV_EPSS_FLOOR = 0.9

    def __post_init__(self):
        # A risk score the tool cannot justify is worse than no score. An
        # out-of-range criticality silently multiplies the result past 100,
        # so reject it at construction rather than print an impossible number.
        if not 0.0 <= self.asset_criticality <= 1.0:
            raise ValueError(
                f"asset_criticality must be between 0.0 and 1.0, got {self.asset_criticality}")

    @property
    def _risk_unclamped(self) -> Optional[float]:
        if self.cvss is None:
            return None
        epss = self.epss if self.epss is not None else 0.1
        if self.in_kev:
            epss = max(epss, self._KEV_EPSS_FLOOR)
        return (self.cvss / 10.0) * epss * self.asset_criticality * 100

    @property
    def risk(self) -> Optional[float]:
        """Business-context risk = severity x exploit-likelihood x asset value.

        Clamped to 0-100. With a validated criticality the formula cannot
        exceed 100 on its own, so the clamp is a second line of defence
        against a future change to the formula or an out-of-range CVSS --
        and `risk_clamped` records when it had to apply.
        """
        raw = self._risk_unclamped
        if raw is None:
            return None
        return round(min(max(raw, 0.0), 100.0), 1)

    @property
    def risk_clamped(self) -> bool:
        """True when the raw formula fell outside 0-100 and `risk` capped it."""
        raw = self._risk_unclamped
        return raw is not None and not 0.0 <= round(raw, 1) <= 100.0


RISK_FORMULA = "risk = (CVSS / 10) × exploit likelihood × asset criticality × 100"


def explain_risk(scores: Scores, cve_id: str) -> dict:
    """Break a risk score into its inputs, each with the source it came from.

    The dashboard shows this next to the number so an analyst can check every
    factor instead of trusting an opaque score.
    """
    nvd = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
    epss_url = f"https://api.first.org/data/v1/epss?cve={cve_id}"
    kev_url = ("https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
               f"?search_api_fulltext={cve_id}")

    if scores.cvss is None:
        return {"formula": RISK_FORMULA, "result": None, "factors": [],
                "note": "NVD has no CVSS score for this CVE yet, so it is left "
                        "unscored rather than given a guessed number.",
                "sources": [{"name": "NVD", "url": nvd}]}

    epss = scores.epss
    if scores.in_kev and (epss is None or epss < Scores._KEV_EPSS_FLOOR):
        likelihood = Scores._KEV_EPSS_FLOOR
        epss_txt = "unknown" if epss is None else f"{epss:.3f}"
        basis = (f"On CISA KEV (exploitation observed), so EPSS {epss_txt} is "
                 f"raised to the {Scores._KEV_EPSS_FLOOR} floor")
        source, url = "CISA KEV", kev_url
    elif epss is not None:
        likelihood = epss
        basis = f"EPSS {epss:.4f}: FIRST's predicted probability of exploitation in the next 30 days"
        if scores.in_kev:
            basis += " (also on CISA KEV; EPSS is already above the floor)"
        source, url = "FIRST EPSS", epss_url
    else:
        likelihood = 0.1
        basis = "No EPSS score published yet; a conservative default of 0.1 is used"
        source, url = "default", epss_url

    factors = [
        {"name": "Severity", "value": round(scores.cvss / 10.0, 3),
         "basis": f"CVSS {scores.cvss}" + (f" ({scores.cvss_severity})" if scores.cvss_severity else "") + " ÷ 10",
         "source": "NVD", "url": nvd},
        {"name": "Exploit likelihood", "value": round(likelihood, 4),
         "basis": basis, "source": source, "url": url},
        {"name": "Asset criticality", "value": scores.asset_criticality,
         "basis": ("Default 1.0: treated as a critical asset. Set it per environment with --criticality."
                   if scores.asset_criticality == 1.0 else "Set by you for this environment"),
         "source": "your config", "url": None},
    ]
    note = None
    if scores.risk_clamped:
        note = (f"The formula produced {scores._risk_unclamped:.1f}, outside the 0-100 "
                f"range, so the score shown is capped at {scores.risk}. Treat the "
                f"inputs above as the reliable part of this result.")
    return {"formula": RISK_FORMULA, "result": scores.risk, "factors": factors,
            "note": note,
            "sources": [{"name": "NVD", "url": nvd}, {"name": "FIRST EPSS", "url": epss_url},
                        {"name": "CISA KEV", "url": kev_url}]}


@dataclass
class Remediation:
    fixed_version: Optional[str] = None
    upgrade_path: Optional[str] = None
    workaround: Optional[str] = None
    references: list[str] = field(default_factory=list)
    action: str = "recommend"  # recommend | ticket | pr — never silent auto-patch


@dataclass
class Analysis:
    """The narrative layer — your 5 report fields."""
    what_it_is: str = ""             # 1. vulnerability kya thi
    root_cause: str = ""             # 2. developer ki galti
    how_found: str = ""              # 3. step-by-step discovery
    business_impact: str = ""        # 4. business impact
    principle_violated: str = ""     # 5. security design principle


# --------------------------------------------------------------------------- #
# Top-level record
# --------------------------------------------------------------------------- #
@dataclass
class Finding:
    cve_id: str
    title: str = ""
    description: str = ""
    cwe_ids: list[str] = field(default_factory=list)
    affected: list[str] = field(default_factory=list)   # cpe / package@version
    published: Optional[date] = None

    scores: Scores = field(default_factory=Scores)
    discovery: Discovery = field(default_factory=Discovery)
    disclosure: Disclosure = field(default_factory=Disclosure)
    remediation: Remediation = field(default_factory=Remediation)
    analysis: Analysis = field(default_factory=Analysis)
    references: list[str] = field(default_factory=list)
    # CVE.org "credits" (finder, tool, ...). None = not fetched yet, [] = none listed.
    credits: Optional[list[str]] = None

    def to_dict(self) -> dict:
        def _serialize(o):
            if isinstance(o, Enum):
                return o.value
            if isinstance(o, date):
                return o.isoformat()
            return str(o)
        d = asdict(self)
        # asdict() only serializes declared fields — @property values like
        # Scores.risk (a derived field) are computed fresh here instead.
        d["scores"]["risk"] = self.scores.risk
        d["scores"]["explanation"] = explain_risk(self.scores, self.cve_id)
        import json
        return json.loads(json.dumps(d, default=_serialize))
