"""Discovery/disclosure classification and CWE -> secure-design principle mapping."""
from datetime import date

from groundtrace.classify.discovery import classify_discovery
from groundtrace.classify.disclosure import classify_disclosure
from groundtrace.classify.principles import outcomes_for, principle_for
from groundtrace.models import Confidence, DiscoveryMethod


def test_kev_listing_forces_exploited_in_wild_with_high_confidence():
    # Weak/empty text, but a KEV listing is a strong external signal.
    d = classify_discovery("A vulnerability was reported.", in_kev=True)
    assert d.method == DiscoveryMethod.EXPLOITED_IN_WILD
    assert d.confidence == Confidence.HIGH
    assert any("KEV" in e for e in d.evidence)


def test_public_exploit_is_weaker_than_kev():
    d = classify_discovery("", exploit_public=True)
    assert d.method == DiscoveryMethod.EXPLOITED_IN_WILD
    # exploit_public alone contributes weight 1 -> not HIGH.
    assert d.confidence != Confidence.HIGH


def test_unknown_when_no_signal():
    d = classify_discovery("")
    assert d.method == DiscoveryMethod.UNKNOWN
    assert d.confidence == Confidence.LOW


def test_disclosure_flags_leak_before_fix_from_dates():
    disc = classify_disclosure(
        "Vulnerability details were published.",
        disclosure_date=date(2024, 3, 1),
        patch_date=date(2024, 3, 15),
    )
    assert disc.leaked_before_fix is True


def test_disclosure_exploit_public_from_exploitdb_reference():
    disc = classify_disclosure(
        "RCE in the admin panel.",
        references=["https://www.exploit-db.com/exploits/51234"],
    )
    assert disc.exploit_public is True


def test_principle_for_known_cwe():
    name, rule = principle_for(["CWE-89"])
    assert name == "Input Validation"
    assert "parameterized" in rule.lower()


def test_principle_for_falls_back_to_default():
    name, _ = principle_for(["CWE-99999"])
    assert name == "Secure Design"


def test_principle_for_picks_first_recognized_cwe():
    name, _ = principle_for(["CWE-99999", "CWE-79"])
    assert name == "Output Encoding"


def test_outcomes_for_deduplicates():
    out = outcomes_for(["CWE-79", "CWE-79"])
    assert len(out) == len(set(out))


def test_ai_discovery_named_system():
    from groundtrace.classify.ai_discovery import detect_ai_discovery
    label, ev = detect_ai_discovery("Stack underflow in SQLite.",
                                    ["https://googleprojectzero.blogspot.com/2024/10/from-naptime-to-big-sleep.html"])
    assert label == "Google Big Sleep"
    assert ev


def test_ai_discovery_phrase():
    from groundtrace.classify.ai_discovery import detect_ai_discovery
    assert detect_ai_discovery("This issue was discovered using an AI agent.")[0] == "AI-assisted"
    assert detect_ai_discovery("Found with LLM-assisted fuzzing.")[0] == "AI-assisted"


def test_ai_discovery_ignores_ai_products():
    from groundtrace.classify.ai_discovery import detect_ai_discovery
    # A bug *in* an AI product is not a bug found *by* AI.
    assert detect_ai_discovery("Prompt injection in the LLM chat plugin allows RCE.")[0] is None
    assert detect_ai_discovery("Reported by Aiden Smith.")[0] is None
    assert detect_ai_discovery("AI-powered chatbot leaks credentials.")[0] is None
    assert detect_ai_discovery("Langflow is a tool for building AI-powered agents.")[0] is None


def test_ai_discovery_from_credits():
    from groundtrace.classify.ai_discovery import detect_ai_discovery
    label, _ = detect_ai_discovery("SQLite overflow.", [], [
        "finder: Vlad Stolyarov of Google's Threat Analysis Group, with assistance from Google Big Sleep"])
    assert label == "Google Big Sleep"
    assert detect_ai_discovery("Bug.", [], ["finder: Jane Doe using Claude"])[0] == "Jane Doe using Claude"
    assert detect_ai_discovery("Bug.", [], ["finder: Aiden Smith"])[0] is None
