"""The rule-based grounding check used to flag hallucinated facts in bench runs."""
from groundtrace.bench import grounding


def test_flags_number_not_in_facts():
    facts = "CVE-2024-1234 has CVSS 9.8."
    g = grounding(facts, "The CVE-2024-1234 flaw scores 9.8 and affects 50000 hosts.")
    assert "50000" in g["ungrounded_tokens"]
    assert g["hallucination_flag"] is True


def test_grounded_output_has_no_flag():
    facts = "CVE-2024-1234 has CVSS 9.8 and EPSS 0.5."
    g = grounding(facts, "CVE-2024-1234 is critical at 9.8 with EPSS 0.5.")
    assert g["ungrounded_tokens"] == []
    assert g["hallucination_flag"] is False


def test_sentence_count():
    g = grounding("x", "One sentence. Two sentences. Three sentences.")
    assert g["sentence_count"] == 3


def test_invented_cve_id_is_flagged():
    facts = "CVE-2024-1234 details."
    g = grounding(facts, "Related to CVE-2099-0001.")
    assert "CVE-2099-0001" in g["ungrounded_tokens"]
