from ioc_triage.llm import template_note, _validate_note

def test_template_says_insufficient_evidence():
    assert "insufficient evidence" in template_note({"matches": [], "techniques": []}).lower()

def test_llm_schema_validation():
    assert "Next step" in _validate_note({"summary":"Listed in a local feed.","next_step":"Review internally."})

def test_llm_rejects_bad_schema():
    try:
        _validate_note({"summary":"Only summary"})
    except ValueError:
        return
    assert False, "Expected schema validation failure"


def test_llm_disabled_uses_template(monkeypatch):
    monkeypatch.delenv("IOC_LLM_ENDPOINT", raising=False)
    monkeypatch.delenv("IOC_LLM_API_KEY", raising=False)
    from ioc_triage.llm import llm_note
    note = llm_note({"indicator":"example[.]com", "indicator_type":"domain", "matches":[], "techniques":[], "score":0, "band":"low", "reasons":[]})
    assert "insufficient evidence" in note.lower()
