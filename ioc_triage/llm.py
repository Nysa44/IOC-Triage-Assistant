"""Optional OpenAI-compatible analyst-note layer. Never sends indicators, only defanged evidence."""
import json, os, urllib.request

def template_note(finding: dict) -> str:
    matches = finding.get("matches", [])
    if not matches:
        return "Insufficient evidence: no match was found in the configured local feeds. Do not treat this as proof that the indicator is benign. Next step: validate with approved internal telemetry."
    cats = ", ".join(sorted({m["category"] for m in matches}))
    sources = ", ".join(sorted({m["source"] for m in matches}))
    techniques = ", ".join(f'{t["id"]} {t["name"]}' for t in finding.get("techniques", [])) or "No technique mapping available"
    return (f"Evidence: listed in {sources} under {cats}. "
            f"ATT&CK context: {techniques}. "
            "Next step: analyst should validate against internal telemetry before containment.")

def _validate_note(value):
    if not isinstance(value, dict) or not {"summary", "next_step"}.issubset(value):
        raise ValueError("LLM response must be a JSON object with summary and next_step")
    summary, next_step = value["summary"], value["next_step"]
    if not isinstance(summary, str) or not isinstance(next_step, str) or not summary.strip() or not next_step.strip():
        raise ValueError("summary and next_step must be non-empty strings")
    if len(summary) > 500 or len(next_step) > 300:
        raise ValueError("LLM response exceeds length limits")
    return f"Evidence-based summary: {summary.strip()} Next step: {next_step.strip()}"

def llm_note(finding: dict) -> str:
    """Uses only evidence fields; disabled unless IOC_LLM_ENDPOINT and IOC_LLM_API_KEY are set."""
    endpoint = os.getenv("IOC_LLM_ENDPOINT")
    api_key = os.getenv("IOC_LLM_API_KEY")
    model = os.getenv("IOC_LLM_MODEL", "gpt-4o-mini")
    if not endpoint or not api_key:
        return template_note(finding)
    evidence = {
        "indicator_defanged": finding["indicator"],
        "indicator_type": finding["indicator_type"],
        "matches": finding["matches"],
        "techniques": finding["techniques"],
        "score": finding["score"],
        "band": finding["band"],
        "reasons": finding["reasons"],
    }
    prompt = ("Write a concise SOC analyst note using ONLY the supplied evidence. "
              "Do not infer reputation, intent, attribution, or facts not present. "
              "If evidence is insufficient, explicitly say 'insufficient evidence'. "
              "Return JSON only: {\"summary\":\"...\",\"next_step\":\"...\"}. Evidence: "
              + json.dumps(evidence))
    payload = json.dumps({"model": model, "messages": [
        {"role": "system", "content": "You are a cautious SOC triage assistant. Evidence only."},
        {"role": "user", "content": prompt}
    ], "temperature": 0}).encode()
    request = urllib.request.Request(endpoint, data=payload, headers={
        "Authorization": f"Bearer {api_key}", "Content-Type": "application/json"
    })
    for _ in range(2):
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                body = json.loads(response.read().decode())
            content = body["choices"][0]["message"]["content"]
            return _validate_note(json.loads(content))
        except Exception:
            continue
    return template_note(finding) + " [LLM unavailable or response failed validation; template fallback used.]"
