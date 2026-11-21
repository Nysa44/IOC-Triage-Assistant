import csv, json
from dataclasses import asdict
from pathlib import Path

def write_reports(findings, output_prefix: Path):
    output_prefix = Path(output_prefix)
    output_prefix.parent.mkdir(parents=True, exist_ok=True)
    rows = [asdict(x) for x in findings]
    md = ["# IOC Triage Report", "", "> Local-feed matches are triage signals, not proof of compromise. Indicators are defanged.", "",
          "| Indicator | Type | Score | Band | Human review |", "|---|---:|---:|---|---|"]
    for r in rows:
        md.append(f'| `{r["indicator"]}` | {r["indicator_type"]} | {r["score"]} | {r["band"]} | {"Yes" if r["needs_human_review"] else "No"} |')
        md += ["", f'**Evidence:** {", ".join(f"{m["source"]} ({m["category"]})" for m in r["matches"]) or "No local feed match"}',
               f'**Reasons:** {"; ".join(r["reasons"])}',
               f'**ATT&CK:** {", ".join(f"{t["id"]} {t["name"]}" for t in r["techniques"]) or "No mapping"}',
               f'**Analyst note:** {r["analyst_note"]}', ""]
    (output_prefix.with_suffix(".md")).write_text("\n".join(md), encoding="utf-8")
    with output_prefix.with_suffix(".csv").open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["indicator","indicator_type","score","band","needs_human_review","matches","techniques","reasons","analyst_note"])
        writer.writeheader()
        for r in rows:
            writer.writerow({**r, "matches": json.dumps(r["matches"]), "techniques": json.dumps(r["techniques"]), "reasons": "; ".join(r["reasons"])})
    output_prefix.with_suffix(".json").write_text(json.dumps(rows, indent=2), encoding="utf-8")
