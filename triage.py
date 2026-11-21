from __future__ import annotations
import argparse, json
from pathlib import Path
from dataclasses import asdict
from ioc_triage.core import init_db, load_feed, read_indicators, build_findings
from ioc_triage.llm import llm_note
from ioc_triage.report import write_reports

ROOT = Path(__file__).resolve().parent

def main():
    parser = argparse.ArgumentParser(description="Offline-first, evidence-grounded IOC triage")
    parser.add_argument("--input", default="data/sample_indicators.csv")
    parser.add_argument("--feeds", default="data/feeds")
    parser.add_argument("--db", default="data/ioc_triage.sqlite")
    parser.add_argument("--output", default="reports/triage_report")
    parser.add_argument("--llm", action="store_true", help="Use optional configured LLM for high-risk findings")
    args = parser.parse_args()
    db = Path(args.db)
    db.parent.mkdir(parents=True, exist_ok=True)
    init_db(db)
    feed_paths = sorted(Path(args.feeds).glob("*.csv"))
    if not feed_paths:
        parser.error(f"No CSV feeds found in {args.feeds}")
    loaded = sum(load_feed(db, p) for p in feed_paths)
    indicators, rejected = read_indicators(Path(args.input))
    findings = build_findings(indicators, db, ROOT / "data/attack_mapping.json")
    for item in findings:
        if args.llm and item.band == "high":
            item.analyst_note = llm_note(asdict(item))
        else:
            item.analyst_note = llm_note({**asdict(item), "matches": item.matches}) if args.llm else (
                "Insufficient evidence: no local feed match. Validate using approved internal telemetry."
                if not item.matches else
                f"Evidence: {len(item.matches)} local feed match(es). ATT&CK mappings: " +
                (", ".join(t["id"] for t in item.techniques) or "none") +
                ". Next step: analyst review and corroboration with internal telemetry."
            )
    write_reports(findings, Path(args.output))
    rejected_path = Path(args.output).with_name(Path(args.output).name + "_rejected.json")
    rejected_path.parent.mkdir(parents=True, exist_ok=True)
    rejected_path.write_text(json.dumps(rejected, indent=2), encoding="utf-8")
    print(f"Loaded {loaded} feed rows from {len(feed_paths)} local feed files.")
    print(f"Processed {len(indicators)} unique valid indicators; rejected {len(rejected)} invalid rows.")
    print(f"High: {sum(x.band == 'high' for x in findings)} | Medium: {sum(x.band == 'medium' for x in findings)} | Low: {sum(x.band == 'low' for x in findings)}")
    print(f"Reports: {args.output}.md / .csv / .json")
    print("Safety: no indicator was visited, pinged, or connected to.")

if __name__ == "__main__":
    main()
