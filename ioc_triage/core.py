from __future__ import annotations
import csv, ipaddress, re, sqlite3
from dataclasses import dataclass, asdict
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Iterable

HASH_LENGTHS = {32: "MD5", 40: "SHA-1", 64: "SHA-256"}
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[A-Za-z]{2,63}\.?$")

@dataclass
class Finding:
    indicator: str
    indicator_type: str
    matches: list[dict]
    techniques: list[dict]
    score: int
    band: str
    reasons: list[str]
    needs_human_review: bool
    analyst_note: str = ""

def classify_indicator(value: str) -> str:
    value = value.strip()
    if not value:
        raise ValueError("empty indicator")
    try:
        ipaddress.ip_address(value)
        return "ip"
    except ValueError:
        pass
    if len(value) in HASH_LENGTHS and re.fullmatch(r"[0-9a-fA-F]+", value):
        return "hash"
    if DOMAIN_RE.fullmatch(value):
        return "domain"
    raise ValueError(f"invalid indicator: {value}")

def read_indicators(path: Path) -> tuple[list[str], list[dict]]:
    accepted, rejected = [], []
    path = Path(path)
    if path.suffix.lower() == ".csv":
        with path.open(newline="", encoding="utf-8-sig") as f:
            reader = csv.DictReader(f)
            if not reader.fieldnames:
                raise ValueError("CSV must have a header containing 'indicator'")
            key = next((h for h in reader.fieldnames if h.lower() == "indicator"), None)
            if not key:
                raise ValueError("CSV must contain an 'indicator' column")
            values = [row.get(key, "") for row in reader]
    else:
        values = path.read_text(encoding="utf-8").splitlines()
    seen = set()
    for line_no, raw in enumerate(values, 1):
        value = str(raw).strip()
        if not value or value.startswith("#"):
            continue
        try:
            classify_indicator(value)
            canonical = value.lower().rstrip(".")
            if canonical not in seen:
                accepted.append(canonical)
                seen.add(canonical)
        except ValueError as exc:
            rejected.append({"line": line_no, "value": value, "error": str(exc)})
    return accepted, rejected

def init_db(db_path: Path) -> None:
    with sqlite3.connect(db_path) as con:
        con.execute("""CREATE TABLE IF NOT EXISTS blocklist (
            indicator TEXT NOT NULL, indicator_type TEXT NOT NULL,
            source TEXT NOT NULL, category TEXT NOT NULL,
            date_added TEXT, PRIMARY KEY(indicator, source)
        )""")
        con.execute("CREATE INDEX IF NOT EXISTS idx_blocklist_indicator ON blocklist(indicator)")

def load_feed(db_path: Path, feed_path: Path, source_name: str | None = None) -> int:
    """Load a CSV feed with indicator,category,date_added columns."""
    source = source_name or Path(feed_path).stem
    count = 0
    with Path(feed_path).open(newline="", encoding="utf-8-sig") as f, sqlite3.connect(db_path) as con:
        reader = csv.DictReader(f)
        required = {"indicator", "category"}
        if not reader.fieldnames or not required.issubset({x.lower() for x in reader.fieldnames}):
            raise ValueError(f"{feed_path}: required CSV columns are indicator,category (date_added optional)")
        # Resolve case-insensitive headers.
        headers = {x.lower(): x for x in reader.fieldnames}
        for row in reader:
            indicator = (row.get(headers["indicator"]) or "").strip().lower().rstrip(".")
            category = (row.get(headers["category"]) or "unspecified").strip().lower()
            if not indicator or not category:
                continue
            try:
                kind = classify_indicator(indicator)
            except ValueError:
                continue
            added = (row.get(headers.get("date_added", "")) or "").strip() or None
            con.execute("""INSERT OR REPLACE INTO blocklist
                (indicator, indicator_type, source, category, date_added)
                VALUES (?, ?, ?, ?, ?)""", (indicator, kind, source, category, added))
            count += 1
    return count

def lookup_matches(db_path: Path, indicator: str) -> list[dict]:
    with sqlite3.connect(db_path) as con:
        con.row_factory = sqlite3.Row
        rows = con.execute("""SELECT source, category, date_added FROM blocklist
            WHERE indicator=? ORDER BY source""", (indicator.lower().rstrip("."),)).fetchall()
    return [dict(r) for r in rows]

def map_techniques(matches: list[dict], mapping_path: Path) -> list[dict]:
    mapping = json_load(mapping_path)
    output, seen = [], set()
    for match in matches:
        for item in mapping.get(match["category"].lower(), []):
            key = item["id"]
            if key not in seen:
                output.append({"id": item["id"], "name": item["name"], "url": item.get("url", "")})
                seen.add(key)
    return output

def json_load(path: Path):
    import json
    return json.loads(Path(path).read_text(encoding="utf-8"))

def score_indicator(matches: list[dict], today: date | None = None) -> tuple[int, str, list[str]]:
    """Transparent heuristic. Scores are prioritisation aids, not probabilities."""
    today = today or datetime.now(timezone.utc).date()
    if not matches:
        return 0, "low", ["No local blocklist matches"]
    score, reasons = 20, ["Listed in at least one local feed (+20)"]
    sources = {m["source"] for m in matches}
    if len(sources) >= 2:
        score += 25
        reasons.append("Listed by 2 or more independent feed files (+25)")
    high_risk = {"malware", "malware-c2", "command-and-control", "phishing", "ransomware", "botnet"}
    if any(m["category"].lower() in high_risk for m in matches):
        score += 30
        reasons.append("High-risk category present (+30)")
    dates = []
    for m in matches:
        try:
            dates.append(date.fromisoformat(m["date_added"][:10]))
        except (TypeError, ValueError):
            pass
    if dates and (today - max(dates)).days <= 30 and max(dates) <= today:
        score += 15
        reasons.append("At least one listing is 30 days old or newer (+15)")
    score = min(score, 100)
    band = "high" if score >= 70 else "medium" if score >= 40 else "low"
    return score, band, reasons

def defang(value: str, kind: str) -> str:
    if kind == "ip":
        # Preserve the address while making it non-clickable / non-routable in reports.
        return value.replace(".", "[.]").replace(":", "[:]")
    if kind == "domain":
        return value.replace(".", "[.]")
    return value

def build_findings(indicators: Iterable[str], db_path: Path, mapping_path: Path) -> list[Finding]:
    findings = []
    for indicator in indicators:
        kind = classify_indicator(indicator)
        matches = lookup_matches(db_path, indicator)
        techniques = map_techniques(matches, mapping_path)
        score, band, reasons = score_indicator(matches)
        findings.append(Finding(
            indicator=defang(indicator, kind), indicator_type=kind,
            matches=matches, techniques=techniques, score=score, band=band,
            reasons=reasons, needs_human_review=(band != "low" or not matches),
        ))
    return sorted(findings, key=lambda x: (-x.score, x.indicator))
