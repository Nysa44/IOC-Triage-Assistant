# IOC Triage Assistant — Evidence-Grounded Threat Triage

An offline-first Python command-line project that classifies IP addresses, domains and file hashes; matches them against local CSV threat-feed snapshots stored in SQLite; maps matched categories to selected MITRE ATT&CK techniques; calculates transparent risk scores; and produces Markdown, CSV and JSON analyst reports.

**Important:** the included `demo_feed_*.csv` files are synthetic demonstration fixtures, not live public blocklists and not claims about real malicious infrastructure. Replace them with locally downloaded feeds only after checking each provider's terms, schema and update cadence. The sample IP ranges are documentation ranges (RFC 5737), reserved for examples.

## Features

- IP/domain/MD5/SHA-1/SHA-256 classification and input validation.
- Local CSV feed ingestion into SQLite; no indicator is visited, pinged or connected to.
- Multi-source matching and category-to-ATT&CK mapping.
- Explainable 0–100 heuristic scoring with reasons and low/medium/high bands.
- Defanged indicators in reports.
- Optional LLM note generation for high-risk findings. It sends only defanged evidence fields, never makes network requests to indicators, validates JSON output, retries once and falls back to a deterministic template.
- Invalid rows written to a separate JSON file.
- pytest coverage for parsing, matching, scoring, defanging, input rejection and LLM fallback primitives.

## Requirements

- Python 3.10+
- `pytest` for tests
- No runtime third-party dependencies for offline mode.

## Run

From this directory:

```bash
python -m venv .venv
# Windows:
.venv\Scripts\activate
# macOS/Linux:
source .venv/bin/activate

pip install -r requirements.txt
python triage.py
```

Expected sample run summary (the exact high/medium/low counts can vary with the current date because recency is one scoring factor):

```text
Loaded 20 feed rows from 3 local feed files.
Processed 25 unique valid indicators; rejected 1 invalid rows.
Reports: reports/triage_report.md / .csv / .json
Safety: no indicator was visited, pinged, or connected to.
```

The tool creates `data/ioc_triage.sqlite` and three reports under `reports/`, plus `triage_report_rejected.json`.

## Use your own input

Text file: one indicator per line. CSV file: a header named `indicator` and one indicator per row.

```bash
python triage.py --input data/my_indicators.csv --feeds data/feeds --output reports/my_run
```

Feed CSV format:

```csv
indicator,category,date_added
198.51.100.10,phishing,2026-11-10
```

Required columns: `indicator`, `category`. `date_added` is optional and should use ISO date format (`YYYY-MM-DD`). Each CSV filename becomes its source name. Feed ingestion validates indicators and ignores malformed feed rows.

## Optional LLM notes

Offline template notes are the default. To enable the optional OpenAI-compatible chat-completions endpoint, set environment variables (never commit secrets):

```bash
# PowerShell
$env:IOC_LLM_ENDPOINT="https://api.openai.com/v1/chat/completions"
$env:IOC_LLM_API_KEY="YOUR_KEY"
$env:IOC_LLM_MODEL="gpt-4o-mini"
python triage.py --llm
```

Only high-band findings are sent to the configured LLM. The payload contains the defanged indicator, type, local feed matches, ATT&CK mappings, score and reasons. No raw indicator is sent. The response must be JSON with non-empty `summary` and `next_step`; it is length-checked, retried once, and falls back to a template if unavailable or invalid. Review provider data-handling terms before enabling.

## Scoring model

| Signal | Points |
|---|---:|
| At least one local feed match | +20 |
| Listed by 2+ distinct feed files | +25 |
| High-risk category (malware, malware-C2, phishing, ransomware, botnet) | +30 |
| At least one listing dated within the last 30 days | +15 |
| Maximum | 90 |

Bands: low = 0–39, medium = 40–69, high = 70–100. Scores are prioritisation heuristics, **not probabilities** and not a verdict that a host is compromised. A clean result means only “not present in these local feed snapshots.”

## ATT&CK mapping

The mapping file is intentionally small and illustrative. Technique names and IDs are linked to MITRE ATT&CK pages in `data/attack_mapping.json`. A category-to-technique association is a contextual mapping, not proof that the technique occurred. Validate mappings and keep them current before using the project operationally.

## Safety and limitations

- The program does not perform DNS resolution, HTTP requests, ping, port scanning or connections to indicators.
- Included feeds are synthetic fixtures. They are only for demonstrating parsing, matching and scoring.
- Public blocklists can have different licenses, update cadences, formats and false-positive rates. Check terms before use and preserve source attribution.
- No threat attribution is attempted. A match is not proof of maliciousness or compromise.
- MITRE mapping is category-based and approximate.
- The scoring model is a transparent demo heuristic, not a calibrated detection model.
- The LLM is optional and can hallucinate; its note is constrained to supplied evidence, validated structurally, and should always be reviewed by a human.
- Do not upload confidential indicators or internal telemetry to a third-party LLM without approval.

## Tests

```bash
pytest -q
```
