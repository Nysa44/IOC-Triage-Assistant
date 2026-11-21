from datetime import date
from pathlib import Path
import pytest
from ioc_triage.core import classify_indicator, init_db, load_feed, lookup_matches, score_indicator, defang, read_indicators

def test_classify_ip_domain_hash():
    assert classify_indicator("8.8.8.8") == "ip"
    assert classify_indicator("example.com") == "domain"
    assert classify_indicator("a"*32) == "hash"

def test_invalid_indicator_rejected():
    with pytest.raises(ValueError):
        classify_indicator("not an indicator")

def test_feed_load_and_match(tmp_path):
    db = tmp_path / "test.db"
    init_db(db)
    feed = tmp_path / "feed.csv"
    feed.write_text("indicator,category,date_added\nexample.com,phishing,2026-11-01\n")
    assert load_feed(db, feed) == 1
    assert lookup_matches(db, "example.com")[0]["category"] == "phishing"

def test_multiple_sources_increase_score():
    one = [{"source":"a","category":"phishing","date_added":"2026-11-20"}]
    two = one + [{"source":"b","category":"phishing","date_added":"2026-11-20"}]
    assert score_indicator(two, date(2026,11,21))[0] > score_indicator(one, date(2026,11,21))[0]

def test_clean_indicator_scores_low():
    score, band, reasons = score_indicator([])
    assert score == 0 and band == "low"

def test_high_risk_category_scores_high():
    matches = [{"source":"a","category":"phishing","date_added":"2026-11-20"},
               {"source":"b","category":"phishing","date_added":"2026-11-20"}]
    assert score_indicator(matches, date(2026,11,21))[1] == "high"

def test_defang():
    assert defang("example.com", "domain") == "example[.]com"
    assert defang("1.2.3.4", "ip") == "1[.]2[.]3[.]4"

def test_read_input_rejects_invalid(tmp_path):
    f = tmp_path / "in.txt"
    f.write_text("example.com\nnot valid\n8.8.8.8\n")
    accepted, rejected = read_indicators(f)
    assert len(accepted) == 2 and len(rejected) == 1
