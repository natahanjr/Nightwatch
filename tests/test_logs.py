import json

from nightwatch.logs import (collect, analyze, generate_markdown_report,
                             load_rules)


def test_json_logs_are_normalized(tmp_path):
    path = tmp_path / "app.json"
    path.write_text(json.dumps([
        {"timestamp": "2025-01-01T10:00:00", "level": "ERROR",
         "message": "Failed password for root from 10.0.0.5"},
        {"timestamp": "2025-01-01T10:00:01", "level": "INFO",
         "message": "Login successful"},
    ]), encoding="utf-8")

    events = collect(str(path))
    assert len(events) == 2
    assert events[0]["level"] == "ERROR"
    assert events[0]["timestamp"] == "2025-01-01T10:00:00"

    result = analyze(events)
    assert result["events_total"] == 2
    labels = [f["label"] for f in result["findings"]]
    assert "failed-login" in labels
    assert "privileged-account" in labels


def test_jsonl_logs_are_parsed_per_line(tmp_path):
    path = tmp_path / "events.jsonl"
    path.write_text(
        json.dumps({"timestamp": "2026-08-03T12:00:00", "level": "ERROR",
                    "message": "Failed password for root"}) + "\n"
        + json.dumps({"timestamp": "2026-08-03T12:00:01", "level": "INFO",
                      "message": "ok"}) + "\n",
        encoding="utf-8")

    events = collect(str(path))
    assert len(events) == 2
    assert events[0]["level"] == "ERROR"
    assert events[0]["message"] == "Failed password for root"
    result = analyze(events)
    assert any(f["label"] == "failed-login" for f in result["findings"])
    assert result["levels"] == {"ERROR": 1, "INFO": 1}


def test_syslog_lines_are_parsed(tmp_path):
    path = tmp_path / "sys.log"
    path.write_text(
        "<34>Oct 11 22:14:15 myhost sshd[123]: Failed password for root "
        "from 192.168.1.5\n"
        "<86>Oct 11 22:14:16 myhost sshd[123]: Accepted password for alice\n",
        encoding="utf-8")

    events = collect(str(path))
    assert len(events) == 2
    assert events[0]["timestamp"] == "Oct 11 22:14:15"
    assert events[0]["source"] == "myhost"
    assert "Failed password" in events[0]["message"]

    result = analyze(events)
    assert any(f["label"] == "failed-login" for f in result["findings"])


def test_plain_timestamped_lines_are_parsed(tmp_path):
    path = tmp_path / "plain.log"
    path.write_text(
        "2025-01-01 10:00:00 web01 401 unauthorized from 10.0.0.9\n"
        "2025-01-01 10:00:05 web01 GET /index.html 200\n",
        encoding="utf-8")

    events = collect(str(path))
    assert len(events) == 2
    assert events[0]["timestamp"] == "2025-01-01 10:00:00"
    result = analyze(events)
    assert any(f["label"] == "forbidden-access" for f in result["findings"])


def test_csv_logs_are_parsed(tmp_path):
    path = tmp_path / "app.csv"
    path.write_text(
        "timestamp,level,message\n"
        "2025-01-01T10:00:00,ERROR,SQL injection attempt blocked\n"
        "2025-01-01T10:00:01,INFO,health check ok\n",
        encoding="utf-8")

    events = collect(str(path))
    assert len(events) == 2
    result = analyze(events)
    assert any(f["label"] == "sql-injection" for f in result["findings"])


def test_directory_collection_merges_files(tmp_path):
    (tmp_path / "a.json").write_text(json.dumps([
        {"message": "Failed password"}, {"message": "ok"}]), encoding="utf-8")
    (tmp_path / "b.json").write_text(json.dumps([
        {"message": "Failed password"}]), encoding="utf-8")

    events = collect(str(tmp_path))
    assert len(events) == 3
    assert len([e for e in events if "Failed" in e["message"]]) == 2


def test_burst_detection(tmp_path):
    events = [
        {"timestamp": "2025-01-01T10:00:00", "source": "web01",
         "message": "x"}
        for _ in range(12)
    ]
    result = analyze(events)
    assert len(result["bursts"]) == 1
    assert result["bursts"][0]["count"] == 12


def test_burst_window_is_respected(tmp_path):
    # 12 events spread across 5-minute buckets of 60s should NOT burst.
    events = [
        {"timestamp": 1000 + i * 30, "source": "web01", "message": "x"}
        for i in range(12)
    ]
    result = analyze(events)
    assert result["bursts"] == []

    # Same 12 events inside a 60s window -> one burst.
    events2 = [
        {"timestamp": 1000 + i, "source": "web01", "message": "x"}
        for i in range(12)
    ]
    assert len(analyze(events2)["bursts"]) == 1

    # Epoch float timestamps are supported and windowed correctly.
    events3 = [
        {"timestamp": 1700000000.0 + i * 100, "source": "s", "message": "x"}
        for i in range(12)
    ]
    assert analyze(events3)["bursts"] == []


def test_burst_sliding_window_crosses_bucket_boundary(tmp_path):
    # 10 events at t=55..64: a fixed 60s bucket splits them (5 in [0,59),
    # 5 in [60,119)) and misses the burst, but a sliding window catches it.
    events = [{"timestamp": 55 + i, "source": "web01", "message": "x"}
              for i in range(10)]
    result = analyze(events)
    assert len(result["bursts"]) == 1
    assert result["bursts"][0]["count"] == 10
    # Human-readable window start is present.
    assert isinstance(result["bursts"][0]["window_start"], str)
    assert "window_start_epoch" in result["bursts"][0]


def test_burst_threshold_and_window_are_configurable(tmp_path):
    events = [{"timestamp": i, "source": "s", "message": "x"}
              for i in range(8)]  # 8 events in 7s
    # Default threshold (10) -> no burst.
    assert analyze(events)["bursts"] == []
    # Lowered threshold -> burst.
    assert len(analyze(events, threshold=5)["bursts"]) == 1
    # Tightened window (5s) over 8 events spanning 7s -> still a burst, but a
    # window of 3s splits them.
    assert len(analyze(events, threshold=5, window_seconds=5)["bursts"]) == 1
    assert analyze(events, threshold=5, window_seconds=3)["bursts"] == []


def test_markdown_report_generated(tmp_path):
    events = [{"timestamp": "2025-01-01T10:00:00", "level": "HIGH",
               "source": "app", "message": "Failed password for root"}]
    out = tmp_path / "report.md"
    result = generate_markdown_report(str(out), events)

    assert result["events_total"] == 1
    content = out.read_text(encoding="utf-8")
    assert content.startswith("# Nightwatch Log Analysis Report")
    assert "[HIGH] failed-login" in content


def test_custom_rules_load_from_json(tmp_path):
    rules_path = tmp_path / "rules.json"
    rules_path.write_text(json.dumps([
        {"pattern": "token expired", "severity": "HIGH",
         "label": "token-expiry"},
        {"pattern": "disk full", "severity": "LOW", "label": "disk-space"},
    ]), encoding="utf-8")

    rules = load_rules(str(rules_path))
    assert len(rules) == 2

    events = [
        {"timestamp": "2025-01-01T10:00:00", "message":
            "auth token expired for user bob"},
        {"timestamp": "2025-01-01T10:00:01", "message": "health ok"},
    ]
    result = analyze(events, rules=rules)
    labels = [f["label"] for f in result["findings"]]
    assert labels == ["token-expiry"]
    assert result["findings"][0]["severity"] == "HIGH"


def test_custom_rules_missing_pattern_rejected(tmp_path):
    rules_path = tmp_path / "bad.json"
    rules_path.write_text(json.dumps([{"severity": "HIGH"}]),
                          encoding="utf-8")
    import pytest
    with pytest.raises(ValueError):
        load_rules(str(rules_path))
