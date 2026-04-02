"""Tests for log parsing logic."""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from app.core.log_parser import parse_logs, detect_log_format, detect_source_system


class TestLogFormatDetection:
    def test_detects_syslog(self):
        text = "Apr  1 08:23:17 server sshd[1234]: Failed password for root"
        assert detect_log_format(text) == "syslog"

    def test_detects_json(self):
        text = '{"timestamp": "2026-04-01", "event": "login_failed"}'
        assert detect_log_format(text) == "JSON"

    def test_detects_cef(self):
        text = "CEF:0|Security|IDS|1.0|100|Attack detected|5|src=10.0.0.1"
        assert detect_log_format(text) == "CEF"

    def test_detects_kv(self):
        text = "timestamp=2026-04-01 src=10.0.0.1 dst=10.0.0.2 action=block proto=TCP"
        assert detect_log_format(text) == "key-value"

    def test_detects_free_text(self):
        text = "Something weird happened on the network today."
        assert detect_log_format(text) == "free-text"


class TestSourceDetection:
    def test_detects_proofpoint(self):
        assert detect_source_system("Alert from Proofpoint gateway") == "Proofpoint"

    def test_detects_crowdstrike(self):
        assert detect_source_system("CrowdStrike Falcon detection") == "CrowdStrike"

    def test_detects_windows(self):
        assert detect_source_system("EventID 4625 Security-Auditing") == "Windows Event Log"

    def test_returns_none_for_unknown(self):
        assert detect_source_system("some random text") is None


class TestTimestampExtraction:
    def test_extracts_iso8601(self):
        text = "Event at 2026-04-01T08:23:17Z was suspicious"
        parsed = parse_logs(text)
        assert len(parsed.timestamps) >= 1

    def test_extracts_syslog_timestamp(self):
        text = "Apr  1 08:23:17 server sshd: test"
        parsed = parse_logs(text)
        assert len(parsed.timestamps) >= 1


class TestParsedLogMetadata:
    def test_line_count(self):
        text = "line1\nline2\nline3"
        parsed = parse_logs(text)
        assert parsed.line_count == 3

    def test_char_count(self):
        text = "hello"
        parsed = parse_logs(text)
        assert parsed.char_count == 5
