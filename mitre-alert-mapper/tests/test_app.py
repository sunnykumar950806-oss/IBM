"""
Unit tests for alert parsing, indicator extraction, MITRE mapping,
confidence calculation, and FastAPI endpoints.
"""
import json
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# ── Test DB setup ────────────────────────────────────────────────────────────
from app.database import Base, get_db
from app.main import app

TEST_DB_URL = "sqlite:///./test_mitre_alerts.db"
test_engine = create_engine(TEST_DB_URL, connect_args={"check_same_thread": False})
TestSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)


def override_get_db():
    db = TestSessionLocal()
    try:
        yield db
    finally:
        db.close()


@pytest.fixture(scope="session", autouse=True)
def setup_test_db():
    from app.models.db_models import Alert, MitreMapping, SigmaMatch  # noqa
    Base.metadata.create_all(bind=test_engine)
    app.dependency_overrides[get_db] = override_get_db
    yield
    Base.metadata.drop_all(bind=test_engine)
    import os
    if os.path.exists("./test_mitre_alerts.db"):
        os.remove("./test_mitre_alerts.db")


@pytest.fixture
def client():
    return TestClient(app)


# ═══════════════════════════════════════════════════════════════════════════
# 1. Alert Parsing Tests
# ═══════════════════════════════════════════════════════════════════════════

class TestAlertParser:
    def test_parse_powershell_text(self):
        from app.services.alert_parser import parse_alert
        raw = "Process: powershell.exe CommandLine: powershell -EncodedCommand abc123 User: jsmith"
        result = parse_alert(raw, "text")
        assert result["alert_type"] == "PowerShell Execution"
        assert result["process_name"] is not None
        assert "powershell" in result["process_name"].lower()

    def test_parse_failed_login_text(self):
        from app.services.alert_parser import parse_alert
        raw = "failed login | username: administrator | SourceIP: 192.168.1.100 | EventID: 4625"
        result = parse_alert(raw, "text")
        assert result["alert_type"] == "Failed Authentication"
        assert result["username"] == "administrator"
        assert result["source_ip"] == "192.168.1.100"

    def test_parse_json_format(self):
        from app.services.alert_parser import parse_alert
        data = {
            "event_type": "process_creation",
            "process": "cmd.exe",
            "command_line": "cmd /c whoami",
            "user": "testuser",
            "host": "TESTHOST",
            "source_ip": "10.0.0.5"
        }
        result = parse_alert(json.dumps(data), "json")
        assert result["process_name"] == "cmd.exe"
        assert result["username"] == "testuser"
        assert result["hostname"] == "TESTHOST"
        assert result["source_ip"] == "10.0.0.5"
        assert result["command_line"] == "cmd /c whoami"

    def test_ip_extraction(self):
        from app.services.alert_parser import parse_alert
        raw = "Connection from 203.0.113.5 to 10.1.1.20 on port 443"
        result = parse_alert(raw, "text")
        assert result["source_ip"] == "203.0.113.5"
        assert result["destination_ip"] == "10.1.1.20"

    def test_lsass_alert_type(self):
        from app.services.alert_parser import parse_alert
        raw = "lsass.exe accessed by mimikatz process credential dump attempt"
        result = parse_alert(raw, "text")
        assert result["alert_type"] == "Credential Dumping"

    def test_scheduled_task_alert_type(self):
        from app.services.alert_parser import parse_alert
        raw = "schtasks.exe /Create /TN BackdoorTask /TR evil.exe"
        result = parse_alert(raw, "text")
        assert result["alert_type"] == "Scheduled Task"

    def test_new_user_alert_type(self):
        from app.services.alert_parser import parse_alert
        raw = "new user created: net user /add hacker123"
        result = parse_alert(raw, "text")
        assert result["alert_type"] == "Account Creation"

    def test_empty_input(self):
        from app.services.alert_parser import parse_alert
        result = parse_alert("   ", "text")
        assert result["alert_type"] == "Security Alert"
        assert result["username"] is None

    def test_domain_user_stripping(self):
        from app.services.alert_parser import parse_alert
        raw = "Logon: DOMAIN\\jsmith logged in from 192.168.1.5"
        result = parse_alert(raw, "text")
        assert result["username"] == "jsmith"


# ═══════════════════════════════════════════════════════════════════════════
# 2. Indicator Extraction Tests
# ═══════════════════════════════════════════════════════════════════════════

class TestIndicatorExtraction:
    def test_multiple_ips(self):
        from app.services.alert_parser import parse_alert
        raw = "Traffic from 1.2.3.4 to 5.6.7.8 and also 9.10.11.12"
        result = parse_alert(raw, "text")
        assert result["source_ip"] == "1.2.3.4"
        assert result["destination_ip"] == "5.6.7.8"

    def test_filename_extraction(self):
        from app.services.alert_parser import parse_alert
        raw = "File executed: C:\\Users\\test\\malware.exe by user alice"
        result = parse_alert(raw, "text")
        assert result["file_name"] is not None
        assert "malware.exe" in result["file_name"].lower()

    def test_json_extra_indicators(self):
        from app.services.alert_parser import parse_alert
        data = {"event_id": 4625, "failure_count": 15, "user": "admin"}
        result = parse_alert(json.dumps(data), "json")
        assert "event_id" in result["extra_indicators"] or result["username"] == "admin"

    def test_hostname_extraction(self):
        from app.services.alert_parser import parse_alert
        raw = "hostname: CORP-WS-042 | user: bob | process: powershell.exe"
        result = parse_alert(raw, "text")
        assert result["hostname"] == "CORP-WS-042"

    def test_command_line_truncation(self):
        from app.services.alert_parser import parse_alert
        long_cmd = "powershell.exe " + "A" * 1100
        raw = f"commandline: {long_cmd}"
        result = parse_alert(raw, "text")
        assert result["command_line"] is not None
        assert len(result["command_line"]) <= 1000


# ═══════════════════════════════════════════════════════════════════════════
# 3. MITRE Technique Matching Tests
# ═══════════════════════════════════════════════════════════════════════════

class TestMitreMapper:
    def test_powershell_maps_to_T1059_001(self):
        from app.services.mitre_mapper import map_alert
        raw = "powershell.exe -EncodedCommand abc -ExecutionPolicy Bypass -NoProfile"
        parsed = {"alert_type": "PowerShell", "username": None, "source_ip": None,
                  "destination_ip": None, "process_name": "powershell.exe",
                  "command_line": raw, "file_name": None, "hostname": None, "extra_indicators": {}}
        results = map_alert(raw, parsed)
        assert len(results) > 0
        ids = [r["technique_id"] for r in results]
        assert "T1059.001" in ids or "T1059" in ids

    def test_lsass_maps_to_T1003(self):
        from app.services.mitre_mapper import map_alert
        raw = "lsass.exe accessed by mimikatz credential dump sekurlsa logonpasswords"
        parsed = {"alert_type": "Credential Dumping", "username": None, "source_ip": None,
                  "destination_ip": None, "process_name": "mimikatz.exe",
                  "command_line": raw, "file_name": None, "hostname": None, "extra_indicators": {}}
        results = map_alert(raw, parsed)
        assert len(results) > 0
        ids = [r["technique_id"] for r in results]
        assert any(i.startswith("T1003") for i in ids)

    def test_brute_force_maps_to_T1110(self):
        from app.services.mitre_mapper import map_alert
        raw = "multiple failed login attempts failed logon bad password 4625 brute force"
        parsed = {"alert_type": "Failed Authentication", "username": "admin", "source_ip": "1.2.3.4",
                  "destination_ip": None, "process_name": None, "command_line": None,
                  "file_name": None, "hostname": None, "extra_indicators": {}}
        results = map_alert(raw, parsed)
        assert len(results) > 0
        ids = [r["technique_id"] for r in results]
        assert any(i.startswith("T1110") for i in ids)

    def test_new_account_maps_to_T1136(self):
        from app.services.mitre_mapper import map_alert
        raw = "net user /add backdoor123 new account created 4720"
        parsed = {"alert_type": "Account Creation", "username": None, "source_ip": None,
                  "destination_ip": None, "process_name": "net.exe",
                  "command_line": raw, "file_name": None, "hostname": None, "extra_indicators": {}}
        results = map_alert(raw, parsed)
        assert len(results) > 0
        ids = [r["technique_id"] for r in results]
        assert any(i.startswith("T1136") for i in ids)

    def test_scheduled_task_maps_to_T1053(self):
        from app.services.mitre_mapper import map_alert
        raw = "schtasks /Create /TN persistence /TR evil.exe /SC ONLOGON scheduled task"
        parsed = {"alert_type": "Scheduled Task", "username": None, "source_ip": None,
                  "destination_ip": None, "process_name": "schtasks.exe",
                  "command_line": raw, "file_name": None, "hostname": None, "extra_indicators": {}}
        results = map_alert(raw, parsed)
        assert len(results) > 0
        ids = [r["technique_id"] for r in results]
        assert any(i.startswith("T1053") for i in ids)

    def test_no_match_returns_empty(self):
        from app.services.mitre_mapper import map_alert
        raw = "The weather is sunny today and all is well"
        parsed = {"alert_type": "Security Alert", "username": None, "source_ip": None,
                  "destination_ip": None, "process_name": None, "command_line": None,
                  "file_name": None, "hostname": None, "extra_indicators": {}}
        results = map_alert(raw, parsed)
        assert results == []

    def test_max_results_respected(self):
        from app.services.mitre_mapper import map_alert
        raw = ("powershell lsass mimikatz schtasks net user /add rdp failed login "
               "netstat ipconfig cmd.exe certutil wget scheduled task credential dump")
        parsed = {"alert_type": "Security Alert", "username": None, "source_ip": None,
                  "destination_ip": None, "process_name": None, "command_line": raw,
                  "file_name": None, "hostname": None, "extra_indicators": {}}
        results = map_alert(raw, parsed, max_results=3)
        assert len(results) <= 3

    def test_subtechnique_preferred_over_parent(self):
        from app.services.mitre_mapper import map_alert
        raw = "powershell.exe -EncodedCommand base64data encodedcommand -nop"
        parsed = {"alert_type": "PowerShell", "username": None, "source_ip": None,
                  "destination_ip": None, "process_name": "powershell.exe",
                  "command_line": raw, "file_name": None, "hostname": None, "extra_indicators": {}}
        results = map_alert(raw, parsed)
        ids = [r["technique_id"] for r in results]
        # Sub-technique T1059.001 should appear if T1059 is also matched
        if "T1059.001" in ids and "T1059" in ids:
            # T1059.001 should rank higher
            assert ids.index("T1059.001") < ids.index("T1059")


# ═══════════════════════════════════════════════════════════════════════════
# 4. Confidence Calculation Tests
# ═══════════════════════════════════════════════════════════════════════════

class TestConfidenceCalculation:
    def test_high_confidence_many_keywords(self):
        from app.services.mitre_mapper import map_alert
        raw = "powershell encodedcommand -enc base64 -nop -w hidden bypass downloadstring iex"
        parsed = {"alert_type": "PowerShell", "username": None, "source_ip": None,
                  "destination_ip": None, "process_name": "powershell.exe",
                  "command_line": raw, "file_name": None, "hostname": None, "extra_indicators": {}}
        results = map_alert(raw, parsed)
        top = results[0] if results else None
        assert top is not None
        assert top["confidence"] in ("High", "Medium")

    def test_low_confidence_one_keyword(self):
        from app.services.mitre_mapper import _score_technique, _confidence_label
        tech = {"keywords": ["powershell", "encodedcommand", "bypass", "hidden", "iex"]}
        score, matched = _score_technique("powershell executed", tech)
        confidence = _confidence_label(score, len(matched))
        assert confidence == "Low"

    def test_confidence_score_range(self):
        from app.services.mitre_mapper import map_alert
        raw = "schtasks /Create scheduled task persistence"
        parsed = {"alert_type": "Scheduled Task", "username": None, "source_ip": None,
                  "destination_ip": None, "process_name": None, "command_line": raw,
                  "file_name": None, "hostname": None, "extra_indicators": {}}
        results = map_alert(raw, parsed)
        for r in results:
            assert 0.0 <= r["confidence_score"] <= 1.0

    def test_sorted_by_confidence(self):
        from app.services.mitre_mapper import map_alert
        raw = ("powershell encodedcommand base64 bypass downloadstring iex "
               "lsass mimikatz sekurlsa logonpasswords")
        parsed = {"alert_type": "Mixed", "username": None, "source_ip": None,
                  "destination_ip": None, "process_name": None, "command_line": raw,
                  "file_name": None, "hostname": None, "extra_indicators": {}}
        results = map_alert(raw, parsed)
        order = {"High": 3, "Medium": 2, "Low": 1}
        scores = [order[r["confidence"]] for r in results]
        assert scores == sorted(scores, reverse=True)


# ═══════════════════════════════════════════════════════════════════════════
# 5. Sigma Rule Matching Tests
# ═══════════════════════════════════════════════════════════════════════════

class TestSigmaMatcher:
    def test_powershell_sigma_match(self):
        from app.services.sigma_matcher import match_sigma_rules
        text = "powershell -encodedcommand SQBFAFgA base64 encoded"
        matches = match_sigma_rules(text)
        assert len(matches) > 0
        ids = [m["id"] for m in matches]
        assert "sigma-001" in ids  # PowerShell Encoded Command

    def test_failed_login_sigma_match(self):
        from app.services.sigma_matcher import match_sigma_rules
        text = "multiple failed login 4625 bad password authentication failure"
        matches = match_sigma_rules(text)
        ids = [m["id"] for m in matches]
        assert "sigma-003" in ids  # Multiple Failed Logons

    def test_new_user_sigma_match(self):
        from app.services.sigma_matcher import match_sigma_rules
        text = "new user created net user /add 4720 account created"
        matches = match_sigma_rules(text)
        ids = [m["id"] for m in matches]
        assert "sigma-004" in ids  # New Local User Account Created

    def test_no_match_returns_empty(self):
        from app.services.sigma_matcher import match_sigma_rules
        text = "benign system event normal operation"
        matches = match_sigma_rules(text)
        assert matches == []

    def test_sigma_has_required_fields(self):
        from app.services.sigma_matcher import match_sigma_rules
        text = "lsass mimikatz credential dump"
        matches = match_sigma_rules(text)
        assert len(matches) > 0
        for m in matches:
            assert "id" in m
            assert "title" in m
            assert "description" in m
            assert "level" in m


# ═══════════════════════════════════════════════════════════════════════════
# 6. API Endpoint Tests
# ═══════════════════════════════════════════════════════════════════════════

class TestAPIEndpoints:
    def test_analyze_alert_success(self, client):
        payload = {
            "raw_input": "powershell.exe -EncodedCommand abc -ExecutionPolicy Bypass",
            "input_format": "text"
        }
        r = client.post("/api/alerts/analyze", json=payload)
        assert r.status_code == 200
        data = r.json()
        assert "id" in data
        assert "mappings" in data
        assert data["is_analyzed"] is True
        assert data["mapping_count"] >= 0

    def test_analyze_alert_json_format(self, client):
        payload = {
            "raw_input": json.dumps({
                "event_type": "process_creation",
                "process": "mimikatz.exe",
                "user": "hacker",
                "command_line": "lsass sekurlsa logonpasswords"
            }),
            "input_format": "json"
        }
        r = client.post("/api/alerts/analyze", json=payload)
        assert r.status_code == 200
        data = r.json()
        assert data["process_name"] == "mimikatz.exe"
        assert data["username"] == "hacker"

    def test_analyze_invalid_format(self, client):
        payload = {"raw_input": "test", "input_format": "xml"}
        r = client.post("/api/alerts/analyze", json=payload)
        assert r.status_code == 422

    def test_list_alerts(self, client):
        r = client.get("/api/alerts")
        assert r.status_code == 200
        data = r.json()
        assert isinstance(data, list)

    def test_get_alert_by_id(self, client):
        # First create an alert
        payload = {"raw_input": "cmd.exe /c net user hacker /add", "input_format": "text"}
        create_r = client.post("/api/alerts/analyze", json=payload)
        alert_id = create_r.json()["id"]

        r = client.get(f"/api/alerts/{alert_id}")
        assert r.status_code == 200
        data = r.json()
        assert data["id"] == alert_id

    def test_get_alert_not_found(self, client):
        r = client.get("/api/alerts/99999")
        assert r.status_code == 404

    def test_list_tactics(self, client):
        r = client.get("/api/tactics")
        assert r.status_code == 200
        data = r.json()
        assert len(data) > 0
        assert any(t["id"] == "TA0002" for t in data)  # Execution

    def test_list_techniques(self, client):
        r = client.get("/api/techniques")
        assert r.status_code == 200
        data = r.json()
        assert len(data) > 0
        ids = [t["id"] for t in data]
        assert "T1059" in ids

    def test_search_techniques(self, client):
        r = client.get("/api/techniques?search=powershell")
        assert r.status_code == 200
        data = r.json()
        assert len(data) > 0

    def test_get_technique_by_id(self, client):
        r = client.get("/api/techniques/T1059")
        assert r.status_code == 200
        data = r.json()
        assert data["id"] == "T1059"
        assert "investigation_steps" in data

    def test_get_subtechnique_by_id(self, client):
        r = client.get("/api/techniques/T1059.001")
        assert r.status_code == 200
        data = r.json()
        assert data["id"] == "T1059.001"

    def test_technique_not_found(self, client):
        r = client.get("/api/techniques/T9999")
        assert r.status_code == 404

    def test_dashboard(self, client):
        r = client.get("/api/dashboard")
        assert r.status_code == 200
        data = r.json()
        assert "total_alerts" in data
        assert "top_tactics" in data
        assert "top_techniques" in data
        assert "recent_alerts" in data

    def test_search_alerts(self, client):
        r = client.get("/api/alerts/search")
        assert r.status_code == 200
        data = r.json()
        assert "total" in data
        assert "alerts" in data

    def test_search_alerts_by_type(self, client):
        r = client.get("/api/alerts/search?alert_type=PowerShell")
        assert r.status_code == 200

    def test_search_alerts_by_confidence(self, client):
        r = client.get("/api/alerts/search?confidence=High")
        assert r.status_code == 200

    def test_paginated_alerts(self, client):
        r = client.get("/api/alerts?skip=0&limit=5")
        assert r.status_code == 200
        data = r.json()
        assert len(data) <= 5

    def test_frontend_pages(self, client):
        for path in ["/", "/analyze", "/history", "/techniques", "/about"]:
            r = client.get(path)
            assert r.status_code == 200, f"Page {path} returned {r.status_code}"
            assert "ATT&CK" in r.text or "MITRE" in r.text or "Alert" in r.text

    def test_alert_detail_page(self, client):
        # Create an alert first
        payload = {"raw_input": "rdp remote desktop login 3389 external ip", "input_format": "text"}
        created = client.post("/api/alerts/analyze", json=payload).json()
        r = client.get(f"/alert/{created['id']}")
        assert r.status_code == 200
