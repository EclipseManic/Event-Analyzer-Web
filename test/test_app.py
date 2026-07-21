"""Comprehensive test suite for Event-Analyzer."""

from __future__ import annotations

import io
import json
import os
import threading
from pathlib import Path

import pytest

os.environ["EVTX_VIEWER_DB_PATH"] = ""
os.environ["EVTX_VIEWER_DATA_DIR"] = ""


@pytest.fixture(autouse=True)
def _test_env(tmp_path, monkeypatch):
    """Per-test isolation: unique temp DB, cleared caches."""
    import app.config
    app.config._cached = None

    db_path = tmp_path / "test.db"
    db_path.parent.mkdir(parents=True, exist_ok=True)

    import app.db
    monkeypatch.setattr(app.db, "DB_PATH", db_path)
    monkeypatch.setattr(app.db, "_db_initialized", False)
    monkeypatch.setattr(app.db, "_fts_enabled", False)
    monkeypatch.setattr(app.db, "_thread_local", threading.local())

    import app.sigma_matcher as sm
    with sm._cache_lock:
        sm._rules_cache = None
        sm._compiled_rules = None
        sm._field_mega_regexes = None
        sm._sigma_cache.clear()
        sm._sigma_cache_hits = 0
        sm._sigma_cache_misses = 0


@pytest.fixture
def db():
    from app.db import init_db
    init_db()


@pytest.fixture
def inv_id(db):
    from app.db import create_investigation
    return create_investigation("test-inv", ["file1.evtx"])


@pytest.fixture
def sigma_rules_patcher(tmp_path, monkeypatch):
    rules = [
        {
            "id": "RULE-001",
            "title": "Process Creation Test",
            "level": "high",
            "description": "Detects test process creation",
            "detection": {},
            "logsource": {},
            "tags": ["attack.t1059", "attack.execution"],
            "mitre_techniques": [{"id": "T1059", "name": "Command and Scripting Interpreter"}],
            "false_positives": [],
            "conditions": [
                {"field": "CommandLine", "pattern": r"whoami"},
                {"field": "EventID", "pattern": r"4688"},
            ],
        },
        {
            "id": "RULE-002",
            "title": "Network Connection Test",
            "level": "medium",
            "description": "Detects test network connections",
            "detection": {},
            "logsource": {},
            "tags": ["attack.t1071"],
            "mitre_techniques": [{"id": "T1071", "name": "Application Layer Protocol"}],
            "false_positives": [],
            "conditions": [
                {"field": "EventID", "pattern": r"3"},
                {"field": "DestinationIp", "pattern": r"203\.0\.113\."},
            ],
        },
        {
            "id": "RULE-003",
            "title": "CmdLine Any",
            "level": "low",
            "description": "Matches any command line",
            "detection": {},
            "logsource": {},
            "tags": [],
            "mitre_techniques": [],
            "false_positives": [],
            "conditions": [
                {"field": "CommandLine", "pattern": r"."},
                {"field": "EventID", "pattern": r"0"},
            ],
        },
    ]
    path = tmp_path / "sigma_rules.json"
    path.write_text(json.dumps(rules), encoding="utf-8")
    import app.sigma_matcher as sm
    monkeypatch.setattr(sm, "_RULES_PATH", path)
    return path


# ── config.py ─────────────────────────────────────


class TestConfig:
    def test_defaults(self):
        from app.config import get_config
        cfg = get_config()
        assert cfg.host == "127.0.0.1"
        assert cfg.port == 5050
        assert cfg.debug is False
        assert cfg.max_upload_mb == 100
        assert cfg.max_files_per_upload == 500

    def test_caching(self):
        from app.config import get_config
        c1 = get_config()
        c2 = get_config()
        assert c1 is c2

    def test_env_override(self, monkeypatch):
        monkeypatch.setenv("EVTX_VIEWER_HOST", "0.0.0.0")
        monkeypatch.setenv("EVTX_VIEWER_PORT", "9090")
        monkeypatch.setenv("EVTX_VIEWER_DEBUG", "true")
        monkeypatch.setenv("EVTX_VIEWER_DELETE_AFTER_INGEST", "false")
        import app.config
        app.config._cached = None
        cfg = app.config.get_config()
        assert cfg.host == "0.0.0.0"
        assert cfg.port == 9090
        assert cfg.debug is True
        assert cfg.delete_after_ingest is False


# ── db.py ─────────────────────────────────────────


class TestDb:
    def test_init_db_creates_tables(self, db):
        from app.db import _get_conn
        conn = _get_conn()
        tables = [row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
        assert "investigations" in tables
        assert "events" in tables
        assert "iocs" in tables
        assert "sigma_matches" in tables

    def test_init_db_idempotent(self, db):
        from app.db import init_db
        init_db()
        init_db()

    def test_create_investigation(self, db):
        from app.db import create_investigation
        inv_id = create_investigation("test-inv")
        assert inv_id is not None

    def test_list_investigations(self, db):
        from app.db import create_investigation, list_investigations
        assert list_investigations() == []
        create_investigation("inv-a")
        create_investigation("inv-b")
        names = [i["name"] for i in list_investigations()]
        assert "inv-a" in names
        assert "inv-b" in names

    def test_insert_events_bulk(self, inv_id):
        from app.db import insert_events_bulk, get_events
        events = [
            {
                "id": f"evt-{i}",
                "investigation_id": inv_id,
                "timestamp": f"2025-01-01T00:00:{i:02d}Z",
                "event_id": 4688,
                "event_category": "process_created",
                "channel": "Security",
                "provider": "Test",
            }
            for i in range(5)
        ]
        inserted = insert_events_bulk(events, skip_fts=True, commit=True)
        assert inserted == 5
        results = get_events(inv_id, limit=10)
        assert len(results) == 5

    def test_get_event_count(self, inv_id):
        from app.db import insert_events_bulk, get_event_count
        events = [
            {
                "id": f"evt-{i}",
                "investigation_id": inv_id,
                "timestamp": f"2025-01-01T00:00:{i:02d}Z",
                "event_id": 4688,
                "event_category": "process_created",
                "channel": "Security",
                "provider": "Test",
            }
            for i in range(3)
        ]
        insert_events_bulk(events, skip_fts=True, commit=True)
        assert get_event_count(inv_id) == 3

    def test_get_event_detail(self, inv_id):
        from app.db import insert_events_bulk, get_event_detail
        event = {
            "id": "evt-detail-1",
            "investigation_id": inv_id,
            "timestamp": "2025-01-01T00:00:00Z",
            "event_id": 4688,
            "event_category": "process_created",
            "channel": "Security",
            "provider": "Test",
            "computer": "PC-01",
            "command_line": "whoami",
            "process_name": "cmd.exe",
        }
        insert_events_bulk([event], skip_fts=True, commit=True)
        detail = get_event_detail(inv_id, "evt-detail-1")
        assert detail is not None
        assert detail["event_id"] == 4688
        assert detail["command_line"] == "whoami"
        assert get_event_detail(inv_id, "nonexistent") is None

    def test_iocs_bulk(self, inv_id):
        from app.db import insert_iocs_bulk, get_iocs, insert_events_bulk
        event = {
            "id": "evt-ioc-1",
            "investigation_id": inv_id,
            "timestamp": "2025-01-01T00:00:00Z",
            "event_id": 3,
            "channel": "Sysmon",
            "provider": "Test",
        }
        insert_events_bulk([event], skip_fts=True, commit=True)
        iocs = [
            {"investigation_id": inv_id, "event_id": "evt-ioc-1", "ioc_type": "ip", "value": "10.0.0.1", "source": "cl", "context": "test"},
            {"investigation_id": inv_id, "event_id": "evt-ioc-1", "ioc_type": "hash", "value": "a" * 64, "source": "hv", "context": "test"},
        ]
        insert_iocs_bulk(iocs, commit=True)
        assert len(get_iocs(inv_id, limit=10)) == 2

    def test_sigma_bulk(self, inv_id):
        from app.db import insert_sigma_bulk, get_sigma_grouped, get_sigma_summary, get_sigma_rule_info, insert_events_bulk
        event = {
            "id": "evt-sig-1",
            "investigation_id": inv_id,
            "timestamp": "2025-01-01T00:00:00Z",
            "event_id": 4688,
            "channel": "Security",
            "provider": "Test",
        }
        insert_events_bulk([event], skip_fts=True, commit=True)
        insert_sigma_bulk([
            {
                "investigation_id": inv_id,
                "event_id": "evt-sig-1",
                "rule_id": "RULE-001",
                "rule_title": "Test Rule",
                "level": "high",
                "description": "Detects test",
                "mitre_techniques": [{"id": "T1059", "name": "Exec"}],
            }
        ], commit=True)
        groups = get_sigma_grouped(inv_id)
        assert len(groups) == 1
        assert groups[0]["rule_id"] == "RULE-001"
        info = get_sigma_rule_info(inv_id, "RULE-001")
        assert info is not None
        assert info["rule_title"] == "Test Rule"
        assert get_sigma_summary(inv_id)["total"] == 1

    def test_sigma_rule_events(self, inv_id):
        from app.db import insert_sigma_bulk, get_sigma_rule_events, insert_events_bulk
        event = {
            "id": "evt-sig-evt-1",
            "investigation_id": inv_id,
            "timestamp": "2025-01-01T00:00:00Z",
            "event_id": 4688,
            "event_number": 1,
            "channel": "Security",
            "provider": "Test",
            "computer": "PC-01",
            "user_name": "jdoe",
            "description": "Test event",
        }
        insert_events_bulk([event], skip_fts=True, commit=True)
        insert_sigma_bulk([
            {
                "investigation_id": inv_id,
                "event_id": "evt-sig-evt-1",
                "rule_id": "RULE-001",
                "rule_title": "Test Rule",
                "level": "high",
                "description": "Detects test",
                "mitre_techniques": [],
            }
        ], commit=True)
        events = get_sigma_rule_events(inv_id, "RULE-001")
        assert len(events) == 1
        assert events[0]["event_number"] == 1

    def test_bookmarks(self, inv_id):
        from app.db import add_bookmark, remove_bookmark, get_bookmarked_ids
        assert get_bookmarked_ids(inv_id) == []
        add_bookmark(inv_id, "evt-001")
        add_bookmark(inv_id, "evt-002")
        assert get_bookmarked_ids(inv_id) == ["evt-001", "evt-002"]
        remove_bookmark(inv_id, "evt-001")
        assert get_bookmarked_ids(inv_id) == ["evt-002"]

    def test_notes(self, inv_id):
        from app.db import save_note, get_note
        assert get_note(inv_id) is None
        save_note(inv_id, "test note")
        assert get_note(inv_id) == "test note"
        save_note(inv_id, "updated")
        assert get_note(inv_id) == "updated"


# ── evtx_parser.py ────────────────────────────────


class TestEvtxParser:
    def test_parse_json_event_extracts_fields(self):
        from app.evtx_parser import _parse_json_event
        raw_data = {
            "Event": {
                "System": {
                    "Provider": {"Name": "Microsoft-Windows-Security-Auditing"},
                    "EventID": 4688,
                    "Channel": "Security",
                    "Computer": "PC-01",
                    "EventRecordID": 100,
                    "Level": 4,
                    "Task": 1,
                    "Opcode": 0,
                    "Keywords": "0x8000000000000000",
                    "TimeCreated": {"SystemTime": "2025-06-15T10:30:00.000Z"},
                },
                "EventData": {},
            }
        }
        event = _parse_json_event(raw_data, "inv-1", json.dumps(raw_data), source_file="test.evtx", event_record_id=100)
        assert event is not None
        assert event["provider"] == "Microsoft-Windows-Security-Auditing"
        assert event["event_id"] == 4688
        assert event["channel"] == "Security"
        assert event["computer"] == "PC-01"
        assert event["event_record_id"] == 100
        assert event["timestamp"] == "2025-06-15T10:30:00.000Z"

    def test_parse_json_event_missing_system_returns_none(self):
        from app.evtx_parser import _parse_json_event
        assert _parse_json_event({}, "inv-1", "") is None
        assert _parse_json_event({"Event": {}}, "inv-1", "") is None

    def test_safe_int(self):
        from app.evtx_parser import _safe_int
        assert _safe_int(None) is None
        assert _safe_int(42) == 42
        assert _safe_int("0xFF") == 255
        assert _safe_int("abc") is None

    def test_flatten_event_data(self):
        from app.evtx_parser import _flatten_event_data
        flat = _flatten_event_data({"key1": "val1", "key2": {"#text": "nested"}})
        assert flat["key1"] == "val1"

    def test_get_file_info(self):
        from app.evtx_parser import get_file_info
        import tempfile
        f = tempfile.NamedTemporaryFile(delete=False, suffix=".evtx")
        f.write(b"test")
        f.close()
        try:
            info = get_file_info(f.name)
            assert info["exists"] is True
            assert info["size_bytes"] == 4
        finally:
            os.unlink(f.name)
        info = get_file_info("/nonexistent/file.evtx")
        assert info["exists"] is False


# ── ioc_extractor.py ─────────────────────────────


class TestIocExtractor:
    def test_extract_ip(self):
        from app.ioc_extractor import extract_iocs
        iocs = extract_iocs({"source_ip": "192.168.1.1", "event_id": 3, "command_line": "test"})
        ips = [i for i in iocs if i["ioc_type"] == "ip"]
        assert len(ips) >= 1
        assert ips[0]["value"] == "192.168.1.1"

    def test_extract_hash(self):
        from app.ioc_extractor import extract_iocs
        sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        iocs = extract_iocs({"command_line": f"hash {sha256}", "event_id": 1})
        hashes = [i for i in iocs if i["ioc_type"] == "hash"]
        assert len(hashes) >= 1

    def test_extract_file_path(self):
        from app.ioc_extractor import extract_iocs
        iocs = extract_iocs({"command_line": "regsvr32 C:\\Users\\jdoe\\malware.dll", "event_id": 1})
        files = [i for i in iocs if i["ioc_type"] == "file"]
        assert len(files) >= 1

    def test_extract_registry(self):
        from app.ioc_extractor import extract_iocs
        iocs = extract_iocs({"command_line": "reg add HKLM\\Software\\Test /v Malware", "event_id": 1})
        regs = [i for i in iocs if i["ioc_type"] == "registry"]
        assert len(regs) >= 1

    def test_extract_url(self):
        from app.ioc_extractor import extract_iocs
        iocs = extract_iocs({"command_line": "http://evil.com/payload.exe", "event_id": 1})
        urls = [i for i in iocs if i["ioc_type"] == "url"]
        assert len(urls) >= 1
        assert "http://evil.com" in urls[0]["value"]

    def test_filter_infra_domain(self):
        from app.ioc_extractor import extract_iocs
        iocs = extract_iocs({"command_line": "ping crl.microsoft.com", "event_id": 1})
        assert "crl.microsoft.com" not in [d["value"] for d in iocs if iocs]

    def test_extract_from_structured_fields(self):
        from app.ioc_extractor import extract_iocs
        iocs = extract_iocs({"source_ip": "192.168.1.1", "hash_value": "a" * 64, "event_id": 3, "command_line": "test"})
        types = {i["ioc_type"] for i in iocs}
        assert "ip" in types
        assert "hash" in types

    def test_empty_event_returns_empty(self):
        from app.ioc_extractor import extract_iocs
        assert extract_iocs({"command_line": ""}) == []

    def test_deduplication(self):
        from app.ioc_extractor import extract_iocs
        iocs = extract_iocs({"command_line": "ping 10.0.0.1", "source_ip": "10.0.0.1", "event_id": 1})
        ips = [i for i in iocs if i["ioc_type"] == "ip" and i["value"] == "10.0.0.1"]
        assert len(ips) == 1


# ── mitre_mapper.py ──────────────────────────────


class TestMitreMapper:
    def test_known_category(self):
        from app.mitre_mapper import map_event
        result = map_event({"event_category": "process_created", "event_id": 4688})
        assert len(result) >= 1
        assert any(t["id"] == "T1059" for t in result)

    def test_event_id_fallback(self):
        from app.mitre_mapper import map_event
        result = map_event({"event_category": "unknown", "event_id": 4648})
        assert len(result) == 1
        assert result[0]["id"] == "T1078"

    def test_unknown_returns_empty(self):
        from app.mitre_mapper import map_event
        assert map_event({"event_category": "unknown", "event_id": 99999}) == []

    def test_reverse_mapping(self):
        from app.mitre_mapper import get_event_ids_for_technique
        assert 4688 in get_event_ids_for_technique("T1059")
        assert get_event_ids_for_technique("NONEXISTENT") == []


# ── sigma_matcher.py ─────────────────────────────


class TestSigmaMatcher:
    def test_load_rules(self, sigma_rules_patcher):
        from app.sigma_matcher import load_rules, get_compiled_rules
        rules = load_rules()
        assert len(rules) == 3
        assert len(get_compiled_rules()) == 3

    def test_match_event_hit(self, sigma_rules_patcher):
        from app.sigma_matcher import load_rules, match_event
        load_rules()
        matches = match_event({"event_id": 4688, "command_line": "whoami", "process_name": "cmd.exe"})
        assert len(matches) >= 1
        assert matches[0]["id"] == "RULE-001"

    def test_match_event_miss(self, sigma_rules_patcher):
        from app.sigma_matcher import load_rules, match_event
        load_rules()
        assert match_event({"event_id": 9999}) == []

    def test_cache_stats(self, sigma_rules_patcher):
        from app.sigma_matcher import load_rules, match_event, get_cache_stats, clear_cache
        load_rules()
        ev = {"event_id": 4688, "command_line": "whoami", "process_name": "cmd.exe"}
        match_event(ev)
        stats = get_cache_stats()
        assert stats["misses"] >= 1
        match_event(ev)
        stats = get_cache_stats()
        assert stats["hits"] >= 1
        clear_cache()
        assert get_cache_stats()["size"] == 0

    def test_field_map(self):
        from app.sigma_matcher import _map_field
        assert _map_field("EventID") == "event_id"
        assert _map_field("CommandLine") == "command_line"
        assert _map_field("Image") == "process_name"
        assert _map_field("NonexistentField") == "NonexistentField"


# ── ingest.py ────────────────────────────────────


class TestIngest:
    def test_ingest_files_pipeline(self, inv_id, monkeypatch):
        from app.ingest import ingest_files

        def mock_parse(path, investigation_id, max_events=0):
            yield {
                "id": "evt-ing-1",
                "investigation_id": inv_id,
                "timestamp": "2025-01-01T00:00:00Z",
                "event_id": 4688,
                "event_category": "process_created",
                "channel": "Security",
                "provider": "Test",
                "command_line": "whoami",
                "process_name": "cmd.exe",
            }

        monkeypatch.setattr("app.ingest.parse_evtx_file", mock_parse)
        result = ingest_files(inv_id, ["test.evtx"])
        assert result.total_events >= 1

    def test_ingest_with_stop(self, inv_id, monkeypatch):
        from app.ingest import ingest_files

        def mock_parse(path, investigation_id, max_events=0):
            yield {
                "id": "evt-ing-2",
                "investigation_id": inv_id,
                "timestamp": "2025-01-01T00:00:00Z",
                "event_id": 4688,
                "event_category": "process_created",
                "channel": "Security",
                "provider": "Test",
            }

        monkeypatch.setattr("app.ingest.parse_evtx_file", mock_parse)
        stop = threading.Event()
        stop.set()
        result = ingest_files(inv_id, ["test.evtx"], stop_event=stop)
        assert result.total_events == 0

    def test_cleanup_source_file(self, monkeypatch):
        from app.ingest import _cleanup_source_file
        import tempfile
        f = tempfile.NamedTemporaryFile(delete=False, suffix=".evtx")
        f.close()
        monkeypatch.setenv("EVTX_VIEWER_DELETE_AFTER_INGEST", "true")
        import app.config
        app.config._cached = None
        _cleanup_source_file(f.name)
        assert not os.path.exists(f.name)


# ── api.py ───────────────────────────────────────


class TestApi:
    @pytest.fixture
    def client(self, db):
        from app.api import create_app
        app = create_app()
        app.config["TESTING"] = True
        with app.test_client() as c:
            yield c

    def test_health(self, client):
        assert client.get("/api/health").get_json() == {"status": "ok"}

    def test_list_investigations_empty(self, client):
        assert client.get("/api/investigations").get_json() == []

    def test_create_and_get_investigation(self, client):
        from app.db import create_investigation
        inv_id = create_investigation("api-test")
        resp = client.get(f"/api/investigations/{inv_id}")
        assert resp.get_json()["name"] == "api-test"

    def test_list_investigations(self, client):
        from app.db import create_investigation
        create_investigation("inv-a")
        create_investigation("inv-b")
        names = [i["name"] for i in client.get("/api/investigations").get_json()]
        assert "inv-a" in names
        assert "inv-b" in names

    def test_upload_invalid_file(self, client):
        resp = client.post("/api/upload", data={"file": (io.BytesIO(b"nope"), "test.txt")}, content_type="multipart/form-data")
        assert resp.status_code == 400
        assert "error" in resp.get_json()

    def test_event_crud_via_api(self, client):
        from app.db import create_investigation, insert_events_bulk
        inv_id = create_investigation("evt-test")
        insert_events_bulk([
            {
                "id": f"evt-api-{i}",
                "investigation_id": inv_id,
                "timestamp": f"2025-01-01T00:00:{i:02d}Z",
                "event_id": 4688,
                "event_category": "process_created",
                "channel": "Security",
                "provider": "Test",
                "computer": "PC-01",
                "command_line": "whoami",
                "process_name": "cmd.exe",
            }
            for i in range(3)
        ], skip_fts=True, commit=True)
        resp = client.get(f"/api/investigations/{inv_id}/events")
        assert resp.status_code == 200
        data = resp.get_json()
        assert len(data["items"]) == 3
        assert data["count"] == 3
        assert client.get(f"/api/investigations/{inv_id}/events/count").get_json()["count"] == 3

    def test_sigma_endpoint(self, client):
        from app.db import create_investigation, insert_events_bulk, insert_sigma_bulk
        inv_id = create_investigation("sig-test")
        eid = "evt-sig-api"
        insert_events_bulk([{
            "id": eid, "investigation_id": inv_id, "timestamp": "2025-01-01T00:00:00Z",
            "event_id": 4688, "event_number": 1, "channel": "Security", "provider": "Test",
            "computer": "PC-01", "user_name": "jdoe",
        }], skip_fts=True, commit=True)
        insert_sigma_bulk([{
            "investigation_id": inv_id, "event_id": eid, "rule_id": "RULE-001",
            "rule_title": "Test", "level": "high", "description": "test", "mitre_techniques": [],
        }], commit=True)
        resp = client.get(f"/api/investigations/{inv_id}/sigma")
        assert resp.status_code == 200
        assert len(resp.get_json()["items"]) >= 1

    def test_bookmark_via_api(self, client):
        from app.db import create_investigation
        inv_id = create_investigation("bm-test")
        client.post(f"/api/investigations/{inv_id}/bookmarks", json={"event_id": "evt-bm-1"})
        assert "evt-bm-1" in client.get(f"/api/investigations/{inv_id}/bookmarks").get_json()["ids"]
        client.delete(f"/api/investigations/{inv_id}/bookmarks/evt-bm-1")
        assert "evt-bm-1" not in client.get(f"/api/investigations/{inv_id}/bookmarks").get_json()["ids"]

    def test_notes_via_api(self, client):
        from app.db import create_investigation
        inv_id = create_investigation("note-test")
        client.put(f"/api/investigations/{inv_id}/notes", json={"content": "api note"})
        assert client.get(f"/api/investigations/{inv_id}/notes").get_json()["content"] == "api note"

    def test_upload_invalid_extension(self, client):
        resp = client.post("/api/upload", data={"file": (io.BytesIO(b"x" * 100), "bad.pdf")}, content_type="multipart/form-data")
        assert resp.status_code == 400

    def test_ioc_endpoint(self, client):
        from app.db import create_investigation, insert_events_bulk, insert_iocs_bulk
        inv_id = create_investigation("ioc-test")
        eid = "evt-ioc-api"
        insert_events_bulk([{
            "id": eid, "investigation_id": inv_id, "timestamp": "2025-01-01T00:00:00Z",
            "event_id": 3, "channel": "Sysmon", "provider": "Test",
        }], skip_fts=True, commit=True)
        insert_iocs_bulk([
            {"investigation_id": inv_id, "event_id": eid, "ioc_type": "ip", "value": "10.0.0.1", "source": "t", "context": "t"},
            {"investigation_id": inv_id, "event_id": eid, "ioc_type": "hash", "value": "a" * 64, "source": "t", "context": "t"},
        ], commit=True)
        resp = client.get(f"/api/investigations/{inv_id}/iocs")
        assert resp.get_json()["total"] == 2
        summary = client.get(f"/api/investigations/{inv_id}/iocs/summary").get_json()
        assert summary["types"].get("ip", 0) == 1
        assert summary["total"] == 2


# ── report_generator.py ──────────────────────────


class TestReportGenerator:
    def test_generate_report_valid(self, inv_id, monkeypatch):
        from app.report_generator import generate_report
        from app.db import insert_events_bulk
        monkeypatch.setattr("app.sigma_matcher.load_rules", lambda p=None: [])
        monkeypatch.setattr("app.sigma_matcher.match_event", lambda e: [])
        insert_events_bulk([{
            "id": "evt-rpt-1", "investigation_id": inv_id,
            "timestamp": "2025-01-01T00:00:00Z", "event_id": 4688,
            "event_category": "process_created", "channel": "Security",
            "provider": "Test", "computer": "PC-01",
            "command_line": "whoami", "process_name": "cmd.exe",
        }], skip_fts=True, commit=True)
        html = generate_report(inv_id)
        assert "<html" in html.lower()
        assert "test-inv" in html

    def test_generate_report_invalid(self, db):
        from app.report_generator import generate_report
        assert "not found" in generate_report("nonexistent").lower()


# ── backfill.py ──────────────────────────────────


class TestBackfill:
    def test_backfill_investigation(self, inv_id, monkeypatch, tmp_path):
        from app.backfill import backfill_investigation
        from app.db import insert_events_bulk
        from app.sigma_matcher import load_rules
        rules_f = tmp_path / "sigma_rules.json"
        rules_f.write_text("[]", encoding="utf-8")
        monkeypatch.setattr("app.sigma_matcher._RULES_PATH", rules_f)
        load_rules()
        insert_events_bulk([{
            "id": "evt-bf-1", "investigation_id": inv_id,
            "timestamp": "2025-01-01T00:00:00Z", "event_id": 4688,
            "event_category": "process_created", "channel": "Security",
            "provider": "Test", "computer": "PC-01",
            "command_line": "whoami", "process_name": "cmd.exe",
        }], skip_fts=True, commit=True)
        assert backfill_investigation(inv_id)["events"] >= 1

    def test_backfill_empty_investigation(self, inv_id, monkeypatch, tmp_path):
        from app.backfill import backfill_investigation
        from app.sigma_matcher import load_rules
        rules_f = tmp_path / "sigma_rules.json"
        rules_f.write_text("[]", encoding="utf-8")
        monkeypatch.setattr("app.sigma_matcher._RULES_PATH", rules_f)
        load_rules()
        assert backfill_investigation(inv_id) == {"events": 0, "iocs": 0, "sigma": 0}


# ── sigma_updater.py ─────────────────────────────


class TestSigmaUpdater:
    def test_parse_sigma_yml(self):
        from app.sigma_updater import _parse_sigma_yml
        yaml = """
title: Test Rule
id: abc-123
status: test
description: A test rule
tags:
  - attack.t1059
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains: whoami
    EventID: '4688'
  condition: selection
falsepositives:
  - None
level: high
"""
        rule = _parse_sigma_yml(yaml, "test.yml")
        assert rule is not None
        assert rule["id"] == "abc-123"
        assert rule["title"] == "Test Rule"
        assert rule["level"] == "high"
        assert "attack.t1059" in rule["tags"]

    def test_convert_detection(self):
        from app.sigma_updater import _convert_detection
        conds = _convert_detection({
            "selection": {"CommandLine|contains": "whoami", "EventID": "4688"},
            "condition": "selection",
        }, "process_creation")
        assert any(c["field"] == "CommandLine" and c["pattern"] == "whoami" for c in conds)

    def test_is_rule_included(self):
        from app.sigma_updater import _is_rule_included
        rule = {"id": "test-1", "title": "T", "conditions": [{"field": "EventID", "pattern": r"\d+"}]}
        assert _is_rule_included(rule, {"other"})
        assert not _is_rule_included(rule, {"test-1"})
        bad = {"id": "test-2", "title": "B", "conditions": [{"field": "EventID", "pattern": r"[invalid"}]}
        assert not _is_rule_included(bad, set())
