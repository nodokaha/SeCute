"""Tracker DB tests: per-source storage, merged view, validation,
migration of pre-existing databases."""
import sqlite3

import pytest

from app import db


def _upsert_pair(conn):
    db.upsert_vuln(
        conn, cve_id="CVE-2026-1111", source="kev",
        title="KEV title", summary="KEV summary",
        severity="known-exploited", published_at="2026-11-01",
        url="https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        raw="{}")
    db.upsert_vuln(
        conn, cve_id="CVE-2026-1111", source="osv",
        title="OSV title", summary="OSV summary",
        severity="CVSS:3.1/AV:N/9.8", published_at="2026-10-30",
        url="https://osv.dev/vulnerability/CVE-2026-1111", raw="{}")
    conn.commit()


def test_sources_are_kept_separately_and_merged(conn):
    _upsert_pair(conn)
    sources = db.list_vuln_sources(conn, "CVE-2026-1111")
    assert {s["source"] for s in sources} == {"kev", "osv"}
    vuln = conn.execute(
        "SELECT * FROM vulns WHERE cve_id='CVE-2026-1111'").fetchone()
    # KEV wins display priority; known-exploited severity always wins;
    # the merged record lists both sources instead of overwriting.
    assert vuln["title"] == "KEV title"
    assert vuln["severity"] == "known-exploited"
    assert set(vuln["source"].split(",")) == {"kev", "osv"}


def test_reingest_updates_in_place_without_duplicating(conn):
    _upsert_pair(conn)
    _upsert_pair(conn)  # same data again, as a re-ingest would send
    assert len(db.list_vuln_sources(conn, "CVE-2026-1111")) == 2
    count = conn.execute("SELECT COUNT(*) c FROM vulns").fetchone()["c"]
    assert count == 1


def test_newer_source_record_refreshes_only_its_own_row(conn):
    _upsert_pair(conn)
    db.upsert_vuln(
        conn, cve_id="CVE-2026-1111", source="osv",
        title="OSV title v2", summary="revised", severity="",
        published_at="2026-10-30", url="", raw="{}")
    conn.commit()
    by_source = {s["source"]: s
                 for s in db.list_vuln_sources(conn, "CVE-2026-1111")}
    assert by_source["osv"]["title"] == "OSV title v2"
    assert by_source["kev"]["title"] == "KEV title"


def test_update_item_validates_values(conn):
    asset_id = db.add_asset(conn, "Widget Server", keywords="widget")
    db.upsert_vuln(conn, "CVE-2026-9999", "osv", title="t")
    item = db.find_or_create_item(conn, "CVE-2026-9999", asset_id,
                                  title="t")
    conn.commit()
    with pytest.raises(ValueError):
        db.update_item(conn, item["id"], {"status": "bogus"})
    with pytest.raises(ValueError):
        db.update_item(conn, item["id"], {"triage": "bogus"})
    updated = db.update_item(conn, item["id"], {"status": "in_progress"})
    assert updated["status"] == "in_progress"


def test_find_or_create_item_is_idempotent(conn):
    asset_id = db.add_asset(conn, "Widget Server", keywords="widget")
    db.upsert_vuln(conn, "CVE-2026-9999", "osv", title="t")
    first = db.find_or_create_item(conn, "CVE-2026-9999", asset_id,
                                   title="t")
    second = db.find_or_create_item(conn, "CVE-2026-9999", asset_id,
                                    title="t")
    conn.commit()
    assert first["id"] == second["id"]
    assert len(db.list_items(conn)) == 1


def test_item_records_match_method_and_reason(conn):
    asset_id = db.add_asset(conn, "widget-lib 1.5", version="1.5.0",
                            ecosystem="PyPI", package_name="widget-lib")
    db.upsert_vuln(conn, "CVE-2026-1111", "osv", title="t")
    item = db.find_or_create_item(
        conn, "CVE-2026-1111", asset_id, title="t", triage="watch",
        match_method="version_range",
        match_reason="version 1.5.0 is in the affected range [1.0.0, 2.0.0)")
    conn.commit()
    stored = db.get_item(conn, item["id"])
    assert stored["match_method"] == "version_range"
    assert "1.5.0" in stored["match_reason"]


def test_init_db_migrates_a_legacy_database(tmp_path):
    """A database created before vuln_sources / match columns existed
    gains them on init, with its rows intact."""
    path = str(tmp_path / "legacy.db")
    raw = sqlite3.connect(path)
    raw.executescript(
        "CREATE TABLE vulns (cve_id TEXT PRIMARY KEY, source TEXT, "
        " title TEXT, summary TEXT, severity TEXT, published_at TEXT, "
        " url TEXT, raw TEXT, fetched_at TEXT);"
        "CREATE TABLE items (id INTEGER PRIMARY KEY, cve_id TEXT, "
        " asset_id INTEGER, title TEXT, status TEXT, triage TEXT, "
        " note TEXT, created_at TEXT, updated_at TEXT);")
    raw.execute("INSERT INTO vulns (cve_id, source, title) "
                "VALUES ('CVE-2020-0001', 'kev', 'legacy row')")
    raw.commit()
    raw.close()
    db.init_db(path)
    conn = db.connect(path)
    cols = {r["name"] for r in
            conn.execute("PRAGMA table_info(items)").fetchall()}
    assert {"match_method", "match_reason"} <= cols
    tables = {r["name"] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
    assert {"vuln_sources", "ingest_runs"} <= tables
    row = conn.execute(
        "SELECT title FROM vulns WHERE cve_id='CVE-2020-0001'").fetchone()
    assert row["title"] == "legacy row"
    conn.close()
