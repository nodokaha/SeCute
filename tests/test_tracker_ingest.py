"""Tracker ingest tests: real feed shapes, range matching, per-source
independence. HTTP is replaced by fixtures in the sources' own
formats (CISA KEV JSON feed, OSV.dev query responses)."""
import urllib.error

import pytest

from app import db, ingest

KEV_FEED = {
    "catalogVersion": "2026.11.01",
    "count": 1,
    "vulnerabilities": [{
        "cveID": "CVE-2026-1111",
        "vendorProject": "WidgetCorp",
        "product": "Widget",
        "vulnerabilityName": "Widget RCE (KEV title)",
        "dateAdded": "2026-11-01",
        "shortDescription": "KEV summary",
        "requiredAction": "Apply updates.",
        "dueDate": "2026-11-22",
        "knownRansomwareCampaignUse": "Unknown",
        "notes": "",
        "cwes": ["CWE-78"],
    }],
}

OSV_VULN_RANGED = {
    "id": "CVE-2026-1111",
    "summary": "OSV title that must not overwrite KEV",
    "details": "OSV details",
    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/9.8"}],
    "published": "2026-10-30T00:00:00Z",
    "affected": [{
        "package": {"name": "widget-lib", "ecosystem": "PyPI"},
        "ranges": [{"type": "SEMVER", "events": [
            {"introduced": "1.0.0"}, {"fixed": "2.0.0"}]}],
    }],
}

OSV_VULN_NO_RANGES = {
    "id": "CVE-2026-2222",
    "summary": "Second vuln, no range data",
    "details": "OSV details",
    "published": "2026-10-29T00:00:00Z",
    "affected": [{
        "package": {"name": "widget-lib", "ecosystem": "PyPI"},
    }],
}


@pytest.fixture()
def feeds(monkeypatch):
    """Replace ingest.fetch_json with fixture feeds; state toggles
    failures and the OSV response set."""
    state = {"kev_fails": False,
             "osv_vulns": [OSV_VULN_RANGED, OSV_VULN_NO_RANGES]}

    def fake_fetch(url, payload=None):
        if "cisa.gov" in url:
            if state["kev_fails"]:
                raise urllib.error.HTTPError(url, 503, "down", {}, None)
            return KEV_FEED
        if "osv.dev" in url:
            return {"vulns": state["osv_vulns"]}
        raise AssertionError(url)

    monkeypatch.setattr(ingest, "fetch_json", fake_fetch)
    return state


@pytest.fixture()
def assets(db_path):
    conn = db.connect(db_path)
    ids = {
        "keyword": db.add_asset(conn, "Widget Server", keywords="widget"),
        "in_range": db.add_asset(
            conn, "widget-lib 1.5", version="1.5.0",
            ecosystem="PyPI", package_name="widget-lib"),
        "out_of_range": db.add_asset(
            conn, "widget-lib 2.5", version="2.5.0",
            ecosystem="PyPI", package_name="widget-lib"),
    }
    conn.commit()
    conn.close()
    return ids


def _items_by_asset(db_path):
    conn = db.connect(db_path)
    items = db.list_items(conn)
    conn.close()
    return items


def test_kev_feed_format_and_keyword_match(db_path, feeds, assets):
    results = {r["source"]: r for r in ingest.run(db_path, "kev")}
    assert results["kev"]["status"] == "ok"
    assert results["kev"]["imported"] == 1
    items = _items_by_asset(db_path)
    keyword_items = [i for i in items
                     if i["asset_id"] == assets["keyword"]]
    assert len(keyword_items) == 1
    assert keyword_items[0]["match_method"] == "keyword"
    assert "widget" in keyword_items[0]["match_reason"].lower()


def test_osv_range_matching_in_out_and_unknown(db_path, feeds, assets):
    results = {r["source"]: r for r in ingest.run(db_path, "osv")}
    assert results["osv"]["status"] == "ok"
    # The 1.5.0 asset matches both vulns. The 2.5.0 asset is out of
    # range for the ranged one (skipped, counted, not itemized) but
    # still matches the range-less one by package alone.
    assert results["osv"]["imported"] == 3
    assert results["osv"]["skipped_out_of_range"] == 1
    items = _items_by_asset(db_path)
    by_pair = {(i["asset_id"], i["cve_id"]): i for i in items}
    ranged = by_pair[(assets["in_range"], "CVE-2026-1111")]
    assert ranged["match_method"] == "version_range"
    assert "1.5.0" in ranged["match_reason"]
    assert "2.0.0" in ranged["match_reason"]
    no_ranges = by_pair[(assets["in_range"], "CVE-2026-2222")]
    assert no_ranges["match_method"] == "package"
    assert (assets["out_of_range"], "CVE-2026-1111") not in by_pair
    assert by_pair[(assets["out_of_range"],
                    "CVE-2026-2222")]["match_method"] == "package"


def test_multiple_vulns_for_one_package(db_path, feeds, assets):
    ingest.run(db_path, "osv")
    cves = {i["cve_id"] for i in _items_by_asset(db_path)
            if i["asset_id"] == assets["in_range"]}
    assert cves == {"CVE-2026-1111", "CVE-2026-2222"}


def test_same_cve_from_both_sources_merges(db_path, feeds, assets):
    ingest.run(db_path, "all")
    conn = db.connect(db_path)
    sources = db.list_vuln_sources(conn, "CVE-2026-1111")
    assert {s["source"] for s in sources} == {"kev", "osv"}
    vuln = conn.execute(
        "SELECT * FROM vulns WHERE cve_id='CVE-2026-1111'").fetchone()
    assert vuln["title"] == "Widget RCE (KEV title)"
    assert vuln["severity"] == "known-exploited"
    conn.close()


def test_reingest_is_idempotent(db_path, feeds, assets):
    ingest.run(db_path, "all")
    first = len(_items_by_asset(db_path))
    ingest.run(db_path, "all")
    assert len(_items_by_asset(db_path)) == first
    conn = db.connect(db_path)
    count = conn.execute("SELECT COUNT(*) c FROM vulns").fetchone()["c"]
    assert count == 2  # CVE-2026-1111 and CVE-2026-2222
    conn.close()


def test_one_source_failing_does_not_block_the_other(db_path, feeds,
                                                      assets):
    feeds["kev_fails"] = True
    results = {r["source"]: r for r in ingest.run(db_path, "all")}
    assert results["kev"]["status"] == "error"
    assert results["kev"]["error"] == "http 503"
    assert results["osv"]["status"] == "ok"
    conn = db.connect(db_path)
    runs = {r["source"]: r for r in db.list_ingest_runs(conn, limit=2)}
    assert runs["kev"]["status"] == "error"
    assert runs["kev"]["error"] == "http 503"
    assert runs["osv"]["status"] == "ok"
    conn.close()


@pytest.mark.parametrize("a,b,expected", [
    ("1.5.0", "2.0.0", -1),
    ("1.10.0", "1.9.0", 1),
    ("2.0", "2.0", 0),
    ("1.0.0", "1.0.0", 0),
    ("0.9.9", "1.0.0", -1),
])
def test_compare_versions(a, b, expected):
    got = ingest.compare_versions(a, b)
    assert (got > 0) - (got < 0) == expected


def test_range_match_verdicts_directly():
    asset = {"version": "1.5.0", "package_name": "widget-lib",
             "ecosystem": "PyPI"}
    verdict, reason = ingest.osv_range_match(OSV_VULN_RANGED, asset)
    assert verdict == "in" and "1.5.0" in reason
    verdict, _ = ingest.osv_range_match(
        OSV_VULN_RANGED, {**asset, "version": "2.5.0"})
    assert verdict == "out"
    verdict, _ = ingest.osv_range_match(OSV_VULN_NO_RANGES, asset)
    assert verdict == "unknown"
