"""Tracker Coolify ingest tests: the Coolify API shapes (resource
list + per-resource findings with pagination) with HTTP replaced by
fixtures. Configuration comes from the environment only."""
import json
import re
import urllib.error
import urllib.parse

import pytest

from app import db, ingest

BASE = "https://coolify.example.test"
LIST_URL = BASE + "/api/v1/vulnerabilities"

RESOURCE_APP = {
    "uuid": "app-uuid-1",
    "name": "web",
    "type": "application",
    "project_uuid": "proj-1",
    "environment_uuid": "env-1",
    "server_uuid": "srv-1",
    "images": {"update": 1, "total": 1},
    "security": {"status": "update_now", "problem_count": 2,
                 "critical_count": 1, "high_count": 1,
                 "checked_at": "2026-11-14T00:00:00Z"},
}

RESOURCE_SVC = {
    "uuid": "svc-uuid-1",
    "name": "db",
    "type": "service",
    "project_uuid": "proj-1",
    "environment_uuid": "env-1",
    "server_uuid": "srv-1",
    "images": {"update": 1, "total": 1},
    "security": {"status": "update_now", "problem_count": 1,
                 "critical_count": 1,
                 "checked_at": "2026-11-14T01:00:00Z"},
}

FINDING_KEV = {
    "id": "finding-1",
    "display_id": "CVE-2026-3333",
    "aliases": [],
    "title": "Prototype pollution in lodash",
    "severity": "critical",
    "package": "lodash",
    "version": "4.17.20",
    "package_type": "npm",
    "fixed_in": "4.17.21",
    "state": "fixed",
    "ignore": None,
    "kev": True,
    "epss": 0.42,
    "risk": 88.5,
    "cvss_score": 9.8,
    "advisory_url": "https://example.test/advisory/CVE-2026-3333",
    "image_ref": "registry.example.test/web:1.0",
    "owner_uuid": "app-uuid-1",
}

FINDING_PLAIN = {
    "id": "finding-2",
    "display_id": "CVE-2026-4444",
    "aliases": ["GHSA-xxxx-yyyy"],
    "title": "Buffer overread in OpenSSL",
    "severity": "high",
    "package": "openssl",
    "version": "3.0.13",
    "package_type": "debian",
    "fixed_in": "3.0.14",
    "state": "fixed",
    "ignore": None,
    "kev": False,
    "epss": 0.01,
    "risk": 40.0,
    "cvss_score": 7.5,
    "advisory_url": "https://example.test/advisory/CVE-2026-4444",
    "image_ref": "registry.example.test/web:1.0",
    "owner_uuid": "app-uuid-1",
}

_RESOURCE_URL = re.compile(
    r"^" + re.escape(BASE) +
    r"/api/v1/(applications|databases|services)/([^/]+)/vulnerabilities$")


class FakeCoolify:
    """Stand-in for ingest.fetch_json speaking the Coolify shapes.

    pages maps (segment, uuid, page) to a response payload; any URL
    outside the two documented endpoints fails the test.
    """

    def __init__(self):
        self.requests = []  # (url, headers)
        self.resources = [RESOURCE_APP, RESOURCE_SVC]
        self.pages = {}
        self.list_error = None
        self.resource_error = None

    def fetch(self, url, payload=None, headers=None):
        self.requests.append((url, headers))
        if url == LIST_URL:
            if self.list_error is not None:
                raise self.list_error
            return {"resources": self.resources}
        split = urllib.parse.urlsplit(url)
        m = _RESOURCE_URL.match(BASE + split.path)
        if m:
            if self.resource_error is not None:
                raise self.resource_error
            query = urllib.parse.parse_qs(split.query)
            page = int(query["page"][0])
            key = (m.group(1), m.group(2), page)
            if key in self.pages:
                return self.pages[key]
            raise AssertionError(f"unexpected page request: {url}")
        raise AssertionError(url)

    def requested_pages(self, segment, uuid):
        pages = []
        for url, _ in self.requests:
            split = urllib.parse.urlsplit(url)
            m = _RESOURCE_URL.match(BASE + split.path)
            if m and m.group(1) == segment and m.group(2) == uuid:
                pages.append(int(urllib.parse.parse_qs(split.query)
                                 ["page"][0]))
        return pages


@pytest.fixture()
def coolify(monkeypatch):
    api = FakeCoolify()
    monkeypatch.setattr(ingest, "fetch_json", api.fetch)
    monkeypatch.setenv("COOLIFY_BASE_URL", BASE)
    monkeypatch.setenv("COOLIFY_API_TOKEN", "test-token")
    return api


def _page(findings, page, per_page, total):
    return {"findings": findings,
            "pagination": {"page": page, "per_page": per_page,
                           "total": total}}


def test_findings_are_normalized_and_stored(db_path, coolify):
    coolify.pages[("applications", "app-uuid-1", 1)] = _page(
        [FINDING_KEV, FINDING_PLAIN], page=1, per_page=100, total=2)
    # The same CVE shows up again in a second resource's image.
    coolify.pages[("services", "svc-uuid-1", 1)] = _page(
        [dict(FINDING_KEV, owner_uuid="svc-uuid-1",
              image_ref="registry.example.test/db:2.0")],
        page=1, per_page=100, total=1)

    results = {r["source"]: r for r in ingest.run(db_path, "coolify")}
    result = results["coolify"]
    assert result["status"] == "ok"
    assert result["imported"] == 2  # unique vulnerability ids
    assert result["findings"] == 3
    assert result["resources"] == 2

    # Every request carried the bearer token from the environment.
    assert coolify.requests
    for _, headers in coolify.requests:
        assert headers == {"Authorization": "Bearer test-token"}

    conn = db.connect(db_path)
    sources = db.list_vuln_sources(conn, "CVE-2026-3333")
    assert [s["source"] for s in sources] == ["coolify"]
    record = sources[0]
    # The finding's kev flag maps to the tracker's known-exploited
    # severity, like the KEV source's records.
    assert record["severity"] == "known-exploited"
    assert record["title"] == "Prototype pollution in lodash"
    assert record["url"] == "https://example.test/advisory/CVE-2026-3333"
    assert "lodash 4.17.20" in record["summary"]
    assert "fixed in 4.17.21" in record["summary"]
    assert "CVSS 9.8" in record["summary"]
    raw = json.loads(record["raw"])
    occurrences = raw["occurrences"]
    assert {o["resource_name"] for o in occurrences} == {"web", "db"}
    assert {o["finding"]["image_ref"] for o in occurrences} == {
        "registry.example.test/web:1.0", "registry.example.test/db:2.0"}

    plain = db.list_vuln_sources(conn, "CVE-2026-4444")[0]
    assert plain["severity"] == "high"
    vuln = conn.execute(
        "SELECT * FROM vulns WHERE cve_id='CVE-2026-4444'").fetchone()
    assert vuln["source"] == "coolify"
    conn.close()


def test_pagination_is_followed(db_path, coolify):
    coolify.resources = [RESOURCE_APP]
    third = dict(FINDING_PLAIN, id="finding-3",
                 display_id="CVE-2026-5555")
    coolify.pages[("applications", "app-uuid-1", 1)] = _page(
        [FINDING_KEV, FINDING_PLAIN], page=1, per_page=2, total=3)
    coolify.pages[("applications", "app-uuid-1", 2)] = _page(
        [third], page=2, per_page=2, total=3)

    results = {r["source"]: r for r in ingest.run(db_path, "coolify")}
    assert results["coolify"]["status"] == "ok"
    assert results["coolify"]["imported"] == 3
    assert coolify.requested_pages("applications", "app-uuid-1") == [1, 2]
    conn = db.connect(db_path)
    count = conn.execute("SELECT COUNT(*) c FROM vulns").fetchone()["c"]
    assert count == 3
    conn.close()


def test_missing_config_is_a_classified_failure(db_path, monkeypatch):
    def no_fetch(url, payload=None, headers=None):
        raise AssertionError("config must fail before any HTTP")

    monkeypatch.setattr(ingest, "fetch_json", no_fetch)
    monkeypatch.delenv("COOLIFY_BASE_URL", raising=False)
    monkeypatch.delenv("COOLIFY_API_TOKEN", raising=False)

    results = {r["source"]: r for r in ingest.run(db_path, "coolify")}
    assert results["coolify"]["status"] == "error"
    assert results["coolify"]["error"] == \
        "config: COOLIFY_BASE_URL is not set"
    conn = db.connect(db_path)
    runs = db.list_ingest_runs(conn, limit=1)
    assert runs[0]["source"] == "coolify"
    assert runs[0]["status"] == "error"
    assert runs[0]["error"].startswith("config:")
    conn.close()

    # Base URL present but token missing is also a config failure.
    monkeypatch.setenv("COOLIFY_BASE_URL", BASE)
    results = {r["source"]: r for r in ingest.run(db_path, "coolify")}
    assert results["coolify"]["error"] == \
        "config: COOLIFY_API_TOKEN is not set"


def test_api_errors_are_classified(db_path, coolify):
    coolify.list_error = urllib.error.HTTPError(
        LIST_URL, 401, "Unauthorized", {}, None)
    results = {r["source"]: r for r in ingest.run(db_path, "coolify")}
    assert results["coolify"]["status"] == "error"
    assert results["coolify"]["error"] == "http 401"
    conn = db.connect(db_path)
    runs = db.list_ingest_runs(conn, limit=1)
    assert runs[0]["error"] == "http 401"
    conn.close()

    # A failure on a per-resource fetch is classified the same way.
    coolify.list_error = None
    coolify.resource_error = urllib.error.HTTPError(
        LIST_URL, 500, "Internal Server Error", {}, None)
    results = {r["source"]: r for r in ingest.run(db_path, "coolify")}
    assert results["coolify"]["status"] == "error"
    assert results["coolify"]["error"] == "http 500"
