"""Ingest vulnerability data and match it against the asset inventory.

Sources:
  - CISA KEV (known exploited vulnerabilities catalog, JSON feed)
  - OSV.dev API (per-asset query by package + version)

JPCERT/CC alerts have no stable machine-readable feed used here yet;
add a fetcher alongside these when wiring them up.

Each source is ingested independently: one source failing never blocks
the other, and every run is recorded in ingest_runs with its outcome
(ok / error, with the failure kind) so a missing source is visible
instead of looking like "nothing new".

Matching records how it decided (match_method / match_reason on the
item). Automatic matches create items in the `unconfirmed` status; a
human confirms them by moving the status on. Never present stale data
as new: every record keeps its fetched_at timestamp.
"""
import argparse
import json
import os
import re
import socket
import urllib.error
import urllib.request

from . import db

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
OSV_API = "https://api.osv.dev/v1/query"
USER_AGENT = "SeCute-Tracker/0.2"


def fetch_json(url, payload=None):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(
        url,
        data=data,
        headers={"User-Agent": USER_AGENT, "Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        return json.loads(resp.read().decode("utf-8"))


def classify_error(exc):
    """Bucket a fetch/parse failure so runs can be told apart."""
    if isinstance(exc, urllib.error.HTTPError):
        return f"http {exc.code}"
    if isinstance(exc, (TimeoutError, socket.timeout)):
        return "timeout"
    if isinstance(exc, urllib.error.URLError):
        reason = getattr(exc, "reason", None)
        if isinstance(reason, (TimeoutError, socket.timeout)):
            return "timeout"
        return f"network: {reason}"
    if isinstance(exc, json.JSONDecodeError):
        return "invalid json"
    return f"{type(exc).__name__}: {exc}"


# --- matching ---------------------------------------------------------

def _asset_keywords(asset):
    words = [w.strip().lower() for w in asset["keywords"].split(",") if w.strip()]
    return words or [asset["name"].lower()]


def _keyword_match(asset, text):
    """Return the keyword that matched, or None."""
    text = text.lower()
    for w in _asset_keywords(asset):
        if w in text:
            return w
    return None


_TOKEN_RE = re.compile(r"\d+|[a-zA-Z]+")


def _version_key(version):
    """Split a version into comparable tokens.

    Pragmatic ordering for common version shapes (semver-like, distro
    suffixes): numeric runs compare as numbers and sort before text
    runs at the same position. This is an approximation, not a full
    PEP 440 / RPM version comparison.
    """
    key = []
    for tok in _TOKEN_RE.findall(str(version)):
        if tok.isdigit():
            key.append((0, int(tok), ""))
        else:
            key.append((1, 0, tok.lower()))
    return key


def compare_versions(a, b):
    ka, kb = _version_key(a), _version_key(b)
    for x, y in zip(ka, kb):
        if x != y:
            return -1 if x < y else 1
    if len(ka) == len(kb):
        return 0
    return -1 if len(ka) < len(kb) else 1


def osv_range_match(vuln, asset):
    """Judge an OSV record against an asset using its affected ranges.

    Returns (verdict, reason) where verdict is:
      "in"      - the asset's version falls in an affected range
      "out"     - ranges exist for this package and the version is
                  outside all of them
      "unknown" - no usable range data for this package, so only the
                  package identity itself supports the match
    """
    version = asset["version"]
    ranges = []
    for affected in vuln.get("affected", []):
        pkg = affected.get("package", {})
        if pkg.get("name") != asset["package_name"]:
            continue
        if pkg.get("ecosystem") and asset["ecosystem"] and \
                pkg["ecosystem"] != asset["ecosystem"]:
            continue
        for rng in affected.get("ranges", []):
            if rng.get("type") in ("SEMVER", "ECOSYSTEM"):
                ranges.append(rng.get("events", []))
        if affected.get("versions"):
            if version and version in affected["versions"]:
                return "in", (f"version {version} is listed explicitly "
                              f"in the OSV affected versions")
    if not ranges or not version:
        return "unknown", ""
    for events in ranges:
        introduced = None
        for event in events:
            if "introduced" in event:
                introduced = event["introduced"]
            elif "fixed" in event:
                if introduced is not None and \
                        compare_versions(version, introduced) >= 0 and \
                        compare_versions(version, event["fixed"]) < 0:
                    return "in", (f"version {version} is in the affected "
                                  f"range [{introduced}, {event['fixed']})")
                introduced = None
            elif "last_affected" in event:
                if introduced is not None and \
                        compare_versions(version, introduced) >= 0 and \
                        compare_versions(version, event["last_affected"]) <= 0:
                    return "in", (f"version {version} is in the affected "
                                  f"range [{introduced}, {event['last_affected']}]")
                introduced = None
        if introduced is not None and \
                compare_versions(version, introduced) >= 0:
            return "in", (f"version {version} is at or after the affected "
                          f"range start {introduced} (no fix recorded)")
    return "out", (f"version {version} is outside every affected range "
                   f"OSV lists for this package")


# --- sources ----------------------------------------------------------

def ingest_kev(conn):
    """Import KEV entries that match at least one asset's keywords."""
    assets = db.list_assets(conn)
    if not assets:
        return {"source": "kev", "status": "ok", "imported": 0,
                "note": "no assets registered"}
    feed = fetch_json(KEV_URL)
    imported = 0
    for entry in feed.get("vulnerabilities", []):
        haystack = " ".join([
            entry.get("vendorProject", ""), entry.get("product", ""),
            entry.get("vulnerabilityName", ""), entry.get("cveID", ""),
        ])
        matched = []
        for asset in assets:
            word = _keyword_match(asset, haystack)
            if word:
                matched.append((asset, word))
        if not matched:
            continue
        db.upsert_vuln(
            conn,
            cve_id=entry["cveID"],
            source="kev",
            title=entry.get("vulnerabilityName", ""),
            summary=entry.get("shortDescription", ""),
            severity="known-exploited",
            published_at=entry.get("dateAdded"),
            url="https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            raw=json.dumps(entry, ensure_ascii=False),
        )
        for asset, word in matched:
            db.find_or_create_item(
                conn, entry["cveID"], asset["id"],
                title=entry.get("vulnerabilityName", ""),
                triage="action_needed",
                match_method="keyword",
                match_reason=(f"keyword '{word}' matched the KEV entry "
                              f"(vendor/product/name); KEV lists it as "
                              f"known-exploited. Automatic match, "
                              f"unconfirmed."),
            )
        imported += 1
    conn.commit()
    return {"source": "kev", "status": "ok", "imported": imported}


def ingest_osv(conn):
    """Query OSV.dev for each asset that has an ecosystem + package name.

    When the asset has a version and OSV publishes affected ranges for
    the package, the version is checked against the ranges: outside
    every range means no item (and the skip is counted in the result).
    """
    assets = [a for a in db.list_assets(conn)
              if a["ecosystem"] and a["package_name"]]
    imported = 0
    skipped_out_of_range = 0
    for asset in assets:
        query = {"package": {"name": asset["package_name"],
                             "ecosystem": asset["ecosystem"]}}
        if asset["version"]:
            query["version"] = asset["version"]
        result = fetch_json(OSV_API, query)
        for vuln in result.get("vulns", []):
            vuln_id = vuln.get("id", "")
            if not vuln_id:
                continue
            if asset["version"]:
                verdict, reason = osv_range_match(vuln, asset)
                if verdict == "out":
                    skipped_out_of_range += 1
                    continue
                if verdict == "in":
                    match_method = "version_range"
                    match_reason = reason + " Automatic match, unconfirmed."
                else:
                    match_method = "package"
                    match_reason = ("OSV returned this record for the "
                                    "package, but no affected-range data "
                                    "was available to check the version "
                                    "against. Automatic match, unconfirmed.")
            else:
                match_method = "package"
                match_reason = ("asset has no version registered, so the "
                                "match rests on the package name alone. "
                                "Automatic match, unconfirmed.")
            severity = ""
            for sev in vuln.get("severity", []):
                if sev.get("type") == "CVSS_V3":
                    severity = sev.get("score", "")
                    break
            db.upsert_vuln(
                conn,
                cve_id=vuln_id,
                source="osv",
                title=vuln.get("summary", ""),
                summary=vuln.get("details", "")[:2000],
                severity=severity,
                published_at=vuln.get("published"),
                url=f"https://osv.dev/vulnerability/{vuln_id}",
                raw=json.dumps(vuln, ensure_ascii=False),
            )
            db.find_or_create_item(
                conn, vuln_id, asset["id"],
                title=vuln.get("summary", ""), triage="watch",
                match_method=match_method, match_reason=match_reason,
            )
            imported += 1
    conn.commit()
    result = {"source": "osv", "status": "ok", "imported": imported}
    if skipped_out_of_range:
        result["skipped_out_of_range"] = skipped_out_of_range
    return result


def seed_assets(conn, path):
    with open(path, encoding="utf-8") as f:
        entries = json.load(f)
    ids = []
    for e in entries:
        ids.append(db.add_asset(
            conn,
            name=e["name"],
            version=e.get("version", ""),
            ecosystem=e.get("ecosystem", ""),
            package_name=e.get("package_name", ""),
            keywords=e.get("keywords", ""),
            notes=e.get("notes", ""),
        ))
    conn.commit()
    return ids


SOURCES = {"kev": ingest_kev, "osv": ingest_osv}


def run(db_path, source="all"):
    """Ingest each requested source independently and record the runs.

    A source that raises is recorded as an error run and reported in
    the results; it never prevents the remaining sources from running.
    """
    db.init_db(db_path)
    conn = db.connect(db_path)
    try:
        wanted = list(SOURCES) if source == "all" else [source]
        results = []
        for name in wanted:
            try:
                result = SOURCES[name](conn)
            except Exception as exc:  # one source must not block others
                conn.rollback()
                result = {"source": name, "status": "error",
                          "imported": 0, "error": classify_error(exc)}
            db.record_ingest_run(conn, name, result["status"],
                                 result.get("imported", 0),
                                 result.get("error", ""))
            results.append(result)
        return results
    finally:
        conn.close()


def main():
    parser = argparse.ArgumentParser(description="SeCute tracker ingest")
    parser.add_argument("--db", default=os.environ.get("SECUTE_DB", "data/secute.db"))
    parser.add_argument("--source", choices=["all", "kev", "osv"], default="all")
    parser.add_argument("--seed", help="JSON file with asset entries to register")
    args = parser.parse_args()
    if args.seed:
        db.init_db(args.db)
        conn = db.connect(args.db)
        try:
            ids = seed_assets(conn, args.seed)
            print(f"seeded {len(ids)} assets")
        finally:
            conn.close()
    for result in run(args.db, args.source):
        print(result)


if __name__ == "__main__":
    main()
