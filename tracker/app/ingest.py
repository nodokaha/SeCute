"""Ingest vulnerability data and match it against the asset inventory.

Sources:
  - CISA KEV (known exploited vulnerabilities catalog, JSON feed)
  - OSV.dev API (per-asset query by package + version)

JPCERT/CC alerts have no stable machine-readable feed used here yet;
add a fetcher alongside these when wiring them up.

Every record keeps its fetched_at timestamp; never present stale data
as new.
"""
import argparse
import json
import os
import urllib.request

from . import db

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
OSV_API = "https://api.osv.dev/v1/query"
USER_AGENT = "SeCute-Tracker/0.1"


def fetch_json(url, payload=None):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(
        url,
        data=data,
        headers={"User-Agent": USER_AGENT, "Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _asset_keywords(asset):
    words = [w.strip().lower() for w in asset["keywords"].split(",") if w.strip()]
    return words or [asset["name"].lower()]


def _matches(asset, text):
    text = text.lower()
    return any(w in text for w in _asset_keywords(asset))


def ingest_kev(conn):
    """Import KEV entries that match at least one asset's keywords."""
    assets = db.list_assets(conn)
    if not assets:
        return {"source": "kev", "imported": 0, "note": "no assets registered"}
    feed = fetch_json(KEV_URL)
    imported = 0
    for entry in feed.get("vulnerabilities", []):
        haystack = " ".join([
            entry.get("vendorProject", ""), entry.get("product", ""),
            entry.get("vulnerabilityName", ""), entry.get("cveID", ""),
        ])
        matched = [a for a in assets if _matches(a, haystack)]
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
        for asset in matched:
            db.find_or_create_item(
                conn, entry["cveID"], asset["id"],
                title=entry.get("vulnerabilityName", ""),
                triage="action_needed",
            )
        imported += 1
    conn.commit()
    return {"source": "kev", "imported": imported}


def ingest_osv(conn):
    """Query OSV.dev for each asset that has an ecosystem + package name."""
    assets = [a for a in db.list_assets(conn)
              if a["ecosystem"] and a["package_name"]]
    imported = 0
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
            )
            imported += 1
    conn.commit()
    return {"source": "osv", "imported": imported}


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


def run(db_path, source="all"):
    db.init_db(db_path)
    conn = db.connect(db_path)
    try:
        results = []
        if source in ("all", "kev"):
            results.append(ingest_kev(conn))
        if source in ("all", "osv"):
            results.append(ingest_osv(conn))
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
