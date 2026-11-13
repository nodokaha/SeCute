"""SQLite storage for the SeCute tracker.

Tables:
  assets       - inventory of products in scope (name + version + keywords)
  vulns        - merged vulnerability view shown by the API/dashboard
  vuln_sources - one record per (vuln, source): what each source actually
                 said, kept separately so re-ingesting one source never
                 overwrites another source's data; `vulns` is rebuilt
                 from these rows
  items        - one tracked entry per (vuln, asset) pair; carries the
                 fields the reports are generated from (overview / scope
                 / response / status) plus how the match was decided
                 (match_method / match_reason)
  ingest_runs  - one row per source per ingest run, so a failed source
                 is visible instead of silently missing
"""
import sqlite3

SCHEMA = """
CREATE TABLE IF NOT EXISTS assets (
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL,
  version TEXT NOT NULL DEFAULT '',
  ecosystem TEXT NOT NULL DEFAULT '',
  package_name TEXT NOT NULL DEFAULT '',
  keywords TEXT NOT NULL DEFAULT '',
  notes TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS vulns (
  cve_id TEXT PRIMARY KEY,
  source TEXT NOT NULL,
  title TEXT NOT NULL DEFAULT '',
  summary TEXT NOT NULL DEFAULT '',
  severity TEXT NOT NULL DEFAULT '',
  published_at TEXT,
  url TEXT NOT NULL DEFAULT '',
  fetched_at TEXT NOT NULL DEFAULT (datetime('now')),
  raw TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS vuln_sources (
  cve_id TEXT NOT NULL,
  source TEXT NOT NULL,
  title TEXT NOT NULL DEFAULT '',
  summary TEXT NOT NULL DEFAULT '',
  severity TEXT NOT NULL DEFAULT '',
  published_at TEXT,
  url TEXT NOT NULL DEFAULT '',
  raw TEXT NOT NULL DEFAULT '{}',
  fetched_at TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (cve_id, source)
);
CREATE TABLE IF NOT EXISTS items (
  id INTEGER PRIMARY KEY,
  cve_id TEXT REFERENCES vulns(cve_id),
  asset_id INTEGER REFERENCES assets(id),
  title TEXT NOT NULL DEFAULT '',
  overview TEXT NOT NULL DEFAULT '',
  scope TEXT NOT NULL DEFAULT '',
  response TEXT NOT NULL DEFAULT '',
  triage TEXT NOT NULL DEFAULT 'watch',
  status TEXT NOT NULL DEFAULT 'unconfirmed',
  match_method TEXT NOT NULL DEFAULT '',
  match_reason TEXT NOT NULL DEFAULT '',
  due_date TEXT,
  responded_at TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE(cve_id, asset_id)
);
CREATE TABLE IF NOT EXISTS ingest_runs (
  id INTEGER PRIMARY KEY,
  source TEXT NOT NULL,
  status TEXT NOT NULL,
  imported INTEGER NOT NULL DEFAULT 0,
  error TEXT NOT NULL DEFAULT '',
  started_at TEXT NOT NULL DEFAULT (datetime('now')),
  finished_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_items_status ON items(status);
"""

# Columns added after the first release; init_db applies them to
# existing databases so upgrades need no manual migration.
ITEM_ADDED_COLUMNS = {
    "match_method": "TEXT NOT NULL DEFAULT ''",
    "match_reason": "TEXT NOT NULL DEFAULT ''",
}

TRIAGE_VALUES = {"action_needed", "watch", "not_affected"}
STATUS_VALUES = {"unconfirmed", "in_progress", "patched", "mitigated",
                 "not_affected"}
ITEM_MUTABLE_FIELDS = {
    "title", "overview", "scope", "response",
    "triage", "status", "due_date", "responded_at",
}

# When several sources describe the same vulnerability, earlier sources
# in this list win for display fields in the merged view.
SOURCE_PRIORITY = ["kev", "osv"]


def connect(db_path):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db(db_path):
    conn = connect(db_path)
    try:
        conn.executescript(SCHEMA)
        existing = {r[1] for r in conn.execute("PRAGMA table_info(items)")}
        for column, ddl in ITEM_ADDED_COLUMNS.items():
            if column not in existing:
                conn.execute(f"ALTER TABLE items ADD COLUMN {column} {ddl}")
        conn.commit()
    finally:
        conn.close()


def _merge_source_rows(rows):
    """Merge per-source records of one vulnerability into one view row.

    Display fields come from the highest-priority source that has a
    non-empty value, except severity: a "known-exploited" flag from any
    source always wins, because it changes the urgency.
    """
    def by_priority(field):
        for row in rows:
            if row[field]:
                return row[field]
        return rows[0][field] if rows else ""

    severity = ""
    if any(r["severity"] == "known-exploited" for r in rows):
        severity = "known-exploited"
    else:
        severity = by_priority("severity")
    published = [r["published_at"] for r in rows if r["published_at"]]
    return {
        "source": ",".join(r["source"] for r in rows),
        "title": by_priority("title"),
        "summary": by_priority("summary"),
        "severity": severity,
        "published_at": min(published) if published else None,
        "url": by_priority("url"),
        "raw": by_priority("raw"),
    }


def upsert_vuln(conn, cve_id, source, title="", summary="", severity="",
                published_at=None, url="", raw="{}"):
    """Store one source's record, then rebuild the merged view.

    The per-source record is the unit of storage: another source's
    record for the same vulnerability is left untouched.
    """
    conn.execute(
        """
        INSERT INTO vuln_sources (cve_id, source, title, summary, severity,
                                  published_at, url, raw, fetched_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
        ON CONFLICT(cve_id, source) DO UPDATE SET
          title=excluded.title, summary=excluded.summary,
          severity=excluded.severity, published_at=excluded.published_at,
          url=excluded.url, raw=excluded.raw, fetched_at=datetime('now')
        """,
        (cve_id, source, title, summary, severity, published_at, url, raw),
    )
    rows = [dict(r) for r in conn.execute(
        "SELECT * FROM vuln_sources WHERE cve_id = ?", (cve_id,))]
    rows.sort(key=lambda r: (SOURCE_PRIORITY.index(r["source"])
                             if r["source"] in SOURCE_PRIORITY else 99,
                             r["source"]))
    merged = _merge_source_rows(rows)
    conn.execute(
        """
        INSERT INTO vulns (cve_id, source, title, summary, severity,
                           published_at, url, fetched_at, raw)
        VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'), ?)
        ON CONFLICT(cve_id) DO UPDATE SET
          source=excluded.source, title=excluded.title,
          summary=excluded.summary, severity=excluded.severity,
          published_at=excluded.published_at, url=excluded.url,
          raw=excluded.raw, fetched_at=datetime('now')
        """,
        (cve_id, merged["source"], merged["title"], merged["summary"],
         merged["severity"], merged["published_at"], merged["url"],
         merged["raw"]),
    )


def list_vuln_sources(conn, cve_id):
    return [dict(r) for r in conn.execute(
        "SELECT * FROM vuln_sources WHERE cve_id = ? ORDER BY source",
        (cve_id,))]


def record_ingest_run(conn, source, status, imported=0, error=""):
    conn.execute(
        """
        INSERT INTO ingest_runs (source, status, imported, error, finished_at)
        VALUES (?, ?, ?, ?, datetime('now'))
        """,
        (source, status, imported, error),
    )
    conn.commit()


def list_ingest_runs(conn, limit=20):
    return [dict(r) for r in conn.execute(
        "SELECT * FROM ingest_runs ORDER BY id DESC LIMIT ?", (limit,))]


def add_asset(conn, name, version="", ecosystem="", package_name="",
              keywords="", notes=""):
    cur = conn.execute(
        """
        INSERT INTO assets (name, version, ecosystem, package_name, keywords, notes)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (name, version, ecosystem, package_name, keywords, notes),
    )
    return cur.lastrowid


def list_assets(conn):
    return [dict(r) for r in conn.execute("SELECT * FROM assets ORDER BY name")]


def find_or_create_item(conn, cve_id, asset_id, title="", triage="watch",
                        match_method="", match_reason=""):
    conn.execute(
        """
        INSERT INTO items (cve_id, asset_id, title, triage,
                           match_method, match_reason)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(cve_id, asset_id) DO NOTHING
        """,
        (cve_id, asset_id, title, triage, match_method, match_reason),
    )
    row = conn.execute(
        "SELECT * FROM items WHERE cve_id IS ? AND asset_id IS ?",
        (cve_id, asset_id),
    ).fetchone()
    return dict(row)


def list_items(conn, status=None, triage=None):
    sql = """
        SELECT i.*, v.severity, v.source, v.published_at, v.url,
               a.name AS asset_name, a.version AS asset_version
        FROM items i
        LEFT JOIN vulns v ON v.cve_id = i.cve_id
        LEFT JOIN assets a ON a.id = i.asset_id
        WHERE 1 = 1
    """
    params = []
    if status:
        sql += " AND i.status = ?"
        params.append(status)
    if triage:
        sql += " AND i.triage = ?"
        params.append(triage)
    sql += """
        ORDER BY CASE i.triage WHEN 'action_needed' THEN 0
                               WHEN 'watch' THEN 1 ELSE 2 END,
                 i.updated_at DESC
    """
    return [dict(r) for r in conn.execute(sql, params)]


def get_item(conn, item_id):
    row = conn.execute(
        """
        SELECT i.*, v.severity, v.source, v.summary, v.published_at, v.url,
               a.name AS asset_name, a.version AS asset_version
        FROM items i
        LEFT JOIN vulns v ON v.cve_id = i.cve_id
        LEFT JOIN assets a ON a.id = i.asset_id
        WHERE i.id = ?
        """,
        (item_id,),
    ).fetchone()
    return dict(row) if row else None


def update_item(conn, item_id, fields):
    fields = {k: v for k, v in fields.items()
              if k in ITEM_MUTABLE_FIELDS and v is not None}
    if "triage" in fields and fields["triage"] not in TRIAGE_VALUES:
        raise ValueError(
            f"invalid triage: {fields['triage']!r} "
            f"(allowed: {', '.join(sorted(TRIAGE_VALUES))})")
    if "status" in fields and fields["status"] not in STATUS_VALUES:
        raise ValueError(
            f"invalid status: {fields['status']!r} "
            f"(allowed: {', '.join(sorted(STATUS_VALUES))})")
    if not fields:
        return get_item(conn, item_id)
    assignments = ", ".join(f"{k} = ?" for k in fields)
    conn.execute(
        f"UPDATE items SET {assignments}, updated_at = datetime('now') WHERE id = ?",
        (*fields.values(), item_id),
    )
    conn.commit()
    return get_item(conn, item_id)
