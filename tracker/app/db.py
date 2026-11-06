"""SQLite storage for the SeCute tracker.

Tables:
  assets - inventory of products in scope (name + version + match keywords)
  vulns  - vulnerability records fetched from external sources
  items  - one tracked entry per (vuln, asset) pair; carries the fields the
           reports are generated from: overview / scope / response / status
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
  due_date TEXT,
  responded_at TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE(cve_id, asset_id)
);
CREATE INDEX IF NOT EXISTS idx_items_status ON items(status);
"""

# triage: action_needed / watch / not_affected
# status: unconfirmed / in_progress / patched / mitigated / not_affected
ITEM_MUTABLE_FIELDS = {
    "title", "overview", "scope", "response",
    "triage", "status", "due_date", "responded_at",
}


def connect(db_path):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db(db_path):
    conn = connect(db_path)
    try:
        conn.executescript(SCHEMA)
        conn.commit()
    finally:
        conn.close()


def upsert_vuln(conn, cve_id, source, title="", summary="", severity="",
                published_at=None, url="", raw="{}"):
    conn.execute(
        """
        INSERT INTO vulns (cve_id, source, title, summary, severity,
                           published_at, url, raw, fetched_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
        ON CONFLICT(cve_id) DO UPDATE SET
          source=excluded.source, title=excluded.title,
          summary=excluded.summary, severity=excluded.severity,
          published_at=excluded.published_at, url=excluded.url,
          raw=excluded.raw, fetched_at=datetime('now')
        """,
        (cve_id, source, title, summary, severity, published_at, url, raw),
    )


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


def find_or_create_item(conn, cve_id, asset_id, title="", triage="watch"):
    conn.execute(
        """
        INSERT INTO items (cve_id, asset_id, title, triage)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(cve_id, asset_id) DO NOTHING
        """,
        (cve_id, asset_id, title, triage),
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
    if not fields:
        return get_item(conn, item_id)
    assignments = ", ".join(f"{k} = ?" for k in fields)
    conn.execute(
        f"UPDATE items SET {assignments}, updated_at = datetime('now') WHERE id = ?",
        (*fields.values(), item_id),
    )
    conn.commit()
    return get_item(conn, item_id)
