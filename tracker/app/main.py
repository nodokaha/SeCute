"""SeCute tracker web app (FastAPI).

Personal-use tool: no authentication built in. Run it behind access
control (reverse proxy / VPN / SSO), never exposed to the public net.
"""
import html
import os
from typing import Optional

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from . import db, ingest as ingest_mod

DB_PATH = os.environ.get("SECUTE_DB", "/data/secute.db")

app = FastAPI(title="SeCute Tracker")


@app.on_event("startup")
def _startup():
    db.init_db(DB_PATH)


def _conn():
    return db.connect(DB_PATH)


@app.get("/health")
def health():
    return {"status": "ok"}


class AssetIn(BaseModel):
    name: str
    version: str = ""
    ecosystem: str = ""
    package_name: str = ""
    keywords: str = ""
    notes: str = ""


@app.get("/api/assets")
def get_assets():
    conn = _conn()
    try:
        return db.list_assets(conn)
    finally:
        conn.close()


@app.post("/api/assets")
def post_asset(asset: AssetIn):
    conn = _conn()
    try:
        asset_id = db.add_asset(conn, **asset.model_dump())
        conn.commit()
        return {"id": asset_id}
    finally:
        conn.close()


@app.post("/api/ingest/seed")
def post_seed(entries: list[AssetIn]):
    conn = _conn()
    try:
        ids = [db.add_asset(conn, **e.model_dump()) for e in entries]
        conn.commit()
        return {"seeded": ids}
    finally:
        conn.close()


@app.post("/api/ingest")
def post_ingest(source: str = "all"):
    if source not in ("all", "kev", "osv"):
        raise HTTPException(400, "source must be all, kev or osv")
    return ingest_mod.run(DB_PATH, source)


@app.get("/api/items")
def get_items(status: Optional[str] = None, triage: Optional[str] = None):
    conn = _conn()
    try:
        return db.list_items(conn, status=status, triage=triage)
    finally:
        conn.close()


@app.get("/api/items/{item_id}")
def get_item(item_id: int):
    conn = _conn()
    try:
        item = db.get_item(conn, item_id)
        if item is None:
            raise HTTPException(404, "item not found")
        return item
    finally:
        conn.close()


class ItemPatch(BaseModel):
    title: Optional[str] = None
    overview: Optional[str] = None
    scope: Optional[str] = None
    response: Optional[str] = None
    triage: Optional[str] = None
    status: Optional[str] = None
    due_date: Optional[str] = None
    responded_at: Optional[str] = None


@app.patch("/api/items/{item_id}")
def patch_item(item_id: int, patch: ItemPatch):
    conn = _conn()
    try:
        if db.get_item(conn, item_id) is None:
            raise HTTPException(404, "item not found")
        return db.update_item(conn, item_id, patch.model_dump(exclude_none=True))
    finally:
        conn.close()


@app.get("/", response_class=HTMLResponse)
def dashboard():
    conn = _conn()
    try:
        items = db.list_items(conn)
    finally:
        conn.close()
    rows = []
    for i in items:
        rows.append(
            "<tr>"
            f"<td>{html.escape(i['triage'])}</td>"
            f"<td>{html.escape(i['status'])}</td>"
            f"<td>{html.escape(i['cve_id'] or '')}</td>"
            f"<td>{html.escape(i['title'])}</td>"
            f"<td>{html.escape(i['asset_name'] or '')} {html.escape(i['asset_version'] or '')}</td>"
            f"<td>{html.escape(i['severity'] or '')}</td>"
            f"<td>{html.escape(i['updated_at'] or '')}</td>"
            "</tr>"
        )
    body = "\n".join(rows) or '<tr><td colspan="7">No items yet. Register assets and run ingest.</td></tr>'
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>SeCute Tracker</title>
<style>body{{font-family:sans-serif;margin:2em}}table{{border-collapse:collapse}}
td,th{{border:1px solid #ccc;padding:4px 8px}}</style></head>
<body><h1>SeCute Tracker</h1>
<table><tr><th>triage</th><th>status</th><th>id</th><th>title</th>
<th>asset</th><th>severity</th><th>updated</th></tr>
{body}</table></body></html>"""
