---
name: secute
description: Operate SeCute - run sandbox security checks, review the vulnerability tracker, and draft reports and casual articles from tracked items.
---

# SeCute operations

SeCute tracks only the vulnerabilities that matter to one specific
environment, checks code in a sandbox, and turns the records into
reports and readable articles. This skill is the operating procedure.

## Daily review

1. Refresh data: `POST /api/ingest` on the tracker (or
   `python -m app.ingest --source all`).
2. Read `GET /api/items?status=unconfirmed` and sort by triage.
3. For each new item, decide the triage: `action_needed`, `watch`,
   or `not_affected` (with the reason written into the item).
4. Never present stale data as new: check `fetched_at` /
   `published_at` before summarizing anything.

## Running a check (harness)

```bash
python3 harness/seccheck.py run --target <path> --profile repo --out results/
```

- Default is `--network none`. Use `--network bridge` only when the
  dependency check needs live OSV data, and say so when reporting.
- Never pass production credentials, never mount a Docker socket,
  never run the target outside the sandbox.
- Read `report.json` from the newest results directory and summarize
  only what the tools actually found (tool, rule/id, file/package).

## Drafting a report

- Use `templates/report.md`. Fill it from the tracker item fields
  (overview / scope / response) plus evidence links.
- Every claim needs a source: CVE id, advisory URL, or harness output.
  If something is unverified, write that it is unverified.
- A report is a formal record: exact dates, versions, and numbers.
  Do not round or paraphrase figures from the source data.

## Drafting a casual article

- Use `templates/article.md`. Same source data as the report, written
  as a readable explainer: one-sentence summary, what happens, who is
  affected, what to do, sources with a checked date.
- Casual tone, never casual accuracy: no exaggeration, no rumors.
- Articles are drafts for a human to review. Never publish directly.

## Tracker API quick reference

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/items?status=&triage=` | list tracked items |
| GET | `/api/items/{id}` | one item with vuln + asset detail |
| PATCH | `/api/items/{id}` | update status/triage/overview/scope/response |
| GET | `/api/assets` | list inventory |
| POST | `/api/assets` | register an asset |
| POST | `/api/ingest` | fetch KEV + OSV and match against inventory |
