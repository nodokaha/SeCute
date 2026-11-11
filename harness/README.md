# Harness

Runs security scanners against a target inside a disposable Docker
container and returns a normalized JSON report. The target is treated
as untrusted code: it may get built or executed by the scanners, so
everything happens inside the sandbox.

## Usage

```bash
docker build -f Dockerfile.scanner -t secute-scanner .
python3 seccheck.py run --target /path/to/repo --profile repo --out results/
```

Output lands in `results/<YYYYMMDD-HHMMSS>/`:

- `report.json` — normalized result (this is what the tracker ingests)
- `gitleaks.json` / `osv.json` / `grype.json` — raw tool output
- `sbom.cdx.json` — CycloneDX SBOM of the target (sbom profile; kept as evidence)
- `*.log`, `*.exit` — tool logs and exit codes

## Profiles

| profile | tools | notes |
|---|---|---|
| `repo` | gitleaks, osv-scanner | secrets (incl. git history) + dependency vulnerabilities |
| `sbom` | syft, grype | SBOM-based scan (the approach Coolify uses): Syft catalogs the target's packages into an SBOM, Grype matches it against its vulnerability DB. Findings carry `fix_versions` and a `fix_available` / `no_fix` status. The target needs lockfiles, pinned versions or installed package metadata — unpinned declarations (e.g. a bare `fastapi` line in requirements.txt) identify nothing. The Grype DB is baked into the scanner image, so scans run with `--network none`; rebuild the image to refresh the DB |
| `image` | trivy | planned |
| `web` | header/TLS checks | planned |

## Safety properties

- One throwaway container per run (`--rm`), target mounted read-only
- Host Docker socket is never passed into the container
- Network disabled by default. `--network bridge` exists so osv-scanner
  can reach OSV.dev; with `--network none` dependency results may be
  incomplete (offline DB support is a known TODO)
- Limits: 2 GiB memory, 2 CPUs, 256 pids, hard timeout (default 900 s)
- Only the results directory is writable from inside
- gitleaks matches are reported as rule/file/line only — the secret
  values themselves are never copied into `report.json`
- No production credentials are ever passed to a check; if a target
  needs a token, use a read-only, short-lived, disposable one

## Feeding results into the tracker

`report.json` findings map onto tracker items with:

- overview: tool + rule/vulnerability id + summary
- scope: file or package that matched
- response: (to fill in) rotate the secret / bump the dependency
