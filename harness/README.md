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
- `versions.txt`, `grype-db.json` — version banners and Grype DB metadata, recorded as evidence (see Provenance)
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
  can reach OSV.dev; it grants full outbound (and LAN) access, so it is
  not an allowlist. With `--network none`, a check that needs live data
  reports `error` rather than silently returning nothing (offline DB
  support is a known TODO)
- Limits: 2 GiB memory, 2 CPUs, 256 pids, hard timeout (default 900 s)
- All Linux capabilities dropped (`--cap-drop ALL`),
  `--security-opt no-new-privileges`, the default seccomp profile
  applied explicitly, read-only root filesystem with a 512 MB tmpfs
  on /tmp
- The container never runs as root: the harness passes the host user's
  uid/gid, and the scanner image itself defaults to a non-root user.
  The Grype DB is baked into a fixed, world-readable path
  (`/opt/grype/db`) so non-root runs still find it
- Only the results directory is writable from inside
- gitleaks matches are reported as rule/file/line only — the secret
  values themselves are never copied into `report.json`
- No production credentials are ever passed to a check; if a target
  needs a token, use a read-only, short-lived, disposable one

## Supply chain

The scanner image pins everything it is built from:

- The base image (and the Trivy stage) is pinned by digest in
  `Dockerfile.scanner`.
- Every downloaded tool archive is verified against a SHA256 pinned
  next to its version before it is unpacked; downloads are never
  piped straight into `tar` or `sh`.
- Trivy publishes no binary archives or checksums file on its GitHub
  releases, so the binary is copied from the official
  `aquasec/trivy` image (also digest-pinned) instead.

To update a tool: bump its version, replace its SHA256 with the value
from the new release's published checksums file, and refresh the base
image digest with the tag's current manifest-list digest. Rebuild the
image afterwards — this also refreshes the baked-in Grype DB.

## Check statuses

A check that failed is never reported as a check that found nothing.
Each tool entry in `report.json` carries a `status`:

| status | meaning |
|---|---|
| `passed` | the check ran and found nothing |
| `findings` | the check ran and found something |
| `error` | the tool exited abnormally or produced no output |
| `timeout` | the container timeout cut the check off |
| `invalid` | the tool's output was not valid JSON |

The report as a whole is `complete` when every check ran, `partial`
when some did, and `failed` when none did. If Grype cannot run
because Syft produced no SBOM, its `detail` says so.

## Provenance

`report.json` carries `schema_version` (currently 2) and a
`provenance` section so a result can be re-checked later against the
exact data it was derived from:

- `harness_version`, `started_at` / `finished_at`, and the run
  `settings` (profile, network, timeout)
- `scanner_image`: the image id and repo digests that ran the scan
- `tools`: each tool's version, parsed from the banner the tool
  printed about itself inside the container (raw banner kept)
- `grype_db`: build timestamp and schema version of the baked-in
  vulnerability DB (sbom profile)
- `target_git`: the target's commit SHA, branch, and dirty flag when
  the target is a git work tree
- `raw_outputs`: SHA256 and size of each tool's raw output file

When the planned `image` profile lands, the scanned image's digest
will be recorded here as well; for directory targets the git commit
above is the equivalent anchor.

## Feeding results into the tracker

`report.json` findings map onto tracker items with:

- overview: tool + rule/vulnerability id + summary
- scope: file or package that matched
- response: (to fill in) rotate the secret / bump the dependency
