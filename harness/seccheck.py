#!/usr/bin/env python3
"""SeCute harness: run security scanners against a target inside a
disposable, isolated Docker container and collect a normalized report.

Safety properties:
  - one throwaway container per run, removed afterwards
  - target mounted read-only; host Docker socket is never passed in
  - network is disabled by default (--network bridge only when a check
    genuinely needs live vulnerability data, and documented as a risk;
    bridge is full outbound access, not an allowlist)
  - CPU / memory / pids limits and a hard timeout
  - all Linux capabilities dropped, no-new-privileges set, the default
    seccomp profile applied explicitly, read-only root filesystem with
    a size-capped tmpfs on /tmp
  - the container process never runs as root: it runs with the host
    user's uid/gid (the image also defaults to a non-root user)
  - the only writable mount is the results directory
  - secret values from gitleaks are never copied into the report

Result integrity: every check reports its own status (passed /
findings / error / timeout / invalid) and the report carries an
overall status (complete / partial / failed), so a scanner that
failed is never mistaken for a scanner that found nothing.

Evidence: the report also carries a provenance section — the tool
versions the container itself reported, the scanner image id, the
target's git commit, the run's settings and timestamps, and a
SHA256 of every raw tool output — so a result can be re-checked
later against the exact data it was derived from.
"""
import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from datetime import datetime

IMAGE = "secute-scanner"
HERE = os.path.dirname(os.path.abspath(__file__))
HARNESS_VERSION = "0.3.0"
REPORT_SCHEMA_VERSION = 2

PROFILES = {
    "repo": ["gitleaks", "osv-scanner"],
    # SBOM-based scan (the approach Coolify uses): Syft builds a software
    # bill of materials from the target, Grype matches it against its
    # vulnerability DB. Needs lockfiles / pinned versions / installed
    # package metadata in the target for packages to be identified.
    "sbom": ["syft", "grype"],
    # "image": ["trivy"],  # planned: scan a container image reference
    # "web":   ["headers"],  # planned: TLS / header checks for public surface
}


def docker(*args, timeout=None, capture=True):
    return subprocess.run(
        ["docker", *args],
        timeout=timeout,
        capture_output=capture, text=True,
    )


def ensure_image():
    probe = docker("image", "inspect", IMAGE)
    if probe.returncode != 0:
        print("building scanner image (first run)...", file=sys.stderr)
        build = docker(
            "build", "-f", os.path.join(HERE, "Dockerfile.scanner"),
            "-t", IMAGE, HERE,
            timeout=1800, capture=False,
        )
        if build.returncode != 0:
            raise SystemExit("scanner image build failed")


def run_container(target, out_dir, profile, network, timeout):
    name = "secute-" + datetime.now().strftime("%Y%m%d%H%M%S")
    script = build_scan_script(profile)
    cmd = [
        "run", "--rm", "--name", name,
        "--network", network,
        "--memory", "2g", "--cpus", "2", "--pids-limit", "256",
        "--read-only", "--tmpfs", "/tmp:rw,noexec,nosuid,size=512m",
        # Isolation hardening: no capabilities at all, no privilege
        # escalation via setuid binaries, explicit default seccomp.
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "--security-opt", "seccomp=default",
        # Never root inside the container. The host user's uid/gid also
        # keeps the results directory writable without opening it up.
        "--user", f"{os.getuid()}:{os.getgid()}",
        "--env", "HOME=/tmp",
        # The target is owned by the host user, which git treats as a
        # different owner than the container uid on some setups.
        "--env", "GIT_CONFIG_COUNT=1",
        "--env", "GIT_CONFIG_KEY_0=safe.directory",
        "--env", "GIT_CONFIG_VALUE_0=/target",
        "-v", f"{target}:/target:ro",
        "-v", f"{out_dir}:/out",
        IMAGE, "bash", "-c", script,
    ]
    try:
        proc = docker(*cmd, timeout=timeout)
        return proc.returncode, (proc.stdout or "") + (proc.stderr or ""), False
    except subprocess.TimeoutExpired:
        docker("rm", "-f", name)
        return None, "timeout: container removed", True


# How each tool reports its own version. The scan script records
# these banners before scanning, as report evidence.
VERSION_COMMANDS = {
    "gitleaks": "gitleaks version",
    "osv-scanner": "osv-scanner --version",
    "syft": "syft version",
    "grype": "grype version",
}


def build_scan_script(profile):
    lines = ["set -u", "cd /target || exit 1"]
    for tool in PROFILES[profile]:
        lines.append(
            f"{{ echo '== {tool}'; {VERSION_COMMANDS[tool]} 2>&1 || true; }} "
            ">> /out/versions.txt"
        )
    if "grype" in PROFILES[profile]:
        # Keep the baked-in vulnerability DB's metadata as evidence of
        # which data Grype matched against.
        lines.append(
            "cp /opt/grype/db/*/metadata.json /out/grype-db.json 2>/dev/null "
            "|| true"
        )
    if "gitleaks" in PROFILES[profile]:
        lines.append(
            "gitleaks detect --source /target --no-banner "
            "--report-format json --report-path /out/gitleaks.json "
            "> /out/gitleaks.log 2>&1; echo $? > /out/gitleaks.exit"
        )
    if "osv-scanner" in PROFILES[profile]:
        lines.append(
            "osv-scanner --format json --output /out/osv.json /target "
            "> /out/osv.log 2>&1; echo $? > /out/osv.exit"
        )
    if "syft" in PROFILES[profile]:
        lines.append(
            "syft dir:/target -o cyclonedx-json=/out/sbom.cdx.json "
            "> /out/syft.log 2>&1; echo $? > /out/syft.exit"
        )
    if "grype" in PROFILES[profile]:
        # The vulnerability DB is baked into the scanner image and
        # GRYPE_DB_AUTO_UPDATE=false is set there, so this runs offline.
        lines.append(
            "grype sbom:/out/sbom.cdx.json -o json --file /out/grype.json "
            "> /out/grype.log 2>&1; echo $? > /out/grype.exit"
        )
    return "; ".join(lines)


# Per-tool facts needed to judge whether a check actually ran.
# ok_exits: exit codes that mean the tool finished its scan (some tools
# use 1 for "found something", which is a successful scan, not a
# failure). missing_ok_exits: exit codes under which a missing output
# file still means a clean, successful scan (gitleaks writes no report
# file when it finds nothing).
TOOL_SPECS = {
    "gitleaks": {
        "output": "gitleaks.json", "exit_file": "gitleaks.exit",
        "ok_exits": {0, 1}, "missing_ok_exits": {0},
    },
    "osv-scanner": {
        "output": "osv.json", "exit_file": "osv.exit",
        "ok_exits": {0, 1}, "missing_ok_exits": set(),
    },
    "syft": {
        "output": "sbom.cdx.json", "exit_file": "syft.exit",
        "ok_exits": {0}, "missing_ok_exits": set(),
    },
    "grype": {
        "output": "grype.json", "exit_file": "grype.exit",
        "ok_exits": {0}, "missing_ok_exits": set(),
        "depends_on": "syft",
    },
}

OK_STATUSES = ("passed", "findings")


def extract_findings(tool, raw):
    """Normalize one tool's parsed output into report findings."""
    findings = []
    if tool == "gitleaks":
        for f in raw:
            # Never copy the matched secret itself into the report.
            findings.append({
                "rule": f.get("RuleID"),
                "description": f.get("Description"),
                "file": f.get("File"),
                "line": f.get("StartLine"),
            })
    elif tool == "osv-scanner":
        for result in raw.get("results", []):
            for pkg in result.get("packages", []):
                p = pkg.get("package", {})
                for v in pkg.get("vulnerabilities", []):
                    sev = ""
                    for s in v.get("severity", []):
                        if s.get("type") == "CVSS_V3":
                            sev = s.get("score", "")
                            break
                    findings.append({
                        "id": v.get("id"),
                        "summary": v.get("summary"),
                        "severity": sev,
                        "package": p.get("name"),
                        "version": p.get("version"),
                        "ecosystem": p.get("ecosystem"),
                    })
    elif tool == "grype":
        for m in raw.get("matches", []):
            v = m.get("vulnerability", {})
            a = m.get("artifact", {})
            cve = None
            summary = v.get("description", "")
            for r in m.get("relatedVulnerabilities", []):
                if str(r.get("id", "")).startswith("CVE-"):
                    cve = r["id"]
                    if r.get("description"):
                        summary = r["description"]
                    break
            scores = []
            for c in v.get("cvss", []):
                s = c.get("metrics", {}).get("baseScore")
                if isinstance(s, (int, float)):
                    scores.append(s)
            fix_versions = v.get("fix", {}).get("versions", [])
            finding = {
                "id": cve or v.get("id"),
                "summary": summary,
                "severity": v.get("severity", ""),
                "cvss": max(scores) if scores else None,
                "package": a.get("name"),
                "version": a.get("version"),
                "ecosystem": a.get("type"),
                "fix_versions": fix_versions,
                # Same idea as Coolify's scan statuses: is there a
                # fixed version to move to, or not?
                "status": "fix_available" if fix_versions else "no_fix",
            }
            if cve and v.get("id") and v.get("id") != cve:
                finding["source_id"] = v.get("id")
            findings.append(finding)
    # syft produces the SBOM itself; it has no findings of its own.
    return findings


def read_tool_exit(out_dir, spec):
    path = os.path.join(out_dir, spec["exit_file"])
    try:
        with open(path, encoding="utf-8") as f:
            return int(f.read().strip())
    except (OSError, ValueError):
        return None


def evaluate_tool(tool, out_dir, timed_out):
    """Decide one check's status from its exit code and output file.

    A check that failed must never look like a check that found
    nothing, so the status comes from the evidence, in this order:
    unparseable output is "invalid", a missing output or an unexpected
    exit code is "error", a check cut off by the container timeout is
    "timeout", and only a tool that demonstrably finished gets
    "passed" (no findings) or "findings".
    """
    spec = TOOL_SPECS[tool]
    exit_code = read_tool_exit(out_dir, spec)
    out_path = os.path.join(out_dir, spec["output"])
    entry = {"status": None, "exit_code": exit_code, "findings": []}
    if os.path.exists(out_path):
        try:
            with open(out_path, encoding="utf-8") as f:
                raw = json.load(f)
        except (json.JSONDecodeError, UnicodeDecodeError):
            entry["status"] = "invalid"
            entry["detail"] = f"{spec['output']} is not valid JSON"
            return entry
        if exit_code is not None and exit_code not in spec["ok_exits"]:
            entry["status"] = "error"
            entry["detail"] = f"tool exited with {exit_code}"
            return entry
        entry["findings"] = extract_findings(tool, raw)
        if tool == "syft":
            entry["artifacts"] = len(raw.get("components", []))
        entry["status"] = "findings" if entry["findings"] else "passed"
        return entry
    # No output file at all.
    if exit_code in spec["missing_ok_exits"]:
        entry["status"] = "passed"
    elif timed_out and exit_code is None:
        entry["status"] = "timeout"
        entry["detail"] = "container timed out before this check finished"
    else:
        entry["status"] = "error"
        if exit_code is None:
            entry["detail"] = "tool did not run to completion (no exit code recorded)"
        else:
            entry["detail"] = f"tool exited with {exit_code} and produced no output"
    return entry


# --- provenance (evidence trail) --------------------------------------

_VERSION_RE = re.compile(r"\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?")


def read_tool_versions(out_dir, profile):
    """Parse the version banners the tools printed about themselves."""
    try:
        with open(os.path.join(out_dir, "versions.txt"),
                  encoding="utf-8", errors="replace") as f:
            text = f.read()
    except OSError:
        return {}
    raw_by_tool = {}
    current = None
    for line in text.splitlines():
        if line.startswith("== "):
            current = line[3:].strip()
            raw_by_tool[current] = []
        elif current is not None:
            raw_by_tool[current].append(line)
    versions = {}
    for tool in PROFILES[profile]:
        raw = "\n".join(raw_by_tool.get(tool, [])).strip()
        if not raw:
            continue
        m = _VERSION_RE.search(raw)
        versions[tool] = {"version": m.group(0) if m else None, "raw": raw}
    return versions


def read_grype_db_info(out_dir):
    try:
        with open(os.path.join(out_dir, "grype-db.json"),
                  encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict):
        return None
    return {
        "built": data.get("built"),
        "schema_version": data.get("schemaVersion",
                                   data.get("schema_version")),
    }


def target_git_info(target):
    """Best-effort, read-only evidence about the target's git state."""
    def git(*args):
        proc = subprocess.run(["git", "-C", target, *args],
                              capture_output=True, text=True, timeout=30)
        if proc.returncode != 0:
            raise ValueError("not a git work tree")
        return proc.stdout.strip()
    try:
        return {
            "commit": git("rev-parse", "HEAD"),
            "branch": git("rev-parse", "--abbrev-ref", "HEAD"),
            "dirty": bool(git("status", "--porcelain")),
        }
    except Exception:
        return None


def scanner_image_info():
    proc = docker("image", "inspect", IMAGE)
    if proc.returncode != 0:
        return None
    try:
        data = json.loads(proc.stdout)[0]
    except (json.JSONDecodeError, IndexError, TypeError):
        return None
    return {"id": data.get("Id"),
            "repo_digests": data.get("RepoDigests", [])}


def raw_output_hashes(out_dir, profile):
    """SHA256 and size of each tool's raw output, for later verification."""
    hashes = {}
    for tool in PROFILES[profile]:
        name = TOOL_SPECS[tool]["output"]
        path = os.path.join(out_dir, name)
        if not os.path.exists(path):
            continue
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        hashes[name] = {"sha256": h.hexdigest(),
                        "bytes": os.path.getsize(path)}
    return hashes


def build_provenance(out_dir, target, profile, network, timeout,
                     started_at, finished_at):
    prov = {
        "harness_version": HARNESS_VERSION,
        "started_at": started_at,
        "finished_at": finished_at,
        "settings": {"profile": profile, "network": network,
                     "timeout": timeout},
        "scanner_image": scanner_image_info(),
        "tools": read_tool_versions(out_dir, profile),
        "target_git": target_git_info(target),
        "raw_outputs": raw_output_hashes(out_dir, profile),
    }
    db_info = read_grype_db_info(out_dir)
    if db_info:
        prov["grype_db"] = db_info
    return prov


def normalize(out_dir, target, profile, exit_code, log, timed_out=False,
              provenance=None):
    tools = {}
    for tool in PROFILES[profile]:
        tools[tool] = evaluate_tool(tool, out_dir, timed_out)
    # grype consumes syft's SBOM: if syft did not produce one, a grype
    # failure is a knock-on effect, so say so instead of blaming grype.
    for tool, entry in tools.items():
        depends_on = TOOL_SPECS[tool].get("depends_on")
        if depends_on and entry["status"] in ("error", "timeout"):
            dep_status = tools.get(depends_on, {}).get("status")
            if dep_status not in OK_STATUSES:
                entry["detail"] = (
                    f"input from {depends_on} unavailable "
                    f"({depends_on}: {dep_status}); "
                    + entry.get("detail", "check did not complete")
                )
    ok = sum(1 for e in tools.values() if e["status"] in OK_STATUSES)
    if tools and ok == len(tools):
        overall = "complete"
    elif ok:
        overall = "partial"
    else:
        overall = "failed"
    report = {
        "schema_version": REPORT_SCHEMA_VERSION,
        "target": target,
        "profile": profile,
        "finished_at": datetime.now().isoformat(timespec="seconds"),
        "container_exit_code": exit_code,
        "timed_out": timed_out,
        "status": overall,
        "tools": tools,
        "summary": {
            "total_findings": sum(len(e["findings"]) for e in tools.values()),
            "tools_ok": ok,
            "tools_failed": len(tools) - ok,
        },
    }
    if provenance is not None:
        report["provenance"] = provenance
    if log:
        report["log_tail"] = log[-2000:]
    with open(os.path.join(out_dir, "report.json"), "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    return report


def main():
    parser = argparse.ArgumentParser(description="SeCute sandbox check harness")
    sub = parser.add_subparsers(dest="command", required=True)
    run_p = sub.add_parser("run")
    run_p.add_argument("--target", required=True,
                       help="path to a repository / source tree")
    run_p.add_argument("--profile", choices=sorted(PROFILES), default="repo")
    run_p.add_argument("--out", default="results")
    run_p.add_argument("--network", choices=["none", "bridge"], default="none",
                       help="bridge lets osv-scanner reach OSV.dev; "
                            "with none, dependency results may be incomplete")
    run_p.add_argument("--timeout", type=int, default=900)
    args = parser.parse_args()

    target = os.path.abspath(args.target)
    if not os.path.isdir(target):
        raise SystemExit(f"target is not a directory: {target}")
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    out_dir = os.path.abspath(os.path.join(args.out, stamp))
    os.makedirs(out_dir, exist_ok=True)

    ensure_image()
    started_at = datetime.now().isoformat(timespec="seconds")
    exit_code, log, timed_out = run_container(target, out_dir, args.profile,
                                              args.network, args.timeout)
    provenance = build_provenance(
        out_dir, target, args.profile, args.network, args.timeout,
        started_at, datetime.now().isoformat(timespec="seconds"))
    report = normalize(out_dir, target, args.profile, exit_code, log,
                       timed_out=timed_out, provenance=provenance)
    print(f"report: {os.path.join(out_dir, 'report.json')}")
    print(f"status: {report['status']}")
    print(f"findings: {report['summary']['total_findings']}")
    for tool, data in report["tools"].items():
        line = f"  {tool}: {data['status']}, {len(data['findings'])} findings"
        if data.get("detail"):
            line += f" ({data['detail']})"
        print(line)


if __name__ == "__main__":
    main()
