#!/usr/bin/env python3
"""SeCute harness: run security scanners against a target inside a
disposable, isolated Docker container and collect a normalized report.

Safety properties:
  - one throwaway container per run, removed afterwards
  - target mounted read-only; host Docker socket is never passed in
  - network is disabled by default (--network bridge only when a check
    genuinely needs live vulnerability data, and documented as a risk)
  - CPU / memory / pids limits and a hard timeout
  - the only writable mount is the results directory
  - secret values from gitleaks are never copied into the report
"""
import argparse
import json
import os
import subprocess
import sys
from datetime import datetime

IMAGE = "secute-scanner"
HERE = os.path.dirname(os.path.abspath(__file__))

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
        "--read-only", "--tmpfs", "/tmp",
        "-v", f"{target}:/target:ro",
        "-v", f"{out_dir}:/out",
        IMAGE, "bash", "-c", script,
    ]
    try:
        proc = docker(*cmd, timeout=timeout)
        return proc.returncode, (proc.stdout or "") + (proc.stderr or "")
    except subprocess.TimeoutExpired:
        docker("rm", "-f", name)
        return None, "timeout: container removed"


def build_scan_script(profile):
    lines = ["set -u", "cd /target || exit 1"]
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


def normalize(out_dir, target, profile, exit_code, log):
    report = {
        "target": target,
        "profile": profile,
        "finished_at": datetime.now().isoformat(timespec="seconds"),
        "container_exit_code": exit_code,
        "tools": {},
        "summary": {"total_findings": 0},
    }
    gitleaks_path = os.path.join(out_dir, "gitleaks.json")
    if os.path.exists(gitleaks_path):
        findings = []
        try:
            raw = json.load(open(gitleaks_path, encoding="utf-8"))
            for f in raw:
                # Never copy the matched secret itself into the report.
                findings.append({
                    "rule": f.get("RuleID"),
                    "description": f.get("Description"),
                    "file": f.get("File"),
                    "line": f.get("StartLine"),
                })
        except json.JSONDecodeError:
            findings = []
        report["tools"]["gitleaks"] = {"findings": findings}
        report["summary"]["total_findings"] += len(findings)
    osv_path = os.path.join(out_dir, "osv.json")
    if os.path.exists(osv_path):
        findings = []
        try:
            raw = json.load(open(osv_path, encoding="utf-8"))
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
        except json.JSONDecodeError:
            findings = []
        report["tools"]["osv-scanner"] = {"findings": findings}
        report["summary"]["total_findings"] += len(findings)
    grype_path = os.path.join(out_dir, "grype.json")
    if os.path.exists(grype_path):
        findings = []
        try:
            raw = json.load(open(grype_path, encoding="utf-8"))
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
        except json.JSONDecodeError:
            findings = []
        report["tools"]["grype"] = {"findings": findings}
        report["summary"]["total_findings"] += len(findings)
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
    exit_code, log = run_container(target, out_dir, args.profile,
                                   args.network, args.timeout)
    report = normalize(out_dir, target, args.profile, exit_code, log)
    print(f"report: {os.path.join(out_dir, 'report.json')}")
    print(f"findings: {report['summary']['total_findings']}")
    for tool, data in report["tools"].items():
        print(f"  {tool}: {len(data['findings'])}")


if __name__ == "__main__":
    main()
