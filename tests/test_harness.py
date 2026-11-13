"""Harness tests: per-check statuses, report integrity, provenance.

These feed the harness fabricated tool outputs (exit-code files and
JSON) instead of running real containers, and assert that a failed or
incomplete check is never normalized into a clean result.
"""
import hashlib
import json
import os
import subprocess

import seccheck


def scenario(tmp_path, files, profile, timed_out=False):
    out = str(tmp_path)
    for name, content in files.items():
        with open(os.path.join(out, name), "w", encoding="utf-8") as f:
            f.write(content)
    return seccheck.normalize(out, "/target", profile, 0, "",
                              timed_out=timed_out)


def test_clean_run_is_complete(tmp_path):
    r = scenario(tmp_path, {
        "gitleaks.exit": "0",
        "osv.exit": "0",
        "osv.json": json.dumps({"results": []}),
    }, "repo")
    assert r["status"] == "complete"
    assert r["tools"]["gitleaks"]["status"] == "passed"
    assert r["tools"]["osv-scanner"]["status"] == "passed"
    assert r["summary"]["total_findings"] == 0


def test_findings_and_failure_make_partial_and_never_leak_secrets(tmp_path):
    r = scenario(tmp_path, {
        "gitleaks.exit": "1",
        "gitleaks.json": json.dumps([{
            "RuleID": "generic-api-key", "Description": "d",
            "File": "a.py", "StartLine": 3,
            "Secret": "MUST-NOT-LEAK",
        }]),
        "osv.exit": "1",  # osv produced no output at all: an error
    }, "repo")
    assert r["status"] == "partial"
    assert r["tools"]["gitleaks"]["status"] == "findings"
    assert "MUST-NOT-LEAK" not in json.dumps(r)
    assert r["tools"]["osv-scanner"]["status"] == "error"


def test_broken_json_is_invalid_not_zero_findings(tmp_path):
    r = scenario(tmp_path, {
        "gitleaks.exit": "0",
        "osv.exit": "0",
        "osv.json": "{not json",
    }, "repo")
    assert r["tools"]["osv-scanner"]["status"] == "invalid"
    assert r["status"] == "partial"


def test_container_timeout_marks_tools_timeout(tmp_path):
    r = scenario(tmp_path, {}, "repo", timed_out=True)
    assert r["status"] == "failed"
    assert all(t["status"] == "timeout" for t in r["tools"].values())


def test_unexpected_exit_code_is_error_even_with_parseable_output(tmp_path):
    r = scenario(tmp_path, {
        "gitleaks.exit": "0",
        "osv.exit": "127",
        "osv.json": json.dumps({"results": []}),
    }, "repo")
    assert r["tools"]["osv-scanner"]["status"] == "error"


def _sbom_files():
    sbom = {"bomFormat": "CycloneDX",
            "components": [{"name": "a"}, {"name": "b"}]}
    grype = {"matches": [{
        "vulnerability": {
            "id": "GHSA-x", "description": "d", "severity": "High",
            "cvss": [{"metrics": {"baseScore": 7.5}}],
            "fix": {"versions": ["2.0"]},
        },
        "artifact": {"name": "pkg", "version": "1.0", "type": "python"},
        "relatedVulnerabilities": [
            {"id": "CVE-2026-0001", "description": "cve d"}],
    }]}
    return sbom, grype


def test_sbom_run_complete_and_cve_preferred(tmp_path):
    sbom, grype = _sbom_files()
    r = scenario(tmp_path, {
        "syft.exit": "0", "sbom.cdx.json": json.dumps(sbom),
        "grype.exit": "0", "grype.json": json.dumps(grype),
    }, "sbom")
    assert r["status"] == "complete"
    assert r["tools"]["syft"]["artifacts"] == 2
    finding = r["tools"]["grype"]["findings"][0]
    assert r["tools"]["grype"]["status"] == "findings"
    assert finding["id"] == "CVE-2026-0001"
    assert finding["status"] == "fix_available"


def test_sbom_syft_failure_is_a_knock_on_error_for_grype(tmp_path):
    r = scenario(tmp_path, {"syft.exit": "2", "grype.exit": "1"}, "sbom")
    assert r["tools"]["syft"]["status"] == "error"
    assert r["tools"]["grype"]["status"] == "error"
    assert "syft" in r["tools"]["grype"]["detail"]
    assert r["status"] == "failed"


# --- provenance --------------------------------------------------------

def test_scan_script_records_tool_versions(tmp_path):
    script = seccheck.build_scan_script("sbom")
    assert "syft version" in script and "grype version" in script
    assert "versions.txt" in script
    assert "grype-db.json" in script
    repo_script = seccheck.build_scan_script("repo")
    assert "gitleaks version" in repo_script
    assert "grype-db.json" not in repo_script


def test_tool_versions_parsed_from_banners(tmp_path):
    with open(tmp_path / "versions.txt", "w", encoding="utf-8") as f:
        f.write("== syft\nApplication:   syft\nVersion:       1.57.1\n")
        f.write("== grype\nApplication:   grype\nVersion:       0.121.3\n"
                "Supported DB Schema: 6\n")
    v = seccheck.read_tool_versions(str(tmp_path), "sbom")
    assert v["syft"]["version"] == "1.57.1"
    assert v["grype"]["version"] == "0.121.3"
    assert "Supported DB Schema" in v["grype"]["raw"]
    assert seccheck.read_tool_versions("/nonexistent", "sbom") == {}


def test_grype_db_info_parsed(tmp_path):
    with open(tmp_path / "grype-db.json", "w", encoding="utf-8") as f:
        json.dump({"built": "2026-11-10T00:00:00Z", "schemaVersion": 6}, f)
    assert seccheck.read_grype_db_info(str(tmp_path)) == {
        "built": "2026-11-10T00:00:00Z", "schema_version": 6}


def test_raw_output_hashes_match_content(tmp_path):
    payload = json.dumps({"results": []})
    with open(tmp_path / "osv.json", "w", encoding="utf-8") as f:
        f.write(payload)
    hashes = seccheck.raw_output_hashes(str(tmp_path), "repo")
    assert hashes["osv.json"]["sha256"] == \
        hashlib.sha256(payload.encode()).hexdigest()
    assert hashes["osv.json"]["bytes"] == len(payload)
    assert "gitleaks.json" not in hashes  # missing output is skipped


def _git(cwd, *args):
    subprocess.run(["git", "-C", cwd, *args], check=True,
                   capture_output=True, text=True)


def test_target_git_info(tmp_path):
    repo = str(tmp_path)
    subprocess.run(["git", "init", "-q", repo], check=True)
    _git(repo, "config", "user.email", "t@example.invalid")
    _git(repo, "config", "user.name", "t")
    with open(os.path.join(repo, "a.txt"), "w") as f:
        f.write("x")
    _git(repo, "add", ".")
    _git(repo, "commit", "-qm", "init")
    head = subprocess.run(["git", "-C", repo, "rev-parse", "HEAD"],
                          capture_output=True, text=True).stdout.strip()
    info = seccheck.target_git_info(repo)
    assert info["commit"] == head
    assert info["dirty"] is False
    with open(os.path.join(repo, "b.txt"), "w") as f:
        f.write("y")
    assert seccheck.target_git_info(repo)["dirty"] is True


def test_target_git_info_for_non_repo(tmp_path):
    assert seccheck.target_git_info(str(tmp_path)) is None


def test_normalize_carries_schema_version_and_provenance(tmp_path):
    prov = {"harness_version": seccheck.HARNESS_VERSION,
            "tools": {"syft": {"version": "1.57.1", "raw": "..."}}}
    files = {"gitleaks.exit": "0", "osv.exit": "0",
             "osv.json": json.dumps({"results": []})}
    out = str(tmp_path)
    for name, content in files.items():
        with open(os.path.join(out, name), "w", encoding="utf-8") as f:
            f.write(content)
    r = seccheck.normalize(out, "/target", "repo", 0, "",
                           provenance=prov)
    assert r["schema_version"] == seccheck.REPORT_SCHEMA_VERSION
    assert r["provenance"]["tools"]["syft"]["version"] == "1.57.1"
    r2 = seccheck.normalize(out, "/target", "repo", 0, "")
    assert "provenance" not in r2
