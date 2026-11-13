"""Docker integration tests for the harness sandbox.

Marked `docker`: they need a Docker daemon and the scanner image,
so they skip cleanly where Docker is unavailable. Run them on a
machine with Docker before relying on the harness:

    python -m pytest -m docker

They assert the isolation properties the harness promises: with
--network none the container cannot reach the network, and the
target mount is read-only even for a process inside the sandbox.
"""
import os
import shutil
import subprocess

import pytest

pytestmark = pytest.mark.docker

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _docker(*args, **kw):
    return subprocess.run(["docker", *args], capture_output=True,
                          text=True, timeout=120, **kw)


@pytest.fixture(scope="module")
def scanner_image():
    if not shutil.which("docker"):
        pytest.skip("docker CLI not available")
    if _docker("info").returncode != 0:
        pytest.skip("docker daemon not available")
    if _docker("image", "inspect", "secute-scanner").returncode != 0:
        build = _docker(
            "build", "-f", os.path.join(ROOT, "harness",
                                        "Dockerfile.scanner"),
            "-t", "secute-scanner", os.path.join(ROOT, "harness"),
            timeout=1800)
        if build.returncode != 0:
            pytest.skip("scanner image build failed")
    return "secute-scanner"


def test_network_is_cut(scanner_image, tmp_path):
    proc = _docker(
        "run", "--rm", "--network", "none", "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "--user", f"{os.getuid()}:{os.getgid()}",
        scanner_image, "bash", "-c",
        "curl -sS --max-time 5 https://example.com >/dev/null")
    assert proc.returncode != 0


def test_target_mount_is_read_only(scanner_image, tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    (target / "a.txt").write_text("x", encoding="utf-8")
    proc = _docker(
        "run", "--rm", "--network", "none", "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges", "--read-only",
        "--user", f"{os.getuid()}:{os.getgid()}",
        "-v", f"{target}:/target:ro",
        scanner_image, "bash", "-c",
        "echo pwned > /target/a.txt")
    assert proc.returncode != 0
    assert (target / "a.txt").read_text(encoding="utf-8") == "x"
