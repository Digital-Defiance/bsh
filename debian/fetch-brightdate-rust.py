#!/usr/bin/env python3
"""Ensure brightdate-rust sources exist when git submodules are not expanded."""
import io
import sys
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VERSION_FILE = ROOT / "debian" / "brightdate-rust-version"
TARGET = ROOT / "brightdate-rust"
MARKER = TARGET / "crates" / "btime" / "src" / "color.rs"


def try_git_submodule() -> bool:
    if not (ROOT / ".git").is_dir():
        return False
    import subprocess

    print("fetch-brightdate-rust: trying git submodule update", flush=True)
    result = subprocess.run(
        ["git", "submodule", "update", "--init", "--recursive", "brightdate-rust"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0 and result.stderr.strip():
        print(result.stderr.strip(), file=sys.stderr)
    return MARKER.is_file()


def extract_local_tarball(version: str) -> bool:
    tarball = ROOT / "debian" / f"brightdate-rust-{version}.tar.xz"
    if not tarball.is_file():
        return False

    print(f"fetch-brightdate-rust: extracting {tarball.name}", flush=True)
    if TARGET.exists():
        import shutil

        shutil.rmtree(TARGET)

    with tarfile.open(tarball, mode="r:xz") as tar:
        tar.extractall(path=ROOT)
    return MARKER.is_file()


def main() -> int:
    if MARKER.is_file():
        return 0

    if try_git_submodule():
        return 0

    version = VERSION_FILE.read_text(encoding="utf-8").strip()
    if extract_local_tarball(version):
        return 0

    print(
        "ERROR: brightdate-rust sources missing and Launchpad builders have no "
        "network access.\n"
        f"Expected {MARKER.relative_to(ROOT)} or "
        f"debian/brightdate-rust-{version}.tar.xz\n"
        "Regenerate the tarball with: debian/refresh-brightdate-rust-tarball.sh",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
