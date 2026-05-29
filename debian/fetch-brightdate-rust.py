#!/usr/bin/env python3
"""Fetch brightdate-rust source when git submodules are not expanded (Launchpad)."""
import io
import sys
import tarfile
import urllib.request
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


def main() -> int:
    if MARKER.is_file():
        return 0

    if try_git_submodule():
        return 0

    version = VERSION_FILE.read_text(encoding="utf-8").strip()
    url = (
        "https://github.com/Digital-Defiance/brightdate-rust/"
        f"archive/refs/tags/v{version}.tar.gz"
    )
    print(f"fetch-brightdate-rust: GET {url}", flush=True)

    with urllib.request.urlopen(url) as resp:
        data = resp.read()

    if TARGET.exists():
        import shutil

        shutil.rmtree(TARGET)
    TARGET.mkdir(parents=True)

    prefix = f"brightdate-rust-{version}/"
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
        for member in tar.getmembers():
            if not member.name.startswith(prefix) or member.name == prefix:
                continue
            member.name = member.name[len(prefix) :]
            if member.name:
                tar.extract(member, path=TARGET)

    if not MARKER.is_file():
        print(
            f"ERROR: brightdate-rust v{version} missing {MARKER.relative_to(ROOT)}",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
