#!/usr/bin/env python3
"""Make sure that every setup path uses the CMake executable name."""

from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[1]


def extract(path: Path, pattern: str, label: str) -> str:
    text = path.read_text(encoding="utf-8")
    match = re.search(pattern, text)
    if not match:
        raise AssertionError(f"cannot find {label} in {path.relative_to(ROOT)}")
    return match.group(1)


def main() -> int:
    names = {
        "CMake output": extract(
            ROOT / "CMakeLists.txt",
            r'\bEXE_NAME\s+"([^"]+)"',
            "EXE_NAME",
        ),
        "setup forwarder": extract(
            ROOT / "codegen_setup.c",
            r'\.exe_basename\s*=\s*"([^"]+)"',
            "exe_basename",
        ),
        "release packager": extract(
            ROOT / "scripts" / "package_setup_release.sh",
            r"--exe-name\s+([^\s\\]+)",
            "--exe-name",
        ),
    }

    unique = set(names.values())
    if len(unique) != 1:
        for owner, name in names.items():
            print(f"{owner}: {name}", file=sys.stderr)
        print("FAIL: setup executable names do not match", file=sys.stderr)
        return 1

    print(f"PASS: setup executable name is {unique.pop()}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, AssertionError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        sys.exit(1)
