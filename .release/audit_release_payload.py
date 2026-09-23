#!/usr/bin/env python3
"""Audit exact setup payloads. Promoted from the 2026-09-04 fleet auditor.

The caller supplies the frozen source identities. An OpenBIOS expectation is
an input identity, not publication approval. No retail input is ever allowed.
"""

from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
try:
    import tomllib
except ImportError:  # Ubuntu 20.04 release containers use Python 3.8.
    import tomli as tomllib
import zipfile


PLATFORMS = ("windows-x64", "linux-x64", "macos-arm64", "macos-x64")
OPENBIOS_SHA256 = "FABE498FBF224E4721F12F31B6F5FE0659205E341DC4E5C5F91B9BD1A1011C57"
FORBIDDEN_SUFFIXES = {".cue", ".iso", ".chd", ".mcd", ".rom", ".sav", ".state", ".dmp", ".ram", ".vram"}
PRIVATE_PATTERNS = (
    re.compile(rb"[a-z]:[\\/]+users[\\/]+[^\\/\x00\r\n]+", re.I),
    re.compile(rb"(?:^|[^a-z])[ilz]:[\\/]+(?:agentdata|projects|share)[\\/]", re.I),
    re.compile(rb"/h[o]me/(?!runner(?:/|\x00))[^/\x00\r\n]+", re.I),
    re.compile(rb"/U[s]ers/(?!runner(?:/|\x00))[^/\x00\r\n]+"),
)
PRIVATE_FIXTURE_ALLOWLIST = {
    "psxrecomp/docs/MOD_PACKAGES.md",
    "psxrecomp/recompiler/lib/ELFIO/.vscode/launch.json",
    "psxrecomp/recompiler/lib/ELFIO/examples/sudo_gdb.sh",
    "psxrecomp/recompiler/lib/ELFIO/tests/elf_examples/ARMSCII-8.so",
    "psxrecomp/recompiler/lib/ELFIO/tests/elf_examples/arm_v7m_test_debug.elf",
    "psxrecomp/recompiler/lib/ELFIO/tests/elf_examples/arm_v7m_test_release.elf",
    "psxrecomp/recompiler/lib/ELFIO/tests/elf_examples/crash-e3c41070342cf84dea077356ddbb8ebf4326a601",
    "psxrecomp/recompiler/lib/ELFIO/tests/elf_examples/read_write_arm_elf32_input",
    "psxrecomp/recompiler/lib/toml11/tests/test_lex_string.cpp",
    "psxrecomp/recompiler/lib/toml11/tests/test_parse_string.cpp",
    "psxrecomp/tools/compile_overlays.py",
    "recomp-ui/src/third_party/imgui/imgui.cpp",
    "recomp-ui/src/third_party/tinyfiledialogs.h",
}

# Reviewed Wave 3 SDK examples. Bind the complete file bytes so a later edit
# cannot hide a real developer path behind a broadly exempt documentation name.
PRIVATE_FIXTURE_HASHES = {
    # Hashes are bound over LF-normalized bytes (see the comparison below): a
    # Windows checkout with core.autocrlf=true stages CRLF copies of these
    # files while the CI runners check out LF, and the exemption must not
    # depend on which machine packaged the kit. Both values are the repository
    # bytes at the accepted Wave 4 c3 pin.
    # A filename may bind several accepted byte states so that waves pinned to
    # different framework commits can be audited by this one canonical tool. Each
    # entry is still an exact whole-file hash, so the narrowness is unchanged: an
    # unreviewed edit matches none of them and fails.
    # The Wave 3 bytes below were re-bound on 2026-09-15. The Wave 4 hash had
    # been bound forward after Wave 3 shipped, so every Wave 3 kit failed this
    # gate even though its bytes never changed — identical at framework 5952a72
    # and a839474e. Reviewed before binding: the file matches PRIVATE_PATTERNS
    # on two Windows home-directory placeholders in its setup instructions, both
    # generic stand-ins for the reader's own account, and carries no real
    # developer path. The literal placeholders are deliberately not quoted here,
    # for the same reason as the entry below: this file ships inside release kits
    # and would trip its own private-path gate.
    "psxrecomp/docs/GAME_PROJECT_SETUP.md": (
        "0D3E42801DFAA404FBFF6A047CB442BF925394B234170F0036502FBF48AEA70D",  # Wave 4 c3
        "FB2F038A484942CE0AC46B3471AE66F19CF2DBE1C8F24CEAC5285C888D5C2F78",  # Wave 3
    ),
    # Re-bound for the accepted Wave 4 c2 pin (4f534f2cf). Framework commit
    # 837b7a2f4 "Scope private path fixture exceptions" edited this file after
    # the Wave 3 bytes were bound, so the Wave 3 hash no longer matched and the
    # gate correctly reported a private developer path. The file remains a pure
    # fixture: every match below is a synthetic input or a negative control the
    # gate itself asserts must NOT be flagged.
    # The literal example paths are deliberately not repeated here: this file
    # ships inside release kits and would trip its own private-path gate.
    # Binding the exact bytes keeps the exemption narrow: any later edit to this
    # file fails the audit again.
    "psxrecomp/runtime/tests/test_setup_private_path_gate.py": "6F890A83A48726DF54B2459BD3BB706B575F819FAF9C768E30273B1F78912DA8",
}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def classify_platform(name: str) -> str | None:
    lowered = name.lower()
    return next((platform for platform in PLATFORMS if lowered.endswith(f"-{platform}.zip")), None)


def audit_archive(path: Path, repo: str, expected: dict[str, str]) -> dict[str, object]:
    package_bytes = path.read_bytes()
    problems: list[str] = []
    forbidden: list[str] = []
    generated: list[str] = []
    private_paths: list[str] = []
    allowed_private: list[str] = []
    openbios: list[dict[str, object]] = []
    platform = classify_platform(path.name)
    version = expected["version"][1:] if expected["version"].startswith("v") else expected["version"]
    if platform is None:
        problems.append("filename does not identify one required platform")
    if not path.name.endswith(f"-{version}-{platform}.zip"):
        problems.append(f"filename does not identify version {version}")

    with zipfile.ZipFile(path) as archive:
        infos = archive.infolist()
        names = [item.filename.replace("\\", "/") for item in infos]
        folded_names: set[str] = set()
        mod_manifests = 0
        for info, name in zip(infos, names):
            parts = PurePosixPath(name).parts
            folded = name.casefold()
            if name.startswith("/") or re.match(r"^[A-Za-z]:", name) or ".." in parts:
                problems.append(f"unsafe archive path: {name}")
            if folded in folded_names:
                problems.append(f"case-insensitive duplicate path: {name}")
            folded_names.add(folded)
            if (info.external_attr >> 16) & 0o170000 == 0o120000:
                problems.append(f"symbolic link: {name}")
            if info.is_dir():
                continue
            lower = name.lower()
            suffix = PurePosixPath(lower).suffix
            if suffix in FORBIDDEN_SUFFIXES or (suffix == ".bin" and lower != "psxrecomp/bios/openbios.bin"):
                forbidden.append(name)
            if lower.startswith("generated/") or lower.startswith("disc/"):
                generated.append(name)
            if lower.endswith("/state.toml") or lower == "state.toml":
                problems.append(f"per-machine mod state: {name}")
            data = archive.read(info)
            if any(pattern.search(data) for pattern in PRIVATE_PATTERNS):
                bound = PRIVATE_FIXTURE_HASHES.get(name)
                bound = (bound,) if isinstance(bound, str) else (bound or ())
                if name in PRIVATE_FIXTURE_ALLOWLIST or sha256(data.replace(b"\r\n", b"\n")) in bound:
                    allowed_private.append(name)
                else:
                    private_paths.append(name)
            # A public mod catalog is staged at one of the framework's canonical
            # locations. Framework 4cc04be3 renamed the exe-side catalog from
            # mods/packages to mods/bundled; an auditor pinned to the old
            # spelling counted zero manifests for every kit built after that
            # rename and rejected a complete catalog. Accept any manifest that
            # sits under a mods/ tree in a catalog segment, so neither spelling
            # nor location can silently zero the count. The count, the
            # >= 1 requirement and the developer-channel rejection below are
            # unchanged.
            _catalog_parts = set(PurePosixPath(lower).parts)
            if (lower.endswith("/manifest.toml")
                    and "mods" in _catalog_parts
                    and ({"bundled", "packages"} & _catalog_parts)):
                mod_manifests += 1
                if re.search(rb'^\s*channel\s*=\s*"developer"', data, re.M):
                    problems.append(f"developer-channel mod: {name}")
            if lower == "psxrecomp/bios/openbios.bin":
                openbios.append({"path": name, "bytes": len(data), "sha256": sha256(data)})

        required = {
            "VERSION", "psx_game_version.txt", "project-manifest.toml", "game.toml",
            "catalog_identity.json", "README.md", "README-SETUP.txt",
            "framework_pins.txt",
        }
        if expected.get("openbios_required", False):
            required.add("psxrecomp/bios/OpenBIOS.LICENSE")
        missing = sorted(required.difference(names))
        if missing:
            problems.append(f"missing required entries: {missing}")
        for stamp in ("VERSION", "psx_game_version.txt"):
            if stamp in names and archive.read(stamp).decode().strip() != version:
                problems.append(f"{stamp} is not {version}")
        if "project-manifest.toml" in names:
            try:
                manifest = tomllib.loads(archive.read("project-manifest.toml").decode())
                release_version = str(manifest.get("release", {}).get("version"))
                framework = manifest.get("framework", {})
                if release_version != version:
                    problems.append(f"project-manifest release version is not {version}")
                if framework.get("commit") != expected["framework_commit"]:
                    problems.append("project-manifest framework commit mismatch")
                if framework.get("tree") != expected["framework_tree"]:
                    problems.append("project-manifest framework tree mismatch")
                if framework.get("recomp_ui_commit") != expected["recomp_ui_commit"]:
                    problems.append("project-manifest recomp-ui commit mismatch")
            except Exception as error:
                problems.append(f"project-manifest parse failed: {error}")
        if "framework_pins.txt" in names:
            pin_text = archive.read("framework_pins.txt").decode()
            for commit in (
                expected["framework_commit"], expected["recomp_ui_commit"],
                expected["recomp_net_commit"], expected["rbengine_commit"],
            ):
                if commit not in pin_text:
                    problems.append(f"framework_pins.txt omits {commit}")

    if forbidden:
        problems.append("forbidden retail or player-state payload")
    if generated:
        problems.append("generated retail code or extracted disc payload")
    if private_paths:
        problems.append("private developer path in archive content")
    if mod_manifests < 1:
        problems.append("release zip ships no public mod catalog")
    if expected.get("openbios_required", False):
        if len(openbios) != 1 or openbios[0]["bytes"] != 524288 or openbios[0]["sha256"] != OPENBIOS_SHA256:
            problems.append("OpenBIOS identity mismatch")
    elif openbios:
        problems.append("OpenBIOS must be absent for this retail-BIOS-only package")

    return {
        "repo": repo,
        "source_sha": expected["source_commit"],
        "version": expected["version"],
        "platform": platform,
        "file": path.name,
        "local_path": str(path),
        "bytes": len(package_bytes),
        "sha256": sha256(package_bytes),
        "entry_count": len(infos),
        "openbios": openbios,
        "mod_manifest_count": mod_manifests,
        "forbidden_entries": forbidden,
        "generated_entries": generated,
        "private_path_entries": private_paths,
        "allowed_private_fixture_entries": sorted(set(allowed_private)),
        "problems": problems,
        "status": "pass" if not problems else "fail",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifact-root", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--audit", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    args = parser.parse_args()
    config = json.loads(args.config.read_text(encoding="utf-8-sig"))
    repos: dict[str, dict[str, str]] = config["repositories"]
    results: list[dict[str, object]] = []
    global_problems: list[str] = []
    for repo, expected in sorted(repos.items()):
        repo_root = args.artifact_root / repo
        packages = sorted(repo_root.rglob("*.zip")) if repo_root.exists() else []
        if not packages:
            global_problems.append(f"{repo}: no archives")
        for package in packages:
            results.append(audit_archive(package, repo, expected))

    counts = Counter((str(row["repo"]), str(row["platform"])) for row in results)
    for repo in sorted(repos):
        for platform in PLATFORMS:
            if counts[(repo, platform)] != 1:
                global_problems.append(
                    f"{repo}: expected one {platform} archive; found {counts[(repo, platform)]}"
                )
    passed = not global_problems and all(row["status"] == "pass" for row in results)
    audit = {
        "schema": 1,
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "repository_count": len(repos),
        "package_count": len(results),
        "required_platforms": list(PLATFORMS),
        "global_problems": global_problems,
        "results": results,
        "status": "pass" if passed else "fail",
    }
    manifest = {
        "schema": 1,
        "generated_utc": audit["generated_utc"],
        "scope": config.get("scope", "release fleet"),
        "repository_count": len(repos),
        "package_count": len(results),
        "packages": [
            {key: row[key] for key in ("repo", "version", "source_sha", "platform", "file", "bytes", "sha256")}
            for row in sorted(results, key=lambda item: (str(item["repo"]), str(item["platform"])))
        ],
        "publication": "not-authorized-exact-manifest",
    }
    args.audit.write_text(json.dumps(audit, indent=2) + "\n", encoding="utf-8")
    args.manifest.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({
        "status": audit["status"],
        "repository_count": len(repos),
        "package_count": len(results),
        "failed_packages": sum(row["status"] != "pass" for row in results),
        "global_problems": global_problems,
    }, indent=2))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
