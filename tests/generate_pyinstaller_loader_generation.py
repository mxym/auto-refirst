#!/usr/bin/env python3
"""Generate the compact PyInstaller loader component-generation catalog.

A generation is a source identity for one independently modeled bootstrap
component, not a PyInstaller release identity:

* LEGACY_CORE: the pre-5.3 four-module loader set;
* MODERN_CORE: the 5.3+ three-module cross-platform loader core;
* WINDOWS_EXTENSION: pyimod04_pywin32 when that source exists (5.5+).

Generation identity is SHA-256 over each ordered module basename, NUL, exact
source bytes, NUL. Rows are grouped by generation, component, and declared
Python compatibility. This keeps source equality separate from release/package
identity and allows Windows extension evidence to intersect the core release
set without requiring both components to have the same source hash.

The generator reads an external official PyInstaller git checkout. It emits
only hashes, component names, compatibility bounds, and release aliases; no
upstream source bytes are copied into this repository.
"""
from __future__ import annotations

import argparse
import collections
import hashlib
import pathlib
import re
import subprocess

COMPONENTS = {
    "LEGACY_CORE": (
        "pyimod01_os_path.py",
        "pyimod02_archive.py",
        "pyimod03_importers.py",
        "pyimod04_ctypes.py",
    ),
    "MODERN_CORE": (
        "pyimod01_archive.py",
        "pyimod02_importers.py",
        "pyimod03_ctypes.py",
    ),
    "WINDOWS_EXTENSION": ("pyimod04_pywin32.py",),
}
STABLE_TAG_RE = re.compile(r"^v(\d+)\.(\d+)(?:\.(\d+))?$")
REQUIRES_RE = re.compile(
    r"(?mi)^\s*(?:requires-python|python_requires)\s*=\s*[\"']?([^\"'\n]+)"
)
MIN_VERSION = (4, 10, 0)


def run_git(repo: pathlib.Path, *args: str, check: bool = True) -> bytes:
    cp = subprocess.run(
        ["git", "-C", str(repo), *args], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False
    )
    if check and cp.returncode:
        raise ValueError(cp.stderr.decode("utf-8", "replace").strip() or f"git {' '.join(args)} failed")
    return cp.stdout


def stable_version(tag: str) -> tuple[int, int, int] | None:
    m = STABLE_TAG_RE.fullmatch(tag)
    if not m:
        return None
    return int(m.group(1)), int(m.group(2)), int(m.group(3) or 0)


def show(repo: pathlib.Path, tag: str, path: str) -> bytes | None:
    cp = subprocess.run(
        ["git", "-C", str(repo), "show", f"{tag}:{path}"],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False,
    )
    return cp.stdout if cp.returncode == 0 else None


def has_modules(repo: pathlib.Path, tag: str, modules: tuple[str, ...]) -> bool:
    return all(show(repo, tag, f"PyInstaller/loader/{module}") is not None for module in modules)


def components_for_tag(repo: pathlib.Path, tag: str) -> list[tuple[str, tuple[str, ...]]]:
    legacy = has_modules(repo, tag, COMPONENTS["LEGACY_CORE"])
    modern = has_modules(repo, tag, COMPONENTS["MODERN_CORE"])
    if legacy == modern:
        raise ValueError(f"{tag}: expected exactly one legacy/modern core module set")
    out = [("LEGACY_CORE", COMPONENTS["LEGACY_CORE"])] if legacy else [("MODERN_CORE", COMPONENTS["MODERN_CORE"])]
    win_present = has_modules(repo, tag, COMPONENTS["WINDOWS_EXTENSION"])
    if win_present:
        if legacy:
            raise ValueError(f"{tag}: Windows extension unexpectedly coexists with legacy core")
        out.append(("WINDOWS_EXTENSION", COMPONENTS["WINDOWS_EXTENSION"]))
    return out


def generation_fingerprint(repo: pathlib.Path, tag: str, modules: tuple[str, ...]) -> str:
    h = hashlib.sha256()
    for module in modules:
        payload = show(repo, tag, f"PyInstaller/loader/{module}")
        if payload is None:
            raise ValueError(f"{tag}: missing loader source {module}")
        h.update(module.encode("utf-8")); h.update(b"\0"); h.update(payload); h.update(b"\0")
    return h.hexdigest()


def python_compatibility(repo: pathlib.Path, tag: str) -> tuple[int, int, str]:
    for path in ("pyproject.toml", "setup.cfg"):
        payload = show(repo, tag, path)
        if payload is None:
            continue
        text = payload.decode("utf-8", "strict")
        m = REQUIRES_RE.search(text)
        if not m:
            continue
        spec = m.group(1).strip()
        low = re.search(r">=\s*3\.(\d+)", spec)
        high = re.search(r"<\s*3\.(\d+)", spec)
        if not low or not high:
            raise ValueError(f"{tag}: unsupported Python requirement {spec!r}")
        python_min = 300 + int(low.group(1)); python_max = 300 + int(high.group(1)) - 1
        if python_min > python_max:
            raise ValueError(f"{tag}: invalid Python compatibility {spec!r}")
        return python_min, python_max, spec
    raise ValueError(f"{tag}: Python compatibility metadata not found")


def release_key(release: str) -> tuple[int, int, int]:
    parts = [int(x) for x in release.split(".")]
    return parts[0], parts[1], parts[2] if len(parts) > 2 else 0


def catalog(repo: pathlib.Path, through: str) -> list[tuple[str, str, int, int, list[str]]]:
    through_version = stable_version(through)
    if through_version is None or through_version[0] != 6:
        raise ValueError("--through must be a stable v6 tag")
    tags = []
    for raw in run_git(repo, "tag", "--list", "v[456].*").decode("utf-8", "strict").splitlines():
        version = stable_version(raw)
        if version is not None and MIN_VERSION <= version <= through_version:
            tags.append(raw)
    tags = sorted(set(tags), key=lambda t: stable_version(t))
    if not tags or stable_version(tags[0]) != MIN_VERSION or stable_version(tags[-1]) != through_version:
        raise ValueError("stable tag range is incomplete at one of its endpoints")

    grouped: dict[tuple[str, str, int, int], list[str]] = collections.defaultdict(list)
    seen_release_components: dict[str, set[str]] = {}
    for tag in tags:
        python_min, python_max, _ = python_compatibility(repo, tag)
        components = components_for_tag(repo, tag)
        release = tag.removeprefix("v")
        seen_release_components[release] = {name for name, _ in components}
        for component, modules in components:
            generation = generation_fingerprint(repo, tag, modules)
            grouped[(generation, component, python_min, python_max)].append(release)

    # Transitional correctness: every release has exactly one core; extension is optional.
    for release, components in seen_release_components.items():
        core_count = int("LEGACY_CORE" in components) + int("MODERN_CORE" in components)
        if core_count != 1 or not components <= {"LEGACY_CORE", "MODERN_CORE", "WINDOWS_EXTENSION"}:
            raise ValueError(f"{release}: invalid component set {sorted(components)}")

    rows = []
    for (generation, component, python_min, python_max), releases in grouped.items():
        rows.append((generation, component, python_min, python_max, sorted(releases, key=release_key)))
    rows.sort(key=lambda row: (release_key(row[4][0]), row[1]))
    return rows


def render(rows: list[tuple[str, str, int, int, list[str]]]) -> str:
    out = [
        "// Generated from exact PyInstaller loader source bytes and package Python metadata.",
        "// generation_sha256 is component-specific; core and Windows extension generations are independent.",
        "// python_min/python_max are inclusive encoded minors (for example 310 == Python 3.10).",
        "// Release aliases sharing a component generation are indistinguishable by that source component alone.",
        "static const PyInstallerLoaderGenerationReference kPyInstallerLoaderGenerations[] = {",
    ]
    for generation, component, python_min, python_max, releases in rows:
        out.append(f'  {{"{generation}","{component}",{python_min},{python_max},"{"|".join(releases)}"}},')
    out.append("};")
    return "\n".join(out) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--source-repo", required=True, type=pathlib.Path, help="official PyInstaller git checkout with release tags")
    ap.add_argument("--through", required=True, help="last stable v6 tag to include, for example v6.22.2")
    ap.add_argument("--check", type=pathlib.Path, help="fail if generated output differs from this catalog file")
    args = ap.parse_args()
    if not (args.source_repo / ".git").exists():
        ap.error(f"not a git checkout: {args.source_repo}")
    try:
        text = render(catalog(args.source_repo, args.through))
    except ValueError as exc:
        ap.error(str(exc))
    if args.check is not None:
        if args.check.read_text(encoding="utf-8") != text:
            raise SystemExit(f"generated catalog differs from {args.check}")
        print(f"[PASS] PyInstaller loader component-generation catalog matches {args.check}")
        return 0
    print(text, end=""); return 0

if __name__ == "__main__":
    raise SystemExit(main())
