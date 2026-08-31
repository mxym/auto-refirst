#!/usr/bin/env python3
"""Static consistency gate for PyInstaller component-generation/reference catalogs."""
from __future__ import annotations

import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[1]
GENERATIONS = ROOT / "src" / "reference" / "pyinstaller_loader_generations.inc"
RAW = ROOT / "src" / "reference" / "pyinstaller_loader_refs.inc"
SEM = ROOT / "src" / "reference" / "pyinstaller_loader_semantic_refs.inc"

COMPONENTS = {"LEGACY_CORE", "MODERN_CORE", "WINDOWS_EXTENSION"}
GEN_RE = re.compile(r'^\s*\{"([0-9a-f]{64})","([A-Z_]+)",(\d+),(\d+),"([0-9.|]+)"\},\s*$')
RAW_RE = re.compile(r'^\s*\{"([^"]+)",(\d+),"([^"]+)",(\d+)u,"([0-9a-f]{64})"\},\s*$')
SEM_RE = re.compile(r'^\s*\{"([^"]+)",(\d+),"([^"]+)","([0-9a-f]{64})"\},\s*$')
RELEASE_RE = re.compile(r'^[0-9]+(?:\.[0-9]+){1,2}$')
LEGACY_MODULES = {"pyimod01_os_path", "pyimod02_archive", "pyimod03_importers", "pyimod04_ctypes"}
MODERN_CORE_MODULES = {"pyimod01_archive", "pyimod02_importers", "pyimod03_ctypes"}
WINDOWS_MODULES = {"pyimod04_pywin32"}


def data_lines(path: pathlib.Path):
    for n, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("//") or line.startswith("static ") or line == "};":
            continue
        yield n, raw


def expected_component(module: str, label: str, release_components: dict[str, set[str]]) -> str:
    if module == "struct":
        components = release_components.get(label, set())
        cores = components & {"LEGACY_CORE", "MODERN_CORE"}
        assert len(cores) == 1, (label, module, components)
        return next(iter(cores))
    if module in LEGACY_MODULES:
        return "LEGACY_CORE"
    if module in MODERN_CORE_MODULES:
        return "MODERN_CORE"
    if module in WINDOWS_MODULES:
        return "WINDOWS_EXTENSION"
    raise AssertionError(f"unclassified PyInstaller reference module {module!r}")


def main() -> int:
    release_component_meta: dict[tuple[str, str], tuple[str, int, int]] = {}
    generation_components: dict[str, set[str]] = {}
    release_components: dict[str, set[str]] = {}
    generation_rows = 0
    for n, line in data_lines(GENERATIONS):
        m = GEN_RE.match(line)
        assert m, f"{GENERATIONS}:{n}: malformed generation row"
        digest, component, python_min_s, python_max_s, aliases = m.groups()
        assert component in COMPONENTS, (n, component)
        python_min, python_max = int(python_min_s), int(python_max_s)
        assert 300 <= python_min <= python_max < 400, (digest, python_min, python_max)
        generation_components.setdefault(digest, set()).add(component)
        releases = aliases.split("|")
        assert releases and len(releases) == len(set(releases)), (digest, releases)
        for release in releases:
            assert RELEASE_RE.fullmatch(release), (digest, release)
            key = (release, component)
            assert key not in release_component_meta, f"release {release} component {component} appears in multiple generation rows"
            release_component_meta[key] = (digest, python_min, python_max)
            release_components.setdefault(release, set()).add(component)
        generation_rows += 1

    assert generation_rows and release_components, "empty PyInstaller generation catalog"
    # Every cataloged release has exactly one core. Windows extension is optional.
    for release, components in release_components.items():
        assert int("LEGACY_CORE" in components) + int("MODERN_CORE" in components) == 1, (release, components)
        assert components <= COMPONENTS, (release, components)
        if "LEGACY_CORE" in components:
            assert "WINDOWS_EXTENSION" not in components, (release, components)

    total_refs = 0
    labels: set[str] = set()
    for path, regex in ((RAW, RAW_RE), (SEM, SEM_RE)):
        count = 0
        for n, line in data_lines(path):
            m = regex.match(line)
            assert m, f"{path}:{n}: malformed reference row"
            label, python_minor_s, module = m.group(1), m.group(2), m.group(3)
            python_minor = int(python_minor_s)
            component = expected_component(module, label, release_components)
            key = (label, component)
            assert key in release_component_meta, f"{path}:{n}: reference label {label!r} lacks component {component}"
            _, python_min, python_max = release_component_meta[key]
            assert python_min <= python_minor <= python_max, (
                f"{path}:{n}: {label}/{component} reference Python {python_minor} lies outside "
                f"declared compatibility {python_min}-{python_max}"
            )
            labels.add(label); count += 1
        assert count, f"empty reference table {path}"
        total_refs += count

    unused = sorted(set(release_components) - labels, key=lambda x: tuple(int(v) for v in x.split('.')))
    print(
        f"[PASS] PyInstaller reference catalog: component_generations={len(generation_components)} "
        f"catalog_rows={generation_rows} releases={len(release_components)} reference_rows={total_refs} "
        f"releases_without_direct_payload_rows={len(unused)}"
    )
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
