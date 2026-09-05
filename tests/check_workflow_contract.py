#!/usr/bin/env python3
"""Fail-closed audit for the public exact-commit CI contract."""

from __future__ import annotations

import argparse
import copy
import pathlib
import re
import subprocess
import sys
from collections.abc import Mapping

try:
    import yaml
except ImportError as exc:  # pragma: no cover - a clear failure is safer than a text-only pass
    raise SystemExit("[FAIL] PyYAML is required to parse workflow YAML") from exc


ROOT = pathlib.Path(__file__).resolve().parents[1]
WORKFLOW_DIR = pathlib.Path(".github/workflows")
REQUIRED = ("ci-linux.yml", "ci-sanitizers.yml", "ci-windows.yml")
CHECKOUT_SHA = "11bd71901bbe5b1630ceea73d27597364c9af683"
EXACT_EXPR = "${{ github.event_name == 'pull_request' && github.event.pull_request.head.sha || github.sha }}"
RUNTIME_TOKENS = ("--run", "--apply", "test_directory_orchestration.py", "test_runtime_authorization.py")


class ContractError(RuntimeError):
    pass


def fail(message: str) -> None:
    raise ContractError(message)


def load_documents(texts: Mapping[str, str]) -> dict[str, dict]:
    documents: dict[str, dict] = {}
    for name in REQUIRED:
        text = texts.get(name)
        if text is None:
            fail(f"missing workflow: {name}")
        try:
            document = yaml.load(text, Loader=yaml.BaseLoader)
        except yaml.YAMLError as exc:
            fail(f"invalid YAML in {name}: {exc}")
        if not isinstance(document, dict):
            fail(f"workflow root must be a mapping: {name}")
        documents[name] = document
    return documents


def as_mapping(value: object, context: str) -> dict:
    if not isinstance(value, dict):
        fail(f"{context} must be a mapping")
    return value


def as_steps(job: dict, context: str) -> list[dict]:
    value = job.get("steps")
    if not isinstance(value, list) or not value:
        fail(f"{context}.steps must be a non-empty list")
    if not all(isinstance(step, dict) for step in value):
        fail(f"{context}.steps contains a non-mapping entry")
    return value


def joined_runs(job: dict) -> str:
    return "\n".join(str(step.get("run", "")) for step in as_steps(job, "job"))


def assert_trigger_and_permissions(name: str, document: dict) -> None:
    triggers = as_mapping(document.get("on"), f"{name}.on")
    for trigger in ("workflow_dispatch", "pull_request", "push"):
        if trigger not in triggers:
            fail(f"{name} is missing {trigger} trigger")
    if "pull_request_target" in triggers:
        fail(f"{name} must not use pull_request_target")
    permissions = as_mapping(document.get("permissions"), f"{name}.permissions")
    if permissions != {"contents": "read"}:
        fail(f"{name} permissions must be exactly contents: read")


def assert_exact_checkout(name: str, job_name: str, job: dict) -> None:
    steps = as_steps(job, f"{name}.{job_name}")
    for step in steps:
        uses = str(step.get("uses", ""))
        if uses and not uses.startswith("./") and re.fullmatch(r"[^@]+@[0-9a-fA-F]{40}", uses) is None:
            fail(f"{name}.{job_name} has an unpinned remote action: {uses}")
        if uses.startswith("actions/cache@"):
            fail(f"{name}.{job_name} must not restore a hosted build cache")
    checkout_indexes = [index for index, step in enumerate(steps) if "actions/checkout@" in str(step.get("uses", ""))]
    if checkout_indexes != [0]:
        fail(f"{name}.{job_name} must have one checkout as its first step")
    checkout = steps[0]
    if checkout.get("uses") != f"actions/checkout@{CHECKOUT_SHA}":
        fail(f"{name}.{job_name} checkout action is not pinned to the approved SHA")
    inputs = as_mapping(checkout.get("with"), f"{name}.{job_name}.checkout.with")
    if inputs.get("persist-credentials") != "false":
        fail(f"{name}.{job_name} must disable persisted checkout credentials")
    if inputs.get("ref") != EXACT_EXPR:
        fail(f"{name}.{job_name} checkout ref is not the exact event commit expression")

    if len(steps) < 2:
        fail(f"{name}.{job_name} has no immediate checkout assertion")
    assertion = steps[1]
    if assertion.get("name") != "Assert exact clean checkout":
        fail(f"{name}.{job_name} must assert the exact clean checkout immediately")
    assertion_env = as_mapping(assertion.get("env"), f"{name}.{job_name}.assert.env")
    assertion_run = str(assertion.get("run", ""))
    if assertion_env.get("EXPECTED_SHA") != EXACT_EXPR:
        fail(f"{name}.{job_name} assertion does not bind EXPECTED_SHA")
    for token in ("git rev-parse --verify HEAD", "git status --porcelain=v1"):
        if token not in assertion_run:
            fail(f"{name}.{job_name} assertion is missing {token!r}")
    if ".git" not in assertion_run:
        fail(f"{name}.{job_name} does not require a source-root Git marker")
    is_windows = str(job.get("runs-on", "")).startswith("windows-")
    if is_windows:
        if "$LASTEXITCODE" not in assertion_run or "$sourceStatus.Count" not in assertion_run:
            fail(f"{name}.{job_name} can mistake a failed Windows Git status for clean")
    elif "source_status=\"$(git status" not in assertion_run or 'test -z "$source_status"' not in assertion_run:
        fail(f"{name}.{job_name} can mistake a failed Git status for clean")
    run_text = joined_runs(job)
    job_text = str(job)
    if "AUTO_REFIRST_SOURCE_COMMIT" in job_text:
        fail(f"{name}.{job_name} must not use the archive identity fallback in a live checkout")
    if "restore-keys" in job_text:
        fail(f"{name}.{job_name} must not restore an inexact hosted build cache")
    final_step = steps[-1]
    if final_step.get("name") != "Assert source remains clean" or "git status --porcelain=v1" not in str(final_step.get("run", "")):
        fail(f"{name}.{job_name} must finish by proving the source remains clean")
    final_run = str(final_step.get("run", ""))
    if is_windows:
        if "$LASTEXITCODE" not in final_run or "$sourceStatus.Count" not in final_run:
            fail(f"{name}.{job_name} final Windows clean gate is not fail-closed")
    elif "source_status=\"$(git status" not in final_run or 'test -z "$source_status"' not in final_run:
        fail(f"{name}.{job_name} final clean gate is not fail-closed")
    if "check_public_source_hygiene.py --require-clean" not in joined_runs(job):
        fail(f"{name}.{job_name} must run public hygiene against a clean worktree")


def assert_job_boundaries(name: str, jobs: dict) -> None:
    for job_name, raw_job in jobs.items():
        job = as_mapping(raw_job, f"{name}.{job_name}")
        run_text = joined_runs(job)
        contains_runtime = any(token in run_text for token in RUNTIME_TOKENS)
        declared_runtime = "runtime" in job_name.lower() or "runtime" in str(job.get("name", "")).lower()
        if declared_runtime:
            if job.get("if") != "github.event_name != 'pull_request'":
                fail(f"{name}.{job_name} runtime job must be disabled for pull_request events")
            if not contains_runtime:
                fail(f"{name}.{job_name} is labelled runtime but exercises no runtime contract")
        for step in as_steps(job, f"{name}.{job_name}"):
            command = str(step.get("run", "")).strip()
            if not any(token in command for token in RUNTIME_TOKENS):
                continue
            if "run_public_regression.py" in command:
                fail(f"{name}.{job_name} violates the static-only P0/P1 boundary")
            if declared_runtime:
                continue
            approved_commands = {
                "python3 tests/test_directory_orchestration.py build/auto-refirst",
                "python3 tests/test_runtime_authorization.py build/auto-refirst",
            }
            if (name != "ci-linux.yml" or job_name != "public-static"
                    or command not in approved_commands
                    or step.get("if") != "github.event_name != 'pull_request' && matrix.compiler == 'gcc-13'"):
                fail(f"{name}.{job_name} runtime step lacks the exact non-PR GCC gate")


def assert_linux(document: dict) -> None:
    jobs = as_mapping(document.get("jobs"), "ci-linux.yml.jobs")
    static = as_mapping(jobs.get("public-static"), "ci-linux.yml.public-static")
    matrix = as_mapping(as_mapping(static.get("strategy"), "linux.static.strategy").get("matrix"), "linux.static.matrix")
    include = matrix.get("include")
    if not isinstance(include, list):
        fail("Linux static compiler matrix must use include")
    compilers = {str(row.get("compiler")) for row in include if isinstance(row, dict)}
    if compilers != {"gcc-13", "clang-18"}:
        fail("Linux strict matrix must be exactly GCC 13 and Clang 18")
    static_runs = joined_runs(static)
    for token in (
        "-DAUTO_REFIRST_WARNINGS_AS_ERRORS=ON",
        "cmake -S . -B build",
        "run_public_regression.py",
        "--tier all",
        "--require-clean-source",
        "test_bounded_directory_output.py",
        "auto_refirst_public_provenance_check",
        "auto_refirst_public_install_stage_check",
        "check_ci_build_identity.py",
        '--expected-commit "$EXPECTED_SHA"',
        "--expected-platform Linux/x86_64",
        "--expected-schema 1.0",
        "--self-test",
        "EXPECTED_SHA",
    ):
        if token not in static_runs:
            fail(f"Linux static job is missing {token!r}")
    runtime_runs = static_runs
    for token in ("test_directory_orchestration.py", "test_runtime_authorization.py"):
        if token not in runtime_runs:
            fail(f"Linux runtime job is missing {token!r}")
    if "-DAUTO_REFIRST_WARNINGS_AS_ERRORS=ON" not in runtime_runs:
        fail("Linux runtime job does not enable warnings-as-errors")
    if "cmake -S . -B build" not in runtime_runs:
        fail("Linux runtime job does not configure the exact live checkout")


def assert_sanitizer(document: dict) -> None:
    jobs = as_mapping(document.get("jobs"), "ci-sanitizers.yml.jobs")
    if set(jobs) != {"malformed-static"}:
        fail("sanitizer workflow must contain only the malformed-static job")
    job = as_mapping(jobs["malformed-static"], "ci-sanitizers.yml.malformed-static")
    env = as_mapping(job.get("env"), "ci-sanitizers.yml.malformed-static.env")
    if env.get("CC") != "gcc-13" or env.get("CXX") != "g++-13":
        fail("sanitizer compiler must be GCC 13")
    if "detect_leaks=1" not in str(env.get("ASAN_OPTIONS", "")) or "halt_on_error=1" not in str(env.get("UBSAN_OPTIONS", "")):
        fail("sanitizer fail-fast/leak options are incomplete")
    runs = joined_runs(job)
    for token in ("-DAUTO_REFIRST_WARNINGS_AS_ERRORS=ON", "cmake -S . -B build-san", "address,undefined", "auto_refirst_public_malformed_sanitizer", "--sanitizer-smoke"):
        if token not in runs:
            fail(f"sanitizer job is missing {token!r}")


def assert_windows(document: dict) -> None:
    jobs = as_mapping(document.get("jobs"), "ci-windows.yml.jobs")
    static = as_mapping(jobs.get("public-static"), "ci-windows.yml.public-static")
    if static.get("runs-on") != "windows-2022":
        fail("Windows gate must use the native windows-2022 runner")
    runs = joined_runs(static)
    for token in (
        'Visual Studio 17 2022',
        "-DAUTO_REFIRST_WARNINGS_AS_ERRORS=ON",
        "cmake -S . -B build",
        "run_public_regression.py",
        "--tier all",
        "--require-clean-source",
        "test_bounded_directory_output.py",
        "auto_refirst_public_provenance_check",
        "auto_refirst_public_install_stage_check",
        "check_ci_build_identity.py",
        "--expected-commit $env:EXPECTED_SHA",
        "--expected-platform Windows/AMD64",
        "--expected-schema 1.0",
        "--self-test",
        "EXPECTED_SHA",
    ):
        if token not in runs:
            fail(f"Windows static job is missing {token!r}")


def check_texts(texts: Mapping[str, str]) -> tuple[int, int]:
    documents = load_documents(texts)
    job_count = 0
    step_count = 0
    for name, document in documents.items():
        assert_trigger_and_permissions(name, document)
        jobs = as_mapping(document.get("jobs"), f"{name}.jobs")
        if not jobs:
            fail(f"{name} has no jobs")
        for job_name, raw_job in jobs.items():
            job = as_mapping(raw_job, f"{name}.{job_name}")
            assert_exact_checkout(name, str(job_name), job)
            job_count += 1
            step_count += len(as_steps(job, f"{name}.{job_name}"))
        assert_job_boundaries(name, jobs)
    assert_linux(documents["ci-linux.yml"])
    assert_sanitizer(documents["ci-sanitizers.yml"])
    assert_windows(documents["ci-windows.yml"])
    return job_count, step_count


def mutate(texts: dict[str, str], name: str, old: str, new: str, count: int = 1) -> dict[str, str]:
    changed = copy.deepcopy(texts)
    if old not in changed[name]:
        raise AssertionError(f"self-test mutation anchor not found: {name}: {old!r}")
    changed[name] = changed[name].replace(old, new, count)
    return changed


def self_test(texts: dict[str, str]) -> int:
    mutations = [
        ("pull_request_target", mutate(texts, "ci-linux.yml", "  pull_request:\n", "  pull_request_target:\n")),
        ("missing workflow_dispatch", mutate(texts, "ci-linux.yml", "  workflow_dispatch:\n", "")),
        ("write permission", mutate(texts, "ci-linux.yml", "  contents: read\n", "  contents: write\n")),
        ("floating checkout", mutate(texts, "ci-linux.yml", f"actions/checkout@{CHECKOUT_SHA}", "actions/checkout@v4")),
        ("persisted credentials", mutate(texts, "ci-linux.yml", "persist-credentials: false", "persist-credentials: true")),
        ("implicit checkout ref", mutate(texts, "ci-linux.yml", f"          ref: {EXACT_EXPR}\n", "")),
        ("missing HEAD assertion", mutate(texts, "ci-linux.yml", "git rev-parse --verify HEAD", "git show -s --format=%H HEAD")),
        ("status failure accepted as clean", mutate(texts, "ci-linux.yml", 'source_status="$(git status --porcelain=v1 --untracked-files=all)"\n          test -z "$source_status"', 'test -z "$(git status --porcelain=v1 --untracked-files=all)"')),
        ("missing final clean gate", mutate(texts, "ci-linux.yml", "      - name: Assert source remains clean\n", "      - name: Source residue not checked\n")),
        ("PR runtime enabled", mutate(texts, "ci-linux.yml", "        if: github.event_name != 'pull_request' && matrix.compiler == 'gcc-13'\n", "")),
        ("runtime in static job", mutate(texts, "ci-linux.yml", "test_bounded_directory_output.py build/auto-refirst", "test_bounded_directory_output.py build/auto-refirst --run")),
        ("missing Clang 18", mutate(texts, "ci-linux.yml", "compiler: clang-18", "compiler: clang-17")),
        ("missing public hygiene", mutate(texts, "ci-linux.yml", "python3 tests/check_public_source_hygiene.py --require-clean", "python3 --version")),
        ("P0/P1 accepts dirty source", mutate(texts, "ci-linux.yml", " --tier all --require-clean-source", " --tier all")),
        ("missing exact install checker", mutate(texts, "ci-linux.yml", "auto_refirst_public_install_stage_check", "auto_refirst")),
        ("missing strict configure", mutate(texts, "ci-linux.yml", "-DAUTO_REFIRST_WARNINGS_AS_ERRORS=ON", "-DCMAKE_VERBOSE_MAKEFILE=ON")),
        ("archive fallback in live CI", mutate(texts, "ci-linux.yml", "cmake -S . -B build -DCMAKE_BUILD_TYPE=Release", "AUTO_REFIRST_SOURCE_COMMIT=$EXPECTED_SHA cmake -S . -B build -DCMAKE_BUILD_TYPE=Release")),
        ("configure detached source", mutate(texts, "ci-linux.yml", "cmake -S . -B build", "cmake -S exported-source -B build")),
        ("binary identity detached from event", mutate(texts, "ci-linux.yml", '--expected-commit "$EXPECTED_SHA"', "--expected-commit 0000000000000000000000000000000000000000")),
        ("wrong sanitizer compiler", mutate(texts, "ci-sanitizers.yml", "CC: gcc-13", "CC: gcc-12")),
        ("missing sanitizer smoke", mutate(texts, "ci-sanitizers.yml", "--sanitizer-smoke", "--tier P0")),
        ("non-native Windows", mutate(texts, "ci-windows.yml", "runs-on: windows-2022", "runs-on: ubuntu-24.04")),
        ("missing binary identity", mutate(texts, "ci-windows.yml", "check_ci_build_identity.py", "python --version")),
        ("inexact Windows platform", mutate(texts, "ci-windows.yml", "--expected-platform Windows/AMD64", "--expected-platform Windows/x64")),
        ("invalid YAML", mutate(texts, "ci-windows.yml", "jobs:\n", "jobs: [\n")),
    ]
    for label, candidate in mutations:
        try:
            check_texts(candidate)
        except ContractError:
            continue
        fail(f"mutation was incorrectly accepted: {label}")
    return len(mutations)


def read_workflows(root: pathlib.Path) -> dict[str, str]:
    directory = root / WORKFLOW_DIR
    return {name: (directory / name).read_text(encoding="utf-8") for name in REQUIRED}


def require_clean_worktree(root: pathlib.Path) -> None:
    cp = subprocess.run(
        ["git", "-C", str(root), "status", "--porcelain=v1", "--untracked-files=all"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if cp.returncode != 0:
        fail(f"cannot inspect worktree cleanliness: {cp.stderr.strip()}")
    if cp.stdout:
        fail("worktree is not clean")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true", help="run contract mutation negatives")
    parser.add_argument("--require-clean-worktree", action="store_true")
    args = parser.parse_args()
    try:
        texts = read_workflows(ROOT)
        jobs, steps = check_texts(texts)
        mutation_count = self_test(texts) if args.self_test else 0
        if args.require_clean_worktree:
            require_clean_worktree(ROOT)
    except (ContractError, OSError) as exc:
        print(f"[FAIL] {exc}", file=sys.stderr)
        return 1
    print(f"[PASS] workflow contract: files={len(REQUIRED)} jobs={jobs} steps={steps} mutations={mutation_count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
