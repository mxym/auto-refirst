#!/usr/bin/env python3
"""Verify that source-archive build identity never leaks from an ancestor Git repo."""

import os
import pathlib
import subprocess
import tarfile
import tempfile


ROOT = pathlib.Path(__file__).resolve().parents[1]
FALLBACK = "f" * 40


def run(*args, cwd=None, env=None):
    return subprocess.run(
        [str(x) for x in args], cwd=cwd, env=env, check=True,
        text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )


def configured_build_id(source, build, fallback=None):
    env = dict(os.environ)
    if fallback is None:
        env.pop("AUTO_REFIRST_SOURCE_COMMIT", None)
    else:
        env["AUTO_REFIRST_SOURCE_COMMIT"] = fallback
    run("cmake", "-S", source, "-B", build, cwd=source, env=env)
    text = (build / "generated/prts/build_metadata.hpp").read_text(encoding="utf-8")
    marker = 'kBuildId = "'
    start = text.index(marker) + len(marker)
    return text[start:text.index('"', start)]


def main():
    temp_parent = os.environ.get("TMPDIR") or None
    with tempfile.TemporaryDirectory(prefix="ar-build-id-root-", dir=temp_parent) as raw:
        work = pathlib.Path(raw)
        ancestor = work / "ancestor"
        ancestor.mkdir()
        run("git", "init", ancestor)
        run("git", "config", "user.name", "auto-refirst metadata test", cwd=ancestor)
        run("git", "config", "user.email", "metadata-test@invalid", cwd=ancestor)
        (ancestor / "ancestor.txt").write_text("ancestor\n", encoding="utf-8")
        run("git", "add", "ancestor.txt", cwd=ancestor)
        run("git", "commit", "-m", "ancestor", cwd=ancestor)

        archive = work / "source.tar"
        run("git", "archive", "--format=tar", f"--output={archive}", "HEAD", cwd=ROOT)
        source = ancestor / "nested/source"
        source.mkdir(parents=True)
        with tarfile.open(archive) as tf:
            try:
                tf.extractall(source, filter="data")
            except TypeError:
                # Python versions predating extraction filters still receive a
                # repository-owned archive produced immediately above.
                tf.extractall(source)

        assert not (source / ".git").exists()
        assert configured_build_id(source, work / "build-full", FALLBACK) == FALLBACK
        assert configured_build_id(source, work / "build-short", "abc1234") == "unknown"
        assert configured_build_id(source, work / "build-none") == "unknown"
    print("[PASS] source-root Git marker isolates archive build identity from ancestor repositories")


if __name__ == "__main__":
    main()
