#!/usr/bin/env python3

import argparse
import subprocess
import sys
import time
from pathlib import Path


def log(message: str) -> None:
    print(message, flush=True)


def hr(char: str = "=", width: int = 78) -> str:
    return char * width


def run(cmd: list[str], *, cwd: Path, label: str) -> None:
    start = time.monotonic()
    log(hr())
    log(f"Suite: {label}")
    log(f"Command: {' '.join(cmd)}")

    proc = subprocess.run(cmd, cwd=cwd, text=True)
    elapsed = time.monotonic() - start
    if proc.returncode == 0:
        log(f"Suite result: PASS ({elapsed:.1f}s)")
        return

    raise RuntimeError(
        f"command failed: {' '.join(cmd)} (exit={proc.returncode}, elapsed={elapsed:.1f}s)"
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run the full live Structor integrity suite"
    )
    parser.add_argument("--repo-root", required=True)
    parser.add_argument("--plugin", required=True)
    parser.add_argument("--idump", default="idump")
    args = parser.parse_args()

    repo_root = Path(args.repo_root).resolve()
    plugin_path = Path(args.plugin).resolve()
    if not plugin_path.exists():
        raise RuntimeError(f"plugin not found: {plugin_path}")

    total_start = time.monotonic()
    log(hr())
    log("Structor live integrity suite")
    log(f"Repository: {repo_root}")
    log(f"Plugin: {plugin_path}")
    log(f"idump: {args.idump}")

    common = [
        "--repo-root",
        str(repo_root),
        "--plugin",
        str(plugin_path),
        "--idump",
        args.idump,
    ]

    suites = [
        [
            "python3",
            "integration_tests/check_cmake_embed_consumer.py",
            "--repo-root",
            str(repo_root),
        ],
        ["python3", "integration_tests/check_cpp_api_surface.py", *common],
        ["python3", "integration_tests/check_fixture_contracts.py", *common],
        ["python3", "integration_tests/check_global_recovery_regressions.py", *common],
        ["python3", "integration_tests/check_weaponstats_regressions.py", *common],
        ["python3", "integration_tests/check_vtable_regressions.py", *common],
        ["python3", "integration_tests/check_type_fixer_regressions.py", *common],
    ]

    labels = [
        "external CMake consumer",
        "C++ API surface",
        "exact fixture contracts",
        "global recovery regressions",
        "WeaponStats regressions",
        "vtable regressions",
        "type-fixer regressions",
    ]

    for cmd, label in zip(suites, labels, strict=True):
        run(cmd, cwd=repo_root, label=label)

    total_elapsed = time.monotonic() - total_start
    log(hr())
    log(f"Full live integrity suite: PASS ({total_elapsed:.1f}s)")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"[FAIL] {exc}", file=sys.stderr)
        raise SystemExit(1)
