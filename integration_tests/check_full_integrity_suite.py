#!/usr/bin/env python3

import argparse
import subprocess
import sys
import time
from pathlib import Path


SUITE_TIMEOUT_SECONDS = 900


def log(message: str) -> None:
    print(message, flush=True)


def hr(char: str = "=", width: int = 78) -> str:
    return char * width


def run(cmd: list[str], *, cwd: Path, label: str) -> None:
    start = time.monotonic()
    log(hr())
    log(f"Suite: {label}")
    log(f"Command: {' '.join(cmd)}")

    proc = subprocess.run(
        cmd, cwd=cwd, text=True, timeout=SUITE_TIMEOUT_SECONDS)
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

    # Keep each label with its command so adding a suite cannot desynchronize
    # two parallel registries and skip a late check.
    suites = [
        ("external CMake consumer", [
            sys.executable,
            "integration_tests/check_cmake_embed_consumer.py",
            "--repo-root",
            str(repo_root),
        ]),
        ("C++ API surface", [sys.executable, "integration_tests/check_cpp_api_surface.py", *common]),
        ("index guard regressions", [sys.executable, "integration_tests/check_index_guard_regressions.py", *common]),
        ("assignment and call evaluation regressions", [sys.executable, "integration_tests/check_assignment_order_regressions.py", *common]),
        ("branch-sensitive alias regressions", [sys.executable, "integration_tests/check_alias_flow_regressions.py", *common]),
        ("exact fixture contracts", [sys.executable, "integration_tests/check_fixture_contracts.py", *common]),
        ("fresh-database determinism regressions", [sys.executable, "integration_tests/check_determinism_regressions.py", *common]),
        ("structure-persistence regressions", [sys.executable, "integration_tests/check_persistence_regressions.py", *common]),
        ("global recovery regressions", [sys.executable, "integration_tests/check_global_recovery_regressions.py", *common]),
        ("WeaponStats regressions", [sys.executable, "integration_tests/check_weaponstats_regressions.py", *common]),
        ("vtable regressions", [sys.executable, "integration_tests/check_vtable_regressions.py", *common]),
        ("type-fixer regressions", [sys.executable, "integration_tests/check_type_fixer_regressions.py", *common]),
        ("existing-type matcher regressions", [sys.executable, "integration_tests/check_type_matcher_regressions.py", *common]),
        ("typed-array solver regressions", [sys.executable, "integration_tests/check_array_regressions.py", *common]),
        ("type-application identity regressions", [sys.executable, "integration_tests/check_type_application_regressions.py", *common]),
        ("signature mapping and target ABI regressions", [sys.executable, "integration_tests/check_signature_abi_regressions.py", *common]),
        ("bounded symbolic type query status", [sys.executable, "integration_tests/check_type_query_status.py", *common]),
        ("absolute-memory type evidence", [sys.executable, "integration_tests/check_memory_inference.py", *common]),
        ("local model value evidence", [sys.executable, "integration_tests/check_type_model_evidence.py", *common]),
        ("consulted constraint-source evidence", [sys.executable, "integration_tests/check_constraint_source_evidence.py", *common]),
        ("experimental instruction semantics identity", [sys.executable, "integration_tests/check_instruction_semantics_identity.py", *common]),
        ("type lattice materialization", [sys.executable, "integration_tests/check_type_lattice_regressions.py", *common]),
    ]

    for label, cmd in suites:
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
