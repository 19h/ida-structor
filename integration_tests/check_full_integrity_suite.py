#!/usr/bin/env python3

import argparse
import subprocess
import sys
from pathlib import Path


def run(cmd: list[str], *, cwd: Path) -> None:
    proc = subprocess.run(cmd, cwd=cwd, text=True, capture_output=True)
    if proc.returncode == 0:
        return

    output = (proc.stdout or "") + (proc.stderr or "")
    raise RuntimeError(f"command failed: {' '.join(cmd)}\n{output}")


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

    common = [
        "--repo-root",
        str(repo_root),
        "--plugin",
        str(plugin_path),
        "--idump",
        args.idump,
    ]

    suites = [
        ["python3", "integration_tests/check_fixture_contracts.py", *common],
        ["python3", "integration_tests/check_global_recovery_regressions.py", *common],
        ["python3", "integration_tests/check_vtable_regressions.py", *common],
        ["python3", "integration_tests/check_type_fixer_regressions.py", *common],
    ]

    for cmd in suites:
        run(cmd, cwd=repo_root)
        print(f"[PASS] {' '.join(cmd[0:2])}")

    print("[PASS] full live integrity suite")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"[FAIL] {exc}", file=sys.stderr)
        raise SystemExit(1)
