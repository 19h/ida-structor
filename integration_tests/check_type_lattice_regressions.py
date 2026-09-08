#!/usr/bin/env python3
"""Verify inferred sum materialization against IDA's actual type system."""

import argparse
import sys
from pathlib import Path

from check_cpp_api_surface import require_success, run, run_api_command

EXPECTED = {
    "integer_and_float_views", "packed_three_byte_extent", "distinct_pointer_views",
    "nested_union_views", "function_pointer_view", "unknown_alternative_has_no_materialization",
    "bottom_alternative_has_no_materialization", "void_alternative_has_no_materialization",
    "bare_function_has_no_union_materialization", "empty_sum_has_no_materialization",
    "array_size_boundary_bytes", "unknown_union_extent_is_unknown",
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", required=True)
    parser.add_argument("--plugin", required=True)
    parser.add_argument("--idump", default="idump")
    args = parser.parse_args()
    root = Path(args.repo_root).resolve()
    build = run(["sh", str(root / "integration_tests/build_fixtures.sh"),
                 "test_simple_struct"], cwd=root)
    require_success(build, "building type lattice host fixture")
    data = run_api_command(
        root, Path(args.plugin).resolve(), args.idump,
        binary="test_simple_struct", functions=["process_simple"],
        command="check_type_lattice_materialization",
    )
    checks = data.get("checks", {})
    if set(checks) != EXPECTED or data.get("success") is not True:
        raise RuntimeError(f"type lattice evidence missing or incomplete: {data}")
    for name, passed in checks.items():
        if passed is not True:
            raise RuntimeError(f"type lattice check failed: {name}: {data}")
        print(f"[PASS] {name}", flush=True)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"[FAIL] {exc}", file=sys.stderr)
        raise SystemExit(1)
