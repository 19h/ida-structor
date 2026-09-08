#!/usr/bin/env python3
"""Exercise bounded symbolic-query status through the real opt-in inference engine."""

import argparse
import json
import sys
from pathlib import Path

from check_cpp_api_surface import require_success, run, run_api_command


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", required=True)
    parser.add_argument("--plugin", required=True)
    parser.add_argument("--idump", default="idump")
    parser.add_argument("--record")
    args = parser.parse_args()
    root = Path(args.repo_root).resolve()
    require_success(run(["sh", str(root / "integration_tests/build_fixtures.sh"),
                         "test_simple_struct"], cwd=root), "building query-status carrier")
    data = run_api_command(root, Path(args.plugin).resolve(), args.idump,
                           binary="test_simple_struct", functions=["process_simple"],
                           command="inspect_symbolic_query_status|process_simple")
    if args.record:
        Path(args.record).write_text(json.dumps(data, indent=2) + "\n")
    assert data.get("success") is True and data.get("function_unchanged") is True, data
    expected = {
        "disabled": (0, False, False, 0),
        "exact_array": (5, True, False, 1),
        "preferred_deep_array": (5, True, True, 1),
        "bounded_sat": (5, True, True, 1),
        "bounded_unsat": (6, False, True, 1),
        "budget_exhausted": (7, False, True, 0),
        "exact_unsat": (2, False, False, 1),
        "reused_bounded_sat": (5, True, True, 1),
        "reused_exact_unsat": (2, False, False, 1),
        "default_nested_array": (5, True, True, 1),
        "default_nested_pointer": (5, True, True, 1),
        "default_large_function": (5, True, True, 1),
    }
    cases = data.get("cases", [])
    assert len(cases) == len(expected), data
    assert {case["name"] for case in cases} == set(expected), data
    for case in cases:
        status, success, used_bounds, iterations = expected[case["name"]]
        assert (case["status"], case["success"], case["used_symbolic_bounds"],
                case["solve_iterations"]) == (status, success, used_bounds, iterations), case
        default_positive = case["name"].startswith("default_")
        assert case["inferred_type_matches"] is True, case
        assert case["used_explicit_candidates"] is (default_positive or case["name"] == "preferred_deep_array"), case
        assert case["local_type_count"] == (1 if default_positive else 0), case
        assert case["memory_type_count"] == 0, case
        if case["name"] == "disabled":
            assert case["bounds"] is None, case
        elif default_positive:
            assert case["bounds"] == {"depth": 1, "list_length": 16, "expansions": 4096}, case
        else:
            assert case["bounds"] == {"depth": 0, "list_length": 0,
                                     "expansions": 0 if case["name"] == "budget_exhausted" else 256}, case
        if case["name"] == "bounded_unsat":
            assert "no model within symbolic type bounds" in case["error"], case
        if case["name"] == "budget_exhausted":
            assert "symbolic type query budget exhausted" in case["error"], case
        print(f"[PASS] production query status: {case['name']}", flush=True)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"[FAIL] {exc}", file=sys.stderr)
        raise SystemExit(1)
