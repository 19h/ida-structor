#!/usr/bin/env python3
"""Verify public absolute-memory inference with controlled constraints and native ctree."""

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
    parser.add_argument("--record-dir")
    args = parser.parse_args()
    root = Path(args.repo_root).resolve()
    records = Path(args.record_dir).resolve() if args.record_dir else None
    if records:
        records.mkdir(parents=True, exist_ok=True)
    require_success(run(["sh", str(root / "integration_tests/build_fixtures.sh"),
                         "test_memory_inference"], cwd=root), "building native memory fixture")
    for function in ("memory_inference_globals", "memory_inference_local_pointer",
                     "memory_inference_address_only", "memory_inference_partial_storage"):
        data = run_api_command(root, Path(args.plugin).resolve(), args.idump,
                               binary="test_memory_inference", functions=[function],
                               command=f"inspect_memory_inference|{function}")
        if records:
            (records / (function + ".json")).write_text(json.dumps(data, indent=2) + "\n")
        assert data.get("success") is True and data.get("function_unchanged") is True, data
        cases = {case["name"]: case for case in data["cases"]}
        assert len(data["cases"]) == len(cases) == 7, data
        assert set(cases) == {"disabled", "exact", "conflict", "size_only", "sdk_partial_storage",
                              "sdk_conflicting_views", "native"}, data
        for name, case in cases.items():
            assert (case["status"], case["success"]) == ((0, False) if name == "disabled" else (5, True)), case
            assert case["exact_lookups_passed"] is True, case
        disabled = cases["disabled"]
        assert disabled["memory_types"] == disabled["diagnostics"] == [], disabled
        exact = cases["exact"]
        assert exact["diagnostics"] == [], exact
        views = {(int(v["base"]), v["offset"], v["size"]): v for v in exact["memory_types"]}
        assert set(views) == {(0x100001234, -8, 4), (0x100001234, -8, 8),
                              (0x200001234, -8, 4), (0x1000, 0, 4), (0x1008, 4, 4)}, exact
        assert all(v["evidence"] == "hard_concrete_constraint" for v in views.values()), exact
        for name, issue, view_count in (("conflict", 3, 2), ("size_only", 2, 0),
                                        ("sdk_partial_storage", 2, 0), ("sdk_conflicting_views", 3, 2)):
            case = cases[name]
            assert case["memory_types"] == [] and len(case["diagnostics"]) == 1, case
            diagnostic = case["diagnostics"][0]
            assert diagnostic["issue"] == issue and diagnostic["view_count"] == view_count, case
        native = cases["native"]
        source_types = {int(view["base"]): view for view in data["source_object_types"]}
        for view in native["memory_types"]:
            assert int(view["base"]) in source_types, (view, source_types)
            assert source_types[int(view["base"])]["partial_storage"] is False, source_types
        if function == "memory_inference_globals":
            assert len(native["memory_types"]) == 2 and native["diagnostics"] == [], native
            assert {view["size"] for view in native["memory_types"]} == {4, 8}, native
            assert all(view["offset"] == 0 and view["evidence"] == "soft_concrete_preference"
                       for view in native["memory_types"]), native
            assert native["unresolved_memory_accesses"] == 0, native
        elif function == "memory_inference_local_pointer":
            assert native["memory_types"] == [] and native["unresolved_memory_accesses"] == 1, native
        elif function == "memory_inference_address_only":
            assert native["memory_types"] == native["diagnostics"] == [], native
            assert native["unresolved_memory_accesses"] == 0, native
        else:
            assert len(native["memory_types"]) == 1 and native["diagnostics"] == [], native
            view = native["memory_types"][0]
            assert view["size"] == 8 and view["offset"] == 0, native
            assert view["type"] == "int64" and view["evidence"] == "soft_concrete_preference", native
        print(f"[PASS] public memory inference: {function}", flush=True)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"[FAIL] {exc}", file=sys.stderr)
        raise SystemExit(1)
