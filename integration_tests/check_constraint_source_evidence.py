#!/usr/bin/env python3
"""Verify structured consulted-source metadata through the actual public engine."""

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
                         "test_simple_struct"], cwd=root), "building source-metadata carrier")
    data = run_api_command(root, Path(args.plugin).resolve(), args.idump,
                           binary="test_simple_struct", functions=["process_simple"],
                           command="inspect_constraint_sources|process_simple")
    if args.record:
        Path(args.record).write_text(json.dumps(data, indent=2) + "\n")
    assert data.get("success") is True and data.get("function_unchanged") is True, data
    expected = {"connected", "independent_identity", "inactive_bridge", "unspecified"}
    assert len(data["cases"]) == 4 and {case["name"] for case in data["cases"]} == expected, data
    for case in data["cases"]:
        assert case["status"] == 5 and case["success"] is True and case["solve_iterations"] == 1, case
        assert len(case["locals"]) == 1, case
        local = case["locals"][0]
        assert local["index"] >= 0 and local["type"] == "int32", case
        records = local["records"]
        keys = [(r["site"], r["origin"], r["kind"], r["soft"], r["weight"], r["relation"]) for r in records]
        assert len(keys) == len(set(keys)), case
        sites = [int(site) for site in local["source_sites"]]
        assert sites == sorted(set(sites)), case
        assert set(sites) == {int(r["site"]) for r in records if r["site"] is not None}, case
        flags = [local[name] for name in ("from_signature", "from_decompiler", "from_alias", "from_usage")]
        if case["name"] == "connected":
            assert flags == [True, True, True, True] and len(records) == 6 and len(sites) == 3, case
            assert {r["origin"] for r in records} == set(range(6)), case
            signature = [r for r in records if r["origin"] == 3]
            assert len(signature) == 1 and signature[0]["soft"] is True, case
            assert signature[0]["weight"] == 1 and signature[0]["relation"] == 1, case
            # The connected signature hint asks for float32. Hard int32 plus
            # equality excludes it, yet its consulted origin remains present.
            assert local["type"] != "float32" and local["from_signature"] is True, case
        else:
            assert len(records) == 1 and len(sites) == 1, case
            assert records[0]["relation"] == 0 and records[0]["soft"] is False, case
            assert records[0]["weight"] == 0, case
            if case["name"] == "unspecified":
                assert flags == [False, False, False, False] and records[0]["origin"] == 0, case
            else:
                assert flags == [False, False, False, True] and records[0]["origin"] == 1, case
        print(f"[PASS] public constraint sources: {case['name']}", flush=True)
    counts = data["native_origin_counts"]
    assert len(counts) == 6 and counts[0] == 0, data
    assert all(counts[index] > 0 for index in (1, 2, 3, 5)), data
    print("[PASS] native instruction, decompiler, signature, and heuristic emission origins", flush=True)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"[FAIL] {exc}", file=sys.stderr)
        raise SystemExit(1)
