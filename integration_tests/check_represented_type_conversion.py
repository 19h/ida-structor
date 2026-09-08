#!/usr/bin/env python3
"""Verify represented-type conversion, detached diagnostics and pointer shape using idump."""
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
    require_success(run(["sh", str(root / "integration_tests/build_fixtures.sh"), "test_simple_struct"],
                        cwd=root), "building represented-type carrier")
    data = run_api_command(root, Path(args.plugin).resolve(), args.idump,
                           binary="test_simple_struct", functions=["process_simple"],
                           command="inspect_represented_types|process_simple")
    if args.record:
        Path(args.record).write_text(json.dumps(data, indent=2) + "\n")
    assert data.get("success") is True and data.get("function_unchanged") is True, data
    supported = {
        "int32": "int32", "uint64": "uint64", "bool1": "bool", "float32": "float32",
        "float64": "float64", "int32_pointer": "int32*", "int32_array": "int32[3]",
        "function_pointer": "float64(int32)*", "int32_pointer_cast": "int32*", "int32_cast": "int32",
    }
    unsupported = {
        "partial_qword": 2, "bool4": 7, "enum": 4, "anonymous_udt": 5,
        "partial_pointer": 2, "partial_array": 2, "partial_function": 2,
        "shifted_array": 10, "partial_pointer_cast": 2, "partial_qword_cast": 2,
    }
    cases = {case["name"]: case for case in data["cases"]}
    assert len(cases) == len(data["cases"]) == 23, data
    # A floating declaration projects by target storage width. Record the actual
    # carrier rather than assuming that C long double has a fixed width.
    for name in ("long_double", "extended_float"):
        width = cases[name]["source_size"]
        if width in (4, 8):
            supported[name] = "float32" if width == 4 else "float64"
        else:
            unsupported[name] = 6
    assert cases["extended_float"]["source_size"] not in (4, 8), cases["extended_float"]
    assert set(cases) == set(supported) | set(unsupported) | {"max_count_array"}, data
    for name, case in cases.items():
        if name == "max_count_array":
            # The tested SDK rejects this constructor; its nelems member itself
            # is uint32. No conversion result is claimed for an uncreated type.
            assert case["source_created"] is False and case["unknown"] is True, case
            assert case["conversion_issue"] == 1 and not case["locals"], case
            assert not case["unsupported_observations"], case
            print("[PASS] SDK max-count constructor rejection recorded", flush=True)
            continue
        assert case["source_created"] is True and case["status"] == 5 and case["success"] is True, case
        is_cast = name.endswith("_cast")
        expected_value_pointer = name in {
            "partial_pointer", "int32_pointer", "function_pointer",
            "partial_pointer_cast", "int32_pointer_cast",
        }
        assert case["address_pointer_constraints"] == (0 if is_cast else 1), case
        assert case["value_pointer_constraints"] == int(expected_value_pointer), case
        assert case["pointer_constraints"] == case["address_pointer_constraints"] + case["value_pointer_constraints"], case
        expected_width = 8 if is_cast else case["source_size"]
        expected_size_constraint = int(0 < expected_width < (1 << 32))
        assert case["size_constraints"] == expected_size_constraint, case
        if name in supported:
            assert case["unknown"] is False and case["conversion_issue"] == 0, case
            assert case["inferred"] == supported[name] and not case["unsupported_observations"], case
            assert case["concrete_pointees"] == int(not is_cast), case
            assert case["concrete_types"] == int(is_cast), case
            if not is_cast:
                assert len(case["locals"]) == 1 and case["locals"][0]["type"] == supported[name] + "*", case
        else:
            assert case["unknown"] is True and case["inferred"] == "unknown", case
            assert case["conversion_issue"] == unsupported[name], case
            assert case["concrete_pointees"] == 0 and case["concrete_types"] == 0, case
            observations = case["unsupported_observations"]
            assert len(observations) == 1, case
            observation = observations[0]
            assert observation["issue"] == unsupported[name] and observation["spelling"] == case["source"], case
            assert int(observation["site"]) > 0, case
            expected_metadata_width = case["source_size"] if case["source_size"] != (1 << 64) - 1 else None
            assert observation["byte_width"] == expected_metadata_width, case
        print(f"[PASS] SDK/public represented type: {name}", flush=True)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"[FAIL] {exc}", file=sys.stderr)
        raise SystemExit(1)
