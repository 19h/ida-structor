#!/usr/bin/env python3
"""Verify selected type evidence and application decisions through the public IDA API."""
import argparse
import json
from pathlib import Path
from check_cpp_api_surface import require_success, run, run_api_command

CASES = (
    "hard_scalar", "hard_scalar_bounded_soft", "hard_compound", "hard_alias_chain", "soft_scalar",
    "size_only", "bounded_unique", "zero_query_budget", "zero_time_budget",
    "soft_deep", "hard_apply", "soft_apply_default", "soft_apply_optin",
    "bounded_apply_default", "budget_apply_default", "external_apply",
)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", required=True)
    parser.add_argument("--plugin", required=True)
    parser.add_argument("--idump", default="idump")
    parser.add_argument("--record-dir")
    args = parser.parse_args()
    root = Path(args.repo_root).resolve()
    records = Path(args.record_dir).resolve() if args.record_dir else None
    if records: records.mkdir(parents=True, exist_ok=True)
    require_success(run(["sh", str(root / "integration_tests/build_fixtures.sh"),
                         "test_simple_struct"], cwd=root), "building model-evidence fixture")
    for scenario in CASES:
        data = run_api_command(root, Path(args.plugin).resolve(), args.idump,
            binary="test_simple_struct", functions=["process_simple"],
            command=f"inspect_type_model_evidence|process_simple|{scenario}")
        if records: (records / (scenario + ".json")).write_text(json.dumps(data, indent=2) + "\n")
        expected = {"public_inference_succeeded", "default_conversion", "inference_preserved_ctree"}
        if scenario != "external_apply":
            expected |= {"model_status", "domain_qualification", "alternative_witness",
                         "query_budget", "confidence_category"}
        if scenario != "size_only": expected |= {"complete_candidate", "explicit_candidate_conversion"}
        if scenario == "hard_scalar_bounded_soft": expected.add("soft_only_domain_is_separate")
        if "apply" in scenario:
            expected.add("application_decision")
            if scenario in {"hard_apply", "soft_apply_optin", "external_apply"}:
                expected.add("actual_requested_type")
            else: expected |= {"saved_type_unchanged", "locals_unchanged"}
        assert data.get("success") is True, data
        assert set(data.get("checks", {})) == expected, data
        assert all(value is True for value in data["checks"].values()), data
        print(f"[PASS] public model evidence: {scenario}", flush=True)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
