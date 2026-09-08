#!/usr/bin/env python3
"""Verify configured flow limits, precision provenance, and array-prefix suppression."""
import argparse
import json
import sys
from pathlib import Path
from check_cpp_api_surface import run_api_command
from check_fixture_contracts import build_fixtures


def expected_cases():
    expected = {}
    for cap in (4, 16, 64):
        for source in ("direct_alias_positive", "branch_overflow_forgets_offsets",
                       "branch_overflow_strong_definition_recovers",
                       "loop_offset_widening_avoids_truncated_array",
                       "shared_label_budget_widens_before_observation"):
            offsets, reasons, array = {4}, set(), False
            if source.startswith("branch_overflow"):
                if cap < 19:
                    reasons.add("state_budget")
                    if source == "branch_overflow_forgets_offsets":
                        offsets = set()
                elif source == "branch_overflow_forgets_offsets":
                    offsets, array = set(range(4, 73, 4)), True
            elif source.startswith("loop_offset"):
                reasons.add("state_budget")
            elif source.startswith("shared_label"):
                reasons.add("unknown_jump_entry")
                if cap < 17:
                    offsets = set()
                    reasons.add("state_budget")
                else:
                    offsets, array = set(range(4, 61, 4)), True
            expected[f"{source}_states{cap}"] = (offsets, reasons, array, cap, 65536, False)
    for steps in (1, 16, 64, 65536, 131072):
        limited = steps < 65536
        expected[f"finite_prefix_steps{steps}"] = (
            {4, 8, 12} if limited else {4, 8, 12, 16},
            {"step_budget"} if limited else set(), not limited, 16, steps, False)
    for reason in ("unknown_jump_entry", "unknown_exception_entry", "opaque_assembly"):
        expected[reason] = ({4}, {reason}, False, 16, 65536, False)
    expected["invalid_state_limit"] = (set(), set(), False, 3, 65536, True)
    expected["invalid_step_limit"] = (set(), set(), False, 16, 0, True)
    return expected


def data_arrays(synthesis):
    return [field for field in (synthesis.get("structure") or {}).get("fields", [])
            if field.get("is_array") and not field.get("is_padding")]


def verify_case(case, contract):
    offsets, reasons, has_array, cap, steps, invalid = contract
    pattern = case.get("pattern", {})
    info = pattern.get("flow_analysis", {})
    events = info.get("precision_events", [])
    observed = {(access.get("offset"), access.get("size")) for access in pattern.get("accesses", [])}
    failures = []
    if observed != {(offset, 4) for offset in offsets}:
        failures.append(f"byte evidence {sorted(observed)} != {sorted((offset, 4) for offset in offsets)}")
    if info.get("started") != (not invalid) or info.get("invalid_limits") != invalid:
        failures.append("analysis start/invalid-limit status mismatch")
    if info.get("max_states") != cap or info.get("max_steps") != steps:
        failures.append("configured limits were not preserved")
    if {event.get("reason") for event in events} != reasons:
        failures.append(f"precision reasons differ: {events}")
    exhausted = bool(reasons & {"state_budget", "step_budget"})
    if info.get("budget_exhausted") != exhausted or info.get("precision_lost") != bool(reasons):
        failures.append("loss/budget summary disagrees with provenance")
    if reasons and (info.get("widening_operations", 0) < 1 or any(
            event.get("node_ordinal", 0) < 1 or event.get("occurrences", 0) < 1 for event in events)):
        failures.append("loss lacks concrete stable ctree sites or widening counts")
    if len({(event.get("reason"), event.get("node_ordinal")) for event in events}) != len(events):
        failures.append("event ledger contains duplicate cause/site pairs")
    if "state_budget" in reasons and not any(event.get("max_states_before", 0) > cap
            for event in events if event.get("reason") == "state_budget"):
        failures.append("state exhaustion did not record its observed excess")
    if "step_budget" in reasons and info.get("executed_steps", 0) <= steps:
        failures.append("step exhaustion did not record continued execution")
    synthesis = case.get("synthesis", {})
    diagnostics = synthesis.get("flow_diagnostics", [])
    if len(diagnostics) != 1 or diagnostics[0].get("analysis") != info:
        failures.append("public synthesis result lost collection diagnostics")
    if bool(data_arrays(synthesis)) != has_array:
        failures.append("aggregate array outcome differs from contract")
    if offsets and (not synthesis.get("success") or
            synthesis.get("arrays_suppressed_by_flow_budget") != exhausted):
        failures.append("synthesis failed or hid the array-suppression decision")
    if not offsets and synthesis.get("success"):
        failures.append("empty collection unexpectedly synthesized fields")
    control = case.get("reusable_control", {})
    arrays = data_arrays(control)
    if (not control.get("success") or control.get("arrays_suppressed_by_flow_budget") or
            len(arrays) != 1 or arrays[0].get("offset") != 4 or arrays[0].get("array_count") != 4):
        failures.append("reused synthesizer did not restore the complete four-element array")
    if case.get("error") or not case.get("original_body_restored") or not case.get("repeat_metadata_equal"):
        failures.append("probe failed restoration or repeated-capture determinism")
    return failures


def verify_empty_scan(case):
    pattern = case.get("pattern", {})
    diagnostics = pattern.get("flow_diagnostics", [])
    combined = case.get("name") == "empty_local_scan_suppresses_aggregate"
    expected_count = 2 if combined else 1
    failures = []
    if len(diagnostics) != expected_count:
        failures.append("empty local scan disappeared from unified diagnostics")
    limited = [entry for entry in diagnostics if entry.get("analysis", {}).get("budget_exhausted")]
    if len(limited) != 1 or {event.get("reason") for event in limited[0].get("analysis", {}).get("precision_events", [])} != {"state_budget"}:
        failures.append("omitted scan lost its state-budget cause")
    if len({entry.get("func_ea") for entry in diagnostics}) != expected_count:
        failures.append("source identities were collapsed across local scans")
    patterns = pattern.get("per_function_patterns", [])
    observed = {(entry.get("offset"), entry.get("size")) for entry in pattern.get("accesses", [])}
    if len(patterns) != int(combined) or observed != ({(4, 4), (8, 4), (12, 4), (16, 4)} if combined else set()):
        failures.append("the empty scan unexpectedly contributed access fields")
    synthesis = case.get("synthesis", {})
    if (synthesis.get("flow_diagnostics") != diagnostics or
            not synthesis.get("arrays_suppressed_by_flow_budget") or data_arrays(synthesis) or
            synthesis.get("success") != combined):
        failures.append("unified synthesis lost omitted-scan provenance or manufactured an array")
    if (case.get("error") or not case.get("original_bodies_restored") or
            not case.get("reset_removed_old_diagnostic")):
        failures.append("cross-function probe did not restore/reset local analysis state")
    return failures


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", required=True)
    parser.add_argument("--plugin", required=True)
    parser.add_argument("--idump", default="idump")
    parser.add_argument("--record-file")
    parser.add_argument("--carrier", choices=["alias_ctree_carrier", "alias_pointer_ctree_carrier"])
    args = parser.parse_args()
    root = Path(args.repo_root).resolve()
    build_fixtures(root, "test_alias_ctree_probe")
    expected = expected_cases()
    failures, count = [], 0
    for carrier in ([args.carrier] if args.carrier else ["alias_ctree_carrier", "alias_pointer_ctree_carrier"]):
        data = run_api_command(root, Path(args.plugin).resolve(), args.idump,
            binary="test_alias_ctree_probe", functions=[carrier], command=f"check_flow_precision_ctree|{carrier}")
        if args.record_file:
            path = Path(args.record_file)
            if not args.carrier:
                path = path.with_name(path.stem + "." + carrier + path.suffix)
            path.write_text(json.dumps(data, indent=2) + "\n")
        cases = data.get("cases", [])
        if (data.get("evidence") != "constructed SDK ctree" or not data.get("success") or
                len(cases) != len(expected) or {case.get("name") for case in cases} != set(expected)):
            failures.append(carrier + ": missing, duplicated, unexpected, or unsuccessful ctree cases")
        for case in cases:
            errors = verify_case(case, expected[case["name"]])
            print(f"[{'FAIL' if errors else 'PASS'}] {carrier}: {case['name']}", flush=True)
            failures.extend(carrier + ": " + case["name"] + ": " + error for error in errors)
            count += 1
        empty_cases = data.get("empty_scan_cases", [])
        if len(empty_cases) != 2 or {case.get("name") for case in empty_cases} != {
                "empty_local_scan_is_reported", "empty_local_scan_suppresses_aggregate"}:
            failures.append(carrier + ": missing or duplicated empty-scan cases")
        for case in empty_cases:
            errors = verify_empty_scan(case)
            print(f"[{'FAIL' if errors else 'PASS'}] {carrier}: {case['name']}", flush=True)
            failures.extend(carrier + ": " + case["name"] + ": " + error for error in errors)
            count += 1
    if failures:
        raise RuntimeError("\n".join(failures))
    print(f"Flow precision regressions: PASS ({count} SDK ctree cases)", flush=True)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"[FAIL] {error}", file=sys.stderr)
        raise SystemExit(1)
