#!/usr/bin/env python3
"""Verify native global flow diagnostics through ordinary public API commands.

Assumptions and probes:
A1: The native carrier retains a conditional local alias. Default/low-budget
    offset pairs establish that the final load depends on retained flow state.
A2: JSON diagnostics describe actual local scans. Started state, target identity,
    configured limit, executed steps and concrete cause/site events are checked.
A3: Ordinary preview exposes TIDs and propagation results, not a complete IDB
    type-state snapshot. BADADDR TIDs and no propagation are the checked scope.
Impact: truncated array synthesis and dropped failure diagnostics are high-impact
    interpretation errors; this checker does not establish global type recovery.
Provenance: test_global_flow_budget.c, AccessCollector and public API exporters.
All offsets and widths are bytes. Runtime is 12 serialized idump calls, each
    bounded by the shared harness timeout; validation is linear in JSON size.
"""
import argparse
import hashlib
import json
import sys
from pathlib import Path
from check_cpp_api_surface import BADADDR, require_success, run, run_api_command


ROOTS = {
    "complete": "g_flow_complete",
    "insufficient": "g_flow_insufficient",
    "empty": "g_flow_empty",
}


def arrays(synthesis):
    return [(field["offset"], field["array_count"])
            for field in (synthesis.get("structure") or {}).get("fields", [])
            if field.get("is_array") and not field.get("is_padding")]


def result_parts(data, operation):
    if operation == "analyze":
        analysis = data.get("analysis", {})
        return analysis, analysis.get("pattern", {}), analysis.get("synthesis", {})
    result = data.get("result", {})
    return result, None, result


def verify_diagnostics(diagnostics, *, limited):
    errors = []
    if not diagnostics:
        return ["actual local scans disappeared from the global diagnostic ledger"]
    expected_steps = 1 if limited else 65536
    exhausted_scans = 0
    for record in diagnostics:
        info = record.get("analysis", {})
        if record.get("func_ea", BADADDR) == BADADDR or record.get("var_idx", -1) < 0:
            errors.append("local scan identity is invalid")
        if not info.get("started") or info.get("invalid_limits"):
            errors.append("the recorded scan did not start with valid limits")
        if info.get("max_states") != 16 or info.get("max_steps") != expected_steps:
            errors.append("configured flow limits were not preserved")
        events = info.get("precision_events", [])
        reasons = {event.get("reason") for event in events}
        exceeded = info.get("executed_steps", 0) > expected_steps
        if limited and exceeded:
            exhausted_scans += 1
            if not info.get("budget_exhausted") or not info.get("precision_lost") or "step_budget" not in reasons:
                errors.append("step exhaustion or its precision consequence was dropped")
            if info.get("widening_operations", 0) < 1:
                errors.append("budget loss lacks widening evidence")
            if any(event.get("node_ordinal", 0) < 1 or event.get("occurrences", 0) < 1
                   for event in events):
                errors.append("precision events lack stable ctree sites or occurrence counts")
        elif info.get("budget_exhausted") or info.get("precision_lost") or reasons:
            errors.append("a scan within its configured budget unexpectedly lost precision")
    if limited and exhausted_scans == 0:
        errors.append("limited native consumer lacks its actual exhausted scan")
    return errors


def verify_case(data, shape, limited, operation, baseline):
    outcome, pattern, synthesis = result_parts(data, operation)
    success = shape == "complete" or (shape == "insufficient" and not limited)
    expected_offsets = {
        ("complete", False): {0, 4, 8, 12}, ("complete", True): {0, 4, 8},
        ("insufficient", False): {0, 4}, ("insufficient", True): {0},
        ("empty", False): set(), ("empty", True): set(),
    }[(shape, limited)]
    errors = []
    if outcome.get("success") != success:
        errors.append("success/failure differs from native evidence count")
    expected_error = ("Success" if success else "No dereferences found for variable"
                      if shape == "empty" else "Insufficient accesses for synthesis")
    if outcome.get("error") != expected_error:
        errors.append("failure category does not match the observed access threshold")
    diagnostics = synthesis.get("flow_diagnostics", [])
    if pattern is not None:
        observed = {(entry.get("offset"), entry.get("size")) for entry in pattern.get("accesses", [])}
        if observed != {(offset, 4) for offset in expected_offsets}:
            errors.append(f"native access evidence {sorted(observed)} != {sorted(expected_offsets)} x 4 B")
        if pattern.get("flow_diagnostics", []) != diagnostics:
            errors.append("global analysis did not carry the full ledger into synthesis metadata")
        # These fixture failures are threshold exits before layout. They must
        # not export a successful embedded synthesis that was never performed.
        expected_embedded_error = "Success" if baseline and not success else expected_error
        expected_embedded_success = True if baseline and not success else success
        if synthesis.get("error") != expected_embedded_error or synthesis.get("success") != expected_embedded_success:
            errors.append("pre-layout embedded synthesis status contradicts the outer analysis result")
        if not baseline:
            source_units = {(entry.get("func_ea"), entry.get("var_idx")) for entry in diagnostics}
            target_units = {(entry.get("func_ea"), entry.get("var_idx"))
                            for entry in outcome.get("zero_delta_variables", [])
                            if (entry.get("func_name") or "").lstrip("_") == f"global_flow_{shape}_consumer"}
            if not target_units or not source_units.issuperset(target_units):
                errors.append("unshifted native consumer lacks its attempted-scan record")
    if baseline:
        if diagnostics:
            errors.append("frozen baseline unexpectedly retained the global ledger")
    else:
        errors.extend(verify_diagnostics(diagnostics, limited=limited))
    expected_arrays = [(0, 4)] if shape == "complete" and not limited else []
    if baseline and shape == "complete" and limited:
        expected_arrays = [(0, 3)]
    if arrays(synthesis) != expected_arrays:
        errors.append(f"array result {arrays(synthesis)} != {expected_arrays}")
    # Failure exits occur before layout; they retain diagnostics but have not
    # executed an array-suppression pass. The decision flag can remain false.
    expected_suppression = limited and success and not baseline
    if synthesis.get("arrays_suppressed_by_flow_budget") != expected_suppression:
        errors.append("array-suppression decision differs from the executed layout path")
    if synthesis.get("struct_tid") != BADADDR or synthesis.get("vtable_tid") != BADADDR:
        errors.append("read-only/preview operation returned a persisted type ID")
    if synthesis.get("propagated_to"):
        errors.append("read-only/preview operation reported applied propagation")
    return errors, diagnostics


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", required=True)
    parser.add_argument("--plugin", required=True)
    parser.add_argument("--idump", default="idump")
    parser.add_argument("--record-file")
    parser.add_argument("--expect-baseline-loss", action="store_true",
                        help="require the frozen missing-ledger/truncated-array counterexample")
    args = parser.parse_args()
    root = Path(args.repo_root).resolve()
    plugin = Path(args.plugin).resolve()
    require_success(run(["sh", str(root / "integration_tests/build_fixtures.sh"), "test_global_flow_budget"],
                        cwd=root), "building native global-flow fixture")
    record = {"evidence": "native SDK ctree through ordinary public global commands",
              "baseline_loss_expected": args.expect_baseline_loss,
              "plugin_sha256": hashlib.sha256(plugin.read_bytes()).hexdigest(), "cases": []}
    failures = []
    for shape, target in ROOTS.items():
        for limited in (False, True):
            paired_diagnostics = []
            for operation in ("analyze", "preview"):
                name = f"{shape}_{'limited' if limited else 'default'}_{operation}"
                command = (f"analyze_global_structure|{target}" if operation == "analyze"
                           else f"synthesize_global_structure|{target}|preview")
                data = run_api_command(root, plugin, args.idump, binary="test_global_flow_budget",
                    functions=[f"global_flow_{shape}_consumer", f"global_flow_{shape}_entry"],
                    command=command, config_overrides={"flow_max_steps": 1} if limited else None)
                errors, diagnostics = verify_case(data, shape, limited, operation, args.expect_baseline_loss)
                paired_diagnostics.append(diagnostics)
                record["cases"].append({"name": name, "data": data, "failures": errors})
                failures.extend(name + ": " + error for error in errors)
                print(f"[{'FAIL' if errors else 'PASS'}] global flow: {name}", flush=True)
            if paired_diagnostics[0] != paired_diagnostics[1]:
                failures.append(f"{shape}/{limited}: preview did not preserve the analysis scan ledger")
    if args.record_file:
        Path(args.record_file).write_text(json.dumps(record, indent=2) + "\n")
    if failures:
        raise RuntimeError("\n".join(failures))
    print("Global flow precision: PASS (12 native public-command cases)", flush=True)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"[FAIL] {error}", file=sys.stderr)
        raise SystemExit(1)
