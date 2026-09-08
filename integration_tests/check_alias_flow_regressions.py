#!/usr/bin/env python3
"""Verify branch-sensitive reaching aliases using production collection on SDK ctree."""
import argparse
import json
import sys
from pathlib import Path
from check_cpp_api_surface import run_api_command
from check_fixture_contracts import build_fixtures

EXPECTED_CASES = {
    'direct_alias_positive',
    'sibling_alias_contamination_negative',
    'sibling_incoming_alias_positive',
    'merge_possible_alias_positive',
    'merge_identical_alias_positive',
    'loop_carried_alias_positive',
    'divergent_offset_join_positive',
    'identical_offset_join_positive',
    'complementary_condition_negative',
    'condition_reassignment_positive',
    'distinct_branch_epochs_positive',
    'distinct_branch_epochs_negative',
    'same_branch_reassignment_kills_alias',
    'returning_branch_contamination_negative',
    'returning_branch_incoming_positive',
    'conditional_expression_join_positive',
    'conditional_expression_sibling_negative',
    'conditional_expression_incoming_positive',
    'short_circuit_complement_negative',
    'loop_zero_iteration_incoming_positive',
    'nonterminating_branch_has_no_exit_alias',
    'loop_constant_write_prevents_backedge',
    'loop_known_counter_prevents_backedge',
    'loop_compound_counter_prevents_backedge',
    'scalar_truncation_zero_positive',
    'scalar_truncation_nonzero_negative',
    'scalar_arithmetic_zero_positive',
    'signed_operator_high_bit_negative',
    'unsigned_operator_high_bit_positive',
    'loop_break_preserves_reaching_alias',
    'loop_continue_skips_alias_definition',
    'do_loop_first_body_positive',
    'do_loop_exit_definition_positive',
    'loop_offset_widening_avoids_truncated_array',
    'branch_overflow_forgets_offsets',
    'branch_overflow_strong_definition_recovers',
    'switch_break_isolates_sibling_alias',
    'switch_fallthrough_alias_positive',
    'switch_incoming_sibling_alias_positive',
    'switch_case_predicate_survives_join',
    'switch_default_excludes_explicit_value',
    'switch_no_default_preserves_incoming',
    'goto_bypassed_definition_not_reaching',
    'goto_label_strong_definition_recovers',
    'goto_skips_unreachable_load',
    'irreducible_goto_entries_forget_lexical_alias',
    'finally_kills_alias_before_continuation',
    'finally_defines_alias_for_continuation',
    'finally_observes_returning_alias',
    'finally_return_skips_continuation',
    'wind_cleanup_does_not_replace_normal_alias',
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", required=True)
    parser.add_argument("--plugin", required=True)
    parser.add_argument("--idump", default="idump")
    parser.add_argument("--record-file")
    args = parser.parse_args()
    root = Path(args.repo_root).resolve()
    build_fixtures(root, "test_alias_ctree_probe")
    data = run_api_command(root, Path(args.plugin).resolve(), args.idump,
        binary="test_alias_ctree_probe", functions=["alias_ctree_carrier"],
        command="check_alias_flow_ctree|alias_ctree_carrier")
    if args.record_file:
        Path(args.record_file).write_text(json.dumps(data, indent=2) + "\n")
    cases = data.get("cases", [])
    failures = []
    if (data.get("evidence") != "constructed SDK ctree" or
        len(cases) != len(EXPECTED_CASES) or {case.get("name") for case in cases} != EXPECTED_CASES):
        failures.append("missing, duplicated, or unexpected constructed ctree cases")
    for case in cases:
        passed = case.get("passed") and case.get("original_body_restored") and not case.get("error")
        print(f"[{'PASS' if passed else 'FAIL'}] {case.get('name')}", flush=True)
        if not passed:
            failures.append(json.dumps(case, sort_keys=True))
    if failures or not data.get("success"):
        raise RuntimeError("\n".join(failures) or "probe did not succeed")
    print(f"Alias-flow regressions: PASS ({len(cases)} SDK ctree cases)", flush=True)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"[FAIL] {exc}", file=sys.stderr)
        raise SystemExit(1)
