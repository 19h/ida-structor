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
    'shared_label_preserves_lexical_alias',
    'shared_label_excludes_jumped_definition',
    'shared_label_budget_widens_before_observation',
    'compound_alias_add_uses_element_scale',
    'compound_alias_sub_uses_element_scale',
    'compound_alias_signed_negative_delta',
    'compound_alias_delta_cast_is_preserved',
    'compound_alias_rhs_read_precedes_kill',
    'compound_alias_overflow_discards_offset',
    'compound_alias_minimum_subtraction_rejected',
    'postincrement_load_observes_old_address',
    'preincrement_load_observes_new_address',
    'postdecrement_load_observes_old_address',
    'predecrement_load_observes_new_address',
    'postincrement_assignment_preserves_old_result',
    'preincrement_assignment_preserves_new_result',
    'compound_assignment_result_preserves_new_address',
    'postincrement_loop_recomputes_expression_value',
    'narrowed_postincrement_result_discards_alias',
    'narrowed_conditional_update_discards_alias',
}


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
    failures = []
    total = 0
    for carrier in ([args.carrier] if args.carrier else ["alias_ctree_carrier", "alias_pointer_ctree_carrier"]):
        data = run_api_command(root, Path(args.plugin).resolve(), args.idump,
            binary="test_alias_ctree_probe", functions=[carrier],
            command=f"check_alias_flow_ctree|{carrier}")
        if args.record_file:
            path = Path(args.record_file)
            if not args.carrier:
                path = path.with_name(path.stem + "." + carrier + path.suffix)
            path.write_text(json.dumps(data, indent=2) + "\n")
        cases = data.get("cases", [])
        expected_scale = 2 if carrier == "alias_pointer_ctree_carrier" else 1
        if (data.get("evidence") != "constructed SDK ctree" or
            data.get("alias_element_size") != expected_scale or
            len(cases) != len(EXPECTED_CASES) or {case.get("name") for case in cases} != EXPECTED_CASES):
            failures.append(carrier + ": missing, duplicated, unexpected, or wrongly scaled SDK ctree cases")
        for case in cases:
            passed = case.get("passed") and case.get("original_body_restored") and not case.get("error")
            print(f"[{'PASS' if passed else 'FAIL'}] {carrier}: {case.get('name')}", flush=True)
            if not passed:
                failures.append(carrier + ": " + json.dumps(case, sort_keys=True))
        if not data.get("success"):
            failures.append(carrier + ": probe did not succeed")
        total += len(cases)
    if failures:
        raise RuntimeError("\n".join(failures))
    print(f"Alias-flow regressions: PASS ({total} SDK ctree cases)", flush=True)



if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"[FAIL] {exc}", file=sys.stderr)
        raise SystemExit(1)
