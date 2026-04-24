#!/usr/bin/env python3

import argparse
import json
import sys
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from check_fixture_contracts import (  # noqa: E402
    build_fixtures,
    normalize_result,
    render_pseudocode_snapshot,
    run_case,
)


def function_case(
    name: str, target: str, dump_functions: list[str], *, var_idx: int = 0
):
    return {
        "name": name,
        "synth": {
            "kind": "function",
            "target": target,
            "var_idx": var_idx,
        },
        "dump_functions": dump_functions,
    }


def global_case(name: str, target: str, dump_functions: list[str]):
    return {
        "name": name,
        "synth": {
            "kind": "global",
            "target": target,
        },
        "dump_functions": dump_functions,
    }


CONTRACT_MANIFEST = [
    {
        "fixture": "test_simple_struct",
        "cases": [
            function_case(
                "process_simple", "process_simple", ["process_simple", "init_simple"]
            )
        ],
    },
    {
        "fixture": "test_function_ptr",
        "cases": [
            function_case(
                "invoke_handler",
                "invoke_handler",
                ["invoke_handler", "setup_handler", "update_and_invoke"],
            )
        ],
    },
    {
        "fixture": "test_linked_list",
        "cases": [
            function_case(
                "traverse_list",
                "traverse_list",
                ["traverse_list", "sum_list", "insert_after"],
            )
        ],
    },
    {
        "fixture": "test_mixed_access",
        "cases": [
            function_case(
                "read_mixed",
                "read_mixed",
                ["read_mixed", "write_mixed", "modify_mixed"],
            )
        ],
    },
    {
        "fixture": "test_nested",
        "cases": [
            function_case(
                "access_nested", "access_nested", ["access_nested", "modify_array"]
            )
        ],
    },
    {
        "fixture": "test_nested_2d",
        "cases": [
            function_case("read_matrix", "read_matrix", ["read_matrix", "read_marks"])
        ],
    },
    {
        "fixture": "test_substructure",
        "cases": [
            function_case(
                "process_data", "process_data", ["process_data", "process_node_d"]
            )
        ],
    },
    {
        "fixture": "test_callgraph_return",
        "cases": [
            function_case(
                "process_root",
                "process_root",
                ["process_root", "sibling_reader", "make_sub"],
            ),
            function_case("process_sub", "process_sub", ["process_sub"]),
        ],
    },
    {
        "fixture": "test_cross_conflict_union",
        "cases": [
            function_case(
                "process_conflict",
                "process_conflict",
                ["process_conflict", "read_payload_whole", "read_payload_split"],
            )
        ],
    },
    {
        "fixture": "test_packed_struct",
        "cases": [
            function_case(
                "read_packed",
                "read_packed",
                ["read_packed", "read_small_array", "inspect_flag_slices"],
            )
        ],
    },
    {
        "fixture": "test_packed_nested_array",
        "cases": [
            function_case("read_bundle", "read_bundle", ["read_bundle", "read_tail"])
        ],
    },
    {
        "fixture": "test_packed_union_overlap",
        "cases": [
            function_case("read_whole", "read_whole", ["read_whole", "read_parts"])
        ],
    },
    {
        "fixture": "test_negative_offsets",
        "cases": [
            function_case("consume_window", "consume_window", ["consume_window"])
        ],
    },
    {
        "fixture": "test_array_of_structs",
        "cases": [
            function_case(
                "read_table",
                "read_table",
                ["read_table", "update_tag", "read_checksum"],
            )
        ],
    },
    {
        "fixture": "test_array_of_structs_nested",
        "cases": [
            function_case(
                "read_packets",
                "read_packets",
                ["read_packets", "write_packet_byte", "read_footer"],
            )
        ],
    },
    {
        "fixture": "test_bounded_index",
        "cases": [
            function_case(
                "read_indexed", "read_indexed", ["read_indexed", "read_marks"]
            )
        ],
    },
    {
        "fixture": "test_enum_constants",
        "cases": [
            function_case(
                "inspect_mode", "inspect_mode", ["inspect_mode", "inspect_state"]
            )
        ],
    },
    {
        "fixture": "test_flags_union",
        "cases": [
            function_case(
                "inspect_header",
                "inspect_header",
                [
                    "inspect_header",
                    "inspect_float_view",
                    "inspect_bits",
                    "inspect_bytes",
                ],
            )
        ],
    },
    {
        "fixture": "test_callback_table",
        "cases": [
            function_case(
                "invoke_slot0",
                "invoke_slot0",
                ["invoke_slot0", "invoke_slot2", "read_states"],
            )
        ],
    },
    {
        "fixture": "test_indirect_shifted_call",
        "cases": [
            function_case(
                "dispatch_parent",
                "dispatch_parent",
                ["dispatch_parent", "invoke_child"],
            )
        ],
    },
    {
        "fixture": "test_local_alias_positive",
        "cases": [
            function_case(
                "use_alias_read",
                "use_alias_read",
                ["use_alias_read", "use_alias_chain"],
            )
        ],
    },
    {
        "fixture": "test_pointer_field_pointee",
        "cases": [
            function_case(
                "use_pointer_field",
                "use_pointer_field",
                ["use_pointer_field"],
            )
        ],
    },
    {
        "fixture": "test_alias_lifetime",
        "cases": [
            function_case(
                "alias_rebind_read",
                "alias_rebind_read",
                ["alias_rebind_read"],
            ),
            function_case(
                "alias_overwrite_read",
                "alias_overwrite_read",
                ["alias_overwrite_read"],
            ),
        ],
    },
    {
        "fixture": "test_pointer_constants",
        "cases": [
            function_case(
                "configure_and_invoke",
                "configure_and_invoke",
                ["configure_and_invoke"],
            )
        ],
    },
    {
        "fixture": "test_mixed_subobject_deltas",
        "cases": [
            function_case(
                "read_mixed_anchor",
                "read_mixed_anchor",
                ["read_mixed_anchor", "read_child"],
            )
        ],
    },
    {
        "fixture": "test_shifted_siblings",
        "cases": [
            function_case(
                "process_parent",
                "process_parent",
                ["process_parent", "consume_child"],
            )
        ],
    },
    {
        "fixture": "test_recursive_ctor_chain",
        "cases": [
            function_case(
                "root_init",
                "root_init",
                ["root_init", "child_init", "leaf_init", "use_root"],
            )
        ],
    },
    {
        "fixture": "test_tree_struct",
        "cases": [
            function_case(
                "sum_children",
                "sum_children",
                ["sum_children", "walk_two_levels"],
            )
        ],
    },
    {
        "fixture": "test_partial_overlap",
        "cases": [
            function_case(
                "read_overlap",
                "read_overlap",
                ["read_overlap", "read_shifted_overlap"],
            )
        ],
    },
    {
        "fixture": "test_vtable_direct",
        "cases": [
            function_case(
                "access_object_fields",
                "access_object_fields",
                ["access_object_fields", "modify_object_fields", "increment_fields"],
            )
        ],
    },
    {
        "fixture": "test_vtable_positive",
        "cases": [
            function_case(
                "call_vtable_direct",
                "__Z18call_vtable_directPv",
                ["__Z18call_vtable_directPv", "__Z19call_multiple_slotsPvi"],
            )
        ],
    },
    {
        "fixture": "test_vtable",
        "cases": [
            function_case(
                "call_through_vtable",
                "__Z19call_through_vtablePv",
                ["__Z19call_through_vtablePv", "__Z12access_valuePv"],
            ),
            function_case(
                "main_dispatch_object",
                "main",
                ["main", "__Z19call_through_vtablePv", "__Z12access_valuePv"],
                var_idx=4,
            ),
        ],
    },
    {
        "fixture": "test_global_ctor_chain",
        "cases": [
            global_case(
                "g_widget",
                "g_widget",
                ["widget_ctor", "widget_use_global", "widget_use_leaf"],
            )
        ],
    },
    {
        "fixture": "test_global_ctor_return",
        "cases": [
            global_case("g_session", "g_session", ["session_ctor", "consume_session"])
        ],
    },
    {
        "fixture": "test_global_split_init",
        "cases": [
            global_case(
                "g_device",
                "g_device",
                ["device_header_ctor", "device_attach_cookie", "device_publish_slots"],
            )
        ],
    },
    {
        "fixture": "test_global_subobject_chain",
        "cases": [global_case("g_manager", "g_manager", ["manager_ctor"])],
    },
    {
        "fixture": "test_global_recursive_ctor_chain",
        "cases": [
            global_case(
                "g_root",
                "g_root",
                ["install_root", "root_ctor", "child_ctor", "leaf_ctor", "use_root"],
            )
        ],
    },
    {
        "fixture": "test_global_pointer_singleton",
        "cases": [
            global_case(
                "g_state_storage", "g_state_storage", ["state_ctor", "use_state"]
            )
        ],
    },
    {
        "fixture": "test_global_placement_new",
        "cases": [
            global_case(
                "g_gadget_storage",
                "g_gadget_storage",
                ["__Z23construct_gadget_stage1v", "__Z10use_gadgetv"],
            )
        ],
    },
    {
        "fixture": "test_global_adjacent_objects",
        "cases": [
            global_case(
                "g_dual_arena",
                "g_dual_arena",
                ["build_left", "build_right", "use_left", "use_right"],
            )
        ],
    },
    {
        "fixture": "test_global_cpp_static_ctor",
        "cases": [
            global_case(
                "g_engine",
                "g_engine",
                ["__Z12drive_enginev", "__Z14inspect_enginev"],
            )
        ],
    },
    {
        "fixture": "test_global_ambiguous_scratch",
        "cases": [
            global_case(
                "g_scratch",
                "g_scratch",
                ["fill_scratch", "scramble_scratch", "checksum_scratch"],
            )
        ],
    },
    {
        "fixture": "test_static_local_singleton",
        "cases": [
            global_case(
                "local_cache",
                "__ZZL15get_local_cachevE5cache",
                ["__Z16warm_local_cachev", "__Z16read_local_cachev"],
            )
        ],
    },
]


def generate_contracts(
    repo_root: Path,
    plugin_path: Path,
    idump_path: str,
    contracts_dir: Path,
    selected_fixtures: set[str],
) -> None:
    manifest = [
        entry
        for entry in CONTRACT_MANIFEST
        if not selected_fixtures or entry["fixture"] in selected_fixtures
    ]
    if not manifest:
        raise RuntimeError("no fixture entries selected for contract generation")

    build_fixtures(repo_root, *(entry["fixture"] for entry in manifest))
    contracts_dir.mkdir(parents=True, exist_ok=True)

    for entry in manifest:
        fixture_name = entry["fixture"]
        contract = {"fixture": fixture_name, "cases": []}

        for case in entry["cases"]:
            raw_result, raw_output = run_case(
                repo_root,
                plugin_path,
                idump_path,
                fixture_name,
                case,
                debug_mode=False,
            )
            contract["cases"].append(
                {
                    "name": case["name"],
                    "synth": case["synth"],
                    "dump_functions": case["dump_functions"],
                    "golden_result": normalize_result(raw_result),
                    "golden_pseudocode": render_pseudocode_snapshot(
                        raw_output,
                        case.get("snapshot_functions")
                        or case.get("dump_functions")
                        or [],
                    ),
                }
            )
            print(f"[RECORDED] {fixture_name}/{case['name']}")

        output_path = contracts_dir / f"{fixture_name}.json"
        output_path.write_text(
            json.dumps(contract, indent=2, sort_keys=False) + "\n",
            encoding="utf-8",
        )
        print(f"[WROTE] {output_path}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate exact live fixture contracts from the current blessed baseline"
    )
    parser.add_argument("--repo-root", required=True)
    parser.add_argument("--plugin", required=True)
    parser.add_argument("--idump", default="idump")
    parser.add_argument(
        "--contracts-dir",
        default="integration_tests/contracts",
        help="Destination directory for generated contract JSON files",
    )
    parser.add_argument(
        "--fixture",
        action="append",
        default=[],
        help="Only regenerate the named fixture contract (can be repeated)",
    )
    args = parser.parse_args()

    repo_root = Path(args.repo_root).resolve()
    plugin_path = Path(args.plugin).resolve()
    contracts_dir = (repo_root / args.contracts_dir).resolve()
    if not plugin_path.exists():
        raise RuntimeError(f"plugin not found: {plugin_path}")

    generate_contracts(
        repo_root,
        plugin_path,
        args.idump,
        contracts_dir,
        set(args.fixture),
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"[FAIL] {exc}", file=sys.stderr)
        raise SystemExit(1)
