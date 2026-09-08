#!/usr/bin/env python3
"""Record actual optimized ctree shapes and exact alias-access byte contracts."""
import argparse
import collections
import hashlib
import json
from pathlib import Path
import sys

from build_native_alias_matrix import build
from check_cpp_api_surface import run_api_command


HEADER = {(0, 2), (8, 8)}
FIELD = {(32, 4)}
CASES = {
    "native_alias_direct": HEADER | FIELD,
    "native_alias_sibling_negative": HEADER,
    "native_alias_incoming_positive": HEADER | FIELD,
    "native_alias_join_positive": HEADER | FIELD,
    "native_alias_offset_join": HEADER | {(40, 4), (48, 4)},
    "native_alias_correlated_negative": HEADER,
    "native_alias_condition_reset": HEADER | FIELD,
    "native_alias_return_negative": HEADER,
    "native_alias_loop_carried": HEADER | FIELD,
    "native_alias_loop_zero": HEADER | FIELD,
    "native_alias_switch_negative": HEADER,
    "native_alias_switch_fallthrough": HEADER | FIELD,
}
MEMORY = {"cot_ptr", "cot_idx", "cot_memptr", "cot_memref"}
# Explicit numeric ctype_t declarations from the installed IDA SDK hexrays.hpp.
STATEMENTS = {73: "if", 74: "for", 75: "while", 76: "do", 77: "switch",
              80: "return", 81: "goto", 83: "try", 84: "throw"}
CONTROL_STATEMENTS = {73, 74, 75, 76, 77}


def inspect_witness(data):
    """Report ctree identities; candidate relations are not reaching-definition proofs."""
    items = data.get("ctree", [])
    nodes = {node["id"]: node for node in items}
    children = {identifier: [] for identifier in nodes}
    for node in items:
        if node.get("parent") in children:
            children[node["parent"]].append(node["id"])
    target = data.get("pattern", {}).get("var_idx")

    def subtree(identifier):
        yield nodes[identifier]
        for child in children[identifier]:
            yield from subtree(child)

    def variable_ids(identifier):
        return {node["var_idx"] for node in subtree(identifier)
                if node.get("operation") == "cot_var"}

    def ancestors(identifier):
        result = []
        node = nodes[identifier]
        while node.get("parent") in nodes:
            node = nodes[node["parent"]]
            result.append(node)
        return result

    definitions = []
    for node in items:
        direct = children[node["id"]]
        if node.get("operation") != "cot_asg" or len(direct) != 2:
            continue
        lhs, rhs = (nodes[identifier] for identifier in direct)
        if lhs.get("operation") != "cot_var" or target not in variable_ids(rhs["id"]):
            continue
        if any(child.get("operation") in MEMORY for child in subtree(rhs["id"])):
            continue
        definitions.append({
            "node": node["id"], "var_idx": lhs["var_idx"], "text": node.get("text"),
            "rhs": rhs["id"], "reassigns_selected_base": lhs["var_idx"] == target,
            "control_ancestors": [parent["id"] for parent in ancestors(node["id"])
                                  if parent.get("opcode") in CONTROL_STATEMENTS or
                                  parent.get("operation") in {"cot_tern", "cot_land", "cot_lor"}],
        })
    memories = []
    for node in items:
        direct = children[node["id"]]
        if node.get("operation") not in MEMORY or not direct:
            continue
        variables = variable_ids(direct[0])
        matching = [definition["node"] for definition in definitions
                    if definition["var_idx"] in variables and definition["var_idx"] != target]
        memories.append({
            "node": node["id"], "text": node.get("text"),
            "address_variables": sorted(variables), "direct_base": target in variables,
            "alias_definition_candidates": matching,
            "control_ancestors": [parent["id"] for parent in ancestors(node["id"])
                                  if parent.get("opcode") in CONTROL_STATEMENTS],
        })
    conditional_definitions = {definition["node"] for definition in definitions
                               if definition["control_ancestors"]}
    mutations = []
    for node in items:
        if node.get("operation") not in {"cot_asgadd", "cot_asgsub", "cot_preinc", "cot_predec",
                                         "cot_postinc", "cot_postdec"}:
            continue
        direct = children[node["id"]]
        if not direct or nodes[direct[0]].get("operation") != "cot_var":
            continue
        controls = [parent["id"] for parent in ancestors(node["id"])
                    if parent.get("opcode") in CONTROL_STATEMENTS]
        mutations.append({"node": node["id"], "var_idx": nodes[direct[0]]["var_idx"],
                          "operation": node["operation"], "control_ancestors": controls})
    conditional_mutated_vars = {mutation["var_idx"] for mutation in mutations
                                if mutation["control_ancestors"]}
    conditional_definitions.update(definition["node"] for definition in definitions
                                   if definition["var_idx"] in conditional_mutated_vars)
    retained = any(conditional_definitions.intersection(memory["alias_definition_candidates"])
                   for memory in memories)
    selected_values = [node["id"] for node in items if node.get("operation") == "cot_tern"]
    shape = ("retained_control_alias_candidate" if retained else
             "retained_alias_candidate" if any(memory["alias_definition_candidates"] for memory in memories) else
             "conditional_expression_present" if selected_values else
             "direct_access_or_split_local_rewrite")
    return {
        "valid": bool(nodes) and len(nodes) == len(items) and not data.get("ctree_truncated"),
        "selected_base_var": target, "nodes": len(items), "shape": shape,
        "statements": dict(collections.Counter(STATEMENTS[node["opcode"]] for node in items
                           if not node.get("expression") and node.get("opcode") in STATEMENTS)),
        "ternary_nodes": selected_values, "alias_definition_candidates": definitions,
        "mutations": mutations,
        "labels": [{"node": node["id"], "label": node["label"]} for node in items
                   if node.get("label", -1) != -1],
        "gotos": [{"node": node["id"], "label": node.get("goto_label")} for node in items
                  if node.get("opcode") == 81],
        "memory_nodes": memories,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--plugin", type=Path, required=True)
    parser.add_argument("--idump", required=True)
    parser.add_argument("--architecture", action="append", choices=["arm64", "x86_64"])
    parser.add_argument("--optimization", action="append", type=int, choices=[0, 1, 2])
    parser.add_argument("--case", action="append", choices=sorted(CASES))
    parser.add_argument("--skip-build", action="store_true")
    parser.add_argument("--record-only", action="store_true")
    args = parser.parse_args()
    root = args.repo_root.resolve()
    architectures = args.architecture or ["arm64", "x86_64"]
    optimizations = args.optimization or [0, 1, 2]
    directory = root / "build/native_alias_matrix"
    if not args.skip_build:
        build(root, architectures, optimizations)
    plugin = args.plugin.resolve()
    summary = {"plugin": str(plugin), "plugin_sha256": hashlib.sha256(plugin.read_bytes()).hexdigest(),
               "cases": []}
    for architecture in architectures:
        for optimization in optimizations:
            binary = str(directory / f"test_native_alias_matrix_{architecture}_O{optimization}")
            for function in args.case or CASES:
                key = f"{architecture}_O{optimization}_{function}"
                entry = {"architecture": architecture, "optimization": optimization,
                         "function": function, "expected": sorted(CASES[function])}
                try:
                    data = run_api_command(root, plugin, args.idump, binary=binary,
                        functions=[function], command=f"inspect_base_inference|{function}|0|ctree")
                    (directory / (key + ".json")).write_text(json.dumps(data, indent=2) + "\n")
                    entry["witness"] = inspect_witness(data)
                    accesses = data.get("pattern", {}).get("accesses", [])
                    observed = {(access["offset"], access["size"]) for access in accesses}
                    entry["observed"] = sorted(observed)
                    entry["passed"] = (entry["witness"]["valid"] and observed == CASES[function]
                                       and not data.get("pattern", {}).get("has_vtable"))
                    entry["evidence"] = str(directory / (key + ".json"))
                except Exception as exception:
                    entry["passed"] = False
                    entry["error"] = str(exception)
                summary["cases"].append(entry)
                shape = entry.get("witness", {}).get("shape", "missing_ctree")
                print(f"[{'PASS' if entry['passed'] else 'FAIL'}] {key}: {shape}; "
                      f"observed={entry.get('observed')}", flush=True)
                (directory / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    count = len(summary["cases"])
    passed = sum(case["passed"] for case in summary["cases"])
    print(f"Native alias matrix: {passed}/{count} byte contracts matched", flush=True)
    if passed != count and not args.record_only:
        raise RuntimeError(f"{count - passed} native alias matrix cases failed; see {directory / 'summary.json'}")


if __name__ == "__main__":
    try:
        main()
    except Exception as exception:
        print(f"[FAIL] {exception}", file=sys.stderr)
        raise SystemExit(1)
