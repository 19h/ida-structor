#!/usr/bin/env python3

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


BADADDR = (1 << 64) - 1


def log(message: str) -> None:
    print(message, flush=True)


def hr(char: str = "-", width: int = 78) -> str:
    return char * width


def run(
    cmd: list[str], *, cwd: Path | None = None, env: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, cwd=cwd, env=env, text=True, capture_output=True)


def expand_function_filters(functions: list[str]) -> list[str]:
    expanded: list[str] = []
    for name in functions:
        if name not in expanded:
            expanded.append(name)
        if name and not name.startswith("_"):
            prefixed = f"_{name}"
            if prefixed not in expanded:
                expanded.append(prefixed)
    return expanded


def require_success(proc: subprocess.CompletedProcess[str], description: str) -> None:
    if proc.returncode == 0:
        return
    output = (proc.stdout or "") + (proc.stderr or "")
    raise RuntimeError(f"{description} failed\n{output}")


def build_required_fixtures(repo_root: Path) -> None:
    fixtures = [
        "test_simple_struct",
        "test_substructure",
        "test_global_pointer_singleton",
        "test_vtable_positive",
        "test_overlap_scope",
        "test_local_alias_positive",
    ]
    log(hr("="))
    log("Building C++ API surface fixtures")
    log("  " + ", ".join(fixtures))
    proc = run(
        ["sh", str(repo_root / "integration_tests" / "build_fixtures.sh"), *fixtures],
        cwd=repo_root,
    )
    require_success(proc, "building C++ API fixtures")


def link_license_files(real_home: Path, sandbox_home: Path) -> None:
    real_idapro = real_home / ".idapro"
    sandbox_idapro = sandbox_home / ".idapro"
    sandbox_idapro.mkdir(parents=True, exist_ok=True)

    matched: list[Path] = []
    for pattern in ("ida.reg", "*.hexlic", "*.lic"):
        matched.extend(real_idapro.glob(pattern))

    if not matched:
        raise RuntimeError(f"no IDA license files found in {real_idapro}")

    for src in matched:
        dst = sandbox_idapro / src.name
        if not dst.exists():
            os.symlink(src, dst)


def prepare_plugin_home(plugin_path: Path, real_home: Path) -> Path:
    sandbox_home = Path(tempfile.mkdtemp(prefix="structor-api-idump-home."))
    sandbox_plugins = sandbox_home / ".idapro" / "plugins"
    sandbox_plugins.mkdir(parents=True, exist_ok=True)

    link_license_files(real_home, sandbox_home)

    plugin_dst = sandbox_plugins / plugin_path.name
    shutil.copy2(plugin_path, plugin_dst)

    if sys.platform == "darwin":
        proc = run(["codesign", "-s", "-", "-f", str(plugin_dst)])
        require_success(proc, f"codesigning {plugin_dst}")

    config_path = sandbox_home / ".idapro" / "structor.cfg"
    config_path.write_text(
        "\n".join(
            [
                "debug_mode=false",
                "auto_fix_types=false",
                "auto_fix_verbose=false",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    return sandbox_home


def function_names(entries: list[dict]) -> set[str]:
    result: set[str] = set()
    for entry in entries:
        name = entry.get("name") or entry.get("func_name") or ""
        if not name:
            continue
        result.add(name)
        if name.startswith("_"):
            result.add(name[1:])
    return result


def require(condition: bool, message: str, payload: dict | None = None) -> None:
    if condition:
        return
    suffix = ""
    if payload is not None:
        suffix = "\n" + json.dumps(payload, indent=2, sort_keys=True)
    raise RuntimeError(message + suffix)


def run_api_command(
    repo_root: Path,
    plugin_path: Path,
    idump_path: str,
    *,
    binary: str,
    functions: list[str],
    command: str,
) -> dict:
    real_home = Path.home()
    sandbox_home = prepare_plugin_home(plugin_path, real_home)
    result_path = Path(tempfile.mkdtemp(prefix="structor-api-result.")) / "result.json"
    binary_path = repo_root / "integration_tests" / binary
    if not binary_path.exists():
        raise RuntimeError(f"fixture binary not found: {binary_path}")
    run_dir = Path(tempfile.mkdtemp(prefix="structor-api-binary."))
    run_binary = run_dir / binary_path.name
    shutil.copy2(binary_path, run_binary)

    try:
        env = os.environ.copy()
        env["HOME"] = str(sandbox_home)
        env["STRUCTOR_AUTO_API"] = command
        env["STRUCTOR_EXPORT_API_RESULT"] = str(result_path)

        cmd = [
            idump_path,
            "--plugin",
            "structor",
            "--pseudo-only",
            "-F",
            ",".join(expand_function_filters(functions)),
            str(run_binary),
        ]
        proc = run(cmd, cwd=repo_root, env=env)
        require_success(proc, f"running API command {command}")

        if not result_path.exists():
            output = (proc.stdout or "") + (proc.stderr or "")
            raise RuntimeError(f"missing API result export for {command}\n{output}")

        return json.loads(result_path.read_text(encoding="utf-8"))
    finally:
        shutil.rmtree(sandbox_home, ignore_errors=True)
        shutil.rmtree(result_path.parent, ignore_errors=True)
        shutil.rmtree(run_dir, ignore_errors=True)


def check_local_layout(repo_root: Path, plugin_path: Path, idump_path: str) -> None:
    log(hr("="))
    log("API: local access collection and layout synthesis")
    data = run_api_command(
        repo_root,
        plugin_path,
        idump_path,
        binary="test_simple_struct",
        functions=["process_simple"],
        command="synthesize_layout_local|process_simple|0",
    )
    pattern = data["pattern"]
    structure = data["structure"]
    offsets = {access["offset"] for access in pattern["accesses"]}
    require(data["success"], "local layout synthesis failed", data)
    require(pattern["access_count"] == 3, "expected 3 local accesses", data)
    require(offsets == {0, 8, 16}, "unexpected local access offsets", data)
    require(structure["size"] == 24, "expected 24-byte synthesized layout", data)
    require(
        structure["non_padding_field_count"] == 3, "expected 3 non-padding fields", data
    )


def check_vtable_detection(repo_root: Path, plugin_path: Path, idump_path: str) -> None:
    log(hr("="))
    log("API: vtable detection")
    data = run_api_command(
        repo_root,
        plugin_path,
        idump_path,
        binary="test_vtable_positive",
        functions=["__Z18call_vtable_directPv"],
        command="detect_vtable|__Z18call_vtable_directPv|0",
    )
    vtable = data["vtable"]
    require(data["success"], "vtable detection failed", data)
    require(vtable is not None, "expected vtable details", data)
    require(
        vtable["slot_count"] >= 1, "expected at least one detected vtable slot", data
    )


def check_variable_analysis_and_modes(
    repo_root: Path, plugin_path: Path, idump_path: str
) -> None:
    log(hr("="))
    log("API: variable analysis and synthesis modes")

    analysis = run_api_command(
        repo_root,
        plugin_path,
        idump_path,
        binary="test_simple_struct",
        functions=["process_simple"],
        command="analyze_structure|process_simple|0",
    )
    require(analysis["success"], "variable analysis failed", analysis)
    require(
        analysis["analysis"]["synthesis"]["structure"]["non_padding_field_count"] == 3,
        "expected analyzed structure with 3 non-padding fields",
        analysis,
    )

    preview = run_api_command(
        repo_root,
        plugin_path,
        idump_path,
        binary="test_simple_struct",
        functions=["process_simple"],
        command="synthesize_structure|process_simple|0|preview",
    )
    preview_result = preview["result"]
    require(preview_result["success"], "preview synthesis failed", preview)
    require(
        preview_result["struct_tid"] == BADADDR,
        "preview mode should not create a type",
        preview,
    )
    require(
        preview_result["structure"] is not None,
        "preview mode should return synthesized structure",
        preview,
    )

    persist = run_api_command(
        repo_root,
        plugin_path,
        idump_path,
        binary="test_simple_struct",
        functions=["process_simple"],
        command="synthesize_structure|process_simple|0|persist",
    )
    persist_result = persist["result"]
    require(persist_result["success"], "persist synthesis failed", persist)
    require(
        persist_result["struct_tid"] != BADADDR,
        "persist mode should create a type",
        persist,
    )
    require(
        not persist_result["propagated_to"],
        "persist mode should not propagate",
        persist,
    )

    apply = run_api_command(
        repo_root,
        plugin_path,
        idump_path,
        binary="test_simple_struct",
        functions=["process_simple"],
        command="synthesize_structure|process_simple|0|apply",
    )
    apply_result = apply["result"]
    require(apply_result["success"], "apply synthesis failed", apply)
    require(
        apply_result["struct_tid"] != BADADDR, "apply mode should create a type", apply
    )
    require(
        "process_simple" in function_names(apply_result["propagated_to"]),
        "apply mode should type the origin function",
        apply,
    )


def check_function_surface(repo_root: Path, plugin_path: Path, idump_path: str) -> None:
    log(hr("="))
    log("API: function-wide structure analysis and synthesis")

    analysis = run_api_command(
        repo_root,
        plugin_path,
        idump_path,
        binary="test_simple_struct",
        functions=["process_simple"],
        command="analyze_function_structures|process_simple",
    )
    analysis_result = analysis["result"]
    require(analysis_result["success"], "function-wide analysis failed", analysis)
    require(
        analysis_result["total_variables"] >= 2,
        "expected at least two function variables",
        analysis,
    )
    require(
        analysis_result["succeeded"] >= 1,
        "expected at least one synthesizable variable",
        analysis,
    )

    synthesis = run_api_command(
        repo_root,
        plugin_path,
        idump_path,
        binary="test_simple_struct",
        functions=["process_simple"],
        command="synthesize_function_structures|process_simple|apply",
    )
    synthesis_result = synthesis["result"]
    require(synthesis_result["success"], "function-wide synthesis failed", synthesis)
    require(
        synthesis_result["succeeded"] >= 1,
        "expected at least one successful bulk synthesis result",
        synthesis,
    )


def check_unified_and_propagation(
    repo_root: Path, plugin_path: Path, idump_path: str
) -> None:
    log(hr("="))
    log("API: unified cross-function analysis and propagation")

    unified = run_api_command(
        repo_root,
        plugin_path,
        idump_path,
        binary="test_substructure",
        functions=["process_data", "process_node_d", "setup_links"],
        command="synthesize_layout_unified|process_data|0",
    )
    pattern = unified["pattern"]
    result = unified["result"]
    offsets = {access["offset"] for access in pattern["accesses"]}
    names = function_names(pattern["contributing_functions"])
    require(unified["success"], "unified layout synthesis failed", unified)
    require(
        pattern["unique_access_locations"] >= 4,
        "expected at least four unified access locations",
        unified,
    )
    require(
        {0, 8, 16, 20}.issubset(offsets), "expected normalized unified offsets", unified
    )
    require(
        {"process_data", "process_node_d", "setup_links"}.issubset(names),
        "missing contributing functions",
        unified,
    )
    require(
        result["structure"]["non_padding_field_count"] >= 3,
        "expected at least three unified fields",
        unified,
    )

    propagated = run_api_command(
        repo_root,
        plugin_path,
        idump_path,
        binary="test_substructure",
        functions=["process_data", "process_node_d", "setup_links"],
        command="propagate_synthesized_type|process_data|0",
    )
    propagation = propagated["propagation"]
    require(
        propagation["success_count"] >= 1,
        "expected cross-function propagation successes",
        propagated,
    )
    require(
        {"process_node_d", "setup_links"} & function_names(propagation["sites"]),
        "expected propagation into related substructure functions",
        propagated,
    )


def check_global_surface(repo_root: Path, plugin_path: Path, idump_path: str) -> None:
    log(hr("="))
    log("API: global analysis and synthesis")

    analysis = run_api_command(
        repo_root,
        plugin_path,
        idump_path,
        binary="test_global_pointer_singleton",
        functions=["publish_state", "state_ctor", "use_state", "use_state_leaf"],
        command="analyze_global_structure|g_state_storage",
    )
    analysis_body = analysis["analysis"]
    require(analysis_body["success"], "global analysis failed", analysis)
    require(
        {"publish_state", "use_state", "main"}.issubset(
            function_names(analysis_body["touched_functions"])
        ),
        "missing touched functions in global analysis",
        analysis,
    )
    alias_names = function_names(analysis_body["pointer_alias_globals"])
    require(
        "g_state_ptr" in alias_names,
        "expected pointer alias global to be recovered",
        analysis,
    )

    synthesis = run_api_command(
        repo_root,
        plugin_path,
        idump_path,
        binary="test_global_pointer_singleton",
        functions=["publish_state", "use_state", "use_state_leaf"],
        command="synthesize_global_structure|g_state_storage|apply",
    )
    synth_result = synthesis["result"]
    require(synth_result["success"], "global synthesis failed", synthesis)
    require(
        synth_result["struct_tid"] != BADADDR,
        "global apply mode should create a type",
        synthesis,
    )
    require(
        "use_state_leaf" in function_names(synth_result["propagated_to"]),
        "expected global synthesis to propagate into at least one consumer",
        synthesis,
    )


def check_type_surface(repo_root: Path, plugin_path: Path, idump_path: str) -> None:
    log(hr("="))
    log("API: variable and function type analysis/fixing")

    var_analysis = run_api_command(
        repo_root,
        plugin_path,
        idump_path,
        binary="test_overlap_scope",
        functions=["overlap_scope"],
        command="analyze_variable_type|overlap_scope|4",
    )
    comparison = var_analysis["comparison"]
    require(
        comparison["difference"] in {"significant", "critical", "moderate"},
        "expected a notable variable type difference",
        var_analysis,
    )
    require(
        comparison["primary_reason"] == "int_to_ptr"
        and "*" in comparison["description"],
        "expected pointer promotion in variable analysis",
        var_analysis,
    )

    var_fix = run_api_command(
        repo_root,
        plugin_path,
        idump_path,
        binary="test_overlap_scope",
        functions=["overlap_scope"],
        command="fix_variable_type|overlap_scope|4",
    )
    require(
        var_fix["comparison"]["primary_reason"] == "int_to_ptr"
        and "*" in var_fix["comparison"]["description"],
        "expected pointer promotion in variable fix comparison",
        var_fix,
    )
    require(var_fix["applied"], "expected variable type fix to apply", var_fix)

    fn_analysis = run_api_command(
        repo_root,
        plugin_path,
        idump_path,
        binary="test_overlap_scope",
        functions=["overlap_scope"],
        command="analyze_function_types|overlap_scope",
    )
    fn_analysis_result = fn_analysis["result"]
    require(fn_analysis_result["success"], "function type analysis failed", fn_analysis)
    require(
        fn_analysis_result["differences_found"] >= 1,
        "expected function type analysis differences",
        fn_analysis,
    )
    require(
        any(
            "overlap recovery" in diagnostic
            for diagnostic in fn_analysis_result["diagnostics"]
        ),
        "expected overlap recovery diagnostic",
        fn_analysis,
    )

    fn_fix = run_api_command(
        repo_root,
        plugin_path,
        idump_path,
        binary="test_overlap_scope",
        functions=["overlap_scope"],
        command="fix_function_types|overlap_scope",
    )
    fn_fix_result = fn_fix["result"]
    require(fn_fix_result["success"], "function type fixing failed", fn_fix)
    require(
        fn_fix_result["fixes_applied"] >= 1,
        "expected at least one applied function type fix",
        fn_fix,
    )
    require(
        any(
            "overlap recovery" in diagnostic
            for diagnostic in fn_fix_result["diagnostics"]
        ),
        "expected overlap recovery diagnostic during fixing",
        fn_fix,
    )


def check_direct_apply_and_rewrite(
    repo_root: Path, plugin_path: Path, idump_path: str
) -> None:
    log(hr("="))
    log("API: direct apply/local propagation/rewrite helpers")

    applied = run_api_command(
        repo_root,
        plugin_path,
        idump_path,
        binary="test_simple_struct",
        functions=["process_simple"],
        command="apply_synthesized_type|process_simple|0",
    )
    require(applied["applied"], "expected direct apply_type helper to succeed", applied)

    local_prop = run_api_command(
        repo_root,
        plugin_path,
        idump_path,
        binary="test_local_alias_positive",
        functions=["use_alias_read"],
        command="propagate_local_synthesized_type|use_alias_read|0",
    )
    require(
        local_prop["propagation"]["success_count"] >= 1,
        "expected local propagation success",
        local_prop,
    )

    rewrite = run_api_command(
        repo_root,
        plugin_path,
        idump_path,
        binary="test_simple_struct",
        functions=["process_simple"],
        command="rewrite_preview_structure|process_simple|0",
    )
    require(
        rewrite["analysis"]["success"],
        "expected preview analysis before rewrite to succeed",
        rewrite,
    )
    require(
        rewrite["rewrite"]["success_count"] >= 1,
        "expected at least one rewrite transform",
        rewrite,
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run live C++ API surface checks with idump"
    )
    parser.add_argument("--repo-root", required=True)
    parser.add_argument("--plugin", required=True)
    parser.add_argument("--idump", default="idump")
    args = parser.parse_args()

    repo_root = Path(args.repo_root).resolve()
    plugin_path = Path(args.plugin).resolve()
    if not plugin_path.exists():
        raise RuntimeError(f"plugin not found: {plugin_path}")

    build_required_fixtures(repo_root)
    check_local_layout(repo_root, plugin_path, args.idump)
    check_vtable_detection(repo_root, plugin_path, args.idump)
    check_variable_analysis_and_modes(repo_root, plugin_path, args.idump)
    check_function_surface(repo_root, plugin_path, args.idump)
    check_unified_and_propagation(repo_root, plugin_path, args.idump)
    check_global_surface(repo_root, plugin_path, args.idump)
    check_type_surface(repo_root, plugin_path, args.idump)
    check_direct_apply_and_rewrite(repo_root, plugin_path, args.idump)
    log(hr("="))
    log("C++ API surface: PASS")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"[FAIL] {exc}", file=sys.stderr)
        raise SystemExit(1)
