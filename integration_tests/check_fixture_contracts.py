#!/usr/bin/env python3

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap
import time
from pathlib import Path


ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-9;]*m")
FUNCTION_HEADER_RE = re.compile(r"^Function: (?P<name>.+?) \(")


def strip_ansi(text: str) -> str:
    return ANSI_ESCAPE_RE.sub("", text)


def log(message: str) -> None:
    print(message, flush=True)


def hr(char: str = "-", width: int = 78) -> str:
    return char * width


def format_name_list(names: list[str], *, indent: str = "  ") -> str:
    if not names:
        return f"{indent}<none>"

    return textwrap.fill(
        ", ".join(names),
        width=100,
        initial_indent=indent,
        subsequent_indent=indent,
        break_long_words=False,
        break_on_hyphens=False,
    )


def run(cmd, *, cwd=None, env=None):
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


def require_success(proc, description: str) -> None:
    if proc.returncode == 0:
        return

    output = (proc.stdout or "") + (proc.stderr or "")
    raise RuntimeError(f"{description} failed\n{output}")


def build_fixtures(repo_root: Path, *names: str) -> None:
    log(hr("="))
    log("Building fixture binaries")
    log(format_name_list(list(names)))
    proc = run(
        ["sh", str(repo_root / "integration_tests" / "build_fixtures.sh"), *names],
        cwd=repo_root,
    )
    require_success(proc, "building fixtures")
    log("Build complete")


def link_license_files(real_home: Path, sandbox_home: Path) -> None:
    real_idapro = real_home / ".idapro"
    sandbox_idapro = sandbox_home / ".idapro"
    sandbox_idapro.mkdir(parents=True, exist_ok=True)

    matched = []
    for pattern in ("ida.reg", "*.hexlic", "*.lic"):
        matched.extend(real_idapro.glob(pattern))

    if not matched:
        raise RuntimeError(f"no IDA license files found in {real_idapro}")

    for src in matched:
        dst = sandbox_idapro / src.name
        if dst.exists():
            continue
        os.symlink(src, dst)


def prepare_plugin_home(plugin_path: Path, real_home: Path) -> Path:
    sandbox_home = Path(tempfile.mkdtemp(prefix="structor-contract-idump-home."))
    sandbox_plugins = sandbox_home / ".idapro" / "plugins"
    sandbox_plugins.mkdir(parents=True, exist_ok=True)

    link_license_files(real_home, sandbox_home)

    plugin_dst = sandbox_plugins / plugin_path.name
    shutil.copy2(plugin_path, plugin_dst)

    if sys.platform == "darwin":
        proc = run(["codesign", "-s", "-", "-f", str(plugin_dst)])
        require_success(proc, f"codesigning {plugin_dst}")

    return sandbox_home


def write_structor_config(sandbox_home: Path, *, debug_mode: bool = False) -> None:
    config_path = sandbox_home / ".idapro" / "structor.cfg"
    config_path.write_text(
        "\n".join(
            [
                f"debug_mode={'true' if debug_mode else 'false'}",
                "auto_fix_types=false",
                "auto_fix_verbose=false",
            ]
        )
        + "\n",
        encoding="utf-8",
    )


def _sorted_unique_names(entries: list[dict]) -> list[str]:
    return sorted({entry.get("name") for entry in entries if entry.get("name")})


def normalize_result(raw: dict) -> dict:
    def normalize_union_member(member: dict) -> dict:
        return {
            "name": member.get("name"),
            "offset": member.get("offset"),
            "size": member.get("size"),
            "type": member.get("type"),
        }

    def normalize_field(field: dict) -> dict:
        return {
            "name": field.get("name"),
            "offset": field.get("offset"),
            "size": field.get("size"),
            "semantic": field.get("semantic"),
            "type": field.get("type"),
            "confidence": field.get("confidence"),
            "is_padding": field.get("is_padding"),
            "is_array": field.get("is_array"),
            "array_count": field.get("array_count"),
            "is_union_candidate": field.get("is_union_candidate"),
            "is_bitfield": field.get("is_bitfield"),
            "bit_offset": field.get("bit_offset"),
            "bit_size": field.get("bit_size"),
            "union_members": [
                normalize_union_member(member)
                for member in field.get("union_members", [])
            ],
        }

    def normalize_vtable(vtable: dict | None) -> dict | None:
        if vtable is None:
            return None

        return {
            "name": vtable.get("name"),
            "slot_count": vtable.get("slot_count"),
            "slots": [
                {
                    "index": slot.get("index"),
                    "offset": slot.get("offset"),
                    "name": slot.get("name"),
                    "signature_hint": slot.get("signature_hint"),
                    "type": slot.get("type"),
                }
                for slot in vtable.get("slots", [])
            ],
        }

    def normalize_structure(structure: dict | None) -> dict | None:
        if structure is None:
            return None

        return {
            "name": structure.get("name"),
            "size": structure.get("size"),
            "alignment": structure.get("alignment"),
            "source_func_name": structure.get("source_func_name"),
            "source_var": structure.get("source_var"),
            "field_count": structure.get("field_count"),
            "non_padding_field_count": structure.get("non_padding_field_count"),
            "provenance": _sorted_unique_names(structure.get("provenance", [])),
            "fields": [normalize_field(field) for field in structure.get("fields", [])],
            "vtable": normalize_vtable(structure.get("vtable")),
        }

    z3 = raw.get("z3", {})
    return {
        "success": raw.get("success"),
        "error": raw.get("error"),
        "error_message": raw.get("error_message"),
        "fields_created": raw.get("fields_created"),
        "vtable_slots": raw.get("vtable_slots"),
        "propagated_to": _sorted_unique_names(raw.get("propagated_to", [])),
        "failed_sites": _sorted_unique_names(raw.get("failed_sites", [])),
        "z3": {
            "status": z3.get("status"),
            "used_z3": z3.get("used_z3"),
            "used_fallback": z3.get("used_fallback"),
        },
        "structure": normalize_structure(raw.get("structure")),
    }


def extract_pseudocode_blocks(output: str) -> dict[str, str]:
    lines = output.splitlines()
    blocks: dict[str, str] = {}
    i = 0
    while i < len(lines):
        match = FUNCTION_HEADER_RE.match(lines[i])
        if not match:
            i += 1
            continue

        name = match.group("name")
        i += 1
        while i < len(lines) and not lines[i].startswith("-- Pseudocode"):
            if FUNCTION_HEADER_RE.match(lines[i]) or lines[i].startswith("Summary"):
                break
            i += 1

        if i >= len(lines) or not lines[i].startswith("-- Pseudocode"):
            continue

        i += 1
        block_lines: list[str] = []
        while i < len(lines):
            line = lines[i]
            if (
                FUNCTION_HEADER_RE.match(line)
                or line.startswith("USER LVAR INFO FOR ")
                or line.startswith("Summary")
                or line.startswith("[*] Done.")
                or line.startswith(
                    "=============================================================================="
                )
            ):
                break
            block_lines.append(line)
            i += 1

        while block_lines and not block_lines[-1].strip():
            block_lines.pop()
        block = "\n".join(block_lines)
        blocks[name] = block
        if name.startswith("_") and name[1:] not in blocks:
            blocks[name[1:]] = block

    return blocks


def render_pseudocode_snapshot(output: str, function_names: list[str]) -> str:
    blocks = extract_pseudocode_blocks(output)
    sections = []
    for name in function_names:
        if name not in blocks:
            raise RuntimeError(f"missing pseudocode block for function: {name}")
        sections.append(f">>> {name}\n{blocks[name].rstrip()}\n<<<")
    return "\n\n".join(sections) + "\n"


def load_contracts(contract_dir: Path, selected: list[str]) -> list[dict]:
    if not contract_dir.exists():
        raise RuntimeError(f"contract directory not found: {contract_dir}")

    contracts = []
    for path in sorted(contract_dir.glob("*.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        data["__path"] = path
        fixture = data.get("fixture")
        if selected and fixture not in selected:
            continue
        contracts.append(data)

    if selected:
        found = {contract["fixture"] for contract in contracts}
        missing = [name for name in selected if name not in found]
        if missing:
            raise RuntimeError(
                "missing contract files for fixtures: " + ", ".join(sorted(missing))
            )

    return contracts


def make_auto_synth_value(spec: dict) -> tuple[str, str]:
    kind = spec.get("kind")
    target = spec.get("target")
    if not kind or not target:
        raise RuntimeError(f"invalid synth spec: {spec}")

    if kind == "global":
        return "STRUCTOR_AUTO_SYNTH_GLOBAL", target

    if kind != "function":
        raise RuntimeError(f"unsupported synth kind: {kind}")

    if "var_name" in spec:
        selector = spec["var_name"]
        return "STRUCTOR_AUTO_SYNTH", f"{target}:{selector}"

    selector = spec.get("var_idx", 0)
    return "STRUCTOR_AUTO_SYNTH", f"{target}:{selector}"


def describe_synth(spec: dict) -> str:
    kind = spec.get("kind")
    target = spec.get("target")
    if kind == "global":
        return f"global symbol `{target}`"

    if "var_name" in spec:
        return f"function `{target}`, variable `{spec['var_name']}`"

    return f"function `{target}`, variable #{spec.get('var_idx', 0)}"


def describe_solver_status(status: str | None) -> str:
    mapping = {
        "success": "Z3 solved the layout directly",
        "success_relaxed": "Z3 solved the layout after relaxing constraints",
        "fallback_heuristic": "heuristic fallback synthesis was used",
        "fallback_raw_bytes": "raw-byte fallback synthesis was used",
        "not_used": "the solver was not used",
    }
    return mapping.get(status, status or "unknown")


def log_case_header(
    case_label: str, synth_desc: str, dump_functions: list[str]
) -> None:
    log(hr())
    log(f"Case: {case_label}")
    log(f"Target: {synth_desc}")
    log("Pseudocode checked:")
    log(format_name_list(dump_functions))


def log_case_result(normalized_result: dict) -> None:
    structure = normalized_result.get("structure")
    z3 = normalized_result.get("z3", {})
    if structure is None:
        log("Outcome: no structure synthesized")
        log(
            f"Reason: {normalized_result.get('error_message') or normalized_result.get('error')}"
        )
        log(f"Solver: {describe_solver_status(z3.get('status'))}")
        return

    log(f"Outcome: synthesized `{structure.get('name')}`")
    log(f"Solver: {describe_solver_status(z3.get('status'))}")
    log(
        "Layout: "
        f"{structure.get('size')} bytes, "
        f"{structure.get('field_count')} total fields, "
        f"{structure.get('non_padding_field_count')} non-padding fields, "
        f"{normalized_result.get('vtable_slots', 0)} vtable slots"
    )
    log("Propagated to:")
    log(format_name_list(normalized_result.get("propagated_to") or []))


def run_case(
    repo_root: Path,
    plugin_path: Path,
    idump_path: str,
    fixture_name: str,
    case: dict,
    *,
    debug_mode: bool,
) -> tuple[dict, str]:
    real_home = Path.home()
    sandbox_home = prepare_plugin_home(plugin_path, real_home)
    write_structor_config(sandbox_home, debug_mode=debug_mode)

    binary = repo_root / "integration_tests" / fixture_name
    if not binary.exists():
        raise RuntimeError(f"fixture binary not found: {binary}")

    run_dir = Path(tempfile.mkdtemp(prefix="structor-contract-binary."))
    sandbox_binary = run_dir / binary.name
    shutil.copy2(binary, sandbox_binary)

    result_path = sandbox_home / "structor_last_result.json"

    try:
        env = os.environ.copy()
        env["HOME"] = str(sandbox_home)
        env["STRUCTOR_EXPORT_LAST_RESULT"] = str(result_path)

        env_key, env_value = make_auto_synth_value(case["synth"])
        env[env_key] = env_value

        functions = case.get("dump_functions") or []
        if not functions:
            raise RuntimeError(
                f"case is missing dump_functions: {fixture_name}/{case['name']}"
            )

        proc = run(
            [
                idump_path,
                "--plugin",
                "structor",
                "--pseudo-only",
                "-F",
                ",".join(expand_function_filters(functions)),
                str(sandbox_binary),
            ],
            cwd=repo_root,
            env=env,
        )
        require_success(proc, f"running idump for {fixture_name}/{case['name']}")

        if not result_path.exists():
            output = strip_ansi((proc.stdout or "") + (proc.stderr or ""))
            raise RuntimeError(
                f"missing exported synthesis result for {fixture_name}/{case['name']}\n{output}"
            )

        result = json.loads(result_path.read_text(encoding="utf-8"))
        output = strip_ansi((proc.stdout or "") + (proc.stderr or ""))
        return result, output
    finally:
        shutil.rmtree(sandbox_home, ignore_errors=True)
        shutil.rmtree(run_dir, ignore_errors=True)


def require_contains(text: str, needles: list[str], context: str) -> None:
    missing = [needle for needle in needles if needle not in text]
    if missing:
        raise AssertionError(
            f"missing expected output for {context}: " + ", ".join(missing)
        )


def require_not_contains(text: str, needles: list[str], context: str) -> None:
    present = [needle for needle in needles if needle in text]
    if present:
        raise AssertionError(f"unexpected output for {context}: " + ", ".join(present))


def require_exact(expected, actual, context: str) -> None:
    if expected == actual:
        return

    expected_text = json.dumps(expected, indent=2, sort_keys=True)
    actual_text = json.dumps(actual, indent=2, sort_keys=True)
    raise AssertionError(
        f"{context}: normalized output mismatch\nEXPECTED:\n{expected_text}\nACTUAL:\n{actual_text}"
    )


def compare_field(expected: dict, actual: dict, context: str) -> None:
    for key in (
        "name",
        "offset",
        "size",
        "semantic",
        "is_padding",
        "is_array",
        "array_count",
        "is_union_candidate",
        "is_bitfield",
        "bit_offset",
        "bit_size",
        "confidence",
    ):
        if key in expected and actual.get(key) != expected[key]:
            raise AssertionError(
                f"{context}: field mismatch for {key}: expected {expected[key]!r}, got {actual.get(key)!r}"
            )

    if "type_equals" in expected and actual.get("type") != expected["type_equals"]:
        raise AssertionError(
            f"{context}: expected type {expected['type_equals']!r}, got {actual.get('type')!r}"
        )

    if "type_contains" in expected and expected["type_contains"] not in actual.get(
        "type", ""
    ):
        raise AssertionError(
            f"{context}: expected type containing {expected['type_contains']!r}, got {actual.get('type')!r}"
        )

    if "type_not_contains" in expected and expected["type_not_contains"] in actual.get(
        "type", ""
    ):
        raise AssertionError(
            f"{context}: unexpected type content {expected['type_not_contains']!r} in {actual.get('type')!r}"
        )


def compare_slots(
    expected_slots: list[dict], actual_slots: list[dict], context: str
) -> None:
    if len(expected_slots) != len(actual_slots):
        raise AssertionError(
            f"{context}: expected {len(expected_slots)} vtable slots, got {len(actual_slots)}"
        )

    for index, (expected, actual) in enumerate(
        zip(expected_slots, actual_slots, strict=True)
    ):
        slot_context = f"{context} slot #{index}"
        for key in ("index", "offset", "name"):
            if key in expected and actual.get(key) != expected[key]:
                raise AssertionError(
                    f"{slot_context}: expected {key}={expected[key]!r}, got {actual.get(key)!r}"
                )

        if "type_contains" in expected and expected["type_contains"] not in actual.get(
            "type", ""
        ):
            raise AssertionError(
                f"{slot_context}: expected type containing {expected['type_contains']!r}, got {actual.get('type')!r}"
            )

        if "signature_hint_contains" in expected and expected[
            "signature_hint_contains"
        ] not in actual.get("signature_hint", ""):
            raise AssertionError(
                f"{slot_context}: expected signature hint containing {expected['signature_hint_contains']!r}, got {actual.get('signature_hint')!r}"
            )


def verify_case(
    contract: dict,
    case: dict,
    raw_result: dict,
    raw_output: str,
    normalized_result: dict,
    pseudocode_snapshot: str,
) -> None:
    context = f"{contract['fixture']}/{case['name']}"
    expect = case.get("expect", {})

    if "golden_result" in case:
        require_exact(case["golden_result"], normalized_result, f"{context} result")

    if "golden_pseudocode" in case:
        if case["golden_pseudocode"] != pseudocode_snapshot:
            raise AssertionError(
                f"{context}: pseudocode snapshot mismatch\nEXPECTED:\n{case['golden_pseudocode']}\nACTUAL:\n{pseudocode_snapshot}"
            )

    if not expect:
        return

    if "success" in expect and raw_result.get("success") != expect["success"]:
        raise AssertionError(
            f"{context}: expected success={expect['success']!r}, got {raw_result.get('success')!r}"
        )

    if "error_contains" in expect and expect["error_contains"] not in raw_result.get(
        "error_message", ""
    ):
        raise AssertionError(
            f"{context}: expected error containing {expect['error_contains']!r}, got {raw_result.get('error_message')!r}"
        )

    if (
        "z3_status" in expect
        and raw_result.get("z3", {}).get("status") != expect["z3_status"]
    ):
        raise AssertionError(
            f"{context}: expected z3 status {expect['z3_status']!r}, got {raw_result.get('z3', {}).get('status')!r}"
        )

    if (
        "z3_status_in" in expect
        and raw_result.get("z3", {}).get("status") not in expect["z3_status_in"]
    ):
        raise AssertionError(
            f"{context}: expected z3 status in {expect['z3_status_in']!r}, got {raw_result.get('z3', {}).get('status')!r}"
        )

    if (
        "used_fallback" in expect
        and raw_result.get("z3", {}).get("used_fallback") != expect["used_fallback"]
    ):
        raise AssertionError(
            f"{context}: expected used_fallback={expect['used_fallback']!r}, got {raw_result.get('z3', {}).get('used_fallback')!r}"
        )

    structure = raw_result.get("structure")
    if expect.get("require_structure", True):
        if not structure:
            raise AssertionError(f"{context}: expected synthesized structure details")

        if (
            "structure_size" in expect
            and structure.get("size") != expect["structure_size"]
        ):
            raise AssertionError(
                f"{context}: expected structure size {expect['structure_size']!r}, got {structure.get('size')!r}"
            )

        if (
            "non_padding_field_count" in expect
            and structure.get("non_padding_field_count")
            != expect["non_padding_field_count"]
        ):
            raise AssertionError(
                f"{context}: expected non-padding field count {expect['non_padding_field_count']!r}, got {structure.get('non_padding_field_count')!r}"
            )

        actual_fields = structure.get("fields", [])
        if expect.get("ignore_padding", True):
            actual_fields = [
                field for field in actual_fields if not field.get("is_padding")
            ]

        expected_fields = expect.get("exact_fields")
        if expected_fields is not None:
            if len(expected_fields) != len(actual_fields):
                raise AssertionError(
                    f"{context}: expected {len(expected_fields)} fields, got {len(actual_fields)}"
                )

            for index, (expected, actual) in enumerate(
                zip(expected_fields, actual_fields, strict=True)
            ):
                compare_field(expected, actual, f"{context} field #{index}")

        for index, expected in enumerate(expect.get("contains_fields", [])):
            matches = [
                field
                for field in actual_fields
                if field.get("offset") == expected.get("offset")
            ]
            if not matches:
                raise AssertionError(
                    f"{context}: missing field at offset {expected.get('offset')!r}"
                )
            compare_field(expected, matches[0], f"{context} contains_field #{index}")

        if expect.get("forbid_fields"):
            for forbidden in expect["forbid_fields"]:
                for field in actual_fields:
                    if forbidden.get("offset") != field.get("offset"):
                        continue
                    matches = True
                    for key, value in forbidden.items():
                        if field.get(key) != value:
                            matches = False
                            break
                    if matches:
                        raise AssertionError(
                            f"{context}: forbidden field present: {forbidden!r}"
                        )

        actual_vtable = structure.get("vtable")
        if "vtable_slot_count" in expect:
            actual_count = (
                0 if actual_vtable is None else actual_vtable.get("slot_count", 0)
            )
            if actual_count != expect["vtable_slot_count"]:
                raise AssertionError(
                    f"{context}: expected vtable_slot_count={expect['vtable_slot_count']!r}, got {actual_count!r}"
                )

        if "exact_vtable_slots" in expect:
            if actual_vtable is None:
                raise AssertionError(f"{context}: expected vtable details")
            compare_slots(
                expect["exact_vtable_slots"], actual_vtable.get("slots", []), context
            )

        if "propagated_to_contains" in expect:
            actual_names = {
                entry.get("name") for entry in raw_result.get("propagated_to", [])
            }
            missing = [
                name
                for name in expect["propagated_to_contains"]
                if name not in actual_names
            ]
            if missing:
                raise AssertionError(
                    f"{context}: missing propagated targets: " + ", ".join(missing)
                )

    require_contains(
        pseudocode_snapshot, expect.get("pseudocode_contains", []), context
    )
    require_not_contains(
        pseudocode_snapshot, expect.get("pseudocode_forbid", []), context
    )

    extra_output = expect.get("raw_output_contains", [])
    if extra_output:
        require_contains(raw_output, extra_output, context)


def record_case(
    record_dir: Path,
    fixture_name: str,
    case_name: str,
    normalized_result: dict,
    pseudocode_snapshot: str,
) -> None:
    record_dir.mkdir(parents=True, exist_ok=True)
    stem = f"{fixture_name}__{case_name}"
    (record_dir / f"{stem}.result.json").write_text(
        json.dumps(normalized_result, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (record_dir / f"{stem}.pseudo.txt").write_text(
        pseudocode_snapshot, encoding="utf-8"
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run exact fixture contracts against Structor live idump output"
    )
    parser.add_argument("--repo-root", required=True)
    parser.add_argument("--plugin", required=True)
    parser.add_argument("--idump", default="idump")
    parser.add_argument(
        "--contracts-dir",
        default="integration_tests/contracts",
        help="Directory containing fixture contract JSON files",
    )
    parser.add_argument(
        "--fixture",
        action="append",
        default=[],
        help="Only run the named fixture contract (can be repeated)",
    )
    parser.add_argument(
        "--record-dir",
        help="Write actual exported results and pseudocode for each case to this directory",
    )
    parser.add_argument(
        "--debug-mode",
        action="store_true",
        help="Enable Structor debug_mode during idump runs",
    )
    args = parser.parse_args()

    repo_root = Path(args.repo_root).resolve()
    plugin_path = Path(args.plugin).resolve()
    contracts_dir = (repo_root / args.contracts_dir).resolve()
    if not plugin_path.exists():
        raise RuntimeError(f"plugin not found: {plugin_path}")

    contracts = load_contracts(contracts_dir, args.fixture)
    if not contracts:
        raise RuntimeError(f"no contracts found in {contracts_dir}")

    total_cases = sum(len(contract.get("cases", [])) for contract in contracts)
    log(hr("="))
    log("Exact fixture contracts")
    log(f"Contract directory: {contracts_dir}")
    log(f"Fixture files: {len(contracts)}")
    log(f"Cases: {total_cases}")

    build_fixtures(
        repo_root, *(sorted({contract["fixture"] for contract in contracts}))
    )

    record_dir = None if not args.record_dir else Path(args.record_dir).resolve()

    case_count = 0
    total_start = time.monotonic()
    for contract in contracts:
        fixture_name = contract["fixture"]
        for case in contract.get("cases", []):
            case_count += 1
            case_label = f"{fixture_name}/{case['name']}"
            log_case_header(
                case_label,
                describe_synth(case["synth"]),
                case.get("dump_functions") or [],
            )
            case_start = time.monotonic()
            result, output = run_case(
                repo_root,
                plugin_path,
                args.idump,
                fixture_name,
                case,
                debug_mode=args.debug_mode,
            )
            normalized_result = normalize_result(result)
            pseudocode_snapshot = render_pseudocode_snapshot(
                output,
                case.get("snapshot_functions") or case.get("dump_functions") or [],
            )
            log_case_result(normalized_result)
            if record_dir is not None:
                record_case(
                    record_dir,
                    fixture_name,
                    case["name"],
                    normalized_result,
                    pseudocode_snapshot,
                )
            verify_case(
                contract,
                case,
                result,
                output,
                normalized_result,
                pseudocode_snapshot,
            )
            elapsed = time.monotonic() - case_start
            log(f"Status: PASS ({elapsed:.1f}s)")

    total_elapsed = time.monotonic() - total_start
    log(hr("="))
    log(f"Verified {case_count} fixture contract case(s) in {total_elapsed:.1f}s")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"[FAIL] {exc}", file=sys.stderr)
        raise SystemExit(1)
