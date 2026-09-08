#!/usr/bin/env python3
"""Check production signature mappings and target ABI selection with licensed idump."""

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from check_cpp_api_surface import require_success, run, run_api_command


def build_fixtures(root: Path, output: Path) -> tuple[Path, list[tuple[str, Path, str, int, int, int]]]:
    output.mkdir(parents=True, exist_ok=True)
    clang = subprocess.check_output(["xcrun", "--find", "clang"], text=True).strip()
    sdk = subprocess.check_output(["xcrun", "--show-sdk-path"], text=True).strip()
    elf_linker = shutil.which("ld.lld")
    pe_linker = shutil.which("lld-link")
    if not elf_linker or not pe_linker:
        raise RuntimeError("cross-target ABI fixtures require ld.lld and lld-link")
    source = root / "integration_tests/test_abi_target.c"
    signature = output / "signature_mapping.macho"
    require_success(run([clang, "-isysroot", sdk, "-O0", "-g", str(root / "integration_tests/test_signature_mapping.c"),
                         "-o", str(signature)]), "building signature mapping carrier")
    cases = []
    for name, triple, emulation, convention, machine, bits, attributes in (
        ("x64_elf", "x86_64-unknown-linux-gnu", "elf_x86_64", "systemv_x64", 0, 64, []),
        ("arm64_elf", "aarch64-unknown-linux-gnu", "aarch64elf", "arm64_aapcs64", 13, 64, []),
        ("arm32_elf", "armv7-unknown-linux-gnueabi", "armelf_linux_eabi", "arm_aapcs", 13, 32, []),
        ("x64_elf_ms_abi", "x86_64-unknown-linux-gnu", "elf_x86_64", "systemv_x64", 0, 64,
         ["-DSTRUCTOR_MS_ABI=1"]),
    ):
        obj = output / f"{name}.o"
        binary = output / f"{name}.elf"
        require_success(run([clang, "--target=" + triple, "-O0", "-ffreestanding",
                             "-fno-stack-protector", *attributes, "-c", str(source), "-o", str(obj)]),
                        f"compiling {name}")
        require_success(run([elf_linker, "-m", emulation, "-e", "abi_target_probe",
                             str(obj), "-o", str(binary)]), f"linking {name}")
        cases.append((name, binary, convention, machine, bits, 18))

    for name, convention, attributes in (
        ("x64_pe", "microsoft_x64", []),
        ("x64_pe_sysv_abi", "microsoft_x64", ["-DSTRUCTOR_SYSV_ABI=1"]),
    ):
        pe_obj = output / f"{name}.obj"
        pe_binary = output / f"{name}.exe"
        require_success(run([clang, "--target=x86_64-pc-windows-msvc", "-O0", "-ffreestanding",
                             "-fno-stack-protector", *attributes, "-c", str(source), "-o", str(pe_obj)]),
                        f"compiling {name}")
        require_success(run([pe_linker, "/entry:abi_target_probe", "/subsystem:console",
                             "/nodefaultlib", "/export:abi_target_probe", str(pe_obj),
                             "/out:" + str(pe_binary)]), f"linking {name}")
        cases.append((name, pe_binary, convention, 0, 64, 11))

    for architecture, convention, machine in (
        ("x86_64", "systemv_x64", 0), ("arm64", "unknown", 13)
    ):
        binary = output / f"{architecture}_macho"
        require_success(run([clang, "-isysroot", sdk, "-arch", architecture, "-O0", "-g", str(source),
                             "-o", str(binary)]), f"building {architecture} Mach-O")
        cases.append((architecture + "_macho", binary, convention, machine, 64, 25))
    return signature, cases


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", required=True)
    parser.add_argument("--plugin", required=True)
    parser.add_argument("--idump", default="idump")
    parser.add_argument("--record-dir")
    parser.add_argument("--fixture-dir")
    parser.add_argument("--build-only", action="store_true")
    parser.add_argument("--mapping-case", action="append", default=[])
    parser.add_argument("--skip-targets", action="store_true")
    args = parser.parse_args()
    root = Path(args.repo_root).resolve()
    plugin = Path(args.plugin).resolve()
    if not plugin.is_file():
        raise RuntimeError(f"plugin not found: {plugin}")
    records = Path(args.record_dir).resolve() if args.record_dir else None
    if records:
        records.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="structor-signature-abi-fixtures.") as temporary:
        output = Path(args.fixture_dir).resolve() if args.fixture_dir else Path(temporary)
        signature, targets = build_fixtures(root, output)
        if args.build_only:
            print(f"Built signature carrier and {len(targets)} target ABI binaries in {output}")
            return 0

        def record(name: str, value: dict) -> None:
            if records:
                (records / f"{name}.json").write_text(json.dumps(value, indent=2) + "\n")

        common_checks = {"argument_mapping_restored", "local_types_unchanged",
                         "prototype_restored", "saved_type_unchanged"}
        mapping_cases = args.mapping_case or ("native", "permuted", "negative",
                                              "out_of_range", "duplicate")
        for case in mapping_cases:
            data = run_api_command(root, plugin, args.idump, binary=str(signature),
                                   functions=["signature_mapping_carrier"],
                                   command=f"inspect_signature_mapping|signature_mapping_carrier|{case}")
            record("mapping_" + case, data)
            expected_checks = set(common_checks)
            if case in ("native", "permuted"):
                expected_checks.update(("mapped_signature_facts", "distinguishable_signature_types"))
            else:
                expected_checks.add("invalid_mapping_no_facts")
            if case == "permuted":
                expected_checks.add("nonidentity_mapping_exercised")
            checks = data.get("checks", {})
            if (data.get("success") is not True or set(checks) != expected_checks or
                    any(value is not True for value in checks.values())):
                raise AssertionError(f"signature mapping {case}: {data}")
            if case in ("native", "permuted"):
                mapped = data["argument_indexes"]
                # This actual SDK carrier retains a partial _QWORD pointer
                # parameter beside two distinguishable represented scalars.
                # Unknown projections must not become signature type facts.
                if set(data["parameter_types"]) != {"unknown", "uint32", "float64"}:
                    raise AssertionError(f"signature carrier lost its category controls: {data}")
                issues = data["parameter_conversion_issues"]
                if (issues != [2 if inferred == "unknown" else 0
                               for inferred in data["parameter_types"]] or
                        not all(data["parameter_source_types"])):
                    raise AssertionError(f"signature omission lacks partial-storage provenance: {data}")
                expected_facts = {
                    local: inferred
                    for local, inferred in zip(mapped, data["parameter_types"], strict=True)
                    if inferred != "unknown"
                }
                actual = data["constraints"]
                if (len(actual) != len(expected_facts) or
                        {fact["local_index"]: fact["type"] for fact in actual} != expected_facts):
                    raise AssertionError(f"misdirected production signature facts: {data}")
            elif data.get("constraints") != []:
                raise AssertionError(f"invalid mapping leaked signature facts: {data}")
            print(f"[PASS] signature mapping: {case}", flush=True)

        if args.skip_targets:
            return 0
        for name, binary, convention, machine, bits, filetype in targets:
            data = run_api_command(root, plugin, args.idump, binary=str(binary),
                                   functions=["abi_target_probe"],
                                   command="inspect_target_calling_convention|abi_target_probe")
            source_override = {"x64_elf_ms_abi": "microsoft_x64",
                               "x64_pe_sysv_abi": "systemv_x64"}.get(name)
            if source_override:
                # The fixture source establishes this override. IDA currently
                # erases it and supplies default-family prototype locations;
                # preserve the contradiction as falsification evidence, not
                # a claim that the source function ABI was recovered.
                data["known_source_abi_override"] = source_override
                data["source_function_abi_recovered"] = data.get("convention") == source_override
            record(name, data)
            if (data.get("success") is not True or data.get("convention") != convention or
                    data.get("processor_id") != machine or data.get("bitness") != bits or
                    data.get("filetype") != filetype or data.get("unspecified_location_count") != 0 or
                    data.get("convention_evidence") != (
                        "unavailable" if convention == "unknown" else "target_default") or
                    data.get("location_assumption") !=
                        "standard_fixed_prototype_complete_abi_arguments"):
                raise AssertionError(f"target ABI mismatch {name}: {data}")
            if convention == "microsoft_x64":
                expected = [{"register": reg, "stack_offset": 0}
                            for reg in ("rcx", "xmm1", "r8", "xmm3")]
                expected += [{"register": None, "stack_offset": off} for off in (40, 48)]
            elif convention == "systemv_x64":
                expected = [{"register": reg, "stack_offset": 0}
                            for reg in ("rdi", "xmm0", "rsi", "xmm1", "rdx", "xmm2")]
            else:
                expected = []
            if data.get("scalar_model_locations") != expected:
                raise AssertionError(f"production ABI location mapping mismatch {name}: {data}")
            if source_override:
                print(f"[WITNESS] {name}: target default {convention}; "
                      f"source override {source_override} is absent from recovered metadata", flush=True)
            else:
                print(f"[PASS] target ABI: {name} -> {convention}", flush=True)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"[FAIL] {exc}", file=sys.stderr)
        raise SystemExit(1)
