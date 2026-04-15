#!/usr/bin/env python3

import argparse
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from check_fixture_contracts import (  # noqa: E402
    build_fixtures,
    expand_function_filters,
    normalize_result,
    prepare_plugin_home,
    require_success,
    run,
    strip_ansi,
    write_structor_config,
)


def log(message: str) -> None:
    print(message, flush=True)


def require(condition: bool, message: str, output: str | None = None) -> None:
    if condition:
        return
    if output:
        raise RuntimeError(f"{message}\n{output}")
    raise RuntimeError(message)


def run_weaponstats_case(repo_root: Path, plugin_path: Path, idump_path: str) -> None:
    fixture_name = "weaponstats/SWeaponStats__Init_recreated"
    build_fixtures(repo_root, fixture_name)

    binary = repo_root / "integration_tests" / fixture_name
    require(binary.exists(), f"fixture binary not found: {binary}")

    sandbox_home = prepare_plugin_home(plugin_path, Path.home())
    write_structor_config(sandbox_home, debug_mode=False)
    run_dir = Path(tempfile.mkdtemp(prefix="structor-weaponstats-binary."))
    sandbox_binary = run_dir / binary.name
    shutil.copy2(binary, sandbox_binary)
    result_path = sandbox_home / "structor_last_result.json"

    try:
        env = os.environ.copy()
        env["HOME"] = str(sandbox_home)
        env["STRUCTOR_EXPORT_LAST_RESULT"] = str(result_path)
        env["STRUCTOR_AUTO_SYNTH"] = "_SWeaponStats_Init:0"

        proc = run(
            [
                idump_path,
                "--plugin",
                "structor",
                "--pseudo-only",
                "-F",
                ",".join(
                    expand_function_filters(
                        ["_SWeaponStats_Init", "_SRecoilModifier_Init"]
                    )
                ),
                str(sandbox_binary),
            ],
            cwd=repo_root,
            env=env,
        )
        require_success(proc, "running idump for weaponstats regression")

        output = strip_ansi((proc.stdout or "") + (proc.stderr or ""))
        require(result_path.exists(), "missing exported synthesis result", output)

        raw_result = json.loads(result_path.read_text(encoding="utf-8"))
        normalized = normalize_result(raw_result)
        structure = normalized.get("structure")
        require(
            structure is not None,
            "weaponstats regression: missing synthesized structure",
            output,
        )

        fields = {field.get("offset"): field for field in structure.get("fields", [])}
        recoil = fields.get(0x38)
        require(
            recoil is not None, "weaponstats regression: missing recoil field", output
        )
        require(
            recoil.get("name") == "recoil_modifier",
            f"weaponstats regression: expected recoil field name 'recoil_modifier', got {recoil.get('name')!r}",
            output,
        )
        require(
            "auto_recoil_modifier" in (recoil.get("type") or ""),
            "weaponstats regression: recoil field did not recover nested recoil type",
            output,
        )
        require(
            normalized.get("fields_created", 0) < 30,
            f"weaponstats regression: expected factored layout, got {normalized.get('fields_created')} fields",
            output,
        )
        require(
            all(
                field.get("name") != "entries_348"
                for field in structure.get("fields", [])
            ),
            "weaponstats regression: old flat entries_348 layout resurfaced in final structure",
            output,
        )
        require(
            "recoil_modifier" in output,
            "weaponstats regression: pseudocode did not expose recoil_modifier",
            output,
        )
        require(
            "auto_recoil_modifier *__fastcall SRecoilModifier_Init" in output,
            "weaponstats regression: nested recoil type was not propagated to SRecoilModifier_Init",
            output,
        )
    finally:
        shutil.rmtree(sandbox_home, ignore_errors=True)
        shutil.rmtree(run_dir, ignore_errors=True)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run focused live regressions against the recreated WeaponStats example"
    )
    parser.add_argument("--repo-root", required=True)
    parser.add_argument("--plugin", required=True)
    parser.add_argument("--idump", default="idump")
    args = parser.parse_args()

    repo_root = Path(args.repo_root).resolve()
    plugin_path = Path(args.plugin).resolve()
    require(plugin_path.exists(), f"plugin not found: {plugin_path}")

    log("WeaponStats regression: running recreated fixture")
    run_weaponstats_case(repo_root, plugin_path, args.idump)
    log("WeaponStats regression: PASS")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"[FAIL] {exc}", file=sys.stderr)
        raise SystemExit(1)
