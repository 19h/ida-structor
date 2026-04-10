#!/usr/bin/env python3

import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-9;]*m")


def strip_ansi(text: str) -> str:
    return ANSI_ESCAPE_RE.sub("", text)


def run(cmd, *, cwd=None, env=None):
    return subprocess.run(cmd, cwd=cwd, env=env, text=True, capture_output=True)


def require_success(proc, description: str) -> None:
    if proc.returncode == 0:
        return

    output = (proc.stdout or "") + (proc.stderr or "")
    raise RuntimeError(f"{description} failed\n{output}")


def build_vtable_fixture(repo_root: Path) -> Path:
    proc = run(
        [
            "sh",
            str(repo_root / "integration_tests" / "build_fixtures.sh"),
            "test_vtable_positive",
        ],
        cwd=repo_root,
    )
    require_success(proc, "building test_vtable_positive")

    binary = repo_root / "integration_tests" / "test_vtable_positive"
    if not binary.exists():
        raise RuntimeError(f"expected fixture binary was not created: {binary}")

    return binary


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
    sandbox_home = Path(tempfile.mkdtemp(prefix="structor-vtable-idump-home."))
    sandbox_plugins = sandbox_home / ".idapro" / "plugins"
    sandbox_plugins.mkdir(parents=True, exist_ok=True)

    link_license_files(real_home, sandbox_home)

    plugin_dst = sandbox_plugins / plugin_path.name
    shutil.copy2(plugin_path, plugin_dst)

    if sys.platform == "darwin":
        proc = run(["codesign", "-s", "-", "-f", str(plugin_dst)])
        require_success(proc, f"codesigning {plugin_dst}")

    return sandbox_home


def write_structor_config(sandbox_home: Path) -> None:
    config_path = sandbox_home / ".idapro" / "structor.cfg"
    config_path.write_text(
        "\n".join(
            [
                "debug_mode=false",
                "auto_fix_types=true",
                "auto_fix_verbose=false",
            ]
        )
        + "\n",
        encoding="utf-8",
    )


def run_idump(
    repo_root: Path,
    plugin_path: Path,
    idump_path: str,
    binary: Path,
    function_names: list[str],
    auto_synth: str,
) -> str:
    real_home = Path.home()
    sandbox_home = prepare_plugin_home(plugin_path, real_home)
    write_structor_config(sandbox_home)

    sandbox_binary = sandbox_home / binary.name
    shutil.copy2(binary, sandbox_binary)

    dsym_src = binary.with_name(binary.name + ".dSYM")
    dsym_dst = sandbox_home / dsym_src.name
    if dsym_src.exists():
        shutil.copytree(dsym_src, dsym_dst)

    try:
        env = os.environ.copy()
        env["HOME"] = str(sandbox_home)
        env["STRUCTOR_AUTO_SYNTH"] = auto_synth

        proc = run(
            [
                idump_path,
                "--plugin",
                "structor",
                "--pseudo-only",
                "-F",
                ",".join(function_names),
                str(sandbox_binary),
            ],
            cwd=repo_root,
            env=env,
        )
        require_success(proc, f"running idump for {binary.name}")
        return strip_ansi((proc.stdout or "") + (proc.stderr or ""))
    finally:
        shutil.rmtree(sandbox_home, ignore_errors=True)


def require_substrings(output: str, needles: list[str], description: str) -> None:
    missing = [needle for needle in needles if needle not in output]
    if missing:
        raise RuntimeError(
            f"missing expected output for {description}: "
            + ", ".join(missing)
            + "\n"
            + output
        )


def forbid_substrings(output: str, needles: list[str], description: str) -> None:
    present = [needle for needle in needles if needle in output]
    if present:
        raise RuntimeError(
            f"unexpected output for {description}: "
            + ", ".join(present)
            + "\n"
            + output
        )


def run_vtable_positive_regression(
    repo_root: Path, plugin_path: Path, idump_path: str
) -> None:
    binary = build_vtable_fixture(repo_root)
    output = run_idump(
        repo_root,
        plugin_path,
        idump_path,
        binary,
        ["__Z18call_vtable_directPv", "__Z19call_multiple_slotsPvi"],
        "0x100000530:0",
    )

    require_substrings(
        output,
        [
            "call_vtable_direct(auto_z18call_vtable_directpv *obj)",
            "obj->vtable->slot_0(a1: obj);",
            "obj->vtable->slot_1",
            "call_multiple_slots(auto_z18call_vtable_directpv *obj, int arg)",
            "obj->vtable->slot_2",
            "obj->vtable->slot_3",
            'printf(a1: "data: %d\\n", obj->u32_8);',
            'printf(a1: "data2: %d\\n", obj->u32_C);',
            'printf(a1: "ptr: %p\\n", obj->ptr_10);',
        ],
        "vtable positive regression",
    )

    forbid_substrings(
        output,
        [
            "obj->fn_0",
            "obj->fn_8",
            "+ 1))(a1: obj)",
            "obj->vtable[1].slot_0",
            "obj->vtable[1].slot_1",
        ],
        "vtable positive regression",
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run live vtable regression checks with idump"
    )
    parser.add_argument("--repo-root", required=True)
    parser.add_argument("--plugin", required=True)
    parser.add_argument("--idump", default="idump")
    args = parser.parse_args()

    repo_root = Path(args.repo_root).resolve()
    plugin_path = Path(args.plugin).resolve()
    if not plugin_path.exists():
        raise RuntimeError(f"plugin not found: {plugin_path}")

    run_vtable_positive_regression(repo_root, plugin_path, args.idump)
    print("[PASS] vtable positive regression")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"[FAIL] {exc}", file=sys.stderr)
        raise SystemExit(1)
