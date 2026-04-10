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


def build_fixtures(repo_root: Path, *names: str) -> None:
    proc = run(
        ["sh", str(repo_root / "integration_tests" / "build_fixtures.sh"), *names],
        cwd=repo_root,
    )
    require_success(proc, "building global recovery fixtures")


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
    sandbox_home = Path(tempfile.mkdtemp(prefix="structor-global-idump-home."))
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
    functions: list[str],
    auto_global: str,
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
        env["STRUCTOR_AUTO_SYNTH_GLOBAL"] = auto_global

        proc = run(
            [
                idump_path,
                "--plugin",
                "structor",
                "--pseudo-only",
                "-F",
                ",".join(functions),
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


def run_ctor_chain_regression(
    repo_root: Path, plugin_path: Path, idump_path: str
) -> None:
    binary = repo_root / "integration_tests" / "test_global_ctor_chain"
    output = run_idump(
        repo_root,
        plugin_path,
        idump_path,
        binary,
        ["widget_ctor", "widget_use_global", "widget_use_leaf"],
        "g_widget",
    )
    require_substrings(
        output,
        [
            "Structor: Auto-synthesis OK",
            "auto_g_widget *dst",
            "dst->u32_0",
            "g_widget.u32_0",
            "g_widget.u32_18",
            "g_widget.u64_10",
            "dst->u8s_20[2]",
        ],
        "global ctor chain",
    )


def run_return_helper_regression(
    repo_root: Path, plugin_path: Path, idump_path: str
) -> None:
    binary = repo_root / "integration_tests" / "test_global_ctor_return"
    output = run_idump(
        repo_root,
        plugin_path,
        idump_path,
        binary,
        ["session_ctor", "consume_session"],
        "g_session",
    )
    require_substrings(
        output,
        [
            "Structor: Auto-synthesis OK",
            "auto_g_session *dst",
            "auto_g_session *v0",
            "v0->u64_8",
        ],
        "global return helper",
    )


def run_split_init_regression(
    repo_root: Path, plugin_path: Path, idump_path: str
) -> None:
    binary = repo_root / "integration_tests" / "test_global_split_init"
    output = run_idump(
        repo_root,
        plugin_path,
        idump_path,
        binary,
        ["device_header_ctor", "device_attach_cookie", "device_publish_slots"],
        "g_device",
    )
    require_substrings(
        output,
        [
            "Structor: Auto-synthesis OK",
            "auto_g_device *dst",
            "dst->entries_8[1].u64_0 = dst",
            "dst->entries_8[2].u64_0 = 0xAAAABBBBCCCCDDDDLL",
        ],
        "global split init",
    )


def run_pointer_singleton_regression(
    repo_root: Path, plugin_path: Path, idump_path: str
) -> None:
    binary = repo_root / "integration_tests" / "test_global_pointer_singleton"
    output = run_idump(
        repo_root,
        plugin_path,
        idump_path,
        binary,
        ["state_ctor", "use_state"],
        "g_state_storage",
    )
    require_substrings(
        output,
        [
            "Structor: Auto-synthesis OK",
            "auto_g_state_storage *dst",
            "g_state_ptr->u32_0",
            "g_state_ptr->u32_4",
            "g_state_ptr->u64s_8[1]",
            "g_state_ptr->u32_20",
        ],
        "pointer singleton direct rewrite",
    )


def run_subobject_regression(
    repo_root: Path, plugin_path: Path, idump_path: str
) -> None:
    binary = repo_root / "integration_tests" / "test_global_subobject_chain"
    output = run_idump(
        repo_root,
        plugin_path,
        idump_path,
        binary,
        ["manager_ctor"],
        "g_manager",
    )
    require_substrings(
        output,
        [
            "Structor: Auto-synthesis OK",
            "auto_g_manager *dst",
            "child_ctor(child: &dst->u8_20, kind: 9u)",
        ],
        "global subobject chain",
    )


def run_negative_scratch_regression(
    repo_root: Path, plugin_path: Path, idump_path: str
) -> None:
    binary = repo_root / "integration_tests" / "test_global_ambiguous_scratch"
    output = run_idump(
        repo_root,
        plugin_path,
        idump_path,
        binary,
        ["fill_scratch", "scramble_scratch", "checksum_scratch"],
        "g_scratch",
    )
    require_substrings(
        output,
        ["Structor: Auto-synthesis FAILED - No global/static structure accesses found"],
        "ambiguous scratch negative",
    )
    if "auto_g_scratch" in output:
        raise RuntimeError(
            "unexpected synthesized scratch structure in negative regression"
        )


def run_cpp_static_lookup_regression(
    repo_root: Path, plugin_path: Path, idump_path: str
) -> None:
    binary = repo_root / "integration_tests" / "test_global_cpp_static_ctor"
    output = run_idump(
        repo_root,
        plugin_path,
        idump_path,
        binary,
        ["drive_engine", "inspect_engine"],
        "g_engine",
    )
    require_substrings(
        output,
        [
            "Structor: Running auto global synthesis for name=g_engine",
            "Structor: Auto-synthesis FAILED -",
        ],
        "cpp static global lookup",
    )
    if "Global 'g_engine' not found" in output:
        raise RuntimeError("demangled C++ static global lookup regressed")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run live global/static recovery regressions with idump"
    )
    parser.add_argument("--repo-root", required=True)
    parser.add_argument("--plugin", required=True)
    parser.add_argument("--idump", default="idump")
    args = parser.parse_args()

    repo_root = Path(args.repo_root).resolve()
    plugin_path = Path(args.plugin).resolve()
    if not plugin_path.exists():
        raise RuntimeError(f"plugin not found: {plugin_path}")

    build_fixtures(
        repo_root,
        "test_global_ctor_chain",
        "test_global_ctor_return",
        "test_global_split_init",
        "test_global_pointer_singleton",
        "test_global_subobject_chain",
        "test_global_cpp_static_ctor",
        "test_global_ambiguous_scratch",
    )

    run_ctor_chain_regression(repo_root, plugin_path, args.idump)
    run_return_helper_regression(repo_root, plugin_path, args.idump)
    run_split_init_regression(repo_root, plugin_path, args.idump)
    run_pointer_singleton_regression(repo_root, plugin_path, args.idump)
    run_subobject_regression(repo_root, plugin_path, args.idump)
    run_negative_scratch_regression(repo_root, plugin_path, args.idump)
    run_cpp_static_lookup_regression(repo_root, plugin_path, args.idump)

    print("[PASS] global ctor chain regression")
    print("[PASS] global return helper regression")
    print("[PASS] global split init regression")
    print("[PASS] pointer singleton rewrite regression")
    print("[PASS] global subobject regression")
    print("[PASS] global negative scratch regression")
    print("[PASS] cpp static global lookup regression")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"[FAIL] {exc}", file=sys.stderr)
        raise SystemExit(1)
