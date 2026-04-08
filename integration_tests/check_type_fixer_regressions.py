#!/usr/bin/env python3

import argparse
import os
import platform
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
    proc = subprocess.run(
        cmd,
        cwd=cwd,
        env=env,
        text=True,
        capture_output=True,
    )
    return proc


def require_success(proc, description: str) -> None:
    if proc.returncode == 0:
        return

    output = (proc.stdout or "") + (proc.stderr or "")
    raise RuntimeError(f"{description} failed\n{output}")


def build_missing_regarg_fixture(repo_root: Path) -> Path:
    arch = platform.machine().lower()
    if arch not in {"arm64", "aarch64"}:
        raise RuntimeError(
            f"missing-regarg fixture requires arm64/aarch64, found {arch}"
        )

    proc = run(
        [
            "sh",
            str(repo_root / "integration_tests" / "build_fixtures.sh"),
            "test_missing_regarg",
        ],
        cwd=repo_root,
    )
    require_success(proc, "building test_missing_regarg")

    binary = repo_root / "integration_tests" / "test_missing_regarg"
    if not binary.exists():
        raise RuntimeError(f"expected fixture binary was not created: {binary}")

    return binary


def build_overlap_scope_fixture(repo_root: Path) -> Path:
    proc = run(
        [
            "sh",
            str(repo_root / "integration_tests" / "build_fixtures.sh"),
            "test_overlap_scope",
        ],
        cwd=repo_root,
    )
    require_success(proc, "building test_overlap_scope")

    binary = repo_root / "integration_tests" / "test_overlap_scope"
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
    sandbox_home = Path(tempfile.mkdtemp(prefix="structor-idump-home."))
    sandbox_plugins = sandbox_home / ".idapro" / "plugins"
    sandbox_plugins.mkdir(parents=True, exist_ok=True)

    link_license_files(real_home, sandbox_home)

    plugin_dst = sandbox_plugins / plugin_path.name
    shutil.copy2(plugin_path, plugin_dst)

    if sys.platform == "darwin":
        proc = run(["codesign", "-s", "-", "-f", str(plugin_dst)])
        require_success(proc, f"codesigning {plugin_dst}")

    return sandbox_home


def write_structor_config(
    sandbox_home: Path, *, debug_mode: bool = False, auto_fix_verbose: bool = False
) -> None:
    config_path = sandbox_home / ".idapro" / "structor.cfg"
    lines = [
        f"debug_mode={'true' if debug_mode else 'false'}",
        "auto_fix_types=true",
        f"auto_fix_verbose={'true' if auto_fix_verbose else 'false'}",
    ]
    config_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def run_idump(
    repo_root: Path,
    plugin_path: Path,
    idump_path: str,
    binary: Path,
    function_name: str,
    *,
    debug_mode: bool = False,
    auto_fix_verbose: bool = False,
) -> dict:
    real_home = Path.home()
    sandbox_home = prepare_plugin_home(plugin_path, real_home)
    write_structor_config(
        sandbox_home, debug_mode=debug_mode, auto_fix_verbose=auto_fix_verbose
    )

    try:
        env = os.environ.copy()
        env["HOME"] = str(sandbox_home)
        proc = run(
            [
                idump_path,
                "--plugin",
                "structor",
                "--pseudo-only",
                "-f",
                function_name,
                str(binary),
            ],
            cwd=repo_root,
            env=env,
        )
        require_success(proc, f"running idump for {function_name}")
        return {"output": strip_ansi((proc.stdout or "") + (proc.stderr or ""))}
    finally:
        shutil.rmtree(sandbox_home, ignore_errors=True)


def run_missing_regarg_regression(
    repo_root: Path, plugin_path: Path, idump_path: str
) -> None:
    binary = build_missing_regarg_fixture(repo_root)
    run = run_idump(
        repo_root,
        plugin_path,
        idump_path,
        binary,
        "regarg_callee",
    )
    output = run["output"]

    required_substrings = [
        "Structor: possible missing argument in _regarg_callee",
        "v0 (w19)",
        "is populated by 1 caller before the call",
        "inferred type",
        "variable 'v0' is possibly undefined",
        "// w19",
    ]
    missing = [needle for needle in required_substrings if needle not in output]
    if missing:
        raise RuntimeError(
            "missing expected output from missing-regarg regression: "
            + ", ".join(missing)
            + "\n"
            + output
        )


def run_overlap_regression(repo_root: Path, plugin_path: Path, idump_path: str) -> None:
    binary = build_overlap_scope_fixture(repo_root)
    run = run_idump(
        repo_root,
        plugin_path,
        idump_path,
        binary,
        "overlap_scope",
        debug_mode=True,
        auto_fix_verbose=True,
    )
    output = run["output"]

    required_substrings = [
        "Structor: diagnostic: overlap recovery in overlap_scope selected Pair *",
        "from var #0 (p @ x0)",
        "var #4 (var#4 @ x0)",
        "Structor: Auto-fixed 1 types in overlap_scope",
        "integer -> Pair *",
        "Pair *slot;",
        "slot->left",
    ]
    missing = [needle for needle in required_substrings if needle not in output]
    if missing:
        raise RuntimeError(
            "missing expected output from overlap regression: "
            + ", ".join(missing)
            + "\n"
            + output
        )

    if "possible missing argument in overlap_scope" in output:
        raise RuntimeError("unexpected missing-argument warning for overlap_scope")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run live type-fixer regressions with idump"
    )
    parser.add_argument("--repo-root", required=True)
    parser.add_argument("--plugin", required=True)
    parser.add_argument("--idump", default="idump")
    args = parser.parse_args()

    repo_root = Path(args.repo_root).resolve()
    plugin_path = Path(args.plugin).resolve()
    if not plugin_path.exists():
        raise RuntimeError(f"plugin not found: {plugin_path}")

    run_missing_regarg_regression(repo_root, plugin_path, args.idump)
    run_overlap_regression(repo_root, plugin_path, args.idump)
    print("[PASS] missing register argument regression")
    print("[PASS] overlap recovery regression")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"[FAIL] {exc}", file=sys.stderr)
        raise SystemExit(1)
