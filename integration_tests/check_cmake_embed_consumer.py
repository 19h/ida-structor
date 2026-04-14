#!/usr/bin/env python3

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


def run(
    cmd: list[str], *, cwd: Path | None = None, env: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, cwd=cwd, env=env, text=True, capture_output=True)


def require_success(proc: subprocess.CompletedProcess[str], description: str) -> None:
    if proc.returncode == 0:
        return
    output = (proc.stdout or "") + (proc.stderr or "")
    raise RuntimeError(f"{description} failed\n{output}")


def detect_ida_sdk_dir(repo_root: Path) -> str:
    env_value = os.environ.get("IDA_SDK_DIR")
    if env_value:
        return env_value

    cache_path = repo_root / "build" / "CMakeCache.txt"
    if cache_path.exists():
        for line in cache_path.read_text(encoding="utf-8").splitlines():
            if line.startswith("IDA_SDK_DIR:"):
                _, value = line.split("=", 1)
                if value:
                    return value

    raise RuntimeError(
        "IDA_SDK_DIR is not set and could not be detected from build/CMakeCache.txt"
    )


def write_consumer_project(project_dir: Path, repo_root: Path) -> None:
    cmake_text = (
        f"""
cmake_minimum_required(VERSION 3.20)
project(structor_embed_consumer LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(STRUCTOR_BUILD_PLUGIN OFF CACHE BOOL "" FORCE)

add_subdirectory("{repo_root.as_posix()}" structor)

add_executable(consumer_smoke main.cpp)
target_link_libraries(consumer_smoke PRIVATE structor::core)
""".strip()
        + "\n"
    )

    main_text = """
#include <structor/api.hpp>
#include <structor/host_integration.hpp>

#include <string_view>

int main() {
    auto& api = structor::StructorAPI::instance();
    (void)api;

    structor::HostIntegration integration;
    integration.set_auto_type_fixing_suppressed(true);
    integration.handle_ctree_maturity(nullptr, CMAT_FINAL);
    integration.handle_func_printed(nullptr);
    integration.shutdown();

    if (std::string_view(structor::materialization_mode_str(structor::MaterializationMode::Persist)) != "persist") {
        return 1;
    }

    return 0;
}
""".lstrip()

    (project_dir / "CMakeLists.txt").write_text(cmake_text, encoding="utf-8")
    (project_dir / "main.cpp").write_text(main_text, encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build a minimal external CMake consumer of structor::core"
    )
    parser.add_argument("--repo-root", required=True)
    args = parser.parse_args()

    repo_root = Path(args.repo_root).resolve()
    ida_sdk_dir = detect_ida_sdk_dir(repo_root)

    temp_root = Path(tempfile.mkdtemp(prefix="structor-cmake-consumer."))
    try:
        src_dir = temp_root / "src"
        build_dir = temp_root / "build"
        src_dir.mkdir(parents=True, exist_ok=True)
        write_consumer_project(src_dir, repo_root)

        configure = run(
            [
                "cmake",
                "-S",
                str(src_dir),
                "-B",
                str(build_dir),
                f"-DIDA_SDK_DIR={ida_sdk_dir}",
                "-DCMAKE_BUILD_TYPE=Release",
            ],
            cwd=repo_root,
        )
        require_success(configure, "configuring external consumer")

        build = run(
            [
                "cmake",
                "--build",
                str(build_dir),
                "--parallel",
                "--target",
                "consumer_smoke",
            ],
            cwd=repo_root,
        )
        require_success(build, "building external consumer")

        print("External CMake consumer: PASS", flush=True)
        return 0
    finally:
        shutil.rmtree(temp_root, ignore_errors=True)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"[FAIL] {exc}", file=sys.stderr)
        raise SystemExit(1)
