#!/usr/bin/env python3
"""Build reproducible native alias fixtures for macOS arm64 and x86-64."""
import argparse
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys


def run(command):
    return subprocess.run(command, text=True, capture_output=True, check=True)


def build(root, architectures, optimizations):
    if sys.platform != "darwin":
        raise RuntimeError("this matrix currently targets the installed macOS SDK")
    compiler = run(["xcrun", "--sdk", "macosx", "--find", "clang"]).stdout.strip()
    sdk = run(["xcrun", "--sdk", "macosx", "--show-sdk-path"]).stdout.strip()
    disassembler = run(["xcrun", "--find", "llvm-objdump"]).stdout.strip()
    source = root / "integration_tests/test_native_alias_matrix.c"
    directory = root / "build/native_alias_matrix"
    directory.mkdir(parents=True, exist_ok=True)
    manifest = {
        "compiler": run([compiler, "--version"]).stdout,
        "sdk": sdk,
        "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        "variants": [],
    }

    def one(architecture, optimization):
        name = f"test_native_alias_matrix_{architecture}_O{optimization}"
        binary = directory / name
        command = [compiler, "-arch", architecture, "-isysroot", sdk,
                   "-mmacosx-version-min=15.0", "-std=c11", "-g", f"-O{optimization}",
                   "-Wall", "-Wextra", "-Werror", "-fno-lto", "-o", str(binary), str(source)]
        result = run(command)
        assembly = run([disassembler, "--macho", "--disassemble", str(binary)]).stdout
        assembly_path = directory / (name + ".asm")
        assembly_path.write_text(assembly)
        return {
            "architecture": architecture, "optimization": optimization,
            "binary": name, "command": command,
            "sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
            "compiler_stdout": result.stdout, "compiler_stderr": result.stderr,
            "disassembly": str(assembly_path),
        }

    variants = [(architecture, optimization) for architecture in architectures
                for optimization in optimizations]
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(one, architecture, optimization)
                   for architecture, optimization in variants]
        for future in futures:
            variant = future.result()
            manifest["variants"].append(variant)
            print(f"[BUILT] {variant['binary']} {variant['sha256']}", flush=True)
    (directory / "build_manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return manifest


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--architecture", action="append", choices=["arm64", "x86_64"])
    parser.add_argument("--optimization", action="append", type=int, choices=[0, 1, 2])
    args = parser.parse_args()
    build(args.repo_root.resolve(), args.architecture or ["arm64", "x86_64"],
          args.optimization or [0, 1, 2])
