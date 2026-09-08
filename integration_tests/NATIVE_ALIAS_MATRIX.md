# Native alias and branch regression matrix

Build and check the twelve fixtures at -O0, -O1, and -O2 on both macOS arm64 and x86-64:

```sh
python3 integration_tests/check_native_alias_matrix.py --repo-root . --plugin build/structor.dylib --idump /path/to/idump
```

This explicit matrix uses the installed macOS SDK, Apple clang, and llvm-objdump. It records compiler commands, source and binary hashes, disassembly, all 72 actual ctree exports, and `build/native_alias_matrix/summary.json`. Each invocation uses a fresh database and an isolated, ad-hoc codesigned plugin copy through the existing idump harness. Generated binaries, disassembly, and JSON stay in the ignored build directory. `--skip-build` reuses the recorded binaries. `--architecture`, `--optimization`, and `--case` select a subset. The ordinary integrity runner also exercises the constructed alias checker on both integer-address and 2-byte-pointer carriers.

The byte contracts are separate from the ctree witness classifications. Every function reads base+0 (2 B) and base+8 (8 B). Positive alias paths additionally read base+32 (4 B), except the offset join, which reads base+40 and base+48 (4 B each). Negative paths have only the two anchors. Base and other are distinct symbolic inputs; the fixture entry point allocates distinct backing objects. Candidate alias definitions, mutations, memory uses, label numbers, and goto targets are recorded by ctree identity. Optimizer-eliminated or split aliases are not counted as retained alias witnesses.

The unchanged integrated collector passed 68/72 contracts. The four failures were:

* arm64 -O1 and -O2: the two-offset join became a 2-byte pointer initialized with `base + 8 B`, followed by conditional `pointer += 4` elements. Dropping the pointer alias on compound assignment lost the base+48 B access.
* arm64 and x86-64 -O0: switch fallthrough became an if/goto tree with a shared load label. Unconditional label invalidation discarded the valid lexical base-alias predecessor. The pre-branch collector found this access on both binaries, confirming a recall regression.

The corrected collector passes 72/72 unchanged contracts. It preserves normal lexical predecessors separately from unknown jump entries, widens before observing a label when the added entry exceeds the state budget, and updates known address aliases using checked element scaling. Prefix operations return the updated address; postfix operations retain the old expression result while committing the new alias. Per-expression snapshots are cleared on re-evaluation. Unknown values, loaded-pointer aliases, invalid pointee sizes, overflow, and lossy address conversions do not create adjusted address aliases.

The constructed checker verifies 71 cases on each of two actual carrier types (142 cases total). Its required element-size field rejects an integer carrier masquerading as pointer-scaling coverage. The cases include the original 51 branch witnesses, shared-label positives and skipped-definition negatives, label-entry budget overflow, scaled +=/-=, signed deltas, cast preservation, RHS reads before update, overflow, pre/post increments/decrements, expression-result assignment, loop re-evaluation, and narrowing conversions. No lvar types, saved user types, or cfunc caches are changed by the probes; each replacement body is restored after collection.

Scope: unresolved jump destinations remain unknown; this is not a full CFG/SCC analysis. The existing state and traversal budgets remain finite. Unknown jump-entry precision loss is distinct from budget widening, and a truncated budget prefix is not emitted as a complete offset set. The native matrix covers the stated two 64-bit architectures and three optimization levels; other targets are unverified by this matrix.
