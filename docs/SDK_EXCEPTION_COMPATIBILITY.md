# Exception ctree compatibility

The collector's structured-exception traversal compiled against IDA SDK 9.4,
but failed against both SDK revisions pinned by CI. The older `ctry_t` exposes
`is_wind` as a Boolean data member and its `ccatch_t` has no `is_finally()`.
The compatibility helper selects the available representation at compile time.
Ordinary legacy catch-all handlers remain exception handlers; wind handlers
remain cleanup paths that cannot resume normal continuation. SDKs with an
explicit finally representation retain normal-finally traversal.

Primary evidence is the `ctry_t` and `ccatch_t` declarations in
[`hexrays.hpp`, stable pin](https://github.com/HexRaysSA/ida-sdk/blob/70e29758997745524e917e296fbbfeef5faf9c57/src/include/hexrays.hpp)
and the
[`ida931` pin](https://github.com/HexRaysSA/ida-sdk/blob/acacbbcc8fa349d919cc185d88b1ab3710ca252d/src/include/hexrays.hpp).
The failed build is recorded in
[CI run 34214814457](https://github.com/19h/ida-structor/actions/runs/34214814457).

## Assumptions and falsification

| ID | Assumption | Probe | Result scope |
| --- | --- | --- | --- |
| C1 | The two pinned SDK declarations are the supported legacy representations. | Compile the complete plugin against each exact commit; exercise Boolean and method representations in portable tests. | Both local macOS arm64 builds pass; remote platform execution is separate. |
| C2 | Wind cleanup cannot establish a normal continuation alias. | Retain exceptional-exit traversal and test legacy wind, ordinary catch-all, and current finally distinctions. | Three compatibility groups pass; the existing flow semantics are unchanged. |

Each isolated build starts from Structor `c60dd403` plus this compatibility
change. All 209 standalone CTest entries pass against each pinned SDK
(32.39 s and 32.52 s). These first pinned builds disabled live-test hooks.
Enabling hooks in CI exposed the same SDK representation difference in the
constructed-ctree builder. Its legacy branch now constructs wind cleanup as a
catch-all and explicitly reports unsupported setup for normal-finally cases,
which that SDK cannot represent. The complete plugin subsequently compiles
with hooks enabled against both exact pinned SDKs. The current-SDK builder
retains its existing finally/wind construction. The combined worktree also compiles against the local
9.4 SDK. These checks establish compile compatibility and helper behavior;
they do not constitute a new native exception-runtime matrix. [C1, C2]

The helper uses constant time and constant space per handler. No byte offsets,
layout units, or solver constraints change. A medium-impact compatibility
boundary remains: future SDK exception representations require declaration
inspection and directed tests before extending this claim. Quality review
covered both representation branches, ordinary catch-all behavior, unchanged
wind/finally semantics, exact SDK provenance, and the bounded platform claim.
