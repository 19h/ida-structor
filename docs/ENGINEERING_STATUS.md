# Engineering status

This work pursues accuracy, flexibility, adaptability, and evidence-based
inference across Structor. A passing local regression suite is evidence for the
covered behavior; it does not establish complete recovery of source-level types
or completion of this project-wide objective.

## Requirements and evidence

| Requirement | Verification source | Status |
| --- | --- | --- |
| Preserve every observed byte range when generating array candidates | Production `ArrayConstraintBuilder` tests; sparse and overlapping fixture contracts | Eighteen detector cases and seven live layout/diagnostic cases pass |
| Preserve selected array element types when extracting nested subobjects | Residual-fragment helper tests and exact recursive-constructor contracts | Nine helper cases and both live constructor contracts pass; known residual types survive byte-array fallback |
| Use index bounds only where the comparison holds for the same variable value | Fresh-IDB collector tests for branches, short-circuit expressions, mutation, loops, and casts | All 35 combined-plugin cases pass; original collector fails six selected differential cases |
| Observe assignment and call operands before their effects; reject bounds invalidated by sibling effects | Eleven native ctree and five constructed SDK ctree cases, plus the unchanged guard suite | All 16 sequencing cases and 35 guard cases pass; matched baseline fails 11 sequencing cases |
| Preserve separate reaching aliases across branches, joins, loop backedges, and structured exits | 51 constructed SDK ctree cases with exact access expectations and carrier restoration | All 51 pass; the original collector fails four of six initial differential cases |
| Distinguish the type of a pointer base from the type of its loaded field | Production access inference helper tests and real `TypeFixer::analyze_variable` calls | Twenty-two focused helper cases and 13 live type-fixer cases pass |
| Preserve full function/variable identity in inference caches | Production composite-key and semantics tests, forced collisions, distinct high addresses/SSA versions, and live ctree extraction | Caller cache and experimental variable identities verified; live extraction emits 19 constraints from 16 expressions |
| Preserve complete type values in lattice caches | Real function/structure hash collisions, mutable child aliases, and returned-result mutation | Directed production lattice tests pass; cache entries own detached snapshots |
| Preserve the declared abstract subtype order when joining, meeting, and materializing types | Production-linked law enumeration and actual IDA union/member/extent checks | 43 types, 1849 pairs, and 79507 triples pass the sampled laws; all 12 live materialization checks pass |
| Preserve complete compound type values and bounded-query provenance in the experimental SMT path | Production-linked codec/semantics tests, sanitizer probes, and public IDA engine calls | Ten codec groups and 12 live engine cases pass; full structure IDs, recursive values, soft candidates, and distinct bound failures are preserved |
| Publish absolute-memory types with complete address/displacement/width identity and explicit evidence | Forced collisions, checked address intervals, production extraction, and public IDA engine scenarios | Twelve portable groups and 28 live cases pass against the compound backend; insufficient/conflicting views are omitted and hard/soft provenance is retained |
| Merge existing types without losing evidence, observed storage, padding, or protected names | Production matcher unit tests and anonymous IDA type checks | Standalone tests and 11 real-IDA checks pass |
| Return solver diagnostics that remain valid after the synthesis context is destroyed | Production solver/optimizer UNSAT tests and public API return/destruction checks | Standalone lifetime checks and public API UNSAT/relaxation checks pass |
| Reject inference results belonging to another function before applying types | Real local/prototype snapshots, foreign/unknown/high-address rejection, and positive application controls | All nine live checks pass within the active IDB |
| Map signature arguments to actual locals and distinguish target ABI defaults from recovered function evidence | Fifteen portable tests, five live argument-map cases, and six target-family cases | All pass; two foreign-ABI fixtures explicitly falsify the assumption that every function follows its target default |
| Preserve pointer forwarding as address evidence rather than inventing a field load | Alias-only call/comparison negatives and loaded-field positive controls | Live controls pass; original-collector isolation confirms removal of a fictitious linked-list pointer observation |
| Maintain public API, deterministic layouts, transactional persistence, global recovery, vtables, and type fixing | Full licensed integrity suite and external CMake consumer | All 20 suites pass against the combined compound/memory artifact (364.9 s); no layout contracts changed |
| Maintain reproducible, usable builds and diagnostics | CMake build, CTest, compile-gated hook checks, explicit `idump` runtime diagnostics | 198 standalone CTest entries pass; the release build excludes all 15 hook markers and its installed copy passes codesign verification |
| Extend adaptive and interprocedural inference beyond existing supported paths | Production implementation, adversarial fixtures, convergence/resource tests | Incomplete; see remaining work |

## Assumption register

Dependent findings reference these identifiers.

| ID | Assumption | Stress test / falsification probe | Dependent results |
| --- | --- | --- | --- |
| A1 | The local integration target is macOS arm64 with IDA/Hex-Rays 9.4 and an ABI-compatible `idump`. | Load the plugin in a fresh IDB, require actual pseudocode, and compare exact contracts. Repeat on each supported OS, ISA, and SDK before extending the platform claim. | Local runtime and build results only |
| A2 | A reconstructed type describes observed storage; unobserved source declarations are unknown. A regular sparse sequence is a candidate array, not proof of an original array declaration. | Supply incompatible element types, overlapping access widths, missing positions, and explicit element caps. Require the candidate to contain every observed byte and retain competing interpretations. | Array inference |
| A3 | A finite symbolic range requires a condition that dominates the access and still describes the accessed variable value; integer expressions retain their declared width. | Test the opposite branch, a later/prior comparison, disjunction, narrowing, mutation, calls, loop backedges, unstructured entry, high/negative bounds, and wraparound. | Bounded-index expansion |
| A4 | A direct, consistently typed load at offset zero supports one extra pointer level; partial or conflicting views do not identify a unique pointee. | Test scalar loads, pointer loads, callbacks, displaced/nested accesses, narrow reads from larger pointees, and aliases used without loads. | Base-type inference |
| A5 | Existing-type reuse may add information but cannot silently remove observed storage or analyst-protected names. | Reject shrinking/conflicting overlays; verify untouched field types/evidence, padding fragments, array metadata, union/bitfield preservation, and name collisions. | Existing-type merges |
| A6 | Hashes choose cache buckets; equality uses the complete semantic identity. | Use function addresses separated by 2^32 bytes, distinct variable indices, and a deliberately constant hash. | Caller-inference cache |
| A7 | An externally supplied inference result belongs to the current IDB and the same function revision; its full function address must match the application target. | Reject another function, `BADADDR`, and addresses differing above bit 31; verify unchanged local/prototype types and positive same-function writes. IDB identity and stale same-function indices require separate revision tracking. | Type application |
| A8 | Exported diagnostics contain metadata and do not own Z3 expressions tied to an expired context. | Produce real solver and optimizer UNSAT cores, destroy the context, then copy/move/read/destroy the returned diagnostics. Repeat through the public synthesis API. | Diagnostic lifetime |
| A9 | Experimental variable identities are session-local; the ctree stays stable during each extraction pass. Hashes and diagnostic labels are not identities. | Force collisions, vary high address bits/SSA/width/function scope, reuse diagnostic IDs, and recycle node storage between passes. | Experimental extraction and solver variables |
| A10 | Abstract types are finite acyclic trees. Cached keys/results must not retain caller-mutable child aliases; Z3 expressions and external encoders borrow their context. | Mutate the ninth function parameter without changing its hash, mutate a returned cached result, and instantiate multiple encoders in one context. | Lattice cache snapshots and shared sort declarations |
| A11 | Assignment state changes follow operand observations; call-body effects follow argument observations. Ctree sibling order does not prove argument evaluation order. | Actual `q = *q`, indexed assignments, pre/post increments, loads around escaped-index calls, and constructed sibling reference/write combinations. | Expression sequencing |
| A12 | Signature parameters follow the recovered `argidx`; target defaults do not prove a particular function's ABI. Location models require a complete lowered fixed prototype. | Nonidentity/invalid maps, six cross-target binaries, foreign ABI overrides, hidden return pointers, mixed register banks, and stack exhaustion. | Signature/ABI facts; details in [SIGNATURE_ABI_INFERENCE.md](SIGNATURE_ABI_INFERENCE.md) |
| A13 | The lattice is the finite abstract order specified in [TYPE_LATTICE_CONTRACT.md](TYPE_LATTICE_CONTRACT.md), and materialized sums preserve complete object alternatives. | Exhaustive checks over the recorded finite sample; actual IDA packed/nested/function-pointer unions, invalid alternatives, and extent boundaries. | CPU lattice algebra and union conversion; this is not a C conversion or source-type recovery claim |
| A14 | Reaching aliases and simple path predicates are tracked within a bounded state domain; widening and unknown goto/exception entry lose precision. | Divergent/sibling branches, loop backedges, complementary/stale predicates, 18-way overflow, switch fallthrough, irreducible goto entry, finally, and wind cleanup. | Branch analysis; limits and further assumptions in [BRANCH_ALIAS_ANALYSIS.md](BRANCH_ALIAS_ANALYSIS.md) |
| A15 | Compound values retain the current abstract type domain; generic symbolic predicates use recorded bounds and optional candidate extensions. | Full-width IDs/counts, deep round trips, complete parameter lists, conflicting hard equalities, deep soft candidates, bound increases, budget exhaustion, and engine reuse. | SMT codec and query status; [COMPOUND_TYPE_ENCODING.md](COMPOUND_TYPE_ENCODING.md) and [TYPE_QUERY_STATUS.md](TYPE_QUERY_STATUS.md) |
| A16 | Absolute-memory origins must be established from address expressions; a concrete view requires actual constraint evidence and matching width/model. | High/colliding addresses, overlapping widths, negative offsets, wraparound, partial storage, conflicting views, local unknown pointees, and address-only controls. | [MEMORY_TYPE_INFERENCE.md](MEMORY_TYPE_INFERENCE.md); no pointer-relative/global alias inference is implied |

## Changes and reproducibility

Array extents now include missing positions. For example, observed 4-byte loads
at offsets 0, 4, and 12 with stride 4 require
`((12 - 0) / 4) + 1 = 4` elements and `4 * 4 = 16` bytes. The former three-element
candidate covered only `[0, 12)` and excluded the load at offset 12. Checked
integer arithmetic rejects unrepresentable extents; configured caps count
unobserved positions as well as observed elements. [A2]

Conflicting element types retain separate array interpretations. Homogeneous
runs are partitioned by normalized storage type, and unknown observations do
not bridge incompatible runs. Each candidate owns the observation identities
supporting that view; candidate generation and layout coverage use those
identities rather than only offset and width. Reversed observation order is
checked against the same materialized union layout. [A2]

The corrected sparse extent also exposed a subobject-splitting downgrade:
removing the child interval rebuilt a complete residual element from `_QWORD`
storage and discarded the selected unsigned element type. Residuals now retain
that type when their offset and size align with complete source elements and
their previous type is empty or partial. Independently known equal types remain
unchanged. Known pointers,
callbacks, aggregates, scalar interpretations, and array dimensions are not
overwritten by a more generic array. Both recursive-constructor contracts keep
their original unsigned tail-field requirement. [A2]

Type merges stage each accepted overlay before replacing the input. They check
storage conflicts before changing names or moving fields, split intersected
padding, synchronize array metadata, and reserve protected names during
deduplication. Rejected overlays do not reorder or rename the input. Ten initial
regressions failed against the original production implementation; additional
review added protected-name and exact-no-op cases. [A5]

The index collector now controls branch/loop traversal order explicitly. Live
testing exposed two SDK boundary assumptions: the parent list includes a null
root sentinel, and the default visitor enumerates branch/loop bodies before
their conditions. The verified collector handles both, including lowered
sign-bit guards and index postincrements. [A1, A3]

Assignments now commit alias/value state after operand observations. The actual
linked-list `q = *q` load survives this order, as do indexed assignment and
increment controls. Call-body effects follow argument traversal, while sibling
expressions that can modify an index prevent expansion under an obsolete guard.
Eleven native and five constructed SDK ctree cases pass; the latter verify
restoration of the original function body. [A1, A11]

Branch traversal now retains separate reaching environments and observes each
retained feasible alternative. Loop exploration stabilizes these environments
before publishing observations; capped exploration does not convert the first
N offsets into an array extent. Supported predicates retain value epochs and
ctree comparison signedness. Structured exits, switch fallthrough/default,
finally, and wind cleanup have directed controls. All 51 constructed SDK cases
pass in the combined artifact. Goto/exception entry and budget widening remain
explicit precision boundaries. [A1, A14]

Signature constraints validate `argidx` and map each recovered parameter to its
actual local. The detector selects supported target families without host-OS
macros and reports the evidence source. Two stripped foreign-ABI examples show
that recovered argument locations can agree with the wrong target default;
this limitation remains explicit. Modeled x64 stack locations start at callee
entry: System V uses `SP + 8 bytes`, Microsoft uses `SP + 40 bytes`. Full
contracts, primary references, and falsification records are described in
[SIGNATURE_ABI_INFERENCE.md](SIGNATURE_ABI_INFERENCE.md). [A12]

An overlapping-array test exposed a returned diagnostic retaining a Z3 tracking
expression after its context had been destroyed. The public synthesis boundary
now copies metadata only. Weighted Max-SMT also tracks hard assumptions so an
UNSAT result can identify the observations responsible. [A8]

An integer run with a floating-point view of its final element retains both
typed views. When the scalar/union layout wins, `success_relaxed` reports the
unmet aggregate preferences. A live 12-byte example verifies all three
4-byte positions, the two offset-8 views, and all four dropped preference
descriptions; the candidate is not removed merely to make the status read
`success`. [A2, A8]

A full unchanged-HEAD build distinguishes inherited snapshot drift from code
regressions. Six cases produce identical results and pseudocode in that build
and the changed plugin; their runtime baseline is documented in
[`integration_tests/contracts/README.md`](../integration_tests/contracts/README.md).
Collector-only isolation separately proves that a linked-list pointer union
came from comparing an address alias with zero, not from a pointer-typed load.
Both versions preserve the machine-code loop limit omitted by the old snapshot.
The revised collector removes the fictitious field interpretation. [A1, A4]

Type application checks the full function address before capturing or changing
locals, and direct signature application also requires successful inference.
The rejection checks snapshot real local and saved prototype types; positive
controls verify actual same-function writes. [A7]
All seven rejection cases mutate locals or saved signatures with the original
applicator; the two same-function positive controls pass with both versions.

Experimental extraction now analyzes each ctree node inside one function/pass.
Previously its full-function visitor called the single-expression API with a
null function, which returned no constraints. Exact interning includes full
function addresses, SSA versions, memory widths, and expression-node identity;
independent public factory calls remain distinct even when their diagnostic IDs
and labels match. Copies retain identity. Rebuild embedding C++ consumers because
the public object layouts changed, although factory signatures are unchanged.
The integrated live check observes 19 constraints from 16 expressions, and an
external CMake consumer builds successfully. [A1, A9]

Lattice join/meet and encoding caches compare complete types. Directed tests
use two nine-parameter functions with the same bounded hash and a scalar/struct
hash collision. Snapshot tests also mutate shared parameter children after a
cache insertion and mutate cache-hit results; keys and cached values now remain
unchanged. Multiple encoders in one context share its BaseType declaration.
These cache repairs are separate from the compound SMT encoding. [A6, A10]

The CPU lattice now checks source-sum alternatives before destination sums,
retains incomparable alternatives in joins, and distributes meets over sums.
The production-linked finite law check covers 43 types, 1849 ordered pairs,
and 79507 ordered triples, including associativity and deterministic
operand-order representation. Original code fails 11 sampled law groups.
All 12 actual IDA conversion/extent checks pass, including a 3-byte packed union
whose two alternative widths are 3 and 2 bytes. Live validation exposed IDA's
consuming `create_udt` API: the expected size must be saved before creation.
The mock now models that ownership rule. Byte-size multiplication uses a
64-bit intermediate and reports unknown on overflow. The detailed contract,
assumptions, and complexity limits are in
[TYPE_LATTICE_CONTRACT.md](TYPE_LATTICE_CONTRACT.md). [A1, A10, A13]

The experimental SMT codec now uses shared recursive type/list declarations.
It preserves full structure IDs, array counts, nested pointees, function returns
and all parameters, and sum alternatives. Generic symbolic predicates use
finite expansions; exact hard evidence specializes those predicates while soft
candidates remain guarded choices. All 12 public engine status cases pass,
including complete nested arrays, double pointers, and a 17-parameter function
pointer under default limits. A bounded UNSAT result and an exhausted expansion
budget have distinct public statuses. This does not establish uniqueness of a
selected model value. [A15]

The combined run completed 18 checks before a new command lacked its matching
label in the runner's parallel registries. The omitted final lattice check
passed separately. Each command now owns its label in one registry, eliminating
that registration mismatch. The complete 20-suite run now passes with the corrected registry and memory implementation. All 198 standalone CTest entries also pass. [A1]

Absolute-memory inference now keys outputs by full origin, signed byte
displacement, and access width. Actual constraints must supply one concrete
view that matches the model and storage width. Conflicting or storage-only
views are omitted with diagnostics; soft preferences retain their provenance.
Four native functions each pass seven public-engine scenarios against the
compound backend, including explicit `_QWORD` and conflicting SDK ctree controls.
The layout synthesizer no longer treats a function address as the origin of a
selected pointer's fields. [A16]

The installed `idump` on the development machine could load the plugin but could
not initialize its own decompiler API. It returned success with assembly-only
output. The fixture harness now reports that condition explicitly. A locally
built IDA 9.4 `idump` produced the exact expected alias-lifetime result and
pseudocode. This is a tool/runtime compatibility observation, not evidence of a
Structor synthesis failure. [A1]

Use an `idump` built for the selected IDA runtime:

```sh
cmake -S . -B build -G Ninja \
  -DIDA_SDK_DIR=/path/to/idasdk \
  -DCMAKE_BUILD_TYPE=Release \
  -DBUILD_TESTS=ON -DSTRUCTOR_ENABLE_LIVE_TEST_HOOKS=ON
cmake --build build --parallel
ctest --test-dir build --output-on-failure --no-tests=error -E '_live$'
python3 integration_tests/check_full_integrity_suite.py \
  --repo-root . --plugin build/structor.dylib --idump /path/to/compatible/idump
```

The integration runners install and codesign temporary plugin copies. Production
builds must exclude live-test hooks. The Linux and Windows plugin suffixes are
`.so` and `.dll`, respectively; local runtime evidence here does not verify those
platforms.

## Algorithm bounds

- Array candidate validation: O(n log n) time and O(n) auxiliary storage for
  n observations, including deterministic ordering of owned evidence. Typed-run
  partitioning takes O(nT + n log n) time for T distinct normalized storage
  types, excluding SDK type-comparison internals. Z3 solve time is bounded by
  its configured timeout, not a polynomial-time guarantee. [A2]
- Direct base-type inference: O(n + d) type operations for n observations and
  d compared pointer levels, with O(1) auxiliary type handles, excluding IDA
  type-object internals. [A4]
- Residual array-type retention: O(1) interval arithmetic and type operations,
  excluding SDK equality and type-construction internals. The source type's
  exact byte extent must match the selected field. [A2]
- Bounded integer evaluation: O(BE) time for E expression nodes and B candidate
  index values, with B limited to 32; O(E) evaluation stack. Guard ancestry and
  cached loop-effect analysis add their own traversal costs. Finite intervals
  enclose possible values; disjoint predicates can leave unreachable values
  inside the interval. This is not a complete path-reachability solver. [A3]
- Existing-type overlay: O(mS + f log f) expected time and O(S) auxiliary storage,
  where m is the number of incoming fields, f is the resulting field count, and
  S includes the copied field/evidence payload. Hash operations assume ordinary
  dispersion. The merge is bounded by `MAX_FIELDS` and `MAX_STRUCT_SIZE`. [A5]
- Caller inference cache: expected O(1) lookup and O(k) entries for k distinct
  function/variable pairs, with full-key comparison on collision. [A6]
- Function identity preflight: O(1) time and space. The existing application
  pipeline retains its own per-variable traversal and propagation costs. [A7]
- Diagnostic export: O(D + L) time and space for D records containing L bytes
  of description text; no solver handles cross the boundary. [A8]
- Exact variable interning: expected O(1) per key, plus O(L) for L name bytes;
  adversarial collisions require O(V) equality checks. Storage is O(V + E + S)
  for persistent keys, current-pass expression nodes, and name bytes. [A9]
- Type-cache snapshots: O(T) time and space for T logical tree nodes. Complete
  equality resolves collisions; caches do not use hashes as type values. [A10]
- Type joins: O(k log k) structural comparisons and O(k²) subtype comparisons
  for k flattened alternatives. Meets can distribute over Cartesian products;
  detailed output-sensitive bounds are in the lattice contract. [A13]
- Sibling-effect scans: O(V²) worst-case time across a pathological call tree
  containing V expression nodes; each scan uses O(H) stack for tree height H.
  Indexed expansion remains capped at 32 candidate values. [A11]
- Branch state normalization compares retained environments pairwise. Detailed
  exploration widens after 16 alternatives or 65536 stateful steps; these are
  not wall-clock or whole-CFG bounds. See the branch-analysis contract. [A14]

## Bounded scope expansion and remaining work

- **High impact — experimental type representation:** complete compound values,
  context move adoption, and bounded-query status are now implemented and tested.
  Absolute-memory result indexing and direct evidence publication are also
  implemented. Pointer-relative memory and global alias equivalence remain
  separate work. The current abstract type domain
  lacks structure layout, qualifiers, variadic mode, and per-function ABI
  metadata; a complete encoding of that domain does not recover those absent
  facts. The experimental pipeline remains disabled by default.
- **High impact — function ABI and revision identity:** prototype mapping and
  target-default selection are repaired. Per-function ABI overrides absent from
  recovered metadata still require machine-code evidence; stale inference across
  IDB/function revisions requires explicit revision tracking. Foreign function
  address rejection is implemented and live-tested.
- **High impact — provenance:** preserve load versus address-flow evidence and
  independent observation sites across deduplication. Access count alone is not
  a confidence calibration. Branch-state joins and loop-carried aliases now
  have reaching-definition checks within a bounded domain. Analysis precision
  diagnostics and configurable state limits remain separate work. The
  experimental engine also needs to distinguish uniquely constrained types
  from arbitrary values selected by one satisfiable model.
- **High impact — interprocedural inference:** the experimental fixed-point API
  remains explicitly unimplemented. Completing it requires convergence,
  recursion/SCC, widening, and resource-bound contracts; a successful local
  layout test cannot verify this requirement.
- **Medium impact — control flow:** lexical guard proofs do not cover general
  dominance, arbitrary goto entry, loop induction, or exact disjoint index sets.
  Finite intervals may overapproximate reachable values; supporting exact path
  predicates requires retaining them through synthesis. The collector now
  retains a bounded subset of simple predicate relations through collection.
- **Medium impact — validation breadth:** extend live coverage across compiler
  optimization levels, calling conventions, target bitness, and platforms. The
  current local fixture matrix alone cannot establish that breadth.
- **Medium impact — matching completeness:** sparse byte-field matching does not
  yet establish semantic equivalence of whole aggregates or import arbitrary
  bitfield layouts. Preserve those observations until a representable merge is
  established.
- **Medium impact — callee evidence availability:** a local call whose callee has
  not been decompiled may have only scalar placeholder argument types. Pointer
  depth cannot be inferred from source declarations absent from the analyzed
  ctree. Pair unknown-prototype preservation controls with known-prototype
  positives; bounded callee-body inference remains a separate capability.
- **Low impact — artifact hygiene:** fixture compilation rewrites tracked binary
  artifacts. Generated local changes should not obscure source review; migrate
  runners to isolated fixture outputs in subsequent build-system work.

## Quality gates

QG1: no normative or ethical judgment is required. QG2: assumptions and
falsification probes are recorded above. QG3: the requirement table preserves
the full objective and explicitly marks incomplete coverage. QG4: byte offsets,
integer extents, overflow checks, and algorithm bounds are specified. QG5:
adversarial unit and live regressions are required before claiming each repair
verified. QG6: provenance is the production source, original-code regression
runs, and actual build/runtime output; no external claims are inferred from
mock-only tests. QG7: bounded adjacent risks and opportunities are listed above.
Project-wide completion remains unproven.
