# Experimental absolute-memory type evidence

The experimental inference engine now publishes memory results keyed by `(absolute origin, signed byte displacement, access width)`. Previously the public result slot used a hash as identity and ordinary engine extraction did not populate it. The pipeline remains disabled by default.

`FunctionTypeInferenceResult::get_mem_type(base, offset, size)` performs exact lookup. The deprecated two-argument lookup returns no result when multiple widths share the origin/displacement, even if their types match. The public `memory_types` map uses complete key equality, so hash collisions cannot merge locations. This changes the C++ map key type and requires client source updates/rebuilds.

Production ctree extraction resolves explicit globals, literal absolute addresses, constant array indices, and member addresses. Pointer arithmetic uses the expression's target element width; checked signed byte displacement and target address-range checks reject wraparound and incomplete/lossy address expressions. The address resolver has a 64-node recursion cap. A global pointer's storage address never stands for its unknown pointee address. Local pointer origins and dynamic indices remain unresolved.

For each exact location, publication requires one concrete view directly supported by its actual constraints, an exact storage-width match, and agreement with all corresponding decoded model variables. Only directly attached `IsBase`, `IsPointerTo`, and concrete `OneOf` constraints justify a view. Contradictory or ambiguous views are omitted with diagnostics; insertion order does not select a winner. Registration, access width, or an arbitrary model completion cannot establish a concrete type. Equality-only propagation is outside this bounded implementation.

`memory_provenance` distinguishes `HardConcreteConstraint` from `SoftConcretePreference` and records distinct constraint source addresses. Source addresses are not independent observations. Repeated same-type ctree views are deduplicated; the recorded sites need not enumerate every occurrence. There is no memory confidence score. `memory_diagnostics` records invalid locations, inconsistent variable metadata, insufficient concrete evidence, conflicting views, or unsupported model values. Unresolvable ctree locations contribute to `stats.unresolved_memory_accesses`.

IDA partial storage types such as `_QWORD` are not promoted to an integer solely because they occupy eight bytes. Supported decompiler views include represented integral/Boolean/floating scalar types and supported pointer chains; enums, aggregates, and full function prototypes require additional evidence. Native source types can differ from recovered IDA types: the native integer fixture is recovered as signed `int64`, while a separate constructed SDK `_QWORD` control tests storage-only omission.

The layout synthesizer no longer looks up memory using a function entry address as the presumed origin of the selected pointer's fields. Absolute/global evidence has no implicit correspondence to pointer-relative structure offsets.

## Assumption register and falsification probes

| ID | Assumption and dependent result | Stress/falsification probe |
|---|---|---|
| M1 | Origins are explicit absolute data origins, not function identities or arbitrary local pointer values. | Local-pointer dereference remains unresolved; address-only expressions add no memory view. |
| M2 | Identity includes all 64 origin bits, signed byte displacement, and access width. | High origins sharing low 32 bits, negative offsets, overlapping widths, legacy XOR-colliding pairs, and a hash function returning zero remain distinct. |
| M3 | An access interval lies in the analyzed target address space. | Test 32/64-bit boundaries, reserved `BADADDR`, zero width, negative underflow, positive overflow, and `INT64_MIN` displacement. |
| M4 | A concrete view is evidence only when directly attached to the actual memory variable. | Registration-only and size-only constraints emit no type; incompatible models and conflicting concrete views are omitted. |
| M5 | Decompiler concrete views are preferences, not independently established source declarations. | Preserve the soft provenance and verify actual SDK object-type metadata. `_QWORD` emits an insufficient-evidence diagnostic. |
| M6 | Repeated views are correlated observations. | Repeated equal constraints produce one view, deduplicated recorded source sites, and no confidence increase. |
| M7 | Public inference performs no IDB application. | Live checks compare cfunc body identity, argument mapping, local types, and saved function type before/after. |

For an origin `0x100001234`, displacement `-8 bytes`, and width `4 bytes`, the interval is `[0x10000122C, 0x100001230)`. Width `8 bytes` denotes a separate view `[0x10000122C, 0x100001234)`. The signed displacement calculation and complete byte interval are validated before lookup/extraction; this integer arithmetic has no rounding error.

## Algorithm and complexity

1. Resolve an explicit address and access width; otherwise record the unresolved expression.
2. Intern the complete location and attach an access-width constraint plus each distinct represented decompiler preference.
3. Group actual constraints by complete location and detect inconsistent variable metadata.
4. Deduplicate concrete views; reject zero/multiple/ambiguous views and width mismatches.
5. Decode every associated memory variable and publish the sole view only if all agree.

With `E` ctree expressions, address traversal cap `D=64`, and fixed-size scalar views, address discovery takes expected `O(E D)` time. Evidence extraction scans `C` constraints; linear per-location deduplication gives worst-case `O(C²)` type/identity comparisons and `O(C)` stored entries, excluding Z3 model/solver costs. Structured type comparison adds its represented type size to each comparison. Exact hash-map lookup is expected `O(1)`, worst-case `O(M)` for `M` locations; the legacy widthless lookup is `O(M)`. Hash collisions affect cost, not identity.

## Reproduction and observed validation

```sh
cmake --build build --target test_memory_type_evidence test_instruction_semantics_identity
ctest --test-dir build --output-on-failure -R 'memory_type_evidence|instruction_semantics_identity'
python3 integration_tests/check_memory_inference.py \
  --repo-root . --plugin build/structor.dylib --idump /path/to/idump \
  --record-dir /tmp/structor-memory-evidence
```

The live hook requires `-DSTRUCTOR_ENABLE_LIVE_TEST_HOOKS=ON` and is excluded from production artifacts. Testing used licensed IDA 9.4 `idump`, not `idat`. On 2026-09-08 the SDK plugin build, 12 direct evidence groups, and the instruction-identity target passed. Four native functions each passed seven public-engine scenarios: disabled, exact complete keys, conflicting constraints, size-only constraints, constructed SDK partial storage, constructed SDK conflicting ctree views, and native extraction. The native cases cover floating globals, local-pointer dereference, address-only use, and recovered integer storage. Full function/type restoration checks passed.

The same public reproducer also passes against the combined compound backend. All 198 standalone CTest entries and the complete 20-suite licensed integrity run pass (364.9 s). The production artifact excludes all 15 test-hook markers and its installed copy passes strict codesign verification. No claim of completed interprocedural memory inference follows from this validation.

## Bounded scope

- **High impact:** Distinct origin/displacement pairs can denote the same physical address. This implementation preserves explicit origins and does not perform global alias equivalence or pointer-relative object reconstruction.
- **Medium impact:** Soft-only concrete views remain suggestions with explicit provenance. A missing output may reflect unresolved origin, insufficient evidence, or conflict; inspect diagnostics and unresolved counts.
- **Low impact:** The deprecated widthless lookup preserves source-level convenience only for unambiguous widths and has linear lookup cost.

Primary provenance is the SDK definitions of `cexpr_t`, `ctree_visitor_t`, and `tinfo_t` in the IDA 9.4 SDK, production `instruction_semantics.cpp`/`memory_type_evidence.cpp`, and the public-engine JSON emitted by `memory_inference_live_checks.hpp`. The forced-collision test uses the production equality/lookup code with an injected colliding hash; it does not assume hash uniqueness.
