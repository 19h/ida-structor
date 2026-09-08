# Represented IDA type conversion

`InferredType::from_tinfo()` projects an IDA type into Structor's represented type domain. It returns `Unknown` when a source category or a child cannot be represented. Storage width alone does not identify an integer type. The optional `TypeConversionIssue` output records the first conversion failure category.

| Source | Conversion |
| --- | --- |
| Explicit signed/unsigned integer, 1, 2, 4 or 8 B | Corresponding integer base |
| Boolean, 1 B | `Bool` |
| Floating type, 4 or 8 B | `Float32` or `Float64` |
| `void` | `Void` |
| Pointer with represented child | Recursive `Pointer` |
| Function with represented return and all parameter types | Return and ordered parameter projection |
| Array with represented element, base 0 and positive `uint32_t` count | `Array(element, count)` |
| Structure/union with a valid source TID | Opaque `Struct(TID)` |
| Partial storage (`_QWORD`, etc.), enum, bitfield, anonymous aggregate, unsupported scalar width, unknown integer signedness, unsupported array bounds or unsupported child | `Unknown` with an issue |

This is an abstract type projection. It does not preserve declaration qualifiers, function calling conventions, variadic metadata, argument locations or other ABI attributes. A floating declaration whose target storage is 8 B projects to `Float64`, including the tested carrier's 8 B `long double`. The conversion does not establish equivalence between all source C declarations with the same projection. A nominal enum is unsupported even when its underlying storage width matches a represented integer.

An unsupported child invalidates a concrete compound conversion. `Pointer(Unknown)` would be an exact ADT value, so it is not emitted as a replacement for an unknown pointed type. The instruction extractor retains independent facts: dereferencing an address requires `IsPointer(address)`; a loaded pointer value or pointer cast target has its own `IsPointer(value)` fact; an observed object width retains `HasSize(value, n B)`. A partial pointer child therefore does not erase the known outer shape. These facts do not create an additional variable-to-pointee relation, which remains outside the existing constraint vocabulary.

Unsupported observations are exported as `FunctionTypeInferenceResult::unsupported_type_observations`. Each observation contains the source address, issue, original spelling, optional numeric TID and optional byte width. The data contains no Z3 or `tinfo_t` handles and remains readable after the analysis context or source type object is destroyed. The spelling is display text and is never solver evidence or an identity key. A numeric TID retains only its original IDB meaning. Repeated observations can remain separate; they are not independent evidence counts. Diagnostics are independent of source-origin flags and selected-model evidence.

The representation traversal takes O(n) time for n visited type nodes and O(n + d) auxiliary/output storage for recursion depth d. Traversal stops after 64 nested nodes and reports `DepthLimit`. Array-count conversion checks the range before narrowing. The tested SDK declares `array_type_data_t::nelems` as `uint32`; its constructor rejected the `UINT32_MAX` test array. The portable shim deliberately has a wider count to test the narrowing guard, and that test is not a claim that the SDK can construct such an array. Array extent remains subject to the existing checked `InferredType::size()` arithmetic.

## Assumption register and falsification probes

| ID | Assumption and dependent result | Probe |
| --- | --- | --- |
| A1 | SDK category tags distinguish partial storage, Boolean, enum and represented integer types. Conversion uses those tags. | Actual SDK `_QWORD`, `_BOOL1`, `_BOOL4`, enum and explicit integer controls record category tags, width, emitted constraints and public results. |
| A2 | The abstract domain intentionally omits qualifiers and function ABI metadata. Function results are projections only. | Paired complete/partial function children exercise full ordered parameter conversion; differing ABI metadata does not establish source-type equivalence. |
| A3 | Zero-based arrays with a positive 32-bit count match the represented constructor. | Base-1, zero-count, maximum-count, portable wider-count and complete-element controls. |
| A4 | A bounded traversal may omit deeper source types. Such omission is explicit. | A 64-pointer chain returns `DepthLimit`; ordinary nested pointer/array/function positives remain represented. |
| A5 | Diagnostic spellings and numeric IDs describe the original observation, without global identity guarantees. | Portable metadata is copied and inspected after the type and extractor are destroyed. |

## Validation and bounded findings

The actual baseline SDK probe reproduced `_QWORD -> uint64`, `_BOOL1 -> int8`, `_BOOL4 -> int32`, enum -> `int32`, and a 4 B anonymous structure -> `uint32`; all were emitted as hard dereference pointee claims through the public engine. Partial pointer, array and function children inherited the fabricated scalar recursively. These are high-impact conversion findings because a selected model could satisfy a hard assertion that was introduced by a lossy conversion. The baseline also dropped a source array's nonzero base (medium impact). The correction retains supported narrow and compound positives and reports unrepresented forms explicitly.

The optional conversion argument and new result fields change the C++ binary
interface. Embedding consumers must rebuild against the updated headers.

Validation on 2026-09-08: the full SDK plugin build passed; all eight portable conversion groups passed along with the memory, source-origin, inactive-preference and lattice regression targets; all 23 actual SDK/public-engine controls passed. The extended-floating control had an unsupported storage width and was retained as a diagnostic. The combined artifact also passes all 206 standalone CTest entries and all nine affected runtime suites (conversion, query status, memory, model evidence, source origins, signature/ABI mapping, application identity, lattice materialization, and instruction identity).

Run the portable target `test_represented_type_conversion` and the SDK integration checker:

```sh
python3 integration_tests/check_represented_type_conversion.py \
  --repo-root . --plugin /path/to/structor.dylib --idump idump
```

The signature checker records `_QWORD *` as an unsupported partial projection and verifies that it contributes no concrete parameter fact; the represented `unsigned int` and `double` facts remain correctly mapped. Its focused hook initializes the observation collector used by the production inference entry.

The integration checker uses the actual SDK, production extractor and public `infer_function()` on controlled expressions. The original carrier body, argument mapping, local types and saved function type are verified unchanged. These controlled expressions test conversion and constraint boundaries; they do not claim that every source compiler/decompiler emits each expression naturally. Native plugins are installed into an isolated test home and codesigned by the existing idump harness.

Quality gates: QG1 has no normative dependency; QG2 is the register above; QG3 covers conversion, extraction, diagnostics and paired controls; QG4 uses byte units and checks integer narrowing; QG5 distinguishes represented values from unsupported metadata and SDK construction limits; QG6 uses repository implementation and the installed SDK declarations as primary provenance; QG7 is limited to the conversion findings and documented representation boundaries above.
