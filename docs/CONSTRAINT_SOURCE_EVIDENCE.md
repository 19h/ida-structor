# Consulted constraint-source metadata

`TypeConstraint::origin` identifies the producer of a constraint independently of the constraint's hard/soft status. Its default is `TypeConstraintOrigin::Unspecified`; caller-created constraints remain unspecified unless the caller uses `sourced_from(...)`. Description text is never parsed to assign origin.

| Origin | Tagged production emissions |
|---|---|
| `InstructionUsage` | Assignment/comparison relationships and operator requirements derived from ctree usage. |
| `DecompilerType` | Concrete expression type views and sizes obtained from IDA `tinfo_t`, including casts, pointee views, member types, and absolute-memory views. |
| `FunctionSignature` | Call argument/return preferences and the engine's validated formal-argument mapping. |
| `AliasRelation` | Steensgaard equality and Andersen pointer/pointee constraints. |
| `Heuristic` | Signedness preference, small/large-constant and pointer-use suggestions, and the existing conditional-integer assumption. |
| `Unspecified` | No explicit producer annotation. |

A producer category is not a statement that the constraint is correct. A generated hard constraint can originate from a heuristic or decompiler type. Hard-model uniqueness, when separately established, is uniqueness under the installed formulas.

`InferredVariableType::source_evidence` contains source-site/category records from the queried variable's connected effective-constraint component. Records retain origin, constraint kind, source address, hard/soft status, soft weight, and `Direct`/`Related` relation. `Direct` means the constraint explicitly mentions the variable. `Related` means it is reachable through constraints relating other variables. Both hard and positive-weight soft binary relations connect variables; nonpositive soft constraints are excluded, matching the solver converter.

These are **consulted origins**, including soft constraints the selected model may violate. They are not accepted support, causal explanations, independent samples, model-satisfaction certificates, or evidence that a selected type is unique. The helper does not re-encode constraints or modify type, confidence, application policy, or the model-evidence result. Selected-model satisfaction is not computed by this metadata layer.

The existing `from_signature`, `from_decompiler`, `from_alias`, and `from_usage` flags mean that the corresponding origin occurs in the consulted component. A violated signature preference can therefore coexist with `from_signature=true`. Heuristic and unspecified records remain visible in the typed record list without being relabeled as one of the older flag categories.

`source_constraints` holds sorted distinct recorded source addresses, excluding unavailable `BADADDR`. Records at the same address remain distinct when category, kind, hard/soft status, weight, or relation differ. Repeated records with the same tuple are deduplicated; different concrete constraint values can share a source record. None of these record counts estimates independent evidence.

## Assumption register

| ID | Assumption and dependent result | Stress/falsification probe |
|---|---|---|
| S1 | Origin is explicit metadata. | Descriptions containing every category name remain unspecified; unrelated descriptions do not change explicit origin. |
| S2 | Variable identity uses the complete session identity. | A new variable with the same diagnostic index, function address, and local index remains disconnected. |
| S3 | The graph represents consulted effective constraints. | A zero/negative-weight soft equality must not import the other variable's signature origin. |
| S4 | Connectivity is descriptive, not causal. | A hard int32 local connected to a violated float32 signature preference retains its int32 result and the related consulted signature record. |
| S5 | Site repetition is correlated. | Repeated equal records collapse; direct/related and hard/soft distinctions remain separate. |
| S6 | The indexed constraint set remains immutable and alive for the index's lifetime. | The engine constructs/uses the index within result extraction; published records copy primitive metadata and have no pointers to constraint storage. |
| S7 | Provenance extraction performs no IDB application. | The live probe compares body identity, argument mapping, local types, and saved function type before and after inference. |

Addresses remain full-width IDA `ea_t` values and are serialized as decimal strings in diagnostic JSON. No address truncation or numeric confidence calculation is performed.

## Algorithm and complexity

```text
index each effective constraint under every valid variable it mentions
for each queried local:
    traverse the connected component using complete variable identities
    visit each constraint once and classify it as direct or related
    copy source metadata, sort it, and deduplicate equal source records
    derive distinct available addresses and origin-presence flags
```

With `C` constraints, index construction requires expected `O(C)` time and `O(C)` auxiliary entries. A query reaching `Vq` variables and `Cq` constraints requires expected `O(Vq + Cq log Cq)` time, including record sorting, and `O(Vq + Cq)` working space. Hash collisions affect lookup cost but not identity. Across `L` local queries the component work is repeated; worst-case connected inputs therefore require `O(L (V + C log C))` expected time. Z3 solving/proof-query costs are separate.

## Reproduction

```sh
cmake --build build --target test_constraint_sources
ctest --test-dir build --output-on-failure -R '^constraint_source_evidence$'
python3 integration_tests/check_constraint_source_evidence.py \
  --repo-root . --plugin build/structor.dylib --idump /path/to/idump \
  --record /tmp/structor-constraint-sources.json
```

The compile-gated live hook requires `-DSTRUCTOR_ENABLE_LIVE_TEST_HOOKS=ON`; production marker checks exclude it from distributed plugin artifacts. Use licensed `idump`, not `idat`.

Nine portable groups exercise the production source index and actual assignment/cast, comparison/heuristic, memory/call, and both alias-generator emissions. The public-engine live check covers connected consulted metadata, a fresh identity sharing diagnostic coordinates, inactive soft bridges, and unspecified caller annotations. Native phase emitters are also checked for structured instruction/decompiler/signature/heuristic origins. The controlled constraints' source-site addresses are synthetic test annotations; the native origin counts come from actual production phase output.

On 2026-09-08 the IDA 9.4 SDK plugin build, all nine portable groups, four public-engine cases, and native producer-origin checks passed with licensed IDA 9.4 `idump`. Function body identity, argument mapping, local types, and saved function type remained unchanged.

## Bounded scope

- **High impact:** Hard/soft status is independent of producer reliability. Neither an origin flag nor a record count validates a source declaration or proves model uniqueness.
- **Medium impact:** Related metadata can cross an optional soft relation that the final model violates; the explicit `Related` label and hard/soft fields retain this distinction.
- **Low impact:** The new C++ fields change object layout and require plugin/API consumers to rebuild. Large fully connected components can repeat provenance traversal per local.

Primary provenance: production `TypeConstraint` emission sites in `instruction_semantics.cpp`, `type_inference_engine.cpp`, and `alias_analysis.cpp`; `constraint_source_evidence.cpp`; the compile-gated `source_evidence_live_checks.hpp`; and the reproducible portable/live checks above.
