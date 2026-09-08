# Experimental type-query status

The opt-in `TypeInferenceEngine::infer_function()` reports the domain used by symbolic compound-type predicates. Exact represented types and exact hard constraints retain their full pointer, array, function-parameter, and sum structure. Generic nonground recursive queries use configured limits; concrete candidates supplied by constraints can extend that query domain without changing their hard/soft status or weight.

`FunctionTypeInferenceResult` records `symbolic_query_bounds`, `used_bounded_symbolic_queries`, and `used_explicit_symbolic_candidates`. Default generic limits are depth 1, list length 16, and 4096 predicate expansions. These are logical search limits, not source-language limits. The experimental pipeline remains disabled by default.

| Status | Interpretation |
|---|---|
| `Success` | The configured query admitted a model. This does not establish uniqueness of the selected type. |
| `NoModelWithinSymbolicBounds` | UNSAT after a generic bounded predicate was used. This does not prove an unbounded source-type contradiction. |
| `SymbolicQueryBudgetExceeded` | Predicate generation exhausted its expansion budget before a solver result. |
| `SolverFailure` | Exact UNSAT, solver unknown, or another ordinary solve failure; inspect the error string. |

The existing status values 0 through 5 are preserved; the two new statuses are 6 and 7. Per-run domain tracking resets before each valid explicitly enabled run, including reuse of an engine after a previous bounded query.

## Assumptions and falsification probes

| ID | Assumption and dependent result | Falsification probe |
|---|---|---|
| Q1 | `Success` means model existence in the recorded query domain. | Size 3 at depth 0/list length 0 has no generic model, while an exact byte array of length 3 succeeds without generic expansion. |
| Q2 | An explicit candidate is optional when its originating constraint is soft. | A soft nested-array candidate plus a hard size constraint succeeds beyond generic depth; original weights and hard equalities remain installed. |
| Q3 | The existing inference entry point is read-only until an applicator is invoked. | The live check compares cfunc body identity, argument mapping, local types, and saved IDB type before/after all cases. |
| Q4 | Bounds provenance belongs to the current run. | Reuse one engine for bounded SAT and exact UNSAT; the latter must clear both domain-extension flags. |

## Reproduction and verification

Build with `-DSTRUCTOR_ENABLE_LIVE_TEST_HOOKS=ON`; the hook is absent from production builds. Run with licensed `idump`, never `idat`:

```sh
python3 integration_tests/check_type_query_status.py \
  --repo-root . --plugin build/structor.dylib --idump /path/to/idump \
  --record /tmp/structor-type-query-status.json
```

The checker exercises the actual public engine with controlled actual constraints attached during its ordinary build phase. It covers disabled operation, exact array SAT, explicit soft deep-array SAT, bounded SAT, bounded UNSAT, exhausted generation budget, exact UNSAT, two engine-reuse cases, and three default-limit local-result positives. The latter preserve a nested array, a double pointer, and a pointer to a function with 17 ordered parameter types and a distinct final parameter type. The complete selected `InferredType` is compared against the supplied candidate; no type is applied to the IDB.

All 12 cases passed on 2026-09-08 with the IDA 9.4 SDK, licensed IDA 9.4 `idump`, and the pinned static Z3 build. SDK build and the compound-encoding and instruction-identity portable targets also passed. The public reproducer is included in the full integrity suite.

## Bounded scope

- **High impact:** A model can be one of several valid types; status `Success` alone must not be interpreted as type uniqueness.
- **Medium impact:** Explicit candidates can exceed generic depth/list limits while retaining bounded-query provenance. Both flags are needed to explain the query domain.
- **Low impact:** The added result fields and enum values require source rebuilds for clients embedding these C++ objects.

Provenance: production `src/z3/type_inference_engine.cpp`, `TypeConstraintSet::to_z3_hard/to_z3_soft`, `TypeLatticeEncoder` query tracking in `src/z3/type_lattice.cpp`, and the compile-gated `src/ui/type_query_status_live_checks.hpp`. These source paths and the live JSON are the evidence for the behavior above; no claim about an unconstrained source-language type universe is inferred from bounded UNSAT.
