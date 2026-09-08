# Evidence for selected local type values

A satisfiable type model can select a concrete type even when the installed
hard constraints admit other types. The experimental engine keeps that selected
candidate in `InferredVariableType::type` and separately records its evidence.
It does not assign every selected value medium confidence.

For selected value v of type variable x, the evidence probe checks
`C_hard ∧ (x ≠ v)`. UNSAT establishes uniqueness relative to the supplied hard
formulas. SAT returns a distinct witness value. Unknown and exhausted budgets
remain distinct. Soft objectives are absent from this query. The selected model
must satisfy every supplied hard formula, and v must be a concrete value that
matches x in that model.

| Local result field | Meaning |
| --- | --- |
| `model_value_status` | Hard-formula determination, alternative model, resource limit, solver unknown, or invalid model |
| `alternative_type` | Decoded witness that differs from the selected candidate; not a second preferred answer |
| `model_value_reason` | Diagnostic text for incomplete/invalid checks |
| `evidence_query_bounds` | Generic symbolic limits used by the hard formulas; present conservatively if any such predicate was used during the function run |

The result owns ordinary C++ type values and text. No model or Z3 expression
escapes the engine through these fields. `infer_variable()` retains the local
qualification when it returns one result outside the function result object.
The context-borrowing expression witness exists only inside the internal probe.

Bounded predicates that occur only in soft objectives do not qualify an otherwise
unbounded hard proof. A dedicated exact-local/independent-soft-size check verifies
that distinction.

Default conversion and application accept engine values only when they are
uniquely determined without generic symbolic bounds. Ambiguous, unverified, and
bounded-only determinations remain inspectable but are skipped. Explicit
`to_ida_types(true)` includes convertible candidates. Applying suggestions
requires `TypeApplicationConfig::allow_model_candidates = true`; the confidence
threshold remains an independent check. Externally constructed results with no
model status retain their caller-provided evidence contract. Direct
`apply_variable()` also takes an explicit caller-provided type.

Medium/low confidence are categories here, not calibrated probabilities.
Unbounded hard-formula determination receives medium; other model values receive
low. Hard constraints can themselves encode incomplete or incorrect assumptions
about a decompiled program. Logical uniqueness is not proof of the lost source
declaration or of the accuracy of every extraction rule.

## Assumption register and falsification probes

| ID | Assumption and dependent result | Stress test / falsification probe |
| --- | --- | --- |
| V1 | The solver model and finite quantifier-free hard formulas share one live context. | Wrong model, foreign contexts, wrong sorts, non-Boolean hard assertions, and `inspect(x,x)` are rejected by the direct helper. |
| V2 | The provided hard formulas define the domain of the proof. | At depth 0, pointer subtyping can make `Ptr(Int32)` unique while full-domain `Ptr(Int8)` is also valid. The bounded flag must survive and block default application. |
| V3 | Preferences do not become hard facts. | Soft scalar and 17-parameter function-pointer candidates have distinct witness models; hard equality chains retain unique compound values. |
| V4 | Solver resources are finite and shared across local checks. | Zero query/time budgets publish resource limits; mixed SAT/UNSAT calls preserve push/pop balance and consume the expected query count. |
| V5 | An exported witness owns no context-bound solver handle. | All 16 live scenarios inspect returned values after context destruction, including nested compound values and alternatives. |
| V6 | Default application must not write an unverified candidate even when the ordinary confidence threshold is lowered. | Actual IDA local/saved-type snapshots remain unchanged for soft, bounded-only, and exhausted-budget candidates. Explicit candidate opt-in and hard/external controls perform the requested writes. |

The shared default budget is 512 solver queries and 1000 ms for the evidence
phase. Local indices are sorted before consuming it so hash iteration does not
decide which variable is checked first. Solver timeouts are cooperative;
constructor-time assertion installation and model evaluation cannot be preempted
by this deadline. A solver unknown retains its own reason and is not relabeled
as a completed proof.

## Verification and reproduction

Seven direct helper groups and eight compound groups pass. The compound checks
also passed AddressSanitizer and UndefinedBehaviorSanitizer. Sixteen actual IDA
public-engine/application scenarios pass, including hard/soft values, equality
chains, bounded uniqueness, two zero-budget cases, conversion policies, context
lifetime, actual writes, and unchanged-type rejection controls.

```sh
ctest --test-dir build --output-on-failure --no-tests=error \
  -R 'model_value_evidence|type_compound_model_value_evidence'
python3 integration_tests/check_type_model_evidence.py \
  --repo-root . --plugin build/structor.dylib --idump /path/to/compatible/idump \
  --record-dir /tmp/structor-model-evidence
```

For V locals and C hard assertions, initial validation performs C model
evaluations; ordering uses O(V log V) time and O(V) indices. At most
min(V, configured query count) additional solver checks run. Their complexity is
solver-dependent. Decoded candidate/witness storage is proportional to the
represented type payload. The query-count and time bounds do not bound SDK
materialization or model-evaluation costs.

- **High impact:** uniqueness depends on the installed extraction rules; rule
  accuracy and ABI/qualifier completeness remain separate requirements.
- **Medium impact:** function-wide bound qualification is conservative. A hard
  scalar independent of another bounded variable can still be marked qualified.
  Dependency-specific unbounded proofs are a possible precision extension.
- **Low impact:** the new C++ result fields and conversion signature require
  rebuilding embedding consumers.

Primary provenance: `model_value_evidence.cpp`, `type_inference_engine.cpp`,
`type_applicator.cpp`, the linked direct/compound tests, and the licensed IDA
checks in `type_model_evidence_live_checks.hpp`. QG1–QG7 apply to this bounded
change; it does not establish project-wide completion.
