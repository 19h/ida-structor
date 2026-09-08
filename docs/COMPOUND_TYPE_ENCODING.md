# Compound type representation

The experimental type solver now represents the complete value carried by
`InferredType`. The CPU lattice and SMT codec share the abstract order described
in [TYPE_LATTICE_CONTRACT.md](TYPE_LATTICE_CONTRACT.md).

| Represented value | SMT representation |
| --- | --- |
| Scalar/top/bottom | Shared `BaseType` enumeration |
| Pointer | Recursive pointee value |
| Pointer with absent stored pointee | Separate constructor; this is not a runtime null address |
| Array | Recursive element value and unsigned 32-bit element count |
| Structure reference | Complete unsigned 64-bit type identifier |
| Function | Recursive return value and complete ordered parameter list |
| Sum | Complete recursive alternative list |

One context owns the mutually recursive type/list declarations. Independent
encoders in that context share those declarations. A moved context reconnects
its internally owned `TypeEncoder` to the destination wrapper. External
encoders still borrow their context wrapper and must not outlive or move away
from it. Encoding caches own detached type snapshots.

Ground type values use exact recursive relations. Generic symbolic relations
use finite, quantifier-free expansions: default depth 1, list length 16, and
4096 expansion steps per predicate invocation. Exceeding the step budget throws
`SymbolicTypeQueryLimit`; it does not substitute `false` or a partial formula.
Limits apply to generic exploration, not representation: a concrete 300-level
type and a function with more than 16 parameters retain their complete values.

Constraint conversion propagates exact hard bindings through hard equality
components. Original equalities remain installed, so inconsistent concrete
observations remain contradictory. Soft and multichoice concrete candidates
extend generic exploration through guarded alternatives; their weights and
hard/soft classification remain unchanged. Converting soft constraints alone
does not assume that hard constraints were installed. Public engine status and
bounds provenance are specified in [TYPE_QUERY_STATUS.md](TYPE_QUERY_STATUS.md).

## Assumption register

| ID | Assumption and dependent result | Stress test / falsification probe |
| --- | --- | --- |
| C1 | Types are finite acyclic values from the current `InferredType` domain. | Round-trip nested pointer/array/function/sum values, absent pointees, full-width IDs/counts, and depth 300. Cyclic externally mutated trees are outside the contract. |
| C2 | Declared function information consists of the stored return and ordered parameter types. | Vary the ninth and seventeenth parameters and the return type. Calling convention, variadic mode, qualifiers, and structure layout are not represented by this object. |
| C3 | Generic symbolic predicates explore the reported finite domain. | A witness excluded at depth 1 or list length 2 reappears when the corresponding bound is increased; zero expansion budget has a distinct failure status. |
| C4 | Optional candidates remain optional. | Deep soft candidates survive a hard size predicate; conflicting hard candidates remain UNSAT, including through equality chains. |
| C5 | Context-owned declarations and expressions do not outlive the context. | Multiple encoders, context move construction/assignment with initialized cached encoders, and sanitizer runs. |
| C6 | A type identifier alone does not supply a structure byte extent. | Structure size queries and arrays/sums containing unknown extents report unknown rather than an invented size. |

## Verification and reproduction

The production-linked compound test has 10 directed groups. The sampled
43-type CPU/SMT cross-check covers all 1849 ordered pairs for subtyping and
compatibility. Compound and semantics-identity groups pass AddressSanitizer and
UndefinedBehaviorSanitizer. Actual IDA checks exercise the public extraction
API and 12 engine scenarios, including default-limit nested array, double
pointer, and 17-parameter function-pointer candidates.

```sh
cmake --build build --parallel
ctest --test-dir build --output-on-failure --no-tests=error \
  -R 'type_compound_encoding|type_instruction_semantics_identity|type_lattice'
python3 integration_tests/check_type_query_status.py \
  --repo-root . --plugin build/structor.dylib --idump /path/to/compatible/idump
```

A generic size query previously entered recursive symbolic reasoning that did
not finish within the configured timeout. The replacement generates no
recursive-function or quantified AST for that symbolic predicate. Recorded
default-depth size-query probes completed in 17–35 ms; this is a local
measurement, not a worst-case latency bound. Solver timeout still governs
search, and deeper domains can return unknown within that timeout. [C3]

## Bounds and adjacent work

Encoding and decoding are O(T) recursive work for T logical type nodes,
excluding Z3/SDK internals; recursion stack is O(H) for height H. Ordered lists
use O(L) storage for L entries. Cached keys retain O(T) detached payload. A
generic predicate emits O(B) expanded subproblems for configured expansion
budget B; their formula sizes also depend on the fixed scalar relation table.
Constraint candidate extensions may compare O(K1 K2) explicit alternatives for
a binary relation. These bounds do not imply polynomial SMT solve time.

- **High impact:** a successful model does not establish a unique type. Local
  candidate evidence and application controls remain separate engineering work.
- **High impact:** complete represented values do not reconstruct missing ABI,
  qualifier, variadic, or structure-layout information. Those facts are unknown.
- **Medium impact:** exploration limits trade completeness for finite formula
  construction. Bounds and explicit-candidate flags must accompany diagnostics.
- **Low impact:** public C++ object layouts changed; embedding consumers require
  rebuilding. No claim of binary ABI compatibility is made.

Provenance is the production implementation in `src/z3/type_lattice.cpp`,
`src/z3/instruction_semantics.cpp`, and `src/z3/context.cpp`, the linked test
sources, and the licensed IDA probes. QG1–QG7 apply to this bounded repair;
project-wide completion remains unproven.
