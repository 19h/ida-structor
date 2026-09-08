# Reaching aliases in access collection

Access collection retains separate reaching environments through branches,
conditional expressions, short-circuit expressions, switch cases, and loop
backedges. A definition in one alternative does not become the incoming value
of its sibling. At a join, each retained feasible alternative contributes its
observed accesses.

This repairs both invented and missed accesses. In the six-case unchanged-code
probe, four cases failed: sibling contamination, loss of an incoming alias,
loss of a possible alias at a join, and loss of a loop-carried alias. The two
positive controls passed. The final constructed SDK ctree suite contains 51
cases and restores the original carrier body after every case.

## State and traversal

Each environment contains pointer aliases, escaped locals, scalar facts,
value epochs, and supported path predicates. Epoch allocation is global to
the collection pass and is not rolled back with a branch snapshot. Assignment
invalidates facts about the previous value.

Predicate normalization uses the ctree operation's width and signedness.
Simple equality and ordering predicates can reject contradictory alternatives.
Literal values and supported arithmetic, casts, and increments also reject
demonstrably impossible loop backedges. This predicate reasoning is separate
from the more restrictive numeric bounds used for array-index expansion.

Loop analysis first explores reaching environments to stabilization, removes
provisional observations, and then observes the stabilized heads. `return`,
`break`, and `continue` have distinct exits. Switch case/default predicates
survive joins, and fallthrough carries its environment to the next case.
Ordinary finalizers execute on outgoing environments; wind cleanup remains
exception-only. Unknown terminated exception paths do not widen a separate
normal continuation.

## Bounds and assumptions

| ID | Assumption or boundary | Falsification probe | Dependent behavior |
| --- | --- | --- | --- |
| B1 | Separate alternatives describe possible reaching definitions within the retained state domain. | Opposite branches, incoming aliases, divergent and identical offsets, complementary conditions, and condition reassignment. | Branch isolation and join observations |
| B2 | At most 16 distinct alternatives and 65536 stateful walk steps are retained before widening alias knowledge. | An 18-way join, an advancing pointer loop, and a strong definition after alternative overflow. | Bounded exploration; omitted aliases after widening remain unknown |
| B3 | Predicate facts refer to the same variable epoch and compatible widths; the ctree opcode specifies comparison signedness. | Stale conditions, high-bit signed/unsigned controls, narrowing `(uint8_t)256`, and constant counter updates. | Feasibility pruning |
| B4 | A lexical walk cannot reconstruct arbitrary goto entry. Labels in functions containing goto start with unknown aliases. | Bypassed definitions, unreachable lexical loads, two-entry cyclic goto regions, and a new definition following a label. | Conservative goto handling |
| B5 | Exception handlers may be entered from unknown points in the try body. | Finalizer mutations, finalizer-established aliases, returning paths, finalizer return, and wind cleanup. | Conservative exception handling |
| B6 | Existing operand sequencing is preserved. General unspecified sibling pointer-alias effects are not solved by this branch repair. | Eleven native and five constructed assignment/call witnesses, plus 35 index-guard cases. | Expression observations and effects |

Widening forgets aliases and predicates; it does not treat the first N pointer
offsets as a complete array. A subsequent strong definition can recover an
alias after alternative overflow. Exhaustion of the global walk-step budget
continues to limit subsequent state retention. Neither budget is a wall-clock
deadline. These limits are currently internal constants; per-analysis precision
diagnostics and configurable limits remain separate work.

State normalization compares at most 16 retained alternatives pairwise before
ordinary continuation. Each comparison examines alias and predicate facts;
predicate membership can itself require pairwise checks. Switch traversal can
visit each fallthrough suffix for each entry. Loop cost depends on retained
environments and nesting. The state-step threshold bounds detailed exploration,
not the total number of source nodes visited or a general CFG/SCC complexity.
Offsets and access widths are measured in bytes.

## Evidence and adjacent scope

The 51-case SDK suite, 16 sequencing cases, and 35 index-guard cases pass in
the isolated production collector. The combined artifact is checked by
`check_full_integrity_suite.py`. The checker verifies the exact set of case
names, positive/negative access expectations, and body restoration.

- **High impact:** incorrect reaching definitions caused invented fields and
  omitted observed fields. The repaired state traversal addresses both within
  the specified domain.
- **Medium impact:** widening, goto entry, and exception entry can reduce
  recall. They do not establish a full control-flow graph analysis.
- **Medium impact:** optimized native functions can replace aliases with
  conditional moves or split locals. Constructed ctree coverage alone does not
  establish behavior for every compiler lowering.

Provenance is the production collector, the unchanged-code differential probe,
the SDK ctree construction/restoration checks, and actual `idump` results.
The live target is IDA/Hex-Rays 9.4 on macOS arm64; broader runtime behavior is
unknown until tested.
