# Flow-analysis precision and limits

Access collection now returns its precision limitations together with field
observations. `SynthOptions::flow` defaults remain 16 reaching alternatives and
65,536 state/item evaluation steps. The configuration file accepts:

```ini
[FlowAnalysis]
flow_max_states=16
flow_max_steps=65536
```

`max_states` accepts integers from 4 through `UINT32_MAX`. Four is the minimum
because normalization retains separate Normal, Return, Break, and Continue
exits. `max_steps` accepts integers from 1 through `UINT64_MAX`. Invalid values
are rejected transactionally by configuration loading and public option
validation. A directly constructed `AccessCollector` reports `invalid_limits`
without starting analysis. Existing configuration files retain the defaults.

The state limit applies to distinct alternatives at normalization points and
loop headers. Temporary vectors and the call stack are not independently
bounded by that number. Exceeding the step threshold enables persistent
widening; collection continues to inspect direct accesses. It does not abort
ctree traversal or establish a wall-clock limit. Counters include provisional
loop exploration and saturate at `UINT64_MAX`.

## Public diagnostics

```cpp
structor::SynthOptions options;
options.flow.max_states = 64;
options.flow.max_steps = 131072;
structor::AccessCollector collector(options);
auto pattern = collector.collect(function_ea, local_index);
structor::LayoutSynthesizer synthesizer(options);
auto result = synthesizer.synthesize(pattern, options);

for (const auto& source : result.flow_diagnostics) {
    for (const auto& event : source.analysis.precision_events) {
        // source.func_ea, source.var_idx, event.reason, event.node_ordinal,
        // event.ea, event.label, event.occurrences, event.max_states_before
    }
}
```

`AccessPattern::flow_analysis` records whether analysis started, the selected
limits, executed steps, peak distinct candidate states, widening operations,
and precision events. Events distinguish `state_budget`, `step_budget`,
`unknown_jump_entry`, `unknown_exception_entry`, and `opaque_assembly`.
A missing event does not prove that every ctree form was understood.

`node_ordinal` is a one-based preorder index of the collected ctree. It is
independent of memory addresses, `print_func()`, and loop replay. It is stable
for repeated collection of the same tree; recompilation, re-decompilation, or
rewriting the tree can change it. The optional `inspect_base_inference|...|ctree`
export includes this index on each node. `ea` can be `BADADDR`, and labels can
be absent. The ordinal identifies a site even in those cases.

`UnifiedAccessPattern::flow_diagnostics` preserves local scan reports
independently of retained access patterns and translated pointer views.
Consequently, a scan that produced zero accesses remains visible through
merging and evidence pruning. `SynthesisResult` and the public `SynthResult`
copy this list on both successful and unsuccessful layout outcomes. The local
site identity is `(function address, local index, node ordinal)`; a view delta
does not change it.

When layout runs and a recorded local scan exhausts a flow budget, synthesis sets
`arrays_suppressed_by_flow_budget` and disables optional aggregate array
inference for that call. The remaining direct fields retain their evidence.
Unknown jump, exception, and assembly causes are reported separately and do
not alone enable this budget-specific gate. Reusing a synthesizer restores
its prior array settings after the call. An empty-evidence or insufficient-access failure returned before layout starts
retains the scan ledger but leaves this decision flag false. Its embedded
synthesis error agrees with the outer analysis error. If layout ran successfully
before a later access-threshold check failed, that successful component remains
distinct from the overall failed operation.

## Evidence controls

Build a plugin with `BUILD_TESTS=ON` and
`STRUCTOR_ENABLE_LIVE_TEST_HOOKS=ON`, then run with the licensed `idump` runtime:

```sh
python3 integration_tests/check_flow_precision.py \
  --repo-root . --plugin build/structor.dylib --idump /path/to/idump \
  --record-file /tmp/structor-flow-precision.json
python3 integration_tests/check_alias_flow_regressions.py \
  --repo-root . --plugin build/structor.dylib --idump /path/to/idump
python3 integration_tests/check_global_flow_precision.py \
  --repo-root . --plugin build/structor.dylib --idump /path/to/idump \
  --record-file /tmp/structor-global-flow-precision.json
```

Both precision checkers are registered in `check_full_integrity_suite.py`.
The local checker uses two actual decompiled carriers: integer byte addresses
and pointers to two-byte elements. It constructs SDK ctrees to retain branch and alias
forms and restores each original body after collection. Its 54 cases cover:

- State caps 4, 16, and 64, including a divergent loop and a shared label.
- Step thresholds 1, 16, 64, 65,536, and 131,072.
- Distinct unknown jump, exception, and assembly entries.
- Invalid limits, stable repeated metadata, and synthesizer reuse.
- Empty local scans omitted from field patterns but preserved in diagnostics.

The finite-prefix probe has direct 4-byte reads at offsets 4, 8, and 12 bytes,
followed by a later alias-dependent 4-byte read at offset 16 bytes. Low step
thresholds preserve the first three observations and report loss of alias
precision. They cannot turn those observations into a three-element array.
Higher thresholds recover all four observations and allow the four-element
array: `(20 B - 4 B) / (4 B per element) = 4 elements`. The 20-byte value is the
exclusive evidence boundary; it is not a claim about the complete object size.

The global checker makes 12 ordinary public API calls across default and
one-step budgets, analysis and preview, and successful, insufficient-access,
and empty outcomes. The uncorrected global analyzer discarded every local scan
report while rebuilding its unified pattern. For four 4-byte observations at
offsets 0, 4, 8, and 12 bytes, the default run created a four-element array; a
one-step budget retained only offsets 0, 4, and 8 bytes and incorrectly created
a three-element array without a precision-loss report. Preserving the ledger
now suppresses that array and retains the observed scalar fields. The empty
and insufficient outcomes preserve attempted scans and consistent errors.
A helper that executes exactly one step remains within that budget; the checker
requires an exhausted consumer scan without falsely classifying every helper
as exhausted. The checked preview scope is invalid persisted TIDs and no
reported propagation, not a full snapshot of all IDB state.

The separate 142-case default alias checker retains the exact byte contracts
from the native alias repair. The native optimization/architecture matrix is
documented in [NATIVE_ALIAS_MATRIX.md](NATIVE_ALIAS_MATRIX.md).

## Assumptions and falsification probes

| Assumption | Dependent behavior | Probe |
| --- | --- | --- |
| State/item steps are a widening threshold, not a hard runtime bound | Budget names and reported counts | Thresholds 1/16/64 record executed steps above the configured value while direct fields survive |
| Four exit categories remain distinct | Minimum state cap 4 | Reject 0/1/2/3 and accept 4; retain default branch/loop/return controls |
| An incomplete set of offsets cannot establish an array extent | Aggregate suppression | Low thresholds retain offsets 4/8/12 without an array; higher thresholds recover offset 16 and a four-element array |
| Local scan identity is independent of translated views | Diagnostic copying through merge/pruning and global reconstruction | Reports retain source function/local identities while empty patterns remain absent; native public analysis and preview preserve equal ledgers |
| Pre-layout failure is distinct from a successful layout followed by a later failure | Public error and suppression flags | Empty and insufficient global evidence return consistent embedded errors with diagnostics; suppression is asserted only when layout executed |
| Preorder ordinals depend only on ctree shape | Repeatable site provenance | Reconstruct each SDK tree and compare complete event/counter records |
| Absence of a recorded loss is not a completeness proof | Public result interpretation | Unknown/non-modeled expression forms remain outside this status contract |

The lower/higher-budget controls establish monotonic evidence handling for the
specified trees. They do not prove a universal subset relation between results
from arbitrary budgets: forgetting predicates can change later path
approximations. Full CFG reconstruction and exceptional reaching-definition
precision are separate work.

## Scope and implementation cost

Additional diagnostic indexing uses one ctree preorder pass. For `N` ctree
nodes, `L` recorded loss occurrences, and `Q` distinct reason/site pairs, the
additional expected work is `O(N + L log Q)` and additional storage is
`O(N + Q)`. The event list has at most five reason entries per indexed node.
These are instrumentation bounds, not bounds on the existing state exploration.

- **High impact:** Empty scans no longer erase evidence that collection lost
  precision before synthesis.
- **Medium impact:** Changing flow budgets can change optional array recovery;
  the explicit suppression flag makes that decision inspectable.
- **Medium impact:** Public C++ result/options structures gained fields;
  embedding consumers require recompilation against the updated headers.
- **Low impact:** Site ordinals require a linear read-only traversal before
  collection; no persistent cfunc state is modified.

Primary implementation references are `access_collector.hpp/.cpp`,
`config.hpp`, `synth_types.hpp`, `cross_function_analyzer.hpp/.cpp`, and
`layout_synthesizer.hpp/.cpp`, `global_object_analyzer.cpp`, and `api.hpp`. The licensed SDK defines ctree traversal and
item labels; no external source is required to reproduce these repository
behavior claims. Host/runtime scope beyond the tested SDK is unknown.
