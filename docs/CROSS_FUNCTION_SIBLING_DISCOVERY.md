# Cross-Function Sibling Callee Discovery

## Status

This document describes a specific implemented improvement to cross-function analysis.

- The underlying behavior is present in the current codebase.
- Some concrete paths and generated-name examples below are historical and may no longer match current filenames or naming heuristics exactly.
- Use `README.md` for the current public summary of cross-function analysis behavior.

### How to read this document

- Treat it as a focused implementation note for one cross-function-analysis change.
- Treat concrete type names and example output as historical illustrations unless they still match current naming heuristics.

## Overview

This document describes the fix for cross-function sibling callee discovery in struct reconstruction.

## The Issue

Prior to the fix, `CrossFunctionAnalyzer::trace_backward` did NOT call `trace_forward` from discovered callers to find sibling callees. This meant that when starting analysis from one callee, other callees of the same caller were NOT discovered.

### Example Scenario

Consider a call graph:

```
main()
  ├── traverse_list(n1)   <- Start analysis here
  ├── sum_list(n1)        <- Sibling callee (same struct)
  └── insert_after(n1, n2) <- Sibling callee (same struct)
```

**Before fix:**
- Start from `traverse_list`
- Trace backward → find `main`
- Collect `main`'s pattern
- **STOP** - siblings `sum_list` and `insert_after` NOT discovered!

**After fix:**
- Start from `traverse_list`
- Trace backward → find `main`
- Collect `main`'s pattern
- **Trace forward from `main`** → discover `sum_list` and `insert_after`
- Collect patterns from ALL siblings

## The Fix

Added to `src/analysis/cross_function_analyzer.cpp` in `trace_backward()`:

```cpp
// Recurse backward
trace_backward(caller_ea, caller_var_idx, cumulative_delta, current_depth + 1, synth_opts);

// IMPORTANT: Also trace forward from the caller to discover sibling callees.
// This ensures that if main() calls both traverse_list() and sum_list()
// with the same struct, we collect access patterns from all siblings.
if (config_.follow_forward) {
    trace_forward(caller_ea, caller_var_idx, cumulative_delta, current_depth + 1, synth_opts);
}
```

This mirrors the behavior already present in the propagation path, which already handled sibling discovery during type propagation but not during access-pattern collection.

## Verification

### Unit Test: `test_linked_list_sibling_discovery`

Added test in `test/test_cross_function.cpp` that simulates the linked list scenario:

```
main() at 0x4000 calls:
  - traverse_list() at 0x1000: accesses offset 0x00 (next), 0x10 (data)
  - sum_list() at 0x2000: accesses offset 0x00 (next), 0x10 (data)
  - insert_after() at 0x3000: accesses offset 0x00 (next), 0x08 (prev)

Expected struct (when starting from traverse_list):
  - offset 0x00: pointer (next) - from all three functions
  - offset 0x08: pointer (prev) - ONLY from insert_after ← Critical!
  - offset 0x10: int (data) - from traverse_list and sum_list
```

The test verifies that offset 0x08 is discovered when starting from `traverse_list`, proving sibling discovery works.

### Test Results

```
=== Cross-Function Analysis Unit Tests ===

[PASS] linked_list_sibling_discovery (0ms)
...
Passed: 15, Failed: 0
```

## Impact on Struct Reconstruction

With this fix, struct reconstruction now properly considers ALL xref callees:

| Function analyzed from | Functions included in analysis |
|------------------------|-------------------------------|
| traverse_list          | traverse_list + main + sum_list + insert_after |
| sum_list               | sum_list + main + traverse_list + insert_after |
| insert_after           | insert_after + main + traverse_list + sum_list |

This results in a more complete struct with fields from ALL related functions.

## Note on the test_linked_list Binary

In the actual `test_linked_list` binary, `insert_after` is NOT called from `main()`, so it won't be discovered as a sibling. This is correct behavior - you can only discover siblings that are actually in the call graph.

The synthesized struct in that case correctly contains fields at:
- offset `0x0` for the next pointer-like field, from `traverse_list` and `sum_list`
- offset `0x10` for the data-like field, from `traverse_list` and `sum_list`

If `insert_after` were called from `main()`, the struct would also include:
- offset `0x8` for the prev pointer-like field, from `insert_after`
