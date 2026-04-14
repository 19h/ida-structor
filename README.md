<h1 align="center">structor</h1>

<h5 align="center">
Structor is a Hex-Rays plugin for two closely related jobs:<br/>
recovering structure layouts from pointer arithmetic and fixing decompiler variable types inside functions.<br/>
</h5>

## Intro

Reverse engineering stripped binaries usually means working against missing type information. Hex-Rays can often recover control flow and basic expressions, but object layouts and variable types still degrade into pointer arithmetic, vague scalars, register-backed temporaries, and overlapped locals.

Structor exists to push that decompilation back toward meaningful C types. It started as a structure synthesis plugin: when Hex-Rays shows raw pointer arithmetic such as `*(int *)((char *)ptr + 8)`, Structor can recover a structure layout, create the corresponding IDA type, apply it to the variable, and refresh pseudocode into member accesses.

The project now also includes a function type-fixing pipeline that runs on decompiled functions. That pipeline can:

- infer more specific local and argument types from observed usage
- recover types for exact-storage overlapped locals by borrowing from sibling variables
- report likely undeclared register-backed inputs that callers clearly populate, without mutating function signatures yet

## Documentation Map

- `README.md`: current features, APIs, configuration, build, installation, and testing
- `docs/Z3_SYNTHESIS_PLAN.md`: historical design plan for the Z3 synthesis path
- `docs/Z3_TYPE_INFERENCE.md`: research notes for richer Z3-driven type inference
- `docs/CROSS_FUNCTION_SIBLING_DISCOVERY.md`: focused note on one implemented cross-function analysis improvement

## What Structor Does Today

Structor has two public workflows.

### 1. Structure Synthesis

- Collect constant-offset dereferences from a selected variable
- Merge evidence across callers and callees when enabled
- Solve a layout with Z3 when available, with heuristic fallback
- Create IDA struct and optional companion vtable types
- Propagate the resulting type to related functions and locals
- Refresh pseudocode so pointer arithmetic becomes field access

### 2. Function Type Fixing

- Analyze variables in a decompiled function
- Compare current decompiler types with inferred types
- Apply significant, confident fixes to locals and arguments
- Emit warnings and diagnostics for unresolved or report-only cases
- Expose the results through IDC getters for automation and testing

## Example

Before Structor, Hex-Rays may show code like this:

```c
void process_object(void *ptr) {
    int type = *(int *)ptr;
    void *data = *(void **)((char *)ptr + 8);
    void (*callback)(void) = *(void (**)(void))((char *)ptr + 0x10);

    if (type == 1) {
        callback();
    }
}
```

After synthesis, the same function can decompile as typed member access:

```c
struct synth_process_object_0 {
    int field_0;
    int _pad_4;
    void *field_8;
    void (*field_10)(void);
};

void process_object(struct synth_process_object_0 *ptr) {
    int type = ptr->field_0;
    void *data = ptr->field_8;
    void (*callback)(void) = ptr->field_10;

    if (type == 1) {
        callback();
    }
}
```

Generated names vary by naming heuristics and the detected field roles.

## Current Capabilities

### Structure synthesis

| Capability | Notes |
| --- | --- |
| Z3-backed layout synthesis | Preferred by default, with fallback to heuristic synthesis |
| Cross-function analysis | Tracks pointer flow across callers and callees |
| Pointer-delta normalization | Handles subobject-style `ptr + const` flows |
| Array detection | Detects regular strided access patterns |
| Union creation | Represents irreducible overlapping fields |
| Nested sub-struct emission | Controlled by `emit_substructs` |
| Vtable detection | Can create a companion vtable struct |
| Type propagation | Propagates inferred struct types to related sites |

### Function type fixing

| Capability | Notes |
| --- | --- |
| Automatic decompilation-time analysis | Controlled by `auto_fix_types` |
| Local and argument type comparison | Uses significant-difference thresholds before applying fixes |
| Overlapped-local recovery | Recovers exact-storage siblings from better-typed peers |
| Missing register-input reporting | Warns when callers populate a non-argument register-backed input |
| IDC-accessible warnings and diagnostics | Query last-run warnings and diagnostics programmatically |

## Requirements

- IDA Pro with the Hex-Rays decompiler
- A valid IDA license
- 64-bit plugin build by default (`IDA_EA64=ON`)
- macOS, Linux, or Windows
- Z3

Z3 is detected from the system first. If no system Z3 is found, the build can fetch and build Z3 from source automatically.

## Building

### Recommended build

```bash
export IDA_SDK_DIR=/path/to/idasdk
make
```

The repository Makefile also accepts `IDASDK` and supports:

- `make`
- `make debug`
- `make install`
- `make clean`
- `make rebuild`

### Direct CMake build

```bash
mkdir -p build
cmake -S . -B build -DIDA_SDK_DIR=/path/to/idasdk
cmake --build build --parallel
```

Useful CMake options:

| Option | Meaning |
| --- | --- |
| `IDA_SDK_DIR` | Path to the IDA SDK |
| `IDA_INSTALL_DIR` | Optional install destination for the plugin |
| `IDA_EA64` | Build for 64-bit IDA, default `ON` |
| `BUILD_TESTS` | Build unit and integration test targets |
| `Z3_USE_CUSTOM` | Use a specific Z3 library/include pair instead of system Z3 |

## Installation

The built plugin is named after the project itself:

- macOS: `structor.dylib`
- Linux: `structor.so`
- Windows: `structor.dll`

Example install on macOS/Linux:

```bash
mkdir -p ~/.idapro/plugins
cp build/structor.dylib ~/.idapro/plugins/structor.dylib
```

On macOS, sign the plugin after copying it into the IDA plugin directory:

```bash
codesign -s - -f ~/.idapro/plugins/structor.dylib
```

If you use the Makefile install target:

```bash
make install
codesign -s - -f ~/.idapro/plugins/structor.dylib
```

## Usage

### Interactive structure synthesis

1. Open a function in the Hex-Rays pseudocode view.
2. Place the cursor on a pointer-like variable.
3. Press `Shift+S` or use the context menu action `Synthesize Structure`.

Structor will collect accesses, synthesize a layout, persist the result in IDA's type system, apply the type, and refresh pseudocode.

### Automatic function type fixing

When `auto_fix_types=true`, Structor also analyzes functions as Hex-Rays prints them.

That pipeline can:

- apply significant type upgrades automatically
- print warning messages for report-only cases
- print per-fix details when `auto_fix_verbose=true`
- emit overlap-recovery diagnostics when `debug_mode=true`

Important: missing undeclared register-backed arguments are currently **reported only**. Structor does not rewrite the function signature for that case yet.

## IDC API

### Structure synthesis IDC functions

| Function | Returns | Meaning |
| --- | --- | --- |
| `structor_synthesize(func_ea, var_idx)` | `tid_t` | Synthesize a structure from a local variable index |
| `structor_synthesize_by_name(func_ea, var_name)` | `tid_t` | Same, but by decompiler variable name |
| `structor_get_error()` | `string` | Error from the last synthesis or type-fix action |
| `structor_get_field_count()` | `long` | Field count from the last synthesis |
| `structor_get_vtable_tid()` | `tid_t` | Companion vtable TID, or `BADADDR` |

### Function type-fixing IDC functions

| Function | Returns | Meaning |
| --- | --- | --- |
| `structor_fix_function_types(func_ea)` | `long` | Apply significant fixes in a function |
| `structor_fix_variable_type(func_ea, var_idx)` | `long` | Fix a single variable by index |
| `structor_fix_variable_by_name(func_ea, var_name)` | `long` | Fix a single variable by name |
| `structor_analyze_function_types(func_ea)` | `long` | Dry-run analysis without applying changes |
| `structor_get_fix_count()` | `long` | Variables analyzed in the last type-fix run |
| `structor_get_fixes_applied()` | `long` | Fixes applied, or differences found for dry-run analysis |
| `structor_get_fixes_skipped()` | `long` | Fixes skipped in the last type-fix run |
| `structor_get_fix_warning_count()` | `long` | Warning count from the last type-fix run |
| `structor_get_fix_warning(idx)` | `string` | Warning text by index |
| `structor_get_fix_diagnostic_count()` | `long` | Diagnostic count from the last type-fix run |
| `structor_get_fix_diagnostic(idx)` | `string` | Diagnostic text by index |

### Python example: structure synthesis

```python
import ida_expr
import idc

result = ida_expr.idc_value_t()
ida_expr.eval_idc_expr(result, idc.BADADDR, "structor_synthesize(0x100000460, 0)")
struct_tid = result.i64

if struct_tid != idc.BADADDR:
    count = ida_expr.idc_value_t()
    ida_expr.eval_idc_expr(count, idc.BADADDR, "structor_get_field_count()")
    print(f"Created structure {struct_tid:#x} with {count.num} fields")
else:
    err = ida_expr.idc_value_t()
    ida_expr.eval_idc_expr(err, idc.BADADDR, "structor_get_error()")
    print(err.c_str())
```

### Python example: type-fix dry run

```python
import ida_expr
import idc

result = ida_expr.idc_value_t()
ida_expr.eval_idc_expr(result, idc.BADADDR, "structor_analyze_function_types(0x100000548)")

warn_count = ida_expr.idc_value_t()
ida_expr.eval_idc_expr(warn_count, idc.BADADDR, "structor_get_fix_warning_count()")

for i in range(warn_count.num):
    warn = ida_expr.idc_value_t()
    ida_expr.eval_idc_expr(warn, idc.BADADDR, f"structor_get_fix_warning({i})")
    print(warn.c_str())
```

## C++ API

`StructorAPI` exposes the public programmatic entry points.

### Structure synthesis example

```cpp
#include <structor/api.hpp>

structor::SynthOptions opts = structor::Config::instance().options();
opts.min_accesses = 2;
opts.vtable_detection = true;
opts.z3.cross_function = true;
opts.z3.detect_arrays = true;

structor::SynthResult result =
    structor::StructorAPI::instance().synthesize_structure(func_ea, var_idx, &opts);

if (result.success()) {
    msg("Created struct tid=%llx with %d fields\n",
        static_cast<unsigned long long>(result.struct_tid),
        result.fields_created);
}
```

### Function type-fix example

```cpp
#include <structor/api.hpp>

structor::TypeFixResult result =
    structor::StructorAPI::instance().analyze_function_types(func_ea);

for (const auto &warning : result.warnings) {
    msg("Structor warning: %s\n", warning.c_str());
}

for (const auto &diagnostic : result.diagnostics) {
    msg("Structor diagnostic: %s\n", diagnostic.c_str());
}
```

### Embedding in another plugin

Structor can now be consumed as a normal CMake subproject without going through Structor's plugin init path.

```cmake
set(STRUCTOR_BUILD_PLUGIN OFF CACHE BOOL "" FORCE)
add_subdirectory(path/to/structor)

target_link_libraries(my_plugin PRIVATE structor::core)
```

```cpp
#include <structor/api.hpp>
#include <structor/host_integration.hpp>

structor::HostIntegration host;

// Optional: if your plugin wants Structor's callback-driven behavior,
// either install Structor's Hex-Rays hooks...
host.install_hexrays_hooks();

// ...or forward events from your own Hex-Rays callback.
host.handle_ctree_maturity(cfunc, maturity);
host.handle_func_printed(cfunc);

auto preview = structor::StructorAPI::instance().synthesize_structure(
    func_ea,
    var_idx,
    structor::MaterializationMode::Preview,
    &opts);
```

Use `structor::core` when another plugin wants to orchestrate Structor directly.
The `structor` plugin target remains the UI/IDC/plugin-wrapper build.

## Configuration

Structor stores configuration in `~/.idapro/structor.cfg` and creates the file automatically on first run.

Current keys written by the codebase:

```ini
# Structor Configuration

[General]
hotkey=Shift+S
interactive_mode=false
auto_open_struct=true
debug_mode=false

[TypeFix]
auto_fix_types=true
auto_fix_verbose=false

[Synthesis]
min_accesses=2
alignment=8
vtable_detection=true
emit_substructs=true

[Propagation]
auto_propagate=true
propagate_to_callers=true
propagate_to_callees=true
max_propagation_depth=3

[UI]
highlight_changes=true
highlight_duration_ms=2000
generate_comments=true

[Z3]
z3_mode=preferred
z3_timeout_ms=5000
z3_memory_limit_mb=256
z3_enable_maxsmt=true
z3_enable_unsat_core=true
z3_detect_arrays=true
z3_min_array_elements=3
z3_cross_function=true
z3_max_candidates=1000
z3_allow_unions=true
z3_min_confidence=20
z3_relax_on_unsat=true
z3_max_relax_iterations=5
z3_weight_minimize_padding=1
z3_weight_prefer_non_union=2
```

## Testing

### Build tests

```bash
cmake -S . -B build -DIDA_SDK_DIR=/path/to/idasdk -DBUILD_TESTS=ON
cmake --build build --parallel
```

### Run the full suite

```bash
ctest --test-dir build --output-on-failure
```

### Convenience targets

With `BUILD_TESTS=ON`, the test CMake project also provides:

- `check` for the full suite
- `check_z3` for the Z3-focused subset

### Live plugin regression tests

On supported Apple arm64 hosts with `idump` available and a valid local IDA license, the CTest suite also runs live plugin regressions against real binaries. Those regressions currently exercise:

- missing register-backed argument reporting with `test_missing_regarg`
- overlap-based local type recovery with `test_overlap_scope`

You can also run the live regression script directly:

```bash
python3 integration_tests/check_type_fixer_regressions.py \
  --repo-root /path/to/structor \
  --plugin /path/to/structor/build/structor.dylib \
  --idump idump
```

### Building integration fixtures

```bash
sh integration_tests/build_fixtures.sh
```

Or build only specific fixtures:

```bash
sh integration_tests/build_fixtures.sh test_missing_regarg test_overlap_scope
```

Representative fixture coverage includes:

- simple structs
- nested structs and arrays
- packed structs and packed overlaps
- callback tables and function pointers
- negative offsets and shifted windows
- cross-function subobject deltas
- overlap-based local type recovery
- missing undeclared register-backed arguments

## How It Works

Structor is not doing one monolithic "infer everything" pass. It uses a staged pipeline with different algorithms for synthesis, propagation, and intra-function type repair.

### Access collection

The first stage is a Hex-Rays ctree visitor.

- `AccessPatternVisitor` walks decompiler expressions and looks for `cot_ptr`, `cot_memptr`, `cot_idx`, assignments, comparisons, masked bitfield-style loads, and indirect calls.
- For each relevant expression it tries to reduce the expression to a base variable plus a constant offset.
- It records more than just offset and size: semantic intent, inferred decompiler type, access direction, array stride hints, base-indirection depth, and observed constants from comparisons.
- Local aliases are forwarded through assignments when the right-hand side can be reduced to an access on the target variable.

That means Structor is not limited to raw `*(base + off)` loads. It also learns from patterns like:

- aliased temporaries
- `ptr->field` forms already emitted by Hex-Rays
- masked-and-shifted bitfield reads
- constant comparisons that help refine enum/flag-like fields
- indirect calls that indicate function-pointer or vtable usage

### Cross-function unification

When cross-function analysis is enabled, Structor does not treat each function in isolation.

- `CrossFunctionAnalyzer` traces both forward and backward through the call graph up to configured limits.
- At each call site, `ArgDeltaExtractor` looks for direct passing, casts, `ptr + const`, `ptr - const`, and by-reference forwarding.
- Offsets are normalized into a common coordinate system by accumulating pointer deltas across calls.
- Merged accesses are deduplicated by location and merged by semantic specificity, not just by first-seen order.

This is what lets Structor combine evidence such as:

```c
caller(ptr);          // accesses offset 0x0 and 0x8
callee(ptr + 0x10);   // accesses offset 0x0 and 0x8 relative to the shifted base
```

into one recovered layout with offsets `0x0`, `0x8`, `0x10`, and `0x18`.

The implementation also contains extra normalization for tricky shifted-window cases, including rebasing negative offsets and pruning intermediate positive-delta patterns when they would distort the merged coordinate system.

### Z3-backed layout synthesis

The primary synthesis path is candidate generation plus constraint solving.

- `FieldCandidateGenerator` expands the merged access pattern into plausible field candidates.
- `LayoutConstraintBuilder` encodes the layout problem for Z3.
- The solver prefers a layout that covers all accesses while minimizing ambiguity and unnecessary padding.

At a practical level, the Z3 path is optimizing for things like:

- coverage of every observed access
- non-overlap where possible
- unions only where overlap is irreducible
- alignment and packing consistency
- array recognition for regular stride patterns

If the solve succeeds, Structor extracts a `SynthStruct` directly from the Z3 model and records solver statistics such as arrays detected, unions created, relaxed constraints, and solve time.

If the constraints are unsatisfiable or the solve times out, Structor does not simply fail. It records the failure reason and drops into the fallback path unless Z3 was configured as required.

### Heuristic fallback synthesis

The fallback path is deliberately simpler and faster.

- Sort accesses by offset.
- Group overlapping accesses into offset groups.
- Mark groups as union candidates when same-offset accesses disagree on size or layout.
- Turn groups into fields.
- Insert padding between gaps.
- Infer types heuristically from semantic usage and access width.
- Generate names and compute final structure size.

This is less globally optimal than the Z3 path, but it keeps Structor productive on awkward decompilations and solver-failure cases.

### Array, union, and sub-structure handling

Recovered layouts are not just flat lists of scalars.

- Regular stride patterns are lifted into array fields.
- Conflicting same-region views become unions.
- `emit_substructs` enables nested aggregate emission when a field is better represented as a sub-structure than as a scalar blob.
- Negative-offset layouts are rebased into shifted-view types so the emitted IDA type remains structurally valid.

That combination is why Structor can model packed overlaps, embedded windows into larger objects, and array-of-struct style patterns without collapsing everything into bytes.

### Vtable detection and signature recovery

Vtable recovery is not a separate manual pass; it is driven by access evidence and call-pattern matching.

- `VTableDetector` looks for call shapes of the form `(*(*(var + vtable_offset) + slot_offset))(args)`.
- Slot indices are derived from the slot offset divided by pointer size.
- Slot signatures are reconstructed from the call site by inspecting argument types and how the call result is used.

If enough evidence is present, Structor creates a companion vtable type and links it to the parent object layout.

### Type propagation

After synthesis, Structor attempts to apply the recovered type beyond the original variable.

- It propagates to callers and callees based on how the variable flows through arguments and return values.
- When propagation crosses pointer deltas, `TypePropagator` can construct shifted window or tail views rather than blindly applying the unshifted parent type.
- This is what makes subobject-style propagation viable when one function sees the object at base `0` and another only sees `ptr + delta`.

### Function type-fixing algorithms

The type-fixing pipeline is separate from structure synthesis, but it reuses the same general evidence-first philosophy.

For each variable, `TypeFixer` does three main things.

1. Direct inference from local usage.
   It analyzes the variable's own access patterns and tries to infer a better type from observed dereferences and semantics.

2. Exact-storage overlap recovery.
   If the variable is overlapped, Structor looks for sibling lvars that share the exact same storage location and width.
   That means same stack slot plus width, or same register storage plus width.
   It then borrows the most specific compatible type from the better-typed peer and records a diagnostic describing the recovery.

3. Missing register-backed input reporting.
   For register locals that look like undeclared arguments, Structor uses two complementary strategies.
   It first tries ABI-style parameter-position inference from register families.
   It then has a non-ABI register-handoff path that scans callers, decodes instructions backward from the call site, and checks whether the callee's input register was populated immediately before the call.

That second path is intentionally conservative.

- It rejects obvious false positives where the register write is just copying a previous call's return register into a callee-saved register.
- It reports the case to the output window and IDC warning surface instead of mutating the function signature.

### Decision policy

Structor does not apply every inferred type blindly.

- Synthesis requires a minimum amount of access evidence.
- Type fixing compares current and inferred types and only applies significant improvements.
- Warnings and diagnostics are preserved separately from applied fixes so automation can distinguish "changed", "report-only", and "interesting but unresolved" outcomes.

## Known Limitations

- Structure synthesis still requires at least `min_accesses` observed accesses for a variable.
- Purely computed array indices such as `ptr[i * 4]` do not provide a constant field offset.
- Some aliasing patterns are still opaque to the synthesis path, especially when the interesting accesses happen only through a different local.
- Missing register-backed argument recovery is currently report-only; it does not rewrite function signatures.

## Design Notes

The files under `docs/` go deeper on Z3, cross-function analysis, and related experiments. Treat them as design and research material. Use this README for the current supported workflow and API surface.

## Relationship to Suture

Structor borrows several design ideas from `suture`, especially around access modeling, conflict resolution, and debug-oriented analysis ergonomics. The difference is that Structor is implemented as a native C++ plugin with a structure-synthesis pipeline and an increasingly capable function type-fixing subsystem.
