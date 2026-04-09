# Z3 Type Inference Research Notes

## Status

This document is a research/design note, not a description of the default public synthesis pipeline documented in `README.md`.

### What is true today

- Structor does contain substantial Z3 infrastructure and standalone tests around type encoding, layout constraints, array detection, cross-function analysis, and type-lattice behavior.
- The repository also contains design work for richer type inference than the baseline public structure-synthesis workflow depends on.

### How to read this document

- an exploration of possible instruction-semantics-driven type inference
- a record of constraint ideas and formalization strategies
- a source of direction for future or partial implementations

Do not treat every algorithm or quantitative claim below as fully productized current behavior.

## Constraint Generation Strategy

**Instruction semantics → type constraints:**

```python
from z3 import *

# Type lattice as enumeration
Type = Datatype('Type')
Type.declare('unknown')
Type.declare('int8'); Type.declare('int16'); Type.declare('int32'); Type.declare('int64')
Type.declare('uint8'); Type.declare('uint16'); Type.declare('uint32'); Type.declare('uint64')
Type.declare('float32'); Type.declare('float64')
Type.declare('ptr', ('pointee', Type))
Type = Type.create()

# Each variable/location gets a type variable
def var_type(name):
    return Const(name, Type)
```

**Constraint extraction from instructions:**

| Instruction | Constraint |
|-------------|------------|
| `movzx eax, byte ptr [rbx]` | `type([rbx]) = ptr(uint8)` |
| `movsx rax, dword ptr [rcx]` | `type([rcx]) = ptr(int32)` |
| `imul eax, ebx` | `type(eax) ∈ {int32}`, `type(ebx) ∈ {int32}` |
| `cvtsi2sd xmm0, eax` | `type(eax) ∈ {int32, int64}`, `type(xmm0) = float64` |
| `lea rax, [rbx + rcx*8]` | `type(rbx) = ptr(_)`, `type(rcx) ∈ {int64, uint64}` |
| `add rax, 8` followed by deref | stride analysis → array/struct inference |

## Practical Encoding

```python
s = Solver()

# Example: analyzing a function
rax_t = var_type('rax_0')
rbx_t = var_type('rbx_0')
mem_t = var_type('mem_rbx')

# movzx eax, byte ptr [rbx]  →  rbx is ptr to uint8
s.add(rbx_t == Type.ptr(Type.uint8))

# imul eax, ecx  →  eax is signed 32-bit (implicitly from semantics)
s.add(Or(rax_t == Type.int32, rax_t == Type.uint32))

# Subtyping/widening constraints
def can_widen(t1, t2):
    """t1 can be widened to t2"""
    # encode lattice relationships
    ...

# Propagate through SSA/dataflow
if s.check() == sat:
    m = s.model()
    print(f"rbx: {m[rbx_t]}")
```

## Advanced Techniques

**1. Stride-based struct recovery:**
```python
# Pattern: [base + n*stride + offset] 
# Implies: base is ptr to struct with field at offset, array indexing by n
def infer_struct_layout(accesses):
    """
    accesses = [(base_reg, index_reg, scale, displacement), ...]
    Use Z3 to solve for consistent struct layout
    """
    struct_size = Int('struct_size')
    field_offsets = [Int(f'field_{i}') for i in range(max_fields)]
    
    for base, idx, scale, disp in accesses:
        # disp = field_offset, scale = element_size or struct_size
        s.add(Or([disp == fo for fo in field_offsets]))
        s.add(scale == struct_size)
```

**2. Signedness inference via comparison patterns:**
```python
# jl/jg after cmp → signed comparison → signed operands
# jb/ja after cmp → unsigned comparison → unsigned operands
def infer_signedness(cmp_instr, jmp_instr):
    if jmp_instr.mnemonic in ['jl', 'jle', 'jg', 'jge']:
        return 'signed'
    elif jmp_instr.mnemonic in ['jb', 'jbe', 'ja', 'jae']:
        return 'unsigned'
```

**3. Pointer vs integer discrimination:**
```python
# Heuristics encoded as soft constraints (MaxSMT)
# - Values used in memory operands → likely pointer
# - Values compared against small constants → likely integer
# - Values from malloc return → pointer
# - Values used in arithmetic with large constants → likely integer

s_opt = Optimize()
s_opt.add_soft(Implies(used_as_mem_base(v), is_pointer(var_type(v))), weight=10)
s_opt.add_soft(Implies(compared_small_const(v), is_integer(var_type(v))), weight=5)
```

---

## Challenge 1: Indirect Control Flow

### Problem Statement

Indirect jumps/calls (`jmp rax`, `call [vtable + offset]`) create **incomplete CFGs**, meaning type constraints from unreachable (unresolved) code paths are missing, leading to **under-constrained type variables**.

### Formal Characterization

Let $G = (V, E)$ be the CFG. For direct control flow:
$$E_{direct} = \{(b_i, b_j) \mid b_i \text{ ends with direct branch to } b_j\}$$

For indirect control flow, we have:
$$E_{indirect} = \{(b_i, b_j) \mid b_i \text{ ends with indirect branch}, b_j \in targets(b_i)\}$$

Where $targets(b_i)$ requires solving:
$$targets(b_i) = \{addr \mid \exists \sigma \in ReachableStates(b_i) : eval(\sigma, branch\_expr) = addr\}$$

This is **undecidable** in general (reduces to halting problem).

### Manifestations

**Virtual dispatch (C++ vtables):**
```asm
mov  rax, [rdi]           ; load vtable ptr
mov  rax, [rax + 0x18]    ; load vfunc ptr at offset 0x18
call rax                  ; indirect call
```

Without resolving the vtable, we cannot:
- Know which function is called
- Propagate return type constraints
- Propagate parameter type constraints bidirectionally

**Jump tables (switch statements):**
```asm
cmp  eax, 7
ja   default_case
lea  rcx, [rip + jump_table]
movsxd rax, dword ptr [rcx + rax*4]
add  rax, rcx
jmp  rax
```

Bounds may be recoverable, but target addresses require symbolic evaluation.

**Function pointers:**
```asm
mov  rax, [rbx + 0x10]    ; load callback from struct
call rax
```

Type of callback parameter/return depends on struct field type, which depends on how struct was initialized—potentially **inter-procedural** and **context-sensitive**.

### Impact on Type Constraints

| Scenario | Missing Constraints |
|----------|---------------------|
| Unresolved call target | Return type, parameter types, callee's constraints on globals |
| Unresolved jump target | All constraints from unreached basic blocks |
| Partial target set | Under-approximation: some constraints present, solution may be too permissive |

**Quantified impact:**

Let $C_{total}$ = all type constraints if CFG were complete.
Let $C_{resolved}$ = constraints from resolved CFG.

Type precision loss ∝ $|C_{total} - C_{resolved}|$

In heavily polymorphic C++ code with virtual dispatch, this can be **30-60% of all call sites**.

### Mitigation Strategies

**1. Class Hierarchy Analysis (CHA):**
```python
def resolve_virtual_call(vtable_ptr_type, vtable_offset):
    """
    Given: vtable_ptr_type is known (e.g., Base*)
    Return: set of possible callees
    """
    possible_classes = {vtable_ptr_type.base_class} | descendants(vtable_ptr_type.base_class)
    possible_methods = set()
    for cls in possible_classes:
        if has_vtable_entry(cls, vtable_offset):
            possible_methods.add(get_vtable_entry(cls, vtable_offset))
    return possible_methods
```

**Constraint encoding:**
```python
# For virtual call with possible targets {f1, f2, f3}
ret_type = var_type('call_result')
s.add(Or(
    ret_type == known_return_type(f1),
    ret_type == known_return_type(f2),
    ret_type == known_return_type(f3)
))
```

**2. Iterative refinement (fixed-point):**
```python
def iterative_type_resolution():
    cfg = initial_cfg()
    types = {}
    
    while True:
        # Phase 1: Type inference on current CFG
        new_types = solve_type_constraints(cfg)
        
        # Phase 2: Use types to resolve more indirect calls
        new_edges = []
        for indirect_call in cfg.indirect_calls():
            target_type = new_types.get(indirect_call.target_expr)
            if target_type and is_function_pointer(target_type):
                resolved = resolve_from_type(target_type)
                new_edges.extend(resolved)
        
        # Phase 3: Check fixed-point
        if not new_edges and types == new_types:
            break
        
        cfg.add_edges(new_edges)
        types = new_types
    
    return types
```

**3. Value-set analysis (VSA) integration:**
```python
# Use abstract interpretation to bound possible values
# Then constrain type based on value set

def vsa_informed_types(vsa_result, var):
    vs = vsa_result[var]  # e.g., {0x400000..0x400fff} ∪ {0x601000..0x601fff}
    
    if vs.is_subset_of(code_section):
        # Likely function pointer
        return Type.ptr(Type.function(...))
    elif vs.is_subset_of(data_section):
        return Type.ptr(Type.unknown)  # data pointer
    elif vs.is_bounded_integer():
        return infer_integer_type(vs.bounds)
```

**4. Speculative constraint generation:**
```python
# Generate constraints under assumption that target is resolved
# Use incremental SMT to efficiently backtrack if assumption wrong

s.push()
s.add(assumed_target == specific_function)
# ... add constraints from that function ...
if s.check() == unsat:
    s.pop()  # Assumption led to contradiction
else:
    # Keep constraints, assumption was consistent
```

---

## Challenge 2: Polymorphic Code Patterns

### Problem Statement

Generic functions (memcpy, qsort, container operations) handle data of **arbitrary types**, creating constraints that are either:
- Too weak (allow any type)
- Contradictory (if unified naively)

### Manifestations

**Memory operations:**
```asm
; memcpy(dst, src, n)
memcpy:
    mov  rax, rdi          ; rax = dst
.loop:
    mov  cl, [rsi]         ; load byte
    mov  [rdi], cl         ; store byte
    inc  rsi
    inc  rdi
    dec  rdx
    jnz  .loop
    ret
```

Naively: `type([rsi]) = ptr(uint8)`, `type([rdi]) = ptr(uint8)`

But actual usage might be copying `double[]` or `struct Foo[]`.

**Container operations:**
```cpp
// Generic vector
template<typename T>
T& vector<T>::operator[](size_t i) {
    return data[i];  // return *(data + i * sizeof(T))
}
```

Assembly shows `[rdi + rsi*8]` — is element `int64`, `double`, or `ptr`?

**Comparators:**
```asm
; qsort comparator called with void* params
comparator:
    mov  rax, [rdi]        ; deref first void*
    mov  rcx, [rsi]        ; deref second void*
    ; ... compare ...
```

What's the actual pointed-to type?

### Formal Characterization

**Parametric polymorphism** requires **type schemes** (universally quantified types):
$$memcpy : \forall \alpha. \ ptr(\alpha) \times ptr(\alpha) \times int \rightarrow ptr(\alpha)$$

But Z3's theory of datatypes doesn't directly support universal quantification over sorts.

**Principal typing** — most general type that satisfies all constraints — may not exist or may be trivial (`unknown`).

### Impact on Type Constraints

```python
# Call site 1: memcpy(int_buffer, src1, 40)
# Constraint: type(int_buffer) = ptr(uint8)  # WRONG - loses actual type

# Call site 2: memcpy(float_buffer, src2, 32)  
# Constraint: type(float_buffer) = ptr(uint8)  # WRONG

# If we try to unify across call sites:
# type(int_buffer) = type(float_buffer) = ptr(uint8)  # Lost all precision
```

### Mitigation Strategies

**1. Context-sensitive analysis (cloning):**
```python
def analyze_polymorphic_function(func, call_contexts):
    """
    Create separate type variables for each call context
    """
    results = {}
    for ctx in call_contexts:
        # Fresh type variables for this context
        ctx_types = {v: var_type(f'{v}_{ctx.id}') for v in func.variables}
        
        # Constraints specific to this context
        constraints = generate_constraints(func, ctx_types)
        
        # Add context-specific information
        for i, arg in enumerate(ctx.arguments):
            constraints.add(ctx_types[f'arg{i}'] == type_of(arg))
        
        results[ctx] = solve(constraints)
    
    return results
```

**2. Stride-based type recovery:**
```python
def infer_element_type_from_stride(access_patterns):
    """
    Given: set of memory accesses to same base with different offsets
    Infer: element type from access stride
    """
    strides = set()
    for pattern in access_patterns:
        if pattern.has_index_variable:
            strides.add(pattern.scale)  # scale in [base + idx*scale + disp]
    
    if len(strides) == 1:
        stride = strides.pop()
        # Stride → element size → possible types
        return {
            1: [Type.int8, Type.uint8],
            2: [Type.int16, Type.uint16],
            4: [Type.int32, Type.uint32, Type.float32],
            8: [Type.int64, Type.uint64, Type.float64, Type.ptr(Type.unknown)]
        }.get(stride, [Type.unknown])
```

**3. Use-site based refinement:**
```python
def refine_from_use_sites(generic_result_type, use_sites):
    """
    After generic function returns, how is result used?
    """
    constraints = []
    for use in use_sites:
        if use.is_float_instruction():
            constraints.append(generic_result_type == Type.float64)
        elif use.is_pointer_deref():
            constraints.append(is_pointer(generic_result_type))
        elif use.is_signed_comparison():
            constraints.append(is_signed_integer(generic_result_type))
    
    return And(constraints)
```

**4. Abstract type variables with subtyping:**
```python
# Instead of concrete types, use abstract type variables with ordering

# Lattice: ⊥ < concrete types < ⊤
#          int8 < int16 < int32 < int64
#          ptr(⊥) < ptr(T) < ptr(⊤)

def lub(t1, t2):
    """Least upper bound in type lattice"""
    if t1 == t2:
        return t1
    if is_integer(t1) and is_integer(t2):
        return max_width_integer(t1, t2)
    if is_pointer(t1) and is_pointer(t2):
        return Type.ptr(lub(pointee(t1), pointee(t2)))
    return Type.top

# For polymorphic functions, infer LUB across all uses
```

**5. Type schemes with Z3 (encoding quantification):**
```python
# Encode polymorphism via fresh variables per instantiation

def instantiate_type_scheme(scheme, call_site_id):
    """
    scheme = "forall a. ptr(a) -> ptr(a) -> int -> ptr(a)"
    Returns: concrete type with fresh variables
    """
    fresh_vars = {}
    def instantiate(t):
        if t.is_type_variable():
            if t.name not in fresh_vars:
                fresh_vars[t.name] = var_type(f'{t.name}_{call_site_id}')
            return fresh_vars[t.name]
        elif t.is_ptr():
            return Type.ptr(instantiate(t.pointee))
        else:
            return t
    
    return instantiate(scheme.body), fresh_vars
```

---

## Challenge 3: Union Types / Type Punning

### Problem Statement

The same memory location may legitimately hold values of **different types** at different times, or be interpreted as different types simultaneously (unions, type punning).

### Manifestations

**Explicit unions:**
```c
union Value {
    int64_t as_int;
    double as_float;
    void* as_ptr;
};
```

Assembly accessing same offset with different widths/instructions:
```asm
mov  rax, [rbx]           ; load as int64
movsd xmm0, [rbx]         ; load as double (same location!)
```

**Tagged unions / discriminated unions:**
```c
struct Variant {
    uint8_t tag;
    union {
        int32_t i;
        float f;
        char* s;
    } data;
};
```

```asm
movzx eax, byte ptr [rdi]     ; load tag
cmp   eax, 1
je    .handle_int
cmp   eax, 2
je    .handle_float
; ...
.handle_int:
    mov   eax, [rdi + 8]      ; access as int
    jmp   .done
.handle_float:
    movss xmm0, [rdi + 8]     ; access as float (SAME OFFSET!)
```

**Reinterpretation / bit casting:**
```c
uint64_t bits = *(uint64_t*)&my_double;  // read double bits as int
```

```asm
movsd xmm0, [my_double]
movq  rax, xmm0             ; bit-cast to integer
```

**Register reuse:**
```asm
call  get_pointer
mov   [rbx], rax            ; rax is pointer

; ... later in same function ...

call  get_integer
add   rax, 42               ; rax is now integer
```

Same register, different types at different program points.

### Formal Characterization

**Location-based typing** assigns one type per memory location:
$$\tau : Location \rightarrow Type$$

This is **insufficient** for unions:
$$\tau([rbx + 8]) = \ ?$$

Need either:
1. **Sum types**: $\tau([rbx + 8]) = int32 + float32 + ptr(char)$
2. **Path-sensitive typing**: $\tau([rbx + 8], path) = ...$
3. **Time-indexed typing**: $\tau([rbx + 8], t) = ...$

### Impact on Type Constraints

```python
# Naive approach generates contradiction:
# From `mov eax, [rdi+8]`:
s.add(type_at(rdi_plus_8) == Type.int32)
# From `movss xmm0, [rdi+8]`:  
s.add(type_at(rdi_plus_8) == Type.float32)

# Result: UNSAT
```

### Mitigation Strategies

**1. Sum type encoding:**
```python
# Extend type lattice with sum types
SumType = Datatype('SumType')
SumType.declare('single', ('t', Type))
SumType.declare('sum2', ('t1', Type), ('t2', Type))
SumType.declare('sum3', ('t1', Type), ('t2', Type), ('t3', Type))
SumType = SumType.create()

# Constraint becomes: actual type is ONE OF the sum components
def type_consistent_with_sum(actual_access_type, sum_type):
    return Or(
        actual_access_type == SumType.t1(sum_type),
        actual_access_type == SumType.t2(sum_type),
        actual_access_type == SumType.t3(sum_type)
    )
```

**2. Path-sensitive typing (full SSA with memory):**
```python
def path_sensitive_memory_type():
    """
    SSA for memory: each store creates new memory version
    Each path has its own memory state
    """
    # Memory versions
    mem_0 = var_type('mem_0')  # initial
    mem_1 = var_type('mem_1')  # after store as int
    mem_2 = var_type('mem_2')  # after store as float
    
    # Path predicates
    path_int = Bool('path_int')
    path_float = Bool('path_float')
    
    # Constraints are conditional
    s.add(Implies(path_int, mem_1 == Type.int32))
    s.add(Implies(path_float, mem_2 == Type.float32))
    
    # At merge point: ITE or sum type
    mem_merged = var_type('mem_merged')
    s.add(mem_merged == If(path_int, mem_1, mem_2))
```

**3. Tag-based discrimination:**
```python
def infer_tagged_union(struct_accesses):
    """
    Detect pattern: load tag, compare, conditionally access data
    """
    tag_loads = [a for a in struct_accesses if a.is_small_integer_load and a.offset == 0]
    data_accesses = [a for a in struct_accesses if a.offset > 0]
    
    # Group data accesses by dominating tag comparison
    tag_to_type = {}
    for access in data_accesses:
        dom_cmp = find_dominating_tag_comparison(access)
        if dom_cmp:
            tag_value = dom_cmp.compared_value
            tag_to_type[tag_value] = access.inferred_type
    
    # Build discriminated union type
    return DiscriminatedUnion(tag_offset=0, tag_type=Type.uint8, variants=tag_to_type)
```

**4. Soft constraints with MaxSMT:**
```python
# Accept that some locations have multiple types
# Use soft constraints to prefer single-type interpretation

s_opt = Optimize()

# Hard constraint: type must be consistent with at least one access
s_opt.add(Or(type_of(loc) == Type.int32, type_of(loc) == Type.float32))

# Soft constraint: prefer single type (penalize union)
s_opt.add_soft(Not(is_sum_type(type_of(loc))), weight=5)

# Soft constraint: prefer type consistent with majority of accesses
s_opt.add_soft(type_of(loc) == Type.int32, weight=count_int_accesses)
s_opt.add_soft(type_of(loc) == Type.float32, weight=count_float_accesses)
```

**5. Access pattern clustering:**
```python
def cluster_accesses_by_type_compatibility(location, accesses):
    """
    Partition accesses into compatible groups
    Each group suggests one variant of a union
    """
    clusters = []
    for access in accesses:
        placed = False
        for cluster in clusters:
            if types_compatible(cluster.type, access.implied_type):
                cluster.add(access)
                cluster.type = unify(cluster.type, access.implied_type)
                placed = True
                break
        if not placed:
            clusters.append(Cluster(type=access.implied_type, accesses=[access]))
    
    if len(clusters) == 1:
        return clusters[0].type
    else:
        return SumType([c.type for c in clusters])
```

---

## Challenge 4: Pointer Aliasing

### Problem Statement

Multiple pointers may reference the **same memory location**. Type constraints on one pointer must propagate to aliases, but determining aliasing is undecidable in general.

### Manifestations

**Simple aliasing:**
```asm
lea  rax, [rbp - 0x20]    ; rax points to local
mov  rbx, rax              ; rbx aliases rax
mov  dword ptr [rbx], 42   ; store via rbx
mov  ecx, [rax]            ; load via rax - SAME location
```

Type constraints on `[rbx]` and `[rax]` must be unified.

**Heap aliasing:**
```asm
call malloc
mov  rbx, rax              ; rbx points to allocation
mov  [global_ptr], rax     ; global_ptr also points to it

; Later...
mov  rcx, [global_ptr]
mov  dword ptr [rcx], 1    ; store via global

mov  eax, [rbx]            ; load via rbx - SAME allocation?
```

**Parameter aliasing:**
```c
void foo(int* a, int* b) {
    *a = 1;
    *b = 2;
    return *a;  // Is this 1 or 2? Depends on aliasing
}
```

**Struct embedding:**
```asm
; struct Outer { struct Inner inner; int x; }
lea  rax, [rdi]            ; points to Outer (and to Inner, same address!)
lea  rbx, [rdi]            ; points to Inner
```

`rax` and `rbx` point to same address but have different types.

### Formal Characterization

**May-alias relation**: $MayAlias(p_1, p_2)$ — could $p_1$ and $p_2$ point to same location?

**Must-alias relation**: $MustAlias(p_1, p_2)$ — do $p_1$ and $p_2$ always point to same location?

For type inference:
$$MustAlias(p_1, p_2) \Rightarrow \tau(p_1) = \tau(p_2)$$
$$MayAlias(p_1, p_2) \Rightarrow \tau(p_1) \cap \tau(p_2) \neq \emptyset$$

Computing precise alias information requires:
- **Flow-sensitivity**: tracking pointer values through program
- **Context-sensitivity**: distinguishing call sites
- **Field-sensitivity**: tracking struct fields separately
- **Heap modeling**: abstract representation of dynamic allocation

Trade-off: precision vs scalability. Steensgaard's O(n) vs Andersen's O(n³).

### Impact on Type Constraints

**Under-approximation (miss aliases):**
```python
# If we don't know rbx aliases rax:
s.add(type_at(deref_rbx) == Type.int32)
s.add(type_at(deref_rax) == Type.float32)
# May be SAT even though locations are same!
# Result: inconsistent types for same location
```

**Over-approximation (spurious aliases):**
```python
# If we conservatively assume everything may alias:
# Must unify types of all pointer dereferences
# Result: everything collapses to Type.unknown
```

### Mitigation Strategies

**1. Steensgaard's fast unification-based alias analysis:**
```python
class SteensgaardAnalysis:
    def __init__(self):
        self.union_find = UnionFind()
    
    def process_assignment(self, dst, src):
        """x = y: unify x and y"""
        self.union_find.union(dst, src)
    
    def process_load(self, dst, src_ptr):
        """x = *p: x and *p share type"""
        deref_node = self.get_deref_node(src_ptr)
        self.union_find.union(dst, deref_node)
    
    def process_store(self, dst_ptr, src):
        """*p = x: *p and x share type"""
        deref_node = self.get_deref_node(dst_ptr)
        self.union_find.union(deref_node, src)
    
    def may_alias(self, p1, p2):
        return self.union_find.find(p1) == self.union_find.find(p2)
```

**2. Andersen's inclusion-based analysis:**
```python
def andersen_analysis(program):
    """
    Compute points-to sets using subset constraints
    More precise than Steensgaard but O(n³)
    """
    points_to = defaultdict(set)  # var -> set of locations
    
    worklist = initial_constraints(program)
    while worklist:
        constraint = worklist.pop()
        
        if constraint.is_base():  # p = &x
            if add_to_set(points_to[constraint.p], constraint.x):
                propagate_to_dependents(constraint.p, worklist)
        
        elif constraint.is_assign():  # p = q
            for loc in points_to[constraint.q]:
                if add_to_set(points_to[constraint.p], loc):
                    propagate_to_dependents(constraint.p, worklist)
        
        elif constraint.is_load():  # p = *q
            for loc in points_to[constraint.q]:
                # p ⊇ points_to[loc]
                add_complex_constraint(constraint.p, loc, worklist)
        
        elif constraint.is_store():  # *p = q
            for loc in points_to[constraint.p]:
                # points_to[loc] ⊇ points_to[q]
                add_complex_constraint(loc, constraint.q, worklist)
    
    return points_to
```

**3. Z3 encoding of alias constraints:**
```python
def encode_aliasing_in_z3(alias_analysis, type_constraints):
    """
    Add alias-derived type equalities to constraint system
    """
    s = Solver()
    
    # Add base type constraints
    for constraint in type_constraints:
        s.add(constraint)
    
    # Add alias-derived constraints
    for p1, p2 in alias_analysis.must_alias_pairs():
        s.add(type_of(deref(p1)) == type_of(deref(p2)))
    
    # For may-alias: use disjunction
    for p1, p2 in alias_analysis.may_alias_pairs():
        # Either they don't alias, or they have compatible types
        might_alias = Bool(f'alias_{p1}_{p2}')
        s.add(Implies(might_alias, type_of(deref(p1)) == type_of(deref(p2))))
    
    return s
```

**4. Abstract location modeling:**
```python
# Abstract locations partition memory
@dataclass
class AbstractLocation:
    kind: str  # 'stack', 'heap', 'global', 'param'
    allocation_site: Optional[int]  # for heap
    offset_range: Tuple[int, int]   # for structs/arrays
    
    def may_overlap(self, other):
        if self.kind != other.kind:
            return False
        if self.kind == 'heap':
            return self.allocation_site == other.allocation_site
        # Check offset overlap
        return ranges_overlap(self.offset_range, other.offset_range)

def assign_abstract_locations(program):
    """
    Partition all memory accesses into abstract locations
    Accesses to same abstract location must have compatible types
    """
    locations = {}
    for access in all_memory_accesses(program):
        base = identify_base(access)
        offset = access.displacement
        
        abs_loc = AbstractLocation(
            kind=classify_base(base),
            allocation_site=get_allocation_site(base) if is_heap(base) else None,
            offset_range=(offset, offset + access.size)
        )
        
        if abs_loc not in locations:
            locations[abs_loc] = var_type(f'type_{abs_loc}')
        
        # Constrain this access's type to match location's type
        yield type_of(access) == locations[abs_loc]
```

**5. Field-sensitive struct typing:**
```python
def field_sensitive_typing(base_ptr, accesses):
    """
    Track types at each offset from base pointer
    """
    field_types = {}  # offset -> type variable
    
    for access in accesses:
        offset = access.offset_from_base
        size = access.access_size
        
        if offset not in field_types:
            field_types[offset] = var_type(f'field_{offset}')
        
        # This access constrains the field type
        yield access_type(access) == field_types[offset]
    
    # Build struct type from fields
    struct_type = StructType(
        fields=[(off, field_types[off]) for off in sorted(field_types.keys())]
    )
    yield type_of(base_ptr) == Type.ptr(struct_type)
```

---

## Challenge 5: Under-specification / Non-uniqueness

### Problem Statement

Type constraints derived from binary code often have **multiple valid solutions** (models). The "correct" typing is underdetermined without additional heuristics or domain knowledge.

### Manifestations

**Width ambiguity:**
```asm
mov  eax, [rbx]           ; 32-bit load
; Type of [rbx]: int32? uint32? float32? ptr32 (in 32-bit mode)?
```

All are 32-bit—instruction doesn't disambiguate.

**Signedness ambiguity:**
```asm
add  eax, ebx             ; add doesn't distinguish signed/unsigned
mov  [rcx], eax           ; store doesn't either
```

Without comparison instructions, signedness is unconstrained.

**Pointer vs integer ambiguity:**
```asm
mov  rax, [rbx]           ; load 64-bit value
add  rax, 8               ; could be pointer arithmetic OR integer arithmetic
mov  [rcx], rax           ; store
```

Adding small constant is consistent with both pointer (offset) and integer.

**Array vs struct ambiguity:**
```asm
mov  eax, [rbx + 0]       ; field 0 or array[0]?
mov  ecx, [rbx + 4]       ; field 1 or array[1]?
mov  edx, [rbx + 8]       ; field 2 or array[2]?
```

Uniform stride consistent with both `int[3]` and `struct { int a, b, c; }`.

### Formal Characterization

Given constraints $C$, let $Models(C) = \{\tau \mid \tau \models C\}$.

**Unique typing**: $|Models(C)| = 1$
**Under-specified**: $|Models(C)| > 1$
**Over-specified**: $|Models(C)| = 0$ (UNSAT)

Goal: select the **best** model from $Models(C)$ according to some criteria.

### Impact on Type Constraints

```python
# Constraints from code:
s.add(bit_width(type_of(eax)) == 32)  # SAT by int32, uint32, float32, ptr32

# Multiple models:
# Model 1: type_of(eax) = int32
# Model 2: type_of(eax) = uint32  
# Model 3: type_of(eax) = float32
# Model 4: type_of(eax) = ptr(int8)  # 32-bit pointer

# All satisfy constraints—which is "right"?
```

### Mitigation Strategies

**1. Heuristic preference ordering:**
```python
TYPE_PREFERENCE = {
    # Prefer signed over unsigned (C default)
    Type.int32: 10,
    Type.uint32: 8,
    
    # Prefer smaller types when sufficient
    Type.int8: 12,
    Type.int16: 11,
    Type.int32: 10,
    Type.int64: 9,
    
    # Prefer concrete over unknown
    Type.unknown: 0,
}

def select_preferred_model(models):
    return max(models, key=lambda m: sum(TYPE_PREFERENCE.get(t, 0) for t in m.values()))
```

**2. MaxSMT with weighted soft constraints:**
```python
s_opt = Optimize()

# Hard constraints from code
for c in hard_constraints:
    s_opt.add(c)

# Soft constraints encoding preferences
for var in type_variables:
    # Prefer signed integers
    s_opt.add_soft(Or(
        type_of(var) == Type.int8,
        type_of(var) == Type.int16,
        type_of(var) == Type.int32,
        type_of(var) == Type.int64
    ), weight=5)
    
    # Strongly prefer pointers for values used in memory operands
    if used_as_memory_base(var):
        s_opt.add_soft(is_pointer_type(type_of(var)), weight=20)
    
    # Prefer float if used with float instructions
    if used_with_sse_instructions(var):
        s_opt.add_soft(Or(
            type_of(var) == Type.float32,
            type_of(var) == Type.float64
        ), weight=15)

result = s_opt.check()
```

**3. Probabilistic type inference:**
```python
def probabilistic_typing(constraints, prior_distribution):
    """
    Instead of single answer, compute probability distribution over types
    """
    valid_models = enumerate_models(constraints, limit=1000)
    
    # Weight models by prior
    weighted_models = []
    for model in valid_models:
        likelihood = 1.0
        for var, typ in model.items():
            likelihood *= prior_distribution[typ]
        weighted_models.append((model, likelihood))
    
    # Normalize
    total = sum(w for _, w in weighted_models)
    weighted_models = [(m, w/total) for m, w in weighted_models]
    
    # Marginal probabilities per variable
    marginals = defaultdict(lambda: defaultdict(float))
    for model, weight in weighted_models:
        for var, typ in model.items():
            marginals[var][typ] += weight
    
    return marginals
```

**4. Data-driven priors (machine learning):**
```python
class LearnedTypePrior:
    """
    Train on binaries with debug info to learn:
    - P(type | instruction_sequence)
    - P(type | register)
    - P(type | calling_convention_position)
    """
    
    def __init__(self, model_path):
        self.model = load_model(model_path)
    
    def predict_type_distribution(self, var, context):
        features = extract_features(var, context)
        # features: instruction patterns, register, position, etc.
        return self.model.predict_proba(features)
    
    def as_soft_constraints(self, var, context, solver):
        dist = self.predict_type_distribution(var, context)
        for typ, prob in dist.items():
            if prob > 0.1:  # threshold
                weight = int(prob * 100)
                solver.add_soft(type_of(var) == typ, weight=weight)
```

**5. Interactive refinement:**
```python
def interactive_type_refinement(initial_solution):
    """
    Present ambiguous cases to analyst for resolution
    """
    ambiguous = find_ambiguous_typings(initial_solution)
    
    for var in ambiguous:
        candidates = get_valid_types(var)
        print(f"Variable {var} could be: {candidates}")
        print(f"Context: {get_usage_context(var)}")
        
        choice = analyst_input()
        if choice:
            # Add hard constraint from analyst
            add_constraint(type_of(var) == choice)
            # Re-solve with new constraint
            initial_solution = resolve()
    
    return initial_solution
```

**6. Abduction — inferring missing constraints:**
```python
def abductive_type_inference(constraints, goal_typing):
    """
    Given: constraints C, desired typing τ
    Find: minimal additional constraints Δ such that C ∧ Δ ⊨ τ
    """
    s = Solver()
    s.add(constraints)
    s.add(Not(goal_typing))  # Negate goal
    
    if s.check() == unsat:
        # Goal already follows from constraints
        return []
    
    # Use unsat core to find what's missing
    # Iteratively add assumptions until goal is implied
    assumptions = generate_plausible_assumptions(context)
    
    minimal_delta = []
    for assumption in assumptions:
        s.push()
        s.add(assumption)
        if s.check() == unsat:
            # This assumption, combined with constraints, implies goal
            minimal_delta.append(assumption)
            break
        s.pop()
    
    return minimal_delta
```

---

## Challenge 6: Scalability

### Problem Statement

Real binaries contain **millions of instructions**. Naive constraint generation produces enormous SMT problems that exceed solver capacity.

### Quantification

| Binary Size | Instructions | Type Variables | Constraints | Naive Solve Time |
|-------------|--------------|----------------|-------------|------------------|
| 100 KB | ~25K | ~50K | ~200K | seconds |
| 1 MB | ~250K | ~500K | ~2M | minutes |
| 10 MB | ~2.5M | ~5M | ~20M | hours/timeout |
| 100 MB | ~25M | ~50M | ~200M | intractable |

### Root Causes

1. **Datatype theory** in Z3 is expensive — recursive sorts have high overhead
2. **Quantifier instantiation** for polymorphic encodings
3. **Disjunctions** from union types and aliasing uncertainty
4. **Large equivalence classes** from SSA φ-functions and memory merges

### Mitigation Strategies

**1. Modular / compositional analysis:**
```python
def modular_type_inference(program):
    """
    Analyze functions separately, compose at call sites
    """
    function_summaries = {}
    
    # Phase 1: Analyze each function independently
    for func in program.functions:
        # Local type variables only
        local_types = infer_function_types(func)
        
        # Summarize: input types → output types
        summary = FunctionSummary(
            param_types=[local_types[p] for p in func.params],
            return_type=local_types[func.return_var],
            global_effects=extract_global_effects(func, local_types)
        )
        function_summaries[func] = summary
    
    # Phase 2: Propagate across call graph
    changed = True
    while changed:
        changed = False
        for func in program.functions:
            for call in func.calls:
                callee_summary = function_summaries[call.target]
                # Unify actual arguments with formal parameters
                for actual, formal_type in zip(call.arguments, callee_summary.param_types):
                    if unify(type_of(actual), formal_type):
                        changed = True
    
    return function_summaries
```

**2. Demand-driven / lazy analysis:**
```python
def demand_driven_typing(query_var):
    """
    Only compute types for variables relevant to query
    """
    relevant = compute_backward_slice(query_var)
    
    # Only generate constraints for relevant variables
    constraints = []
    for var in relevant:
        constraints.extend(constraints_for(var))
    
    # Solve smaller system
    return solve(constraints)
```

**3. Abstraction and refinement (CEGAR-style):**
```python
def cegar_type_inference(program):
    """
    Start with coarse abstraction, refine on demand
    """
    # Initial: very coarse type lattice (ptr vs int vs float)
    abstraction = CoarseTypeLattice()
    
    while True:
        # Solve with current abstraction
        solution = solve_abstract(program, abstraction)
        
        # Check if solution is valid at concrete level
        counterexample = check_concrete(solution)
        
        if counterexample is None:
            return solution  # Found valid typing
        
        # Refine abstraction to exclude spurious solution
        abstraction = refine(abstraction, counterexample)
```

**4. Incremental SMT solving:**
```python
def incremental_typing(program):
    """
    Add constraints incrementally, reuse learned clauses
    """
    s = Solver()
    s.set('incremental', True)
    
    for func in topological_order(program.call_graph):
        s.push()
        
        # Add constraints for this function
        for c in constraints_for(func):
            s.add(c)
        
        if s.check() == unsat:
            # Debug: find minimal unsat core
            core = s.unsat_core()
            raise TypingError(f"Inconsistent types in {func}: {core}")
        
        # Extract model for this function
        model = s.model()
        function_types[func] = extract_types(model)
        
        # Keep only interface constraints for later
        s.pop()
        s.add(interface_constraints(func, function_types[func]))
    
    return function_types
```

**5. Parallel solving:**
```python
def parallel_type_inference(program, num_workers=8):
    """
    Partition program into independent regions, solve in parallel
    """
    # Find independent strongly-connected components
    sccs = compute_sccs(program.call_graph)
    
    # Solve SCCs in parallel (no dependencies)
    with ProcessPoolExecutor(max_workers=num_workers) as executor:
        futures = {}
        for scc in sccs:
            if not has_dependencies(scc, futures.keys()):
                future = executor.submit(solve_scc, scc)
                futures[scc] = future
        
        # Collect results and propagate
        results = {scc: f.result() for scc, f in futures.items()}
    
    return merge_results(results)
```

**6. Bitvector encoding instead of datatypes:**
```python
# Encode types as bitvectors — much faster in Z3

# Type representation: 8-bit tag + optional parameters
TYPE_BITS = 16

TYPE_INT8 = 0x01
TYPE_INT16 = 0x02
TYPE_INT32 = 0x03
TYPE_INT64 = 0x04
TYPE_UINT8 = 0x11
TYPE_UINT16 = 0x12
TYPE_UINT32 = 0x13
TYPE_UINT64 = 0x14
TYPE_FLOAT32 = 0x21
TYPE_FLOAT64 = 0x22
TYPE_PTR_BASE = 0x80  # High bit set = pointer, low bits = pointee

def var_type_bv(name):
    return BitVec(name, TYPE_BITS)

def is_pointer(t):
    return Extract(15, 15, t) == 1  # Check high bit

def is_integer(t):
    return And(Extract(15, 15, t) == 0, Extract(7, 4, t) == 0)

def is_signed(t):
    return And(is_integer(t), Extract(4, 4, t) == 0)

# Much faster to solve!
```

---

## Challenge 7: Calling Convention Recovery

### Problem Statement

Type inference at function boundaries requires knowing:
- Which registers/stack slots are parameters vs temporaries
- Which register holds return value
- Caller-save vs callee-save semantics

Without calling convention, parameter/return types are mis-attributed.

### Manifestations

```asm
function:
    push rbx                  ; callee-save
    mov  rbx, rdi             ; rdi is param (System V) or rcx (Windows)?
    mov  eax, [rbx + 0x10]    ; access param field
    pop  rbx
    ret                       ; eax is return? rax?
```

Wrong convention → wrong parameter count → wrong types.

### Mitigation Strategies

**1. Convention detection heuristics:**
```python
def detect_calling_convention(func):
    """
    Heuristics to identify calling convention
    """
    # Check prologue patterns
    if has_windows_prologue(func):
        return 'ms_x64'
    if has_sysv_prologue(func):
        return 'sysv_x64'
    
    # Check parameter register usage
    param_regs_used = get_early_reg_reads(func)
    
    if 'rcx' in param_regs_used and 'rdx' in param_regs_used:
        return 'ms_x64'  # Windows: rcx, rdx, r8, r9
    if 'rdi' in param_regs_used and 'rsi' in param_regs_used:
        return 'sysv_x64'  # System V: rdi, rsi, rdx, rcx, r8, r9
    
    return 'unknown'
```

**2. Type-directed convention inference:**
```python
def infer_convention_from_types(func, call_sites):
    """
    Use call site argument types to infer convention
    """
    for call in call_sites:
        arg_types = [type_of(arg) for arg in call.arguments]
        
        # Check if types match register assignment for each convention
        for convention in ['sysv_x64', 'ms_x64']:
            assignment = assign_to_registers(arg_types, convention)
            if is_consistent(assignment, func.register_usage):
                return convention
```

---

## Challenge 8: Optimized Code Artifacts

### Problem Statement

Compiler optimizations produce code patterns that **obscure original types**:
- **Register coalescing**: different logical variables in same register
- **Dead store elimination**: missing writes that would constrain type
- **Strength reduction**: multiplication → shift (loses type info)
- **Inlining**: merges type contexts from multiple functions

### Manifestations

**Strength reduction:**
```c
// Source
int x = y * 4;
```
```asm
; Compiled
shl  eax, 2              ; shift, not multiply — loses "× 4" semantics
```

Type inference sees shift, infers bitwise operation, not scaling.

**Register coalescing:**
```asm
; Two variables x (int*) and y (int) share eax at different times
mov  eax, [ptr]          ; eax = *ptr (int)
; ... use eax as int ...
lea  eax, [rbx + 0x10]   ; eax = &something (now pointer!)
; ... use eax as pointer ...
```

Single register, multiple types over lifetime — need SSA renaming.

**SIMD promotion:**
```c
// Source
for (int i = 0; i < 4; i++)
    a[i] = b[i] + c[i];
```
```asm
; Compiled (vectorized)
movdqu xmm0, [b]
movdqu xmm1, [c]
paddd  xmm0, xmm1
movdqu [a], xmm0
```

Original `int` type promoted to `__m128i` — need to recover element type.

### Mitigation Strategies

**1. SSA construction with register liveness:**
```python
def ssa_with_types(func):
    """
    Convert to SSA form where each definition gets fresh type variable
    """
    ssa_vars = {}
    version_counter = defaultdict(int)
    
    for block in func.blocks:
        for instr in block.instructions:
            # Rename uses
            for use in instr.uses:
                if use in current_version:
                    instr.rename_use(use, current_version[use])
            
            # Rename defs — create new version and type variable
            for def_ in instr.defs:
                version_counter[def_] += 1
                new_name = f'{def_}_{version_counter[def_]}'
                ssa_vars[new_name] = var_type(new_name)
                instr.rename_def(def_, new_name)
                current_version[def_] = new_name
        
        # Handle φ-functions at block boundaries
        # Types of φ arguments must be compatible
        for phi in block.phi_functions:
            result_type = ssa_vars[phi.result]
            for arg in phi.arguments:
                yield result_type == ssa_vars[arg]
```

**2. Strength reduction reversal:**
```python
STRENGTH_REDUCTION_PATTERNS = [
    # shift left → multiply
    (r'shl\s+(\w+),\s*(\d+)', lambda m: f'{m.group(1)} * {1 << int(m.group(2))}'),
    
    # lea for multiply: lea rax, [rax + rax*2] → rax * 3
    (r'lea\s+(\w+),\s*\[(\w+)\s*\+\s*\2\*(\d+)\]', 
     lambda m: f'{m.group(1)} = {m.group(2)} * {1 + int(m.group(3))}'),
]

def recover_high_level_ops(func):
    """
    Detect strength-reduced patterns and annotate with original semantics
    """
    for block in func.blocks:
        for i, instr in enumerate(block.instructions):
            for pattern, recovery in STRENGTH_REDUCTION_PATTERNS:
                if match := re.match(pattern, str(instr)):
                    instr.original_semantics = recovery(match)
                    # Use original semantics for type inference
```

**3. SIMD element type recovery:**
```python
def infer_simd_element_type(simd_instr):
    """
    Determine element type from SIMD instruction suffix/semantics
    """
    patterns = {
        'paddb': (Type.int8, 16),   # 16 × int8
        'paddw': (Type.int16, 8),   # 8 × int16
        'paddd': (Type.int32, 4),   # 4 × int32
        'paddq': (Type.int64, 2),   # 2 × int64
        'addps': (Type.float32, 4), # 4 × float32
        'addpd': (Type.float64, 2), # 2 × float64
    }
    
    if simd_instr.mnemonic in patterns:
        elem_type, count = patterns[simd_instr.mnemonic]
        return VectorType(element=elem_type, count=count)
    
    return Type.unknown
```

---

## Integrated Architecture for Z3-Based Type Inference

Combining all mitigations into a cohesive system:

```
┌─────────────────────────────────────────────────────────────────┐
│                        Binary Input                              │
└─────────────────────────────┬───────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  Phase 1: IR Lifting + SSA Construction                         │
│  • Disassembly → Intermediate Representation (ΣMIR)             │
│  • SSA renaming (fresh type variable per definition)            │
│  • Strength reduction pattern recovery                          │
└─────────────────────────────┬───────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  Phase 2: Alias Analysis                                        │
│  • Steensgaard (fast) or Andersen (precise)                     │
│  • Abstract location assignment                                 │
│  • Field-sensitive struct partitioning                          │
└─────────────────────────────┬───────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  Phase 3: Constraint Generation                                 │
│  • Hard constraints from instruction semantics                  │
│  • Alias-derived equality constraints                           │
│  • Calling convention constraints                               │
│  • Union type constraints (path-sensitive)                      │
└─────────────────────────────┬───────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  Phase 4: Soft Constraint Generation                            │
│  • Signedness preferences (signed > unsigned)                   │
│  • Width preferences (minimal width)                            │
│  • Pointer heuristics (memory operand bases)                    │
│  • ML-derived priors                                            │
└─────────────────────────────┬───────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  Phase 5: Incremental MaxSMT Solving                            │
│  • Modular: per-function first                                  │
│  • Bitvector type encoding (fast)                               │
│  • Incremental solving with learned clauses                     │
│  • Parallel SCC solving                                         │
└─────────────────────────────┬───────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  Phase 6: Indirect Call Resolution                              │
│  • Use inferred types to resolve vtables                        │
│  • Iterate: more targets → more constraints → better types      │
│  • Fixed-point iteration                                        │
└─────────────────────────────┬───────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  Phase 7: Type Scheme Generalization                            │
│  • Identify polymorphic functions (memcpy, etc.)                │
│  • Generalize to type schemes                                   │
│  • Instantiate at call sites                                    │
└─────────────────────────────┬───────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  Output: Typed IR                                                │
│  • Every variable annotated with inferred type                  │
│  • Struct layouts recovered                                     │
│  • Function signatures                                          │
│  • Confidence scores from soft constraint weights               │
└─────────────────────────────────────────────────────────────────┘
```

---------------
