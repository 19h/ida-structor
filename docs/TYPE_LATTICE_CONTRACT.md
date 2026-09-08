# Abstract type algebra

`TypeLattice` orders finite, acyclic `InferredType` trees. This is an abstract
inference order, not a claim about C assignment conversions, pointer aliasing,
or the source declaration that produced a machine instruction.

## Order and operations

`Bottom` is below every type and `Unknown` is above every type. Signed integers
form one chain ordered by width, and unsigned integers form a separate chain.
Floating-point types and the other scalar kinds compare by identity. Structs
compare by the full `tid_t`. Equal-length arrays compare by their element type.
Pointers compare covariantly by pointee. A pointer with no stored pointee is a
distinct abstract value; it does not assert that the runtime pointer is null.
Functions require equal arity, covariant return types, and contravariant
parameters. The current schema does not encode qualifiers, calling conventions,
variadic state, or aggregate member layouts.

For a sum `S`, `S <= T` requires every alternative to be below `T`; `T <= S`
requires at least one alternative above `T`. The source-sum rule runs first
when both operands are sums. The empty sum is equivalent to `Bottom`.

The join flattens sums and retains a deterministic antichain under this order:

```text
join(a, b):
    candidates = flatten_sum_alternatives(a, b), excluding Bottom
    sort candidates by complete structural type value
    remove each candidate covered by another candidate
    return Bottom, the sole candidate, or Sum(candidates)
```

Thus `join(Int32, UInt32)` retains both alternatives. Choosing `UInt32` alone
was not an upper bound under the implemented signedness order. Similarly,
incomparable pointer interpretations remain explicit alternatives.

The meet distributes over sums. For two incomparable compound types of the
same shape, it meets pointer/array components; functions meet their returns
and join their parameters. `Pointer(Bottom)` and `Array(Bottom, n)` remain
compound values under the declared order. They are not collapsed into the
global `Bottom` value. Compatibility means that the meet is not equivalent to
`Bottom`, including the empty-sum representation.

## IDA conversion and byte extents

Materializing a sum creates an anonymous packed IDA union containing every
representable object alternative. It verifies the resulting byte extent and
does not select the first alternative as a replacement for the whole sum.
Unknown, `Bottom`, void, empty, and bare-function alternatives do not provide
a complete materializable union; conversion returns an empty `tinfo_t`.
Function pointers are object alternatives. This conversion does not claim to
recover an original source-level union.

The abstract byte-size API returns a `uint32_t`; zero denotes an unknown or
unrepresentable extent. Array multiplication uses a `uint64_t` intermediate:

```text
extent = element_size_bytes * element_count
return extent if extent <= 2^32 - 1 bytes, otherwise 0
```

For 8-byte elements, `536870911 * 8 = 4294967288 bytes` is representable;
`536870912 * 8 = 4294967296 bytes` is not. A sum containing an unknown-size
alternative has unknown size instead of inheriting the largest known size.

## Assumptions and falsification

| ID | Assumption | Probe | Dependent result |
| --- | --- | --- | --- |
| L1 | Types are finite acyclic trees and the order above is the intended abstract contract. | Nested sums, empty sums, incomplete pointers, differing array lengths/struct IDs/function arities, and contravariant parameters. | CPU order, join, meet, compatibility |
| L2 | A union represents alternative object views, with byte extent equal to the largest complete member. | Real IDA member/type checks, a 3-byte array overlaid with a 2-byte scalar, nested unions, function pointers, and invalid alternatives. | IDA materialization |
| L3 | The byte-size interface cannot represent extents above `UINT32_MAX`. | Adjacent 8-byte-array boundary cases and a maximum-count array. | Overflow handling |

The production-linked law test enumerates 43 types, 1849 ordered pairs, and
79507 ordered triples. It checks reflexivity, transitivity, join/meet bounds,
least/greatest bounds relative to that candidate set, idempotence, absorption,
associativity, commutativity, and deterministic operand-order representation.
This finite check is not a proof for every possible tree. Directed tests also
cover cache hash collisions and caller-mutable shared children. The SDK suite
checks actual materialization separately from mock construction.

For `k` flattened alternatives of total tree size `T`, join performs
`O(k log k)` structural comparisons and `O(k^2)` subtype comparisons. Each
comparison can traverse compound children; sum comparisons can examine all
pairs of alternatives. Auxiliary candidate storage is `O(T)`, excluding cached
snapshots. Meet can distribute over the Cartesian product of sum alternatives;
its time and output size depend on that product. These CPU operations do not
have a fixed resource budget. The separate SMT encoder has its own contract.

## Bounded adjacent scope

- **High impact:** CPU algebra alone does not repair the old integer encoding
  of compound SMT types or prove that symbolic subtype queries match it. Those
  require separate production encoder and solver checks.
- **Medium impact:** large nested sums can expand during meet; a future budget
  must report resource exhaustion rather than silently select an alternative.
- **Medium impact:** the current schema omits ABI and aggregate-layout detail.
  Round-trip claims must name the schema they preserve.

Provenance is the production implementation, its original-code differential
law run, the production-linked tests, and IDA SDK `typeinf.hpp` definitions for
`udm_t`, `udt_type_data_t`, and `tinfo_t` construction. No source-level type or
cross-platform runtime claim follows from these local tests.
