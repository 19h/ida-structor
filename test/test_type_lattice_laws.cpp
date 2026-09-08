#include "mock_ida.hpp"
#include "structor/z3/type_lattice.hpp"
#include <iostream>
#include <map>
#include <string>
#include <vector>
using namespace structor::z3;

int main() {
    using T = InferredType;
    TypeLattice lattice;
    const auto i8 = T::make_base(BaseType::Int8);
    const auto i32 = T::make_base(BaseType::Int32);
    const auto u32 = T::make_base(BaseType::UInt32);
    const auto f32 = T::make_base(BaseType::Float32);
    std::vector<T> types;
    for (unsigned i = 0; i < static_cast<unsigned>(BaseType::_Count); ++i)
        types.push_back(T::make_base(static_cast<BaseType>(i)));
    for (const auto& t : {T::bottom(), i8, i32, f32, T::unknown()}) {
        types.push_back(T::make_ptr(t));
        types.push_back(T::make_array(t, 3));
        types.push_back(T::make_func(t, {i32}));
    }
    types.push_back(T::make_ptr(std::shared_ptr<T>{}));
    types.push_back(T::make_array(i32, 4));
    types.push_back(T::make_func(i32, {i8}));
    types.push_back(T::make_func(i32, {f32}));
    types.push_back(T::make_func(i32, {i32, i32}));
    types.push_back(T::make_struct(1));
    types.push_back(T::make_struct(2));
    types.push_back(T::make_sum({}));
    types.push_back(T::make_sum({i32, f32}));
    types.push_back(T::make_sum({f32, i32}));
    types.push_back(T::make_sum({i32, u32}));
    types.push_back(T::make_sum({i32, T::unknown()}));
    types.push_back(T::make_sum({T::make_sum({i8, f32}), i32}));
    types.push_back(T::make_sum({T::make_ptr(i32), T::make_ptr(f32)}));
    std::map<std::string, std::size_t> failures;
    const auto check = [&](bool passed, const char* law) {
        if (!passed) ++failures[law];
    };
    const auto eq = [&](const T& a, const T& b) {
        return lattice.is_subtype(a, b) && lattice.is_subtype(b, a);
    };
    for (const auto& a : types) {
        check(lattice.is_subtype(a, a), "subtype reflexivity");
        check(eq(lattice.lub(a, a), a), "join idempotence");
        check(eq(lattice.glb(a, a), a), "meet idempotence");
        for (const auto& b : types) {
            const auto join = lattice.lub(a, b);
            const auto meet = lattice.glb(a, b);
            check(lattice.is_subtype(a, join) && lattice.is_subtype(b, join), "join upper bound");
            check(lattice.is_subtype(meet, a) && lattice.is_subtype(meet, b), "meet lower bound");
            check(eq(join, lattice.lub(b, a)), "join commutativity");
            check(eq(meet, lattice.glb(b, a)), "meet commutativity");
            check(join == lattice.lub(b, a), "join representation order");
            check(meet == lattice.glb(b, a), "meet representation order");
            check(eq(lattice.lub(a, meet), a), "join absorption");
            check(eq(lattice.glb(a, join), a), "meet absorption");
            for (const auto& c : types) {
                check(eq(lattice.lub(join, c), lattice.lub(a, lattice.lub(b, c))),
                      "join associativity");
                check(eq(lattice.glb(meet, c), lattice.glb(a, lattice.glb(b, c))),
                      "meet associativity");
                if (lattice.is_subtype(a, b) && lattice.is_subtype(b, c))
                    check(lattice.is_subtype(a, c), "subtype transitivity");
                if (lattice.is_subtype(a, c) && lattice.is_subtype(b, c))
                    check(lattice.is_subtype(join, c), "join least upper bound");
                if (lattice.is_subtype(c, a) && lattice.is_subtype(c, b))
                    check(lattice.is_subtype(c, meet), "meet greatest lower bound");
            }
        }
    }
    for (const auto& [law, count] : failures)
        std::cerr << law << ": " << count << " counterexamples\n";
    std::cout << types.size() << " types; " << types.size() * types.size()
              << " pairs; " << types.size() * types.size() * types.size()
              << " candidate triples; " << failures.size() << " failed law groups\n";
    return failures.empty() ? 0 : 1;
}
