#include "structor/z3/type_lattice.hpp"
#include "structor/z3/context.hpp"
#include "structor/z3/type_encoding.hpp"

#include <cassert>
#include <iostream>
#include <limits>
#include <string>

using namespace structor::z3;

namespace {
InferredType base(BaseType tag) { return InferredType::make_base(tag); }

void require_truth(Z3Context& context, const ::z3::expr& claim, bool expected) {
    auto solver = context.make_solver();
    solver.add(expected ? !claim : claim);
    assert(solver.check() == ::z3::unsat);
}

std::vector<InferredType> compound_types() {
    const auto i = base(BaseType::Int32), d = base(BaseType::Float64);
    const auto a = InferredType::make_struct(0x100001234ULL);
    const auto b = InferredType::make_struct(0x200001234ULL);
    std::vector<InferredType> parameters(9, i);
    auto f1 = InferredType::make_func(i, parameters);
    parameters[8] = d;
    auto f2 = InferredType::make_func(i, parameters);
    auto deep = a;
    for (unsigned j = 0; j < 300; ++j) deep = InferredType::make_ptr(deep);
    return {a, b, InferredType::make_struct(BADADDR), f1, f2,
        InferredType::make_func(d, parameters),
        InferredType::make_func(base(BaseType::Void), {}),
        InferredType::make_ptr(a), InferredType::make_ptr(b),
        InferredType::make_ptr(f1), InferredType::make_ptr(f2),
        InferredType::make_ptr(std::shared_ptr<InferredType>{}),
        InferredType::make_ptr(InferredType::unknown()), std::move(deep),
        InferredType::make_array(i, 0), InferredType::make_array(i, 255),
        InferredType::make_array(i, 256), InferredType::make_array(i, 512),
        InferredType::make_array(d, 256),
        InferredType::make_array(i, std::numeric_limits<uint32_t>::max()),
        InferredType::make_array(InferredType::make_array(a, 256), 3),
        InferredType::make_sum({}), InferredType::make_sum({i, d}),
        InferredType::make_sum({i, a}),
        InferredType::make_sum({InferredType::make_sum({a, b}), f2})};
}

void check_round_trips() {
    Z3Context context;
    TypeLatticeEncoder encoder(context);
    auto types = compound_types();
    for (unsigned i = 0; i < static_cast<unsigned>(BaseType::_Count); ++i)
        types.push_back(base(static_cast<BaseType>(i)));
    for (const auto& type : types) {
        auto solver = context.make_solver();
        auto variable = encoder.make_type_var("round_trip");
        solver.add(variable == encoder.encode(type));
        assert(solver.check() == ::z3::sat);
        assert(encoder.decode(variable, solver.get_model()) == type);
    }
}

void check_distinct_types() {
    Z3Context context;
    TypeLatticeEncoder encoder(context);
    const auto types = compound_types();
    for (size_t i = 0; i < types.size(); ++i) {
        for (size_t j = i + 1; j < types.size(); ++j) {
            assert(types[i] != types[j]);
            auto variable = encoder.make_type_var("two_exact_types");
            auto solver = context.make_solver();
            solver.add(variable == encoder.encode(types[i]));
            solver.add(variable == encoder.encode(types[j]));
            assert(solver.check() == ::z3::unsat);
        }
    }
}

void check_constructors() {
    Z3Context context;
    TypeLatticeEncoder encoder(context), second(context);
    assert(encoder.type_sort().is_datatype());
    assert(::z3::eq(encoder.type_sort(), second.type_sort()));
    assert(::z3::eq(encoder.base_type_sort(), second.base_type_sort()));
    for (unsigned i = 0; i < static_cast<unsigned>(BaseType::_Count); ++i) {
        auto tag = static_cast<BaseType>(i);
        require_truth(context, encoder.encode_base(tag) == encoder.encode(base(tag)), true);
        require_truth(context, encoder.encode_ptr(encoder.encode_base(tag)) ==
            encoder.encode(InferredType::make_ptr(base(tag))), true);
    }
    auto pointee = encoder.make_type_var("symbolic_pointee");
    auto pointer = encoder.make_type_var("symbolic_pointer");
    const auto callback = InferredType::make_func(base(BaseType::Int32),
        {InferredType::make_ptr(InferredType::make_struct(0x123456789ULL))});
    auto solver = context.make_solver();
    solver.add(pointer == encoder.encode_ptr(pointee));
    solver.add(pointer == second.encode(InferredType::make_ptr(callback)));
    assert(solver.check() == ::z3::sat);
    assert(encoder.decode(pointee, solver.get_model()) == callback);
    solver.add(!encoder.is_pointer_type(pointer));
    assert(solver.check() == ::z3::unsat);
}

void check_predicates_and_sizes() {
    Z3Context context;
    TypeLatticeEncoder encoder(context);
    for (unsigned i = 0; i < static_cast<unsigned>(BaseType::_Count); ++i) {
        const auto tag = static_cast<BaseType>(i);
        const auto encoded = encoder.encode_base(tag);
        require_truth(context, encoder.is_integer_type(encoded), is_integer(tag));
        require_truth(context, encoder.is_signed_type(encoded), is_signed_int(tag));
        require_truth(context, encoder.is_unsigned_type(encoded), is_unsigned_int(tag));
        require_truth(context, encoder.is_floating_type(encoded), is_floating(tag));
        require_truth(context, encoder.is_pointer_type(encoded), false);
    }
    const auto i = base(BaseType::Int32), d = base(BaseType::Float64);
    require_truth(context, encoder.type_has_size(encoder.encode(InferredType::make_array(i, 256)), 1024), true);
    require_truth(context, encoder.type_has_size(encoder.encode(InferredType::make_array(i, 256)), 0), false);
    require_truth(context, encoder.type_has_size(encoder.encode(InferredType::make_sum({i, d})), 8), true);
    require_truth(context, encoder.type_has_size(encoder.encode(InferredType::make_struct(42)), 0), false);
    const auto huge = InferredType::make_array(d, std::numeric_limits<uint32_t>::max());
    require_truth(context, encoder.type_has_size(encoder.encode(huge), 0xFFFFFFF8U), false);
    auto variable = encoder.make_type_var("integer_four_bytes");
    auto solver = context.make_solver();
    solver.add(encoder.is_integer_type(variable));
    solver.add(encoder.type_has_size(variable, 4));
    assert(solver.check() == ::z3::sat);
    const auto decoded = encoder.decode(variable, solver.get_model());
    assert(decoded == i || decoded == base(BaseType::UInt32));
}

void check_subtyping() {
    Z3Config config;
    config.max_symbolic_type_depth = 2;
    config.max_symbolic_type_list_length = 3;
    Z3Context context(config);
    TypeLatticeEncoder encoder(context);
    TypeLattice lattice;
    for (unsigned i = 0; i < static_cast<unsigned>(BaseType::_Count); ++i) {
        for (unsigned j = 0; j < static_cast<unsigned>(BaseType::_Count); ++j) {
            auto a = base(static_cast<BaseType>(i)), b = base(static_cast<BaseType>(j));
            require_truth(context, encoder.subtype_of(encoder.encode(a), encoder.encode(b)),
                          lattice.is_subtype(a, b));
        }
    }
    const auto i8 = base(BaseType::Int8), i32 = base(BaseType::Int32);
    const auto d = base(BaseType::Float64);
    const auto s1 = InferredType::make_struct(1), s2 = InferredType::make_struct(2);
    const auto check = [&](const InferredType& a, const InferredType& b, bool expected) {
        auto x = encoder.make_type_var("subtype_left"), y = encoder.make_type_var("subtype_right");
        auto solver = context.make_solver();
        solver.add(x == encoder.encode(a));
        solver.add(y == encoder.encode(b));
        solver.add(expected ? !encoder.subtype_of(x, y) : encoder.subtype_of(x, y));
        assert(solver.check() == ::z3::unsat);
    };
    check(InferredType::make_ptr(i8), InferredType::make_ptr(i32), true);
    check(InferredType::make_ptr(s1), InferredType::make_ptr(s2), false);
    check(InferredType::make_array(i8, 256), InferredType::make_array(i32, 256), true);
    check(InferredType::make_array(i8, 256), InferredType::make_array(i32, 512), false);
    check(InferredType::make_func(i8, {i32}), InferredType::make_func(i32, {i8}), true);
    check(InferredType::make_func(i32, {i8}), InferredType::make_func(i8, {i32}), false);
    check(InferredType::make_func(i8, {i32}), InferredType::make_func(i32, {}), false);
    check(i8, InferredType::make_sum({i32, d}), true);
    check(InferredType::make_sum({i8, d}), InferredType::make_sum({i32, d}), true);
    check(InferredType::make_sum({i8, d}), i32, false);
    check(InferredType::make_sum({}), s1, true);
    check(s1, InferredType::make_sum({}), false);
    check(InferredType::bottom(), s1, true);
    check(s1, InferredType::unknown(), true);
    const auto null_pointer = InferredType::make_ptr(std::shared_ptr<InferredType>{});
    check(null_pointer, null_pointer, true);
    check(null_pointer, InferredType::make_ptr(InferredType::unknown()), false);
    check(InferredType::make_ptr(InferredType::unknown()), null_pointer, false);
    require_truth(context, encoder.types_compatible(encoder.encode(s1), encoder.encode(s2)), false);
    require_truth(context, encoder.types_compatible(encoder.encode(InferredType::make_ptr(s1)),
        encoder.encode(InferredType::make_ptr(s2))), true);
    require_truth(context, encoder.types_compatible(encoder.encode(null_pointer),
        encoder.encode(InferredType::make_ptr(s2))), false);
    require_truth(context, encoder.types_compatible(encoder.encode(null_pointer),
        encoder.encode(null_pointer)), true);
    require_truth(context, encoder.types_compatible(encoder.encode(InferredType::make_array(i8, 256)),
        encoder.encode(InferredType::make_array(d, 256))), true);
    require_truth(context, encoder.types_compatible(encoder.encode(InferredType::make_func(i8, {i32})),
        encoder.encode(InferredType::make_func(d, {d}))), true);
    require_truth(context, encoder.types_compatible(encoder.encode(InferredType::make_sum({i8, d})),
        encoder.encode(i32)), true);
    require_truth(context, encoder.types_compatible(encoder.encode(InferredType::make_sum({})),
        encoder.encode(InferredType::unknown())), false);
}

void check_routine_symbolic_size_queries() {
    Z3Config config;
    config.timeout_ms = 1000;
    Z3Context context(config);
    TypeLatticeEncoder encoder(context);
    for (const auto bytes : {4U, 8U, 16U, 1024U}) {
        const auto type = encoder.make_type_var("ordinary_symbolic_size");
        const auto predicate = encoder.type_has_size(type, bytes);
        std::vector<::z3::expr> pending{predicate};
        std::unordered_set<unsigned> visited;
        while (!pending.empty()) {
            auto expression = std::move(pending.back());
            pending.pop_back();
            if (!visited.insert(expression.id()).second) continue;
            assert(!expression.is_quantifier());
            if (!expression.is_app()) continue;
            assert(expression.decl().decl_kind() != Z3_OP_RECURSIVE);
            for (unsigned i = 0; i < expression.num_args(); ++i)
                pending.push_back(expression.arg(i));
        }
        auto solver = context.make_solver();
        solver.add(predicate);
        assert(solver.check() == ::z3::sat);
        const auto inferred = encoder.decode(type, solver.get_model());
        assert(inferred.size(context.pointer_size()) == bytes);
    }
}

void check_symbolic_resource_contract() {
    const auto i = base(BaseType::Int32);
    const auto nested = InferredType::make_array(InferredType::make_array(i, 2), 3);
    for (const auto depth : {1U, 2U}) {
        Z3Config config;
        config.max_symbolic_type_depth = depth;
        config.max_symbolic_type_list_length = 3;
        Z3Context context(config);
        TypeLatticeEncoder encoder(context);
        auto variable = encoder.make_type_var("bounded_nested_array");
        auto solver = context.make_solver();
        solver.add(variable == encoder.encode(nested));
        solver.add(encoder.type_has_size(variable, 24));
        assert(encoder.bounded_symbolic_queries_used());
        assert(solver.check() == (depth == 1 ? ::z3::unsat : ::z3::sat));
        encoder.reset_symbolic_query_tracking();
        require_truth(context, encoder.type_has_size(encoder.encode(nested), 24), true);
        require_truth(context, encoder.subtype_of(variable, variable), true);
        require_truth(context, encoder.type_has_size(encoder.encode_ptr(variable), 8), true);
        assert(!encoder.bounded_symbolic_queries_used());
    }
    const auto i8 = base(BaseType::Int8);
    const auto narrow_return = InferredType::make_func(i8, {i, i, i});
    const auto wide_return = InferredType::make_func(i, {i8, i8, i8});
    for (const auto length : {2U, 3U}) {
        Z3Config config;
        config.max_symbolic_type_depth = 1;
        config.max_symbolic_type_list_length = length;
        Z3Context context(config);
        TypeLatticeEncoder encoder(context);
        auto a = encoder.make_type_var("bounded_function_a"), b = encoder.make_type_var("bounded_function_b");
        auto solver = context.make_solver();
        solver.add(a == encoder.encode(narrow_return));
        solver.add(b == encoder.encode(wide_return));
        solver.add(encoder.subtype_of(a, b));
        assert(solver.check() == (length == 2 ? ::z3::unsat : ::z3::sat));
        require_truth(context, encoder.subtype_of(encoder.encode(narrow_return),
            encoder.encode(wide_return)), true);
    }
    Z3Config limited;
    limited.max_symbolic_type_expansions = 1;
    Z3Context context(limited);
    TypeLatticeEncoder encoder(context);
    const auto bounds = encoder.symbolic_query_bounds();
    assert(bounds.max_depth == limited.max_symbolic_type_depth);
    assert(bounds.max_list_length == limited.max_symbolic_type_list_length);
    assert(bounds.max_expansions == 1);
    bool exhausted = false;
    try {
        (void)encoder.type_has_size(encoder.make_type_var("exhausted"), 4);
    } catch (const SymbolicTypeQueryLimit&) {
        exhausted = true;
    }
    assert(exhausted && encoder.bounded_symbolic_queries_used());
    encoder.reset_symbolic_query_tracking();
    require_truth(context, encoder.type_has_size(encoder.encode(nested), 24), true);
    assert(!encoder.bounded_symbolic_queries_used());
}

void check_cpu_relation_agreement() {
    TypeLattice lattice;
    Z3Context context;
    TypeLatticeEncoder encoder(context);
    const auto i8 = base(BaseType::Int8), i32 = base(BaseType::Int32);
    const auto u32 = base(BaseType::UInt32), f32 = base(BaseType::Float32);
    std::vector<InferredType> types;
    for (unsigned i = 0; i < static_cast<unsigned>(BaseType::_Count); ++i)
        types.push_back(base(static_cast<BaseType>(i)));
    for (const auto& t : {InferredType::bottom(), i8, i32, f32, InferredType::unknown()}) {
        types.push_back(InferredType::make_ptr(t));
        types.push_back(InferredType::make_array(t, 3));
        types.push_back(InferredType::make_func(t, {i32}));
    }
    types.push_back(InferredType::make_ptr(std::shared_ptr<InferredType>{}));
    types.push_back(InferredType::make_array(i32, 4));
    types.push_back(InferredType::make_func(i32, {i8}));
    types.push_back(InferredType::make_func(i32, {f32}));
    types.push_back(InferredType::make_func(i32, {i32, i32}));
    types.push_back(InferredType::make_struct(1));
    types.push_back(InferredType::make_struct(2));
    types.push_back(InferredType::make_sum({}));
    types.push_back(InferredType::make_sum({i32, f32}));
    types.push_back(InferredType::make_sum({f32, i32}));
    types.push_back(InferredType::make_sum({i32, u32}));
    types.push_back(InferredType::make_sum({i32, InferredType::unknown()}));
    types.push_back(InferredType::make_sum({InferredType::make_sum({i8, f32}), i32}));
    types.push_back(InferredType::make_sum({InferredType::make_ptr(i32), InferredType::make_ptr(f32)}));
    for (const auto& a : types) {
        for (const auto& b : types) {
            require_truth(context, encoder.subtype_of(encoder.encode(a), encoder.encode(b)), lattice.is_subtype(a, b));
            require_truth(context, encoder.types_compatible(encoder.encode(a), encoder.encode(b)), lattice.are_compatible(a, b));
        }
    }
    assert(types.size() == 43);
    assert(!encoder.bounded_symbolic_queries_used());
}

void check_mutable_cache_inputs() {
    Z3Context context;
    TypeLatticeEncoder encoder(context);
    const auto i = base(BaseType::Int32), d = base(BaseType::Float64);
    auto function = InferredType::make_func(i, std::vector<InferredType>(9, i));
    const auto original = function.snapshot();
    const auto original_hash = function.hash();
    const auto original_encoding = encoder.encode(function);
    *function.param_types()[8] = d;
    assert(original_hash == function.hash());
    require_truth(context, original_encoding == encoder.encode(function), false);
    require_truth(context, original_encoding == encoder.encode(original), true);
    auto pointee = std::make_shared<InferredType>(InferredType::make_struct(1));
    auto pointer = InferredType::make_ptr(pointee);
    const auto pointer_encoding = encoder.encode(pointer);
    *pointee = InferredType::make_struct(2);
    require_truth(context, pointer_encoding == encoder.encode(pointer), false);
}

void check_context_moves() {
    Z3Config config;
    config.pointer_size = 4;
    auto source = std::make_unique<Z3Context>(config);
    auto* original_encoder = &source->type_encoder();
    (void)original_encoder->category_expr(TypeCategory::Int32);
    {
        TypeLatticeEncoder temporary(*source);
        (void)temporary.encode(InferredType::make_struct(0x100001234ULL));
    }
    Z3Context moved(std::move(*source));
    source.reset();
    assert(&moved.type_encoder() == original_encoder);
    assert(moved.type_encoder().natural_size(TypeCategory::Pointer) == 4);
    {
        auto variable = moved.ctx().constant("moved_category", moved.type_encoder().type_sort());
        auto solver = moved.make_solver();
        solver.add(variable == moved.type_encoder().category_expr(TypeCategory::Pointer));
        assert(solver.check() == ::z3::sat);
        TypeLatticeEncoder rebuilt(moved);
        require_truth(moved, rebuilt.type_has_size(rebuilt.encode_ptr(rebuilt.encode_base(BaseType::Int32)), 4), true);
    }
    Z3Context target;
    (void)target.type_encoder().category_expr(TypeCategory::Float64);
    {
        TypeLatticeEncoder existing(target);
        (void)existing.encode(InferredType::make_struct(0x200001234ULL));
    }
    target = std::move(moved);
    assert(&target.type_encoder() == original_encoder);
    assert(target.type_encoder().natural_size(TypeCategory::Pointer) == 4);
    TypeLatticeEncoder rebuilt(target);
    const auto concrete = InferredType::make_array(InferredType::make_struct(0x100001234ULL), 512);
    auto solver = target.make_solver();
    auto variable = rebuilt.make_type_var("after_move_assignment");
    solver.add(variable == rebuilt.encode(concrete));
    assert(solver.check() == ::z3::sat);
    assert(rebuilt.decode(variable, solver.get_model()) == concrete);
}
}

int main(int argc, char** argv) {
    const std::string selected = argc > 1 ? argv[1] : "all";
    const auto run = [&](const char* name, auto check) {
        if (selected == "all" || selected == name) {
            check();
            std::cout << name << ": PASS\n" << std::flush;
        }
    };
    run("round_trips", check_round_trips);
    run("distinct_types", check_distinct_types);
    run("constructors", check_constructors);
    run("predicates_sizes", check_predicates_and_sizes);
    run("subtyping", check_subtyping);
    run("routine_symbolic_sizes", check_routine_symbolic_size_queries);
    run("symbolic_resource_contract", check_symbolic_resource_contract);
    run("cpu_relation_agreement", check_cpu_relation_agreement);
    run("mutable_cache_inputs", check_mutable_cache_inputs);
    run("context_moves", check_context_moves);
}
