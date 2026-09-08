#pragma once

#if defined(STRUCTOR_LIVE_TEST_HOOKS)

#include <structor/z3/type_inference_engine.hpp>
#include <string_view>
#include <vector>

namespace structor::z3 {
struct MemoryInferenceObservation {
    const char* name;
    FunctionTypeInferenceResult result;
    bool exact_lookups_passed = true;
};

/// The public engine consumes controlled actual constraints; the native case
/// uses ordinary production extraction. Neither path applies inferred types.
struct TypeInferenceMemoryTestAccess {
    enum class Scenario { Exact, Conflict, Insufficient, PartialStorage, ConflictingCtree, Native, Disabled };

    static void inject(TypeInferenceEngine& engine, Scenario scenario) {
        const auto u32 = InferredType::make_base(BaseType::UInt32);
        const auto u64 = InferredType::make_base(BaseType::UInt64);
        const auto f32 = InferredType::make_base(BaseType::Float32);
        const auto add = [&](unsigned id, MemoryLocationKey key, const InferredType& type) {
            auto fact = TypeConstraint::make_one_of(
                TypeVariable::for_memory(id, key.base, key.offset, key.size), {type});
            fact.source_ea = 0x100004000ULL + id;
            engine.current_constraints_.add(fact);
        };
        if (scenario == Scenario::Exact) {
            add(1, {0x100001234ULL, -8, 4}, u32);
            add(2, {0x100001234ULL, -8, 8}, u64);
            add(3, {0x200001234ULL, -8, 4}, f32);
            add(4, {0x1000, 0, 4}, u32);
            add(5, {0x1008, 4, 4}, f32);
        } else if (scenario == Scenario::Conflict) {
            auto memory = TypeVariable::for_memory(1, 0x1000, 0, 4);
            engine.current_constraints_.add(TypeConstraint::make_one_of(memory, {u32}).soft(10));
            engine.current_constraints_.add(TypeConstraint::make_one_of(memory, {f32}).soft(10));
        } else if (scenario == Scenario::Insufficient) {
            engine.current_constraints_.add(TypeConstraint::make_has_size(
                TypeVariable::for_memory(1, 0x1000, 0, 4), 4));
        }
    }

    static MemoryInferenceObservation run(cfunc_t* function, Scenario scenario,
                                           const char* name) {
        Z3Config solver;
        solver.max_memory_mb = 0;
        Z3Context context(solver);
        TypeInferenceConfig config;
        config.enable_experimental_pipeline = scenario != Scenario::Disabled;
        config.phase_constraint_extraction = scenario == Scenario::Native ||
            scenario == Scenario::PartialStorage || scenario == Scenario::ConflictingCtree;
        config.phase_alias_analysis = false;
        config.phase_soft_constraints = false;
        config.solver_timeout_ms = 2000;
        TypeInferenceEngine engine(context, config);
        engine.set_progress_callback([&](const char* phase, int, const char*) {
            if (std::string_view(phase) == "Building") inject(engine, scenario);
        });
        FunctionTypeInferenceResult result;
        if (scenario == Scenario::PartialStorage || scenario == Scenario::ConflictingCtree) {
            cinsn_t replacement;
            replacement.op = cit_block;
            replacement.cblock = new cblock_t;
            const auto append_object = [&](type_t kind) {
                auto expression = new cexpr_t(cot_obj, nullptr);
                expression->obj_ea = 0x100001000ULL;
                expression->ea = function->entry_ea;
                expression->type.create_simple_type(kind);
                auto& instruction = replacement.new_insn(function->entry_ea);
                instruction.op = cit_expr;
                instruction.cexpr = expression;
            };
            if (scenario == Scenario::PartialStorage) append_object(BT_UNK_QWORD);
            else {
                append_object(BTF_UINT32);
                append_object(BTF_FLOAT);
            }
            struct BodyGuard {
                cfunc_t& function;
                cinsn_t& body;
                BodyGuard(cfunc_t& f, cinsn_t& b) : function(f), body(b) { function.body.swap(body); }
                ~BodyGuard() { function.body.swap(body); }
            } guard(*function, replacement);
            result = engine.infer_function(function);
        } else result = engine.infer_function(function);
        bool lookups = true;
        if (scenario == Scenario::Exact) {
            lookups = result.get_mem_type(0x100001234ULL, -8, 4) ==
                InferredType::make_base(BaseType::UInt32) &&
                result.get_mem_type(0x100001234ULL, -8, 8) ==
                InferredType::make_base(BaseType::UInt64) &&
                result.get_mem_type(0x200001234ULL, -8, 4) ==
                InferredType::make_base(BaseType::Float32) &&
                result.get_mem_type(0x1000, 0, 4) == InferredType::make_base(BaseType::UInt32) &&
                result.get_mem_type(0x1008, 4, 4) == InferredType::make_base(BaseType::Float32) &&
                !result.get_mem_type(0x100001234ULL, -8, 2) &&
                !find_unambiguous_memory_type(result.memory_types, 0x100001234ULL, -8);
        }
        return {name, std::move(result), lookups};
    }

    static std::vector<MemoryInferenceObservation> collect(cfunc_t* function) {
        std::vector<MemoryInferenceObservation> observations;
        observations.push_back(run(function, Scenario::Disabled, "disabled"));
        observations.push_back(run(function, Scenario::Exact, "exact"));
        observations.push_back(run(function, Scenario::Conflict, "conflict"));
        observations.push_back(run(function, Scenario::Insufficient, "size_only"));
        observations.push_back(run(function, Scenario::PartialStorage, "sdk_partial_storage"));
        observations.push_back(run(function, Scenario::ConflictingCtree, "sdk_conflicting_views"));
        observations.push_back(run(function, Scenario::Native, "native"));
        return observations;
    }
};
} // namespace structor::z3
#endif
