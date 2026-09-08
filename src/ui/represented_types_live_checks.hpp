#pragma once
#if defined(STRUCTOR_LIVE_TEST_HOOKS)
#include <structor/z3/type_inference_engine.hpp>
#include <limits>
#include <string_view>

namespace structor::z3 {
struct RepresentedTypeObservation {
    const char* name;
    tinfo_t source;
    InferredType inferred;
    TypeConversionIssue issue = TypeConversionIssue::None;
    unsigned pointer_constraints = 0;
    unsigned concrete_pointees = 0;
    unsigned concrete_types = 0;
    unsigned address_pointer_constraints = 0;
    unsigned value_pointer_constraints = 0;
    unsigned size_constraints = 0;
    FunctionTypeInferenceResult result;
};
struct TypeInferenceRepresentationTestAccess {
    static std::vector<RepresentedTypeObservation> collect(cfunc_t* function) {
        if (!function || function->argidx.empty())
            throw std::invalid_argument("represented-type carrier requires an argument");
        std::vector<std::pair<const char*, tinfo_t>> inputs;
        const auto add_simple = [&](const char* name, type_t base) {
            tinfo_t type;
            if (!type.create_simple_type(base)) throw std::runtime_error("SDK simple type construction failed");
            inputs.emplace_back(name, type);
        };
        add_simple("partial_qword", BT_UNK_QWORD);
        add_simple("int32", BTF_INT32);
        add_simple("uint64", BTF_UINT64);
        add_simple("bool1", BT_BOOL | BTMT_BOOL1);
        add_simple("bool4", BT_BOOL | BTMT_BOOL4);
        add_simple("float32", BTF_FLOAT);
        add_simple("float64", BTF_DOUBLE);
        add_simple("long_double", BTF_LDOUBLE);
        add_simple("extended_float", BTF_TBYTE);
        tinfo_t enumeration;
        if (!enumeration.create_enum()) throw std::runtime_error("SDK enum construction failed");
        inputs.emplace_back("enum", enumeration);
        udt_type_data_t members;
        members.push_back(udm_t("value", tinfo_t(BTF_INT32), 0));
        members.total_size = 4;
        tinfo_t anonymous_udt;
        if (!anonymous_udt.create_udt(members, BTF_STRUCT))
            throw std::runtime_error("SDK anonymous UDT construction failed");
        inputs.emplace_back("anonymous_udt", anonymous_udt);
        tinfo_t partial_pointer;
        partial_pointer.create_ptr(inputs[0].second);
        inputs.emplace_back("partial_pointer", partial_pointer);
        tinfo_t full_pointer;
        full_pointer.create_ptr(tinfo_t(BTF_INT32));
        inputs.emplace_back("int32_pointer", full_pointer);
        tinfo_t partial_array;
        partial_array.create_array(inputs[0].second, 3);
        inputs.emplace_back("partial_array", partial_array);
        tinfo_t full_array;
        full_array.create_array(tinfo_t(BTF_INT32), 3);
        inputs.emplace_back("int32_array", full_array);
        func_type_data_t full_signature;
        full_signature.rettype = tinfo_t(BTF_DOUBLE);
        full_signature.set_cc(CM_CC_UNKNOWN);
        funcarg_t argument;
        argument.type = tinfo_t(BTF_INT32);
        full_signature.push_back(argument);
        tinfo_t full_function;
        if (!full_function.create_func(full_signature))
            throw std::runtime_error("SDK function construction failed");
        tinfo_t function_pointer;
        function_pointer.create_ptr(full_function);
        inputs.emplace_back("function_pointer", function_pointer);
        // The SDK consumes mutable function details during create_func().
        // Retrieve a fresh copy before creating the partial-child variant.
        if (!full_function.get_func_details(&full_signature) || full_signature.empty())
            throw std::runtime_error("SDK function detail retrieval failed");
        full_signature[0].type = inputs[0].second;
        tinfo_t partial_function;
        if (!partial_function.create_func(full_signature))
            throw std::runtime_error("SDK partial function construction failed");
        inputs.emplace_back("partial_function", partial_function);
        tinfo_t max_array;
        (void)max_array.create_array(tinfo_t(BTF_UINT8), std::numeric_limits<uint32>::max());
        inputs.emplace_back("max_count_array", max_array);
        array_type_data_t shifted_data(1, 3);
        shifted_data.elem_type = tinfo_t(BTF_INT32);
        tinfo_t shifted_array;
        if (!shifted_array.create_array(shifted_data))
            throw std::runtime_error("SDK shifted array construction failed");
        inputs.emplace_back("shifted_array", shifted_array);
        inputs.emplace_back("partial_pointer_cast", partial_pointer);
        inputs.emplace_back("int32_pointer_cast", full_pointer);
        inputs.emplace_back("int32_cast", tinfo_t(BTF_INT32));
        inputs.emplace_back("partial_qword_cast", inputs[0].second);
        std::vector<RepresentedTypeObservation> result;
        for (const auto& [name, source] : inputs) {
            RepresentedTypeObservation observed{name, source, InferredType::unknown()};
            observed.inferred = InferredType::from_tinfo(source, &observed.issue);
            if (source.empty()) { result.push_back(std::move(observed)); continue; }
            Z3Config solver_config;
            solver_config.max_memory_mb = 0;
            Z3Context context(solver_config);
            TypeInferenceConfig config;
            config.enable_experimental_pipeline = true;
            config.phase_constraint_extraction = false;
            config.phase_alias_analysis = false;
            config.phase_soft_constraints = false;
            config.solver_timeout_ms = 2000;
            TypeInferenceEngine engine(context, config);
            engine.set_progress_callback([&](const char* phase, int, const char*) {
                if (std::string_view(phase) != "Building") return;
                cexpr_t dereference;
                const bool is_cast = std::string_view(name).ends_with("_cast");
                dereference.op = is_cast ? cot_cast : cot_ptr;
                dereference.ea = function->entry_ea;
                dereference.type = source;
                if (!is_cast) dereference.ptrsize =
                    source.get_size() <= 16 ? static_cast<int>(source.get_size()) : 0;
                dereference.x = new cexpr_t;
                dereference.x->op = cot_var;
                dereference.x->ea = function->entry_ea;
                dereference.x->v.idx = function->argidx[0];
                if (is_cast) dereference.x->type = tinfo_t(BTF_UINT64);
                else dereference.x->type.create_ptr(source);
                const auto constraints = engine.semantics_extractor_->extract_expr(&dereference, function);
                const auto local = engine.semantics_extractor_->get_var_type(function, function->argidx[0]);
                engine.var_to_type_var_[local.var_idx] = local;
                for (const auto& constraint : constraints) {
                    observed.pointer_constraints += constraint.kind == TypeConstraint::Kind::IsPointer;
                    observed.concrete_pointees += constraint.kind == TypeConstraint::Kind::IsPointerTo;
                    observed.concrete_types += constraint.kind == TypeConstraint::Kind::OneOf;
                    if (constraint.kind == TypeConstraint::Kind::IsPointer) {
                        if (constraint.var1.identity == local.identity) ++observed.address_pointer_constraints;
                        else ++observed.value_pointer_constraints;
                    }
                    observed.size_constraints += constraint.kind == TypeConstraint::Kind::HasSize;
                    engine.current_constraints_.add(constraint);
                }
            });
            observed.result = engine.infer_function(function);
            result.push_back(std::move(observed));
        }
        return result;
    }
};
} // namespace structor::z3
#endif
