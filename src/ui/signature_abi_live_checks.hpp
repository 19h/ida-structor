#pragma once

#if defined(STRUCTOR_LIVE_TEST_HOOKS)

#include <structor/z3/type_inference_engine.hpp>

#include <algorithm>
#include <map>
#include <string>
#include <vector>

namespace structor::z3 {

// Exercise the production signature-constraint method without solving unrelated
// ctree constraints or applying any local/signature type to the database.
struct TypeInferenceSignatureTestAccess {
    static qvector<TypeConstraint> collect(cfunc_t* cfunc) {
        Z3Context context;
        TypeInferenceConfig config;
        config.weight_from_signature = 73;
        TypeInferenceEngine engine(context, config);
        // The production inference entry initializes the observation collector
        // before signature extraction. This focused friend seam must do so too.
        engine.initialize_analyzers();
        auto* locals = cfunc->get_lvars();
        for (std::size_t index = 0; index < locals->size(); ++index) {
            const auto local = static_cast<int>(index);
            engine.var_to_type_var_.emplace(local,
                TypeVariable::for_local(local + 1, cfunc->entry_ea, local));
        }
        engine.add_calling_convention_constraints(cfunc);
        // TypeConstraint/InferredType contain value metadata, not Z3 handles.
        return engine.current_constraints_.constraints();
    }
};

} // namespace structor::z3

namespace structor::detail {

struct SignatureConstraintEvidence {
    int local_index = -1;
    qstring type;
    bool is_soft = false;
    int weight = 0;
};

struct SignatureMappingEvidence {
    std::vector<std::pair<const char*, bool>> checks;
    std::vector<int> argument_indexes;
    std::vector<qstring> parameter_types;
    std::vector<qstring> parameter_source_types;
    std::vector<z3::TypeConversionIssue> parameter_conversion_issues;
    std::vector<SignatureConstraintEvidence> constraints;
    qstring error;
};

inline SignatureMappingEvidence run_live_signature_mapping_check(
    cfunc_t* cfunc, std::string_view scenario)
{
    SignatureMappingEvidence evidence;
    if (!cfunc || !cfunc->get_lvars() || cfunc->argidx.size() < 2) {
        evidence.error = "carrier requires at least two arguments";
        return evidence;
    }
    const bool valid = scenario == "native" || scenario == "permuted";
    if (!valid && scenario != "negative" && scenario != "out_of_range" &&
        scenario != "duplicate") {
        evidence.error = "unrecognized mapping scenario";
        return evidence;
    }

    auto* locals = cfunc->get_lvars();
    const intvec_t original_indexes = cfunc->argidx;
    std::vector<tinfo_t> original_local_types;
    for (const auto& local : *locals) original_local_types.push_back(local.type());
    tinfo_t original_prototype;
    if (!cfunc->get_func_type(&original_prototype)) {
        evidence.error = "carrier prototype is unavailable";
        return evidence;
    }
    tinfo_t saved_type_before;
    const bool had_saved_type = get_tinfo(&saved_type_before, cfunc->entry_ea);

    {
        struct MappingRestore {
            intvec_t& current;
            const intvec_t& original;
            ~MappingRestore() { current = original; }
        } restore{cfunc->argidx, original_indexes};
        if (scenario == "permuted") std::swap(cfunc->argidx[0], cfunc->argidx[1]);
        if (scenario == "negative") cfunc->argidx[0] = -1;
        if (scenario == "out_of_range") cfunc->argidx[0] = static_cast<int>(locals->size());
        if (scenario == "duplicate") cfunc->argidx[1] = cfunc->argidx[0];
        evidence.argument_indexes.assign(cfunc->argidx.begin(), cfunc->argidx.end());

        std::map<int, z3::InferredType> expected;
        bool discriminating_types = false;
        if (valid) {
            tinfo_t prototype;
            func_type_data_t details;
            if (!cfunc->get_func_type(&prototype) ||
                !prototype.get_func_details(&details) ||
                details.size() != cfunc->argidx.size()) {
                evidence.error = "valid carrier mapping/prototype size mismatch";
                return evidence;
            }
            for (std::size_t parameter = 0; parameter < details.size(); ++parameter) {
                z3::TypeConversionIssue issue;
                const auto inferred = z3::InferredType::from_tinfo(details[parameter].type, &issue);
                evidence.parameter_types.push_back(inferred.to_string());
                qstring source_type;
                details[parameter].type.print(&source_type);
                evidence.parameter_source_types.push_back(std::move(source_type));
                evidence.parameter_conversion_issues.push_back(issue);
                if (!inferred.is_unknown()) expected.emplace(cfunc->argidx[parameter], inferred);
                if (parameter != 0 && !(inferred ==
                        z3::InferredType::from_tinfo(details[0].type))) {
                    discriminating_types = true;
                }
            }
        }

        const auto actual = z3::TypeInferenceSignatureTestAccess::collect(cfunc);
        bool facts_match = actual.size() == expected.size();
        for (const auto& constraint : actual) {
            SignatureConstraintEvidence fact;
            fact.local_index = constraint.var1.var_idx;
            fact.is_soft = constraint.is_soft;
            fact.weight = constraint.weight;
            if (constraint.alternatives.size() == 1) {
                fact.type = constraint.alternatives.front().to_string();
            }
            evidence.constraints.push_back(fact);
            const auto expected_type = expected.find(fact.local_index);
            facts_match &= constraint.kind == z3::TypeConstraint::Kind::OneOf &&
                expected_type != expected.end() && constraint.alternatives.size() == 1 &&
                constraint.alternatives.front() == expected_type->second &&
                constraint.is_soft && constraint.weight == 73 &&
                constraint.source_ea == cfunc->entry_ea;
        }
        evidence.checks.emplace_back(valid ? "mapped_signature_facts" : "invalid_mapping_no_facts",
                                     facts_match);
        if (valid) evidence.checks.emplace_back("distinguishable_signature_types", discriminating_types);
        if (scenario == "permuted") {
            bool nonidentity = false;
            for (std::size_t parameter = 0; parameter < cfunc->argidx.size(); ++parameter) {
                nonidentity |= cfunc->argidx[parameter] != static_cast<int>(parameter);
            }
            evidence.checks.emplace_back("nonidentity_mapping_exercised", nonidentity);
        }
    }

    bool locals_unchanged = locals->size() == original_local_types.size();
    for (std::size_t index = 0; locals_unchanged && index < locals->size(); ++index) {
        locals_unchanged &= (*locals)[index].type().equals_to(original_local_types[index]);
    }
    tinfo_t restored_prototype;
    tinfo_t saved_type_after;
    const bool has_saved_type = get_tinfo(&saved_type_after, cfunc->entry_ea);
    evidence.checks.emplace_back("argument_mapping_restored", cfunc->argidx == original_indexes);
    evidence.checks.emplace_back("local_types_unchanged", locals_unchanged);
    evidence.checks.emplace_back("prototype_restored", cfunc->get_func_type(&restored_prototype) &&
        restored_prototype.equals_to(original_prototype));
    evidence.checks.emplace_back("saved_type_unchanged", had_saved_type == has_saved_type &&
        (!had_saved_type || saved_type_after.equals_to(saved_type_before)));
    return evidence;
}

inline const char* calling_convention_name(z3::CallingConvention convention) {
    switch (convention) {
        case z3::CallingConvention::CDecl: return "cdecl";
        case z3::CallingConvention::Stdcall: return "stdcall";
        case z3::CallingConvention::Fastcall: return "fastcall";
        case z3::CallingConvention::Thiscall: return "thiscall";
        case z3::CallingConvention::SystemV_x64: return "systemv_x64";
        case z3::CallingConvention::Microsoft_x64: return "microsoft_x64";
        case z3::CallingConvention::ARM_AAPCS: return "arm_aapcs";
        case z3::CallingConvention::ARM64_AAPCS64: return "arm64_aapcs64";
        default: return "unknown";
    }
}

} // namespace structor::detail

#endif
