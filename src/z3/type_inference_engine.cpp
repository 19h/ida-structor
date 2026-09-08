#include "structor/z3/type_inference_engine.hpp"
#include "structor/z3/signature_argument_map.hpp"
#include <algorithm>
#include <chrono>
#include <stdexcept>

#ifndef STRUCTOR_TESTING
#include <pro.h>
#include <kernwin.hpp>
#include <name.hpp>
#include <funcs.hpp>
#include <idp.hpp>
#endif

namespace structor::z3 {

// ============================================================================
// TypeInferenceStats implementation
// ============================================================================

qstring TypeInferenceStats::summary() const {
    qstring result;
    result.sprnt("Type Inference Statistics:\n");
    result.cat_sprnt("  Functions analyzed: %u\n", functions_analyzed);
    result.cat_sprnt("  Variables typed: %u\n", variables_typed);
    result.cat_sprnt("  Absolute memory: %u typed, %u omitted, %u unresolved expressions\n",
                    memory_locations_typed, memory_locations_omitted, unresolved_memory_accesses);
    result.cat_sprnt("  Constraints: %u hard, %u soft\n", 
                    type_constraints_hard, type_constraints_soft);
    if (constraints_relaxed > 0) {
        result.cat_sprnt("  Constraints relaxed: %u\n", constraints_relaxed);
    }
    result.cat_sprnt("  Alias pairs: %u\n", alias_pairs_found);
    result.cat_sprnt("  Types inferred: %u (ptr=%u, int=%u, float=%u, unknown=%u)\n",
                    types_inferred, types_pointer, types_integer, 
                    types_floating, types_unknown);
    result.cat_sprnt("  Model values: %u determined, %u ambiguous, %u unverified (%u queries, %lldms)\n",
                    model_values_determined, model_values_ambiguous, model_values_unverified,
                    model_evidence_queries, static_cast<long long>(model_evidence_time.count()));
    result.cat_sprnt("  Solve iterations: %u\n", solve_iterations);
    result.cat_sprnt("  Timings:\n");
    result.cat_sprnt("    Constraint extraction: %lldms\n",
                    static_cast<long long>(constraint_extraction_time.count()));
    result.cat_sprnt("    Alias analysis: %lldms\n",
                    static_cast<long long>(alias_analysis_time.count()));
    result.cat_sprnt("    Constraint building: %lldms\n",
                    static_cast<long long>(constraint_building_time.count()));
    result.cat_sprnt("    Solving: %lldms\n",
                    static_cast<long long>(solving_time.count()));
    result.cat_sprnt("    Total: %lldms\n",
                    static_cast<long long>(total_time.count()));
    return result;
}

// ============================================================================
// FunctionTypeInferenceResult implementation
// ============================================================================

std::optional<InferredType> FunctionTypeInferenceResult::get_var_type(int var_idx) const {
    for (const auto& vt : local_types) {
        if (vt.var_idx == var_idx) {
            return vt.type;
        }
    }
    return std::nullopt;
}

std::optional<InferredType> FunctionTypeInferenceResult::get_mem_type(
    ea_t base, sval_t offset, std::uint32_t size) const
{
    return find_memory_type(memory_types, {base, offset, size});
}

std::optional<InferredType> FunctionTypeInferenceResult::get_mem_type(
    ea_t base, 
    sval_t offset) const
{
    return find_unambiguous_memory_type(memory_types, base, offset);
}

std::unordered_map<int, tinfo_t> FunctionTypeInferenceResult::to_ida_types(
    bool include_model_candidates) const {
    std::unordered_map<int, tinfo_t> result;
    for (const auto& vt : local_types) {
        if (!vt.may_apply_model_value(include_model_candidates)) continue;
        auto type = vt.type.to_tinfo();
        if (!type.empty()) result.emplace(vt.var_idx, std::move(type));
    }
    return result;
}

// ============================================================================
// TypeInferenceEngine implementation
// ============================================================================

TypeInferenceEngine::TypeInferenceEngine(
    Z3Context& ctx,
    const TypeInferenceConfig& config)
    : ctx_(ctx)
    , config_(config)
    , current_constraints_(ctx)
    , type_encoder_(ctx)
{
    if (config_.enable_experimental_pipeline) {
        initialize_analyzers();
    }
}

void TypeInferenceEngine::initialize_analyzers() {
    semantics_extractor_ = std::make_unique<InstructionSemanticsExtractor>(
        ctx_, config_.semantics_config);
    alias_analyzer_ = std::make_unique<AliasAnalyzer>(ctx_, config_.alias_config);
}

void TypeInferenceEngine::reset_state() {
    current_cfunc_ = nullptr;
    current_constraints_.clear();
    hard_constraints_use_symbolic_bounds_ = false;
    var_to_type_var_.clear();
}

FunctionTypeInferenceResult TypeInferenceEngine::infer_function(cfunc_t* cfunc) {
    FunctionTypeInferenceResult result;
    last_stats_ = TypeInferenceStats();

    if (!config_.enable_experimental_pipeline) {
        result.status = TypeInferenceStatus::ExperimentalDisabled;
        result.error_message =
            "experimental type-inference pipeline is disabled; set "
            "TypeInferenceConfig::enable_experimental_pipeline=true for "
            "explicit per-function experimentation";
        return result;
    }

    if (!cfunc) {
        result.status = TypeInferenceStatus::InvalidInput;
        result.error_message = "null cfunc";
        return result;
    }
    type_encoder_.reset_symbolic_query_tracking();
    result.symbolic_query_bounds = type_encoder_.symbolic_query_bounds();
    if (ctx_.config().max_memory_mb != 0) {
        result.status = TypeInferenceStatus::UnsupportedOperation;
        result.error_message =
            "configured memory limit cannot be enforced by the type-inference optimizer";
        return result;
    }

    const auto total_start = std::chrono::steady_clock::now();
    bool analyzers_initialized = false;
    const auto finish = [&]() {
        const auto total_end = std::chrono::steady_clock::now();
        last_stats_.total_time =
            std::chrono::duration_cast<std::chrono::milliseconds>(
                total_end - total_start);
        result.stats = last_stats_;
        if (analyzers_initialized && semantics_extractor_) {
            result.unsupported_type_observations = semantics_extractor_->unsupported_type_observations();
        }
        result.used_bounded_symbolic_queries = type_encoder_.bounded_symbolic_queries_used();
        result.used_explicit_symbolic_candidates = type_encoder_.explicit_candidate_queries_used();
    };

    try {
        // Recreate analyzers so mutations made through config() between calls
        // are reflected instead of silently retaining constructor-time values.
        initialize_analyzers();
        analyzers_initialized = true;

        reset_state();
        current_cfunc_ = cfunc;
        result.func_ea = cfunc->entry_ea;

#ifndef STRUCTOR_TESTING
        qstring func_name;
        get_func_name(&func_name, cfunc->entry_ea);
        result.func_name = func_name;
#endif

        last_stats_.functions_analyzed = 1;
        report_progress("Starting", 0,
                        "Initializing experimental type inference");

        if (config_.phase_constraint_extraction) {
            report_progress("Constraints", 10, "Extracting type constraints");
            phase_constraint_extraction(cfunc);
        }

        if (config_.phase_alias_analysis) {
            report_progress("Alias", 30, "Performing alias analysis");
            phase_alias_analysis(cfunc);
        }

        if (config_.phase_soft_constraints) {
            report_progress("Heuristics", 50, "Generating soft constraints");
            phase_soft_constraints(cfunc);
        }

        report_progress("Building", 60, "Building Z3 constraints");
        const auto build_start = std::chrono::steady_clock::now();
        ::z3::optimize opt = build_z3_constraints();
        const auto build_end = std::chrono::steady_clock::now();
        last_stats_.constraint_building_time =
            std::chrono::duration_cast<std::chrono::milliseconds>(
                build_end - build_start);

        report_progress("Solving", 70, "Solving constraints");
        ::z3::model model(ctx_.ctx());
        const auto solved = phase_solve(opt, model);

        if (solved != ::z3::sat) {
            if (solved == ::z3::unsat && type_encoder_.bounded_symbolic_queries_used()) {
                result.status = TypeInferenceStatus::NoModelWithinSymbolicBounds;
                const auto bounds = *result.symbolic_query_bounds;
                result.error_message.sprnt(
                    "no model within symbolic type bounds (depth=%u, list_length=%u, "
                    "expansions=%u); this does not establish an unbounded source-type contradiction",
                    bounds.max_depth, bounds.max_list_length, bounds.max_expansions);
            } else {
                result.status = TypeInferenceStatus::SolverFailure;
                result.error_message = solved == ::z3::unsat
                    ? "type-inference constraints were unsatisfiable"
                    : "type-inference solver returned unknown (including possible timeout)";
            }
        } else {
            report_progress("Extracting", 90, "Extracting inferred types");
            extract_results(model, opt.assertions(), result);
            result.status = TypeInferenceStatus::Success;
            result.success = true;
        }

        report_progress("Complete", 100,
                        result.success ? "Experimental type inference complete"
                                       : "Experimental type inference failed");
    } catch (const SymbolicTypeQueryLimit& exception) {
        result.status = TypeInferenceStatus::SymbolicQueryBudgetExceeded;
        result.success = false;
        result.error_message.sprnt("symbolic type query budget exhausted: %s", exception.what());
        reset_state();
    } catch (const std::exception& exception) {
        result.status = TypeInferenceStatus::InternalError;
        result.success = false;
        result.error_message.sprnt(
            "experimental type-inference exception: %s", exception.what());
        reset_state();
    } catch (...) {
        result.status = TypeInferenceStatus::InternalError;
        result.success = false;
        result.error_message =
            "unknown exception in experimental type-inference pipeline";
        reset_state();
    }

    finish();
    return result;
}

InferredVariableType TypeInferenceEngine::infer_variable(cfunc_t* cfunc, int var_idx) {
    auto full_result = infer_function(cfunc);

    if (!full_result.success) {
        throw std::runtime_error(full_result.error_message.c_str());
    }

    for (const auto& vt : full_result.local_types) {
        if (vt.var_idx == var_idx) {
            return vt;
        }
    }
    
    InferredVariableType not_found;
    not_found.var_idx = var_idx;
    not_found.type = InferredType::unknown();
    not_found.confidence = TypeConfidence::Low;
    return not_found;
}

std::vector<FunctionTypeInferenceResult> TypeInferenceEngine::infer_cross_function(
    const qvector<cfunc_t*>& cfuncs)
{
    std::vector<FunctionTypeInferenceResult> results;
    results.reserve(cfuncs.size());

    for (auto* cfunc : cfuncs) {
        FunctionTypeInferenceResult result;
        result.func_ea = cfunc ? cfunc->entry_ea : BADADDR;
        result.status = TypeInferenceStatus::UnsupportedOperation;
        result.error_message =
            "interprocedural type-inference fixed-point analysis is not implemented";
        results.push_back(std::move(result));
    }

    return results;
}

void TypeInferenceEngine::phase_constraint_extraction(cfunc_t* cfunc) {
    auto start = std::chrono::steady_clock::now();
    
    // Extract constraints from the ctree
    TypeConstraintSet extracted = semantics_extractor_->extract(cfunc);
    
    // Merge into current constraints
    for (const auto& c : extracted.constraints()) {
        current_constraints_.add(c);
    }
    
    // Record type variables
    for (const auto& tv : extracted.variables()) {
        if (tv.is_local()) {
            var_to_type_var_[tv.var_idx] = tv;
        }
    }
    
    auto end = std::chrono::steady_clock::now();
    last_stats_.constraint_extraction_time = std::chrono::duration_cast<std::chrono::milliseconds>(
        end - start);
    last_stats_.type_constraints_hard = static_cast<unsigned>(current_constraints_.hard_count());
    last_stats_.type_constraints_soft = static_cast<unsigned>(current_constraints_.soft_count());
    last_stats_.variables_typed = static_cast<unsigned>(var_to_type_var_.size());
    last_stats_.unresolved_memory_accesses =
        static_cast<unsigned>(semantics_extractor_->stats().unresolved_memory_accesses);
}

void TypeInferenceEngine::phase_alias_analysis(cfunc_t* cfunc) {
    auto start = std::chrono::steady_clock::now();
    
    alias_analyzer_->analyze(cfunc);
    
    // Generate type equality constraints for aliasing locations
    auto alias_constraints = alias_analyzer_->generate_type_constraints(var_to_type_var_);
    for (const auto& c : alias_constraints) {
        current_constraints_.add(c);
        last_stats_.alias_pairs_found++;
    }
    
    auto end = std::chrono::steady_clock::now();
    last_stats_.alias_analysis_time = std::chrono::duration_cast<std::chrono::milliseconds>(
        end - start);
}

void TypeInferenceEngine::phase_soft_constraints(cfunc_t* cfunc) {
    add_type_preferences();
    add_calling_convention_constraints(cfunc);
}

void TypeInferenceEngine::add_type_preferences() {
    // Add soft constraints preferring:
    // 1. Signed integers over unsigned (C default)
    // 2. Concrete types over unknown
    // 3. Smaller types when sufficient
    
    for (const auto& [var_idx, tv] : var_to_type_var_) {
        // Prefer signed integers
        current_constraints_.add(
            TypeConstraint::make_is_signed(tv, BADADDR)
                .soft(config_.weight_signed_over_unsigned)
                .sourced_from(TypeConstraintOrigin::Heuristic)
                .describe("prefer signed integers")
        );
    }
}

void TypeInferenceEngine::add_calling_convention_constraints(cfunc_t* cfunc) {
    if (!cfunc) return;

    lvars_t* lvars = cfunc->get_lvars();
    if (!lvars) return;
    // Validate indexes before asking the SDK to derive a function type; that
    // operation may itself consult the argument-to-local mapping.
    const auto bindings = detail::map_signature_arguments(
        std::span<const int>(cfunc->argidx.begin(), cfunc->argidx.size()),
        cfunc->argidx.size(), lvars->size());
    if (!bindings.has_value()) return;
    
    // Get function type from IDA
    tinfo_t func_type;
    if (!cfunc->get_func_type(&func_type)) return;
    
    func_type_data_t ftd;
    if (!func_type.get_func_details(&ftd) || ftd.size() != bindings->size()) return;

    for (const auto& binding : *bindings) {
        auto it = var_to_type_var_.find(binding.local_index);
        if (it == var_to_type_var_.end()) continue;
        
        const auto inferred = semantics_extractor_->observe_type(
            ftd[binding.parameter_index].type, cfunc->entry_ea);
        if (!inferred) continue;
        
        current_constraints_.add(
            TypeConstraint::make_one_of(it->second, {*inferred}, cfunc->entry_ea)
                .soft(config_.weight_from_signature)
                .sourced_from(TypeConstraintOrigin::FunctionSignature)
                .describe("parameter type from signature")
        );
    }
}

::z3::optimize TypeInferenceEngine::build_z3_constraints() {
    ::z3::optimize opt(ctx_.ctx());
    
    // Set timeout
    ::z3::params p(ctx_.ctx());
    p.set("timeout", config_.solver_timeout_ms);
    opt.set(p);
    
    // Add hard constraints
    ::z3::expr_vector hard = current_constraints_.to_z3_hard(type_encoder_);
    hard_constraints_use_symbolic_bounds_ = type_encoder_.bounded_symbolic_queries_used();
    for (unsigned i = 0; i < hard.size(); ++i) {
        opt.add(hard[i]);
    }
    
    // Add soft constraints with weights
    auto soft = current_constraints_.to_z3_soft(type_encoder_, true);
    for (const auto& [expr, weight] : soft) {
        opt.add_soft(expr, weight);
    }
    
    return opt;
}

::z3::check_result TypeInferenceEngine::phase_solve(::z3::optimize& opt, ::z3::model& out_model) {
    auto start = std::chrono::steady_clock::now();
    
    auto result = opt.check();
    last_stats_.solve_iterations++;
    
    auto end = std::chrono::steady_clock::now();
    last_stats_.solving_time = std::chrono::duration_cast<std::chrono::milliseconds>(
        end - start);
    
    if (result == ::z3::sat) {
        out_model = opt.get_model();
    }
    
    // Unknown (including timeout) is not evidence of satisfiability. Never
    // expose a partial model as successful inferred type information.
    return result;
}

void TypeInferenceEngine::extract_results(
    const ::z3::model& model,
    const ::z3::expr_vector& hard_constraints,
    FunctionTypeInferenceResult& result)
{
    auto memory = extract_memory_type_evidence(current_constraints_, type_encoder_,
                                               model, ctx_.pointer_size());
    result.memory_types = std::move(memory.types);
    result.memory_provenance = std::move(memory.provenance);
    result.memory_diagnostics = std::move(memory.diagnostics);
    last_stats_.memory_locations_typed = static_cast<unsigned>(result.memory_types.size());
    last_stats_.memory_locations_omitted = static_cast<unsigned>(result.memory_diagnostics.size());
    const ConstraintSourceIndex source_index(current_constraints_);
    const auto evidence_start = std::chrono::steady_clock::now();
    ModelValueEvidenceProbe probe(hard_constraints, model, config_.model_evidence_budget);
    // Stable order makes a shared query budget reproducible across hash orders.
    std::vector<int> ordered_variables;
    ordered_variables.reserve(var_to_type_var_.size());
    for (const auto& [index, unused] : var_to_type_var_) ordered_variables.push_back(index);
    std::sort(ordered_variables.begin(), ordered_variables.end());
    qvector<InferredVariableType> local_types;
    local_types.reserve(ordered_variables.size());
    for (const auto var_idx : ordered_variables) {
        const auto& tv = var_to_type_var_.at(var_idx);
        InferredVariableType ivt;
        ivt.var_idx = var_idx;
        ivt.var_name = tv.name;
        ivt.record_source_evidence(source_index.for_variable(tv));
        
        // Get the Z3 expression for this type variable
        ::z3::expr z3_var = current_constraints_.get_z3_var(tv, type_encoder_);
        
        // Decode the model value
        ivt.type = type_encoder_.decode(z3_var, model);
        
        const auto selected_value = model.eval(z3_var, true);
        const auto evidence = probe.inspect(z3_var, selected_value);
        ivt.model_value_status = evidence.status;
        ivt.model_value_reason = evidence.reason.c_str();
        if (hard_constraints_use_symbolic_bounds_)
            ivt.evidence_query_bounds = type_encoder_.symbolic_query_bounds();
        if (evidence.alternative)
            ivt.alternative_type = type_encoder_.decode(*evidence.alternative, model).snapshot();
        // These levels are evidence categories, not calibrated probabilities.
        ivt.confidence = ivt.may_apply_model_value()
            ? TypeConfidence::Medium : TypeConfidence::Low;
        if (evidence.status == ModelValueStatus::DeterminedByHardConstraints)
            ++last_stats_.model_values_determined;
        else if (evidence.status == ModelValueStatus::AlternativeModelExists)
            ++last_stats_.model_values_ambiguous;
        else
            ++last_stats_.model_values_unverified;
        
        // Categorize for statistics
        if (ivt.type.is_pointer()) {
            last_stats_.types_pointer++;
        } else if (ivt.type.is_base()) {
            if (is_integer(ivt.type.base_type())) {
                last_stats_.types_integer++;
            } else if (is_floating(ivt.type.base_type())) {
                last_stats_.types_floating++;
            } else if (ivt.type.base_type() == BaseType::Unknown) {
                last_stats_.types_unknown++;
            }
        }
        last_stats_.types_inferred++;
        
        local_types.push_back(std::move(ivt));
    }
    last_stats_.model_evidence_queries = probe.queries_used();
    last_stats_.model_evidence_time = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - evidence_start);
    result.local_types = std::move(local_types);
}

TypeVariable TypeInferenceEngine::get_type_var(int var_idx) {
    auto it = var_to_type_var_.find(var_idx);
    if (it != var_to_type_var_.end()) {
        return it->second;
    }
    
    // Use the extractor's exact registry so later constraints refer to the
    // same local, independently of diagnostic index allocation order.
    TypeVariable tv = semantics_extractor_->get_var_type(current_cfunc_, var_idx);
    var_to_type_var_[var_idx] = tv;
    return tv;
}

void TypeInferenceEngine::report_progress(
    const char* phase, 
    int progress, 
    const char* message)
{
    if (progress_callback_) {
        progress_callback_(phase, progress, message);
    }
}

// ============================================================================
// TypeScheme implementation
// ============================================================================

std::pair<InferredType, std::unordered_map<int, TypeVariable>> 
TypeScheme::instantiate(
    int call_site_id, 
    std::function<TypeVariable(int, const char*)> make_var) const
{
    (void)call_site_id;
    (void)make_var;
    if (!type_params.empty()) {
        throw std::logic_error(
            "polymorphic TypeScheme instantiation is unsupported because "
            "InferredType has no type-parameter representation");
    }

    return {body, {}};
}

// ============================================================================
// PolymorphicFunctionDetector implementation
// ============================================================================

PolymorphicFunctionDetector::PolymorphicFunctionDetector(Z3Context& ctx) {
    (void)ctx;
}

bool PolymorphicFunctionDetector::is_polymorphic(ea_t func_ea) const {
    return known_schemes_.find(func_ea) != known_schemes_.end();
}

std::optional<TypeScheme> PolymorphicFunctionDetector::get_type_scheme(
    ea_t func_ea) const {
    auto it = known_schemes_.find(func_ea);
    if (it != known_schemes_.end()) {
        return it->second;
    }
    return std::nullopt;
}

void PolymorphicFunctionDetector::register_polymorphic(ea_t func_ea, TypeScheme scheme) {
    known_schemes_[func_ea] = std::move(scheme);
}

// ============================================================================
// CallingConventionDetector implementation
// ============================================================================

CallingConventionDetector::CallingConventionDetector(Z3Context& ctx) : ctx_(ctx) {}

CallingConventionDetector::Convention CallingConventionDetector::detect(cfunc_t* cfunc) {
    return detect_with_evidence(cfunc).convention;
}

CallingConventionDetection CallingConventionDetector::detect_with_evidence(cfunc_t* cfunc) {
    if (!cfunc) return {};

    detail::SignatureConvention signature = detail::SignatureConvention::Default;
    tinfo_t func_type;
    if (cfunc->get_func_type(&func_type)) {
        // callcnv_t preserves extended/custom convention codes; cm_t truncates
        // them and can turn a language-specific ABI into a platform default.
        const callcnv_t cc = func_type.get_cc();
        switch (cc) {
            case CM_CC_UNKNOWN:
            case CM_CC_VOIDARG:
                break;
            case CM_CC_CDECL:
            case CM_CC_ELLIPSIS:
                signature = detail::SignatureConvention::CDecl;
                break;
            case CM_CC_STDCALL:
                signature = detail::SignatureConvention::Stdcall;
                break;
            case CM_CC_FASTCALL:
                signature = detail::SignatureConvention::Fastcall;
                break;
            case CM_CC_THISCALL:
                signature = detail::SignatureConvention::Thiscall;
                break;
            default:
                signature = detail::SignatureConvention::Unsupported;
                break;
        }
    }

    detail::CallingConventionTarget target;
#ifndef STRUCTOR_TESTING
    const auto* processor = get_ph();
    if (processor != nullptr) {
        if (processor->id == PLFM_386) target.machine = detail::TargetMachine::X86;
        if (processor->id == PLFM_ARM) target.machine = detail::TargetMachine::Arm;
    }
    target.bitness = inf_is_64bit() ? 64 : (inf_is_32bit_exactly() ? 32 : 16);
    tinfo_t void_type;
    void_type.create_simple_type(BTF_VOID);
    tinfo_t pointer_type;
    pointer_type.create_ptr(void_type);
    const auto pointer_size = pointer_type.get_size();
    if (pointer_size == 4 || pointer_size == 8) {
        target.pointer_size = static_cast<unsigned>(pointer_size);
    }
    switch (inf_get_filetype()) {
        case f_PE: target.format = detail::TargetObjectFormat::PE; break;
        case f_ELF: target.format = detail::TargetObjectFormat::ELF; break;
        case f_MACHO: target.format = detail::TargetObjectFormat::MachO; break;
        default: break;
    }
    qstring database_abi;
    if (get_abi_name(&database_abi) < 0) return {};
    target.database_abi = database_abi.c_str();
#endif
    const auto convention = detail::select_calling_convention(target, signature);
    if (convention == Convention::Unknown) return {};
    const auto evidence = target.machine == detail::TargetMachine::X86 && target.bitness == 32
        ? CallingConventionEvidence::RecoveredPrototype : CallingConventionEvidence::TargetDefault;
    return {convention, evidence};
}

qvector<InferredType> CallingConventionDetector::get_param_constraints(
    Convention conv,
    cfunc_t* cfunc)
{
    qvector<InferredType> result;
    
    // Get parameters from function type
    tinfo_t func_type;
    if (!cfunc || !cfunc->get_func_type(&func_type)) return result;
    
    func_type_data_t ftd;
    if (!func_type.get_func_details(&ftd)) return result;
    
    for (const auto& arg : ftd) {
        result.push_back(InferredType::from_tinfo(arg.type));
    }
    
    return result;
}

std::optional<InferredType> CallingConventionDetector::get_return_constraint(
    Convention conv,
    cfunc_t* cfunc)
{
    tinfo_t func_type;
    if (!cfunc || !cfunc->get_func_type(&func_type)) return std::nullopt;
    
    func_type_data_t ftd;
    if (!func_type.get_func_details(&ftd)) return std::nullopt;
    
    auto inferred = InferredType::from_tinfo(ftd.rettype);
    return inferred.is_unknown() ? std::nullopt : std::optional<InferredType>(std::move(inferred));
}

std::vector<CallingConventionDetector::ParamLocation>
CallingConventionDetector::get_param_locations(
    Convention conv,
    const qvector<InferredType>& param_types,
    ParameterPassingMode mode)
{
    std::vector<detail::ABIArgument> arguments;
    arguments.reserve(param_types.size());
    for (const auto& type : param_types) {
        detail::ABIArgument argument;
        if (type.is_pointer()) {
            argument.kind = detail::ABIArgumentClass::IntegerOrPointer;
            argument.size = 8;
        } else if (type.is_base()) {
            const auto base = type.base_type();
            if (is_integer(base) || base == BaseType::Bool) {
                argument.kind = detail::ABIArgumentClass::IntegerOrPointer;
            } else if (is_floating(base)) {
                argument.kind = detail::ABIArgumentClass::Floating;
            }
            argument.size = base_type_size(base, 8);
        }
        arguments.push_back(argument);
    }

    const auto modeled = detail::fixed_x64_parameter_locations(conv, arguments, mode);
    std::vector<ParamLocation> result;
    result.reserve(modeled.size());
    for (const auto& location : modeled) {
        ParamLocation converted;
        converted.is_register = location.is_register;
        if (location.is_register) converted.reg_name = location.register_name.data();
        converted.stack_offset = location.stack_offset;
        result.push_back(std::move(converted));
    }
    return result;
}

} // namespace structor::z3
