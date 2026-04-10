#include <structor/global_object_analyzer.hpp>

#include <structor/access_collector.hpp>
#include <structor/utils.hpp>

#include <algorithm>
#include <unordered_set>

namespace structor {

namespace {

struct RegisteredGlobalRewrite {
    ea_t root_ea = BADADDR;
    ea_t root_head_ea = BADADDR;
    qstring root_name;
    SynthStruct structure;
    tinfo_t struct_type;
    tinfo_t ptr_type;
    std::unordered_map<ea_t, sval_t> pointer_alias_globals;
};

class GlobalRewriteRegistry {
public:
    static GlobalRewriteRegistry& instance() {
        static GlobalRewriteRegistry registry;
        return registry;
    }

    void clear() {
        entries_.clear();
        root_index_.clear();
        alias_index_.clear();
    }

    void register_entry(const GlobalObjectAnalysis& analysis,
                        const SynthStruct& synth_struct,
                        const tinfo_t& struct_type) {
        RegisteredGlobalRewrite entry;
        entry.root_ea = analysis.root_ea;
        entry.root_head_ea = analysis.root_head_ea;
        entry.root_name = analysis.root_name;
        entry.structure = synth_struct;
        entry.struct_type = struct_type;
        entry.ptr_type.create_ptr(struct_type);
        entry.pointer_alias_globals = analysis.pointer_alias_globals;

        const std::size_t index = entries_.size();
        entries_.push_back(std::move(entry));
        root_index_[analysis.root_ea] = index;
        if (analysis.root_head_ea != BADADDR) {
            root_index_[analysis.root_head_ea] = index;
        }

        for (const auto& [alias_ea, delta] : analysis.pointer_alias_globals) {
            if (delta == 0) {
                alias_index_[alias_ea] = index;
            }
        }
    }

    [[nodiscard]] const RegisteredGlobalRewrite* find_root(ea_t ea) const {
        auto it = root_index_.find(ea);
        return it == root_index_.end() ? nullptr : &entries_[it->second];
    }

    [[nodiscard]] const RegisteredGlobalRewrite* find_pointer_alias(ea_t ea) const {
        auto it = alias_index_.find(ea);
        return it == alias_index_.end() ? nullptr : &entries_[it->second];
    }

private:
    qvector<RegisteredGlobalRewrite> entries_;
    std::unordered_map<ea_t, std::size_t> root_index_;
    std::unordered_map<ea_t, std::size_t> alias_index_;
};

enum class AliasOrigin : std::uint8_t {
    None,
    RootObject,
    PointerGlobal,
    SourceReturn,
    LocalVar,
};

struct AliasInfo {
    sval_t delta = 0;
    AliasOrigin origin = AliasOrigin::None;

    [[nodiscard]] bool valid() const noexcept {
        return origin != AliasOrigin::None;
    }
};

struct SeedKey {
    ea_t func_ea = BADADDR;
    int var_idx = -1;
    sval_t delta = 0;

    bool operator==(const SeedKey& other) const noexcept {
        return func_ea == other.func_ea && var_idx == other.var_idx && delta == other.delta;
    }
};

struct SeedKeyHash {
    std::size_t operator()(const SeedKey& key) const noexcept {
        std::size_t h1 = std::hash<ea_t>{}(key.func_ea);
        std::size_t h2 = std::hash<int>{}(key.var_idx);
        std::size_t h3 = std::hash<sval_t>{}(key.delta);
        return h1 ^ (h2 << 1) ^ (h3 << 2);
    }
};

struct VarKey {
    ea_t func_ea = BADADDR;
    int var_idx = -1;

    bool operator==(const VarKey& other) const noexcept {
        return func_ea == other.func_ea && var_idx == other.var_idx;
    }
};

struct VarKeyHash {
    std::size_t operator()(const VarKey& key) const noexcept {
        return std::hash<ea_t>{}(key.func_ea) ^ (std::hash<int>{}(key.var_idx) << 1);
    }
};

[[nodiscard]] static std::uint32_t expr_size(const cexpr_t* expr) {
    if (expr && !expr->type.empty()) {
        return utils::get_type_size(expr->type, get_ptr_size());
    }
    return get_ptr_size();
}

[[nodiscard]] static sval_t scale_constant(const cexpr_t* pointer_expr, sval_t value) {
    if (!pointer_expr || !pointer_expr->type.is_ptr()) {
        return value;
    }

    tinfo_t pointed = pointer_expr->type.get_pointed_object();
    if (pointed.empty()) {
        return value;
    }

    const size_t elem_size = pointed.get_size();
    if (elem_size == BADSIZE || elem_size == 0) {
        return value;
    }

    return value * static_cast<sval_t>(elem_size);
}

[[nodiscard]] static ea_t direct_callee_ea(const cexpr_t* call_expr) {
    if (!call_expr || call_expr->op != cot_call || !call_expr->x) {
        return BADADDR;
    }

    const cexpr_t* callee = call_expr->x;
    while (callee && callee->op == cot_cast) {
        callee = callee->x;
    }

    return (callee && callee->op == cot_obj) ? callee->obj_ea : BADADDR;
}

class ExplicitRootScanner : public ctree_visitor_t {
public:
    struct Result {
        qvector<FieldAccess> direct_accesses;
        qvector<FunctionVariable> var_seeds;
        qvector<FunctionVariable> param_seeds;
        std::unordered_map<ea_t, sval_t> pointer_alias_globals;
        std::optional<sval_t> return_delta;
    };

    ExplicitRootScanner(cfunc_t* cfunc,
                        ea_t root_ea,
                        ea_t root_head_ea,
                        const std::unordered_map<ea_t, sval_t>& pointer_alias_globals,
                        const std::unordered_map<ea_t, sval_t>& source_returners)
        : ctree_visitor_t(CV_PARENTS)
        , cfunc_(cfunc)
        , root_ea_(root_ea)
        , root_head_ea_(root_head_ea)
        , pointer_alias_globals_(pointer_alias_globals)
        , source_returners_(source_returners) {}

    int idaapi visit_expr(cexpr_t* expr) override {
        if (!expr) {
            return 0;
        }

        switch (expr->op) {
            case cot_asg:
                process_assignment(expr);
                break;
            case cot_call:
                process_call(expr);
                break;
            case cot_ptr:
                process_ptr_access(expr);
                break;
            case cot_memptr:
            case cot_memref:
                process_member_access(expr);
                break;
            case cot_idx:
                process_index_access(expr);
                break;
            default:
                break;
        }

        return 0;
    }

    int idaapi visit_insn(cinsn_t* insn) override {
        if (!insn || insn->op != cit_return || !insn->creturn) {
            return 0;
        }

        cexpr_t* expr = &insn->creturn->expr;
        if (!expr || expr->op == cot_empty) {
            return 0;
        }

        const AliasInfo alias = extract_alias(expr);
        if (!alias.valid() || alias.delta < 0) {
            return 0;
        }

        if (!result_.return_delta.has_value()) {
            result_.return_delta = alias.delta;
        }

        return 0;
    }

    [[nodiscard]] const Result& result() const noexcept {
        return result_;
    }

private:
    [[nodiscard]] AliasInfo extract_alias(const cexpr_t* expr) const {
        AliasInfo result;
        if (!expr) {
            return result;
        }

        while (expr && expr->op == cot_cast) {
            expr = expr->x;
        }

        if (!expr) {
            return result;
        }

        switch (expr->op) {
            case cot_var: {
                auto it = local_aliases_.find(expr->v.idx);
                if (it == local_aliases_.end()) {
                    return result;
                }
                result.delta = it->second;
                result.origin = AliasOrigin::LocalVar;
                return result;
            }

            case cot_obj:
                if (expr->obj_ea == root_ea_ || expr->obj_ea == root_head_ea_) {
                    result.delta = static_cast<sval_t>(expr->obj_ea - root_ea_);
                    result.origin = AliasOrigin::RootObject;
                    return result;
                }
                if (auto it = pointer_alias_globals_.find(expr->obj_ea);
                    it != pointer_alias_globals_.end()) {
                    result.delta = it->second;
                    result.origin = AliasOrigin::PointerGlobal;
                    return result;
                }
                return result;

            case cot_ref:
                return extract_alias(expr->x);

            case cot_add: {
                const AliasInfo left = extract_alias(expr->x);
                if (left.valid() && expr->y && expr->y->op == cot_num) {
                    result = left;
                    result.delta += scale_constant(expr->x, static_cast<sval_t>(expr->y->numval()));
                    return result;
                }

                const AliasInfo right = extract_alias(expr->y);
                if (right.valid() && expr->x && expr->x->op == cot_num) {
                    result = right;
                    result.delta += scale_constant(expr->y, static_cast<sval_t>(expr->x->numval()));
                    return result;
                }

                return result;
            }

            case cot_sub: {
                const AliasInfo left = extract_alias(expr->x);
                if (!left.valid() || !expr->y || expr->y->op != cot_num) {
                    return result;
                }

                result = left;
                result.delta -= scale_constant(expr->x, static_cast<sval_t>(expr->y->numval()));
                return result;
            }

            case cot_call: {
                const ea_t callee_ea = direct_callee_ea(expr);
                auto it = source_returners_.find(callee_ea);
                if (callee_ea == BADADDR || it == source_returners_.end()) {
                    return result;
                }

                result.delta = it->second;
                result.origin = AliasOrigin::SourceReturn;
                return result;
            }

            default:
                return result;
        }
    }

    [[nodiscard]] AccessType determine_access_type(const cexpr_t* expr) const {
        const cexpr_t* current = expr;
        for (size_t i = 0; i < parents.size(); ++i) {
            const citem_t* parent_item = parents[parents.size() - 1 - i];
            if (!parent_item || !parent_item->is_expr()) {
                continue;
            }

            const cexpr_t* parent = static_cast<const cexpr_t*>(parent_item);
            switch (parent->op) {
                case cot_asg:
                case cot_asgbor:
                case cot_asgxor:
                case cot_asgband:
                case cot_asgadd:
                case cot_asgsub:
                case cot_asgmul:
                case cot_asgsshr:
                case cot_asgushr:
                case cot_asgshl:
                case cot_asgsdiv:
                case cot_asgudiv:
                case cot_asgsmod:
                case cot_asgumod:
                    if (parent->x == current) {
                        return parent->op == cot_asg ? AccessType::Write : AccessType::ReadWrite;
                    }
                    return AccessType::Read;

                case cot_preinc:
                case cot_predec:
                case cot_postinc:
                case cot_postdec:
                    return AccessType::ReadWrite;

                case cot_ref:
                    return AccessType::AddressTaken;

                default:
                    current = parent;
                    break;
            }
        }

        return AccessType::Read;
    }

    [[nodiscard]] SemanticType infer_semantic(const cexpr_t* expr) {
        if (!expr) {
            return SemanticType::Unknown;
        }

        if (!expr->type.empty()) {
            if (expr->type.is_ptr()) {
                return SemanticType::Pointer;
            }
            if (expr->type.is_funcptr()) {
                return SemanticType::FunctionPointer;
            }
            if (expr->type.is_floating()) {
                return expr->type.get_size() == 4 ? SemanticType::Float : SemanticType::Double;
            }
        }

        const cexpr_t* parent = parent_expr();
        if (parent && parent->op == cot_call && parent->x == expr) {
            return SemanticType::FunctionPointer;
        }

        return expr_size(expr) == get_ptr_size() ? SemanticType::Unknown : SemanticType::Integer;
    }

    void add_direct_access(const cexpr_t* expr, sval_t offset) {
        if (offset < 0) {
            return;
        }

        FieldAccess access;
        access.insn_ea = expr->ea;
        access.source_func_ea = cfunc_->entry_ea;
        access.offset = offset;
        access.size = expr_size(expr);
        access.access_type = determine_access_type(expr);
        access.semantic_type = infer_semantic(expr);
        access.context_expr = utils::expr_to_string(expr, cfunc_);
        access.inferred_type = expr->type;
        result_.direct_accesses.push_back(std::move(access));
    }

    void process_assignment(cexpr_t* expr) {
        if (!expr || expr->op != cot_asg || !expr->x || !expr->y) {
            return;
        }

        cexpr_t* lhs = expr->x;
        cexpr_t* rhs = expr->y;
        while (rhs && rhs->op == cot_cast) {
            rhs = rhs->x;
        }

        if (!rhs) {
            return;
        }

        const AliasInfo rhs_alias = extract_alias(rhs);
        if (!rhs_alias.valid()) {
            return;
        }

        if (lhs->op == cot_var) {
            local_aliases_[lhs->v.idx] = rhs_alias.delta;
            if (rhs_alias.origin != AliasOrigin::LocalVar && rhs_alias.delta >= 0) {
                result_.var_seeds.emplace_back(cfunc_->entry_ea, lhs->v.idx, rhs_alias.delta);
            }
            return;
        }

        if (lhs->op == cot_obj && lhs->obj_ea != root_ea_ && lhs->obj_ea != root_head_ea_ && rhs_alias.delta >= 0) {
            result_.pointer_alias_globals.emplace(lhs->obj_ea, rhs_alias.delta);
        }
    }

    void process_call(cexpr_t* expr) {
        if (!expr || expr->op != cot_call || !expr->a) {
            return;
        }

        const ea_t callee_ea = direct_callee_ea(expr);
        if (callee_ea == BADADDR) {
            return;
        }

        for (size_t i = 0; i < expr->a->size(); ++i) {
            const carg_t& arg = expr->a->at(i);
            const AliasInfo alias = extract_alias(&arg);
            if (!alias.valid() || alias.origin == AliasOrigin::LocalVar || alias.delta < 0) {
                continue;
            }

            result_.param_seeds.emplace_back(callee_ea, static_cast<int>(i), alias.delta);
        }
    }

    void process_ptr_access(cexpr_t* expr) {
        if (!expr || !expr->x) {
            return;
        }

        const AliasInfo alias = extract_alias(expr->x);
        if (!alias.valid() || alias.origin == AliasOrigin::LocalVar) {
            return;
        }

        add_direct_access(expr, alias.delta);
    }

    void process_member_access(cexpr_t* expr) {
        if (!expr || !expr->x) {
            return;
        }

        const AliasInfo alias = extract_alias(expr->x);
        if (!alias.valid() || alias.origin == AliasOrigin::LocalVar) {
            return;
        }

        add_direct_access(expr, alias.delta + expr->m);
    }

    void process_index_access(cexpr_t* expr) {
        if (!expr || !expr->x || !expr->y || expr->y->op != cot_num) {
            return;
        }

        const AliasInfo alias = extract_alias(expr->x);
        if (!alias.valid() || alias.origin == AliasOrigin::LocalVar) {
            return;
        }

        sval_t offset = alias.delta;
        const sval_t scaled = scale_constant(expr->x, static_cast<sval_t>(expr->y->numval()));
        add_direct_access(expr, offset + scaled);
    }

    cfunc_t* cfunc_;
    ea_t root_ea_;
    ea_t root_head_ea_;
    const std::unordered_map<ea_t, sval_t>& pointer_alias_globals_;
    const std::unordered_map<ea_t, sval_t>& source_returners_;
    std::unordered_map<int, sval_t> local_aliases_;
    Result result_;
};

class RootVarUsageScanner : public ctree_visitor_t {
public:
    struct Result {
        std::unordered_map<ea_t, sval_t> pointer_alias_globals;
        std::optional<sval_t> return_delta;
    };

    RootVarUsageScanner(cfunc_t* cfunc, int target_var_idx)
        : ctree_visitor_t(CV_FAST)
        , cfunc_(cfunc)
        , target_var_idx_(target_var_idx) {}

    int idaapi visit_expr(cexpr_t* expr) override {
        if (!expr || expr->op != cot_asg || !expr->x || !expr->y) {
            return 0;
        }

        cexpr_t* lhs = expr->x;
        cexpr_t* rhs = expr->y;
        while (rhs && rhs->op == cot_cast) {
            rhs = rhs->x;
        }

        if (!rhs) {
            return 0;
        }

        auto rhs_delta = resolve_delta(rhs);
        if (!rhs_delta.has_value()) {
            return 0;
        }

        if (lhs->op == cot_var) {
            local_aliases_[lhs->v.idx] = *rhs_delta;
            return 0;
        }

        if (lhs->op == cot_obj) {
            result_.pointer_alias_globals.emplace(lhs->obj_ea, *rhs_delta);
        }

        return 0;
    }

    int idaapi visit_insn(cinsn_t* insn) override {
        if (!insn || insn->op != cit_return || !insn->creturn) {
            return 0;
        }

        cexpr_t* expr = &insn->creturn->expr;
        if (!expr || expr->op == cot_empty) {
            return 0;
        }

        auto delta = resolve_delta(expr);
        if (!delta.has_value()) {
            return 0;
        }

        if (!result_.return_delta.has_value()) {
            result_.return_delta = *delta;
        }

        return 0;
    }

    [[nodiscard]] const Result& result() const noexcept {
        return result_;
    }

private:
    [[nodiscard]] std::optional<sval_t> resolve_delta(const cexpr_t* expr) const {
        if (!expr) {
            return std::nullopt;
        }

        while (expr && expr->op == cot_cast) {
            expr = expr->x;
        }

        if (!expr) {
            return std::nullopt;
        }

        switch (expr->op) {
            case cot_var:
                if (expr->v.idx == target_var_idx_) {
                    return 0;
                }
                if (auto it = local_aliases_.find(expr->v.idx); it != local_aliases_.end()) {
                    return it->second;
                }
                return std::nullopt;

            case cot_ref:
                return resolve_delta(expr->x);

            case cot_add: {
                auto left = resolve_delta(expr->x);
                if (left.has_value() && expr->y && expr->y->op == cot_num) {
                    return *left + scale_constant(expr->x, static_cast<sval_t>(expr->y->numval()));
                }

                auto right = resolve_delta(expr->y);
                if (right.has_value() && expr->x && expr->x->op == cot_num) {
                    return *right + scale_constant(expr->y, static_cast<sval_t>(expr->x->numval()));
                }

                return std::nullopt;
            }

            case cot_sub: {
                auto left = resolve_delta(expr->x);
                if (!left.has_value() || !expr->y || expr->y->op != cot_num) {
                    return std::nullopt;
                }

                return *left - scale_constant(expr->x, static_cast<sval_t>(expr->y->numval()));
            }

            case cot_memptr:
            case cot_memref: {
                auto base = resolve_delta(expr->x);
                if (!base.has_value()) {
                    return std::nullopt;
                }
                return *base + expr->m;
            }

            default:
                return std::nullopt;
        }
    }

    cfunc_t* cfunc_;
    int target_var_idx_;
    std::unordered_map<int, sval_t> local_aliases_;
    Result result_;
};

class GlobalObjectAnalysisRunner {
public:
    GlobalObjectAnalysisRunner(ea_t root_ea, const SynthOptions& options)
        : root_ea_(root_ea)
        , root_head_ea_(get_item_head(root_ea))
        , options_(options) {
        if (root_head_ea_ == BADADDR) {
            root_head_ea_ = root_ea_;
        }
        root_name_ = describe_root_name();
        add_candidate_functions_for_data(root_head_ea_);
    }

    [[nodiscard]] GlobalObjectAnalysis run() {
        for (int iteration = 0; iteration < 16; ++iteration) {
            bool progress = false;
            progress |= expand_candidate_functions();

            qvector<ea_t> funcs;
            funcs.reserve(candidate_functions_.size());
            for (ea_t func_ea : candidate_functions_) {
                funcs.push_back(func_ea);
            }
            std::sort(funcs.begin(), funcs.end());
            for (ea_t func_ea : funcs) {
                progress |= scan_explicit_function(func_ea);
            }

            if (!progress) {
                break;
            }
        }

        GlobalObjectAnalysis analysis;
        analysis.root_ea = root_ea_;
        analysis.root_head_ea = root_head_ea_;
        analysis.root_name = root_name_;
        analysis.pattern = build_pattern();
        analysis.touched_functions.reserve(candidate_functions_.size());
        for (ea_t func_ea : candidate_functions_) {
            analysis.touched_functions.push_back(func_ea);
        }
        std::sort(analysis.touched_functions.begin(), analysis.touched_functions.end());
        analysis.zero_delta_variables.clear();
        analysis.zero_delta_variables.reserve(zero_delta_variables_.size());
        for (const auto& key : zero_delta_variables_) {
            analysis.zero_delta_variables.emplace_back(key.func_ea, key.var_idx, 0);
        }
        analysis.pointer_alias_globals = pointer_alias_globals_;
        return analysis;
    }

private:
    [[nodiscard]] qstring describe_root_name() const {
        qstring name;
        get_short_name(&name, root_ea_);
        if (name.empty()) {
            get_name(&name, root_ea_);
        }
        if (name.empty() && root_head_ea_ != BADADDR) {
            get_short_name(&name, root_head_ea_);
            if (name.empty()) {
                get_name(&name, root_head_ea_);
            }
            if (!name.empty() && root_head_ea_ != root_ea_) {
                name.cat_sprnt("_%llX",
                               static_cast<unsigned long long>(root_ea_ - root_head_ea_));
            }
        }
        if (name.empty()) {
            name.sprnt("global_%llX", static_cast<unsigned long long>(root_ea_));
        }
        return name;
    }

    void add_candidate_functions_for_data(ea_t data_ea) {
        xrefblk_t xref;
        for (bool ok = xref.first_to(data_ea, XREF_ALL); ok; ok = xref.next_to()) {
            func_t* func = get_func(xref.from);
            if (func) {
                candidate_functions_.insert(func->start_ea);
            }
        }
    }

    [[nodiscard]] bool expand_candidate_functions() {
        const std::size_t before = candidate_functions_.size();

        for (const auto& [alias_ea, _delta] : pointer_alias_globals_) {
            add_candidate_functions_for_data(alias_ea);
        }

        for (const auto& [func_ea, _delta] : source_returners_) {
            for (ea_t caller_ea : utils::get_callers(func_ea)) {
                candidate_functions_.insert(caller_ea);
            }
        }

        return candidate_functions_.size() != before;
    }

    [[nodiscard]] bool merge_access(FieldAccess access) {
        if (options_.access_filter && !options_.access_filter(access)) {
            return false;
        }

        for (auto& existing : merged_accesses_) {
            if (existing.offset != access.offset || existing.size != access.size) {
                continue;
            }

            if (existing.access_type == AccessType::Read && access.access_type == AccessType::Write) {
                existing.access_type = AccessType::ReadWrite;
            } else if (existing.access_type == AccessType::Write && access.access_type == AccessType::Read) {
                existing.access_type = AccessType::ReadWrite;
            }

            if (semantic_priority(access.semantic_type) > semantic_priority(existing.semantic_type)) {
                existing.semantic_type = access.semantic_type;
            }

            if (!access.inferred_type.empty()) {
                existing.inferred_type = resolve_type_conflict(existing.inferred_type, access.inferred_type);
            }

            if (access.is_vtable_access) {
                existing.is_vtable_access = true;
                existing.vtable_slot = access.vtable_slot;
            }

            for (auto value : access.observed_constants) {
                existing.add_observed_constant(value);
            }

            existing.is_call_argument = existing.is_call_argument || access.is_call_argument;

            if (!access.bitfields.empty()) {
                for (const auto& bf : access.bitfields) {
                    existing.add_bitfield(bf);
                }
            }

            return false;
        }

        merged_accesses_.push_back(std::move(access));
        return true;
    }

    [[nodiscard]] bool add_zero_delta_variable(const FunctionVariable& fv) {
        return zero_delta_variables_.insert(VarKey{fv.func_ea, fv.var_idx}).second;
    }

    [[nodiscard]] bool scan_var_usage(ea_t func_ea, int var_idx, sval_t actual_delta) {
        VarKey key{func_ea, var_idx};
        if (!var_usage_scanned_.insert(key).second) {
            return false;
        }

        cfuncptr_t cfunc = utils::get_cfunc(func_ea);
        if (!cfunc) {
            return false;
        }

        RootVarUsageScanner scanner(cfunc, var_idx);
        scanner.apply_to(&cfunc->body, nullptr);

        bool progress = false;
        for (const auto& [alias_ea, delta] : scanner.result().pointer_alias_globals) {
            const sval_t total_delta = actual_delta + delta;
            if (total_delta < 0) {
                continue;
            }

            auto [it, inserted] = pointer_alias_globals_.emplace(alias_ea, total_delta);
            if (inserted) {
                progress = true;
            }
        }

        if (scanner.result().return_delta.has_value()) {
            const sval_t total_delta = actual_delta + *scanner.result().return_delta;
            if (total_delta >= 0) {
                auto [it, inserted] = source_returners_.emplace(func_ea, total_delta);
                if (inserted) {
                    progress = true;
                }
            }
        }

        return progress;
    }

    [[nodiscard]] bool analyze_seed(ea_t func_ea, int var_idx, sval_t seed_delta) {
        SeedKey key{func_ea, var_idx, seed_delta};
        if (!seed_keys_.insert(key).second) {
            return false;
        }

        CrossFunctionConfig cf_config;
        cf_config.max_depth = options_.max_propagation_depth;
        cf_config.max_functions = 100;
        cf_config.track_pointer_deltas = true;
        cf_config.follow_forward = options_.propagate_to_callees;
        cf_config.follow_backward = options_.propagate_to_callers;

        CrossFunctionAnalyzer analyzer(cf_config);
        UnifiedAccessPattern unified = analyzer.analyze(func_ea, var_idx, options_);

        bool progress = false;
        for (const auto& access : unified.all_accesses) {
            FieldAccess normalized = access;
            normalized.offset += seed_delta;
            progress |= merge_access(std::move(normalized));
        }

        for (const auto& fv : analyzer.equivalence_class().variables) {
            const sval_t actual_delta = seed_delta + fv.base_delta;
            if (actual_delta == 0) {
                progress |= add_zero_delta_variable(fv);
            }
            progress |= scan_var_usage(fv.func_ea, fv.var_idx, actual_delta);
        }

        return progress;
    }

    [[nodiscard]] bool scan_explicit_function(ea_t func_ea) {
        cfuncptr_t cfunc = utils::get_cfunc(func_ea);
        if (!cfunc) {
            return false;
        }

        ExplicitRootScanner scanner(cfunc,
                                    root_ea_,
                                    root_head_ea_,
                                    pointer_alias_globals_,
                                    source_returners_);
        scanner.apply_to(&cfunc->body, nullptr);

        bool progress = false;
        for (const auto& access : scanner.result().direct_accesses) {
            progress |= merge_access(access);
        }

        for (const auto& seed : scanner.result().var_seeds) {
            progress |= analyze_seed(seed.func_ea, seed.var_idx, seed.base_delta);
        }

        for (const auto& seed : scanner.result().param_seeds) {
            progress |= analyze_seed(seed.func_ea, seed.var_idx, seed.base_delta);
        }

        for (const auto& [alias_ea, delta] : scanner.result().pointer_alias_globals) {
            auto [it, inserted] = pointer_alias_globals_.emplace(alias_ea, delta);
            if (inserted) {
                progress = true;
            }
        }

        if (scanner.result().return_delta.has_value()) {
            auto [it, inserted] = source_returners_.emplace(func_ea, *scanner.result().return_delta);
            if (inserted) {
                progress = true;
            }
        }

        return progress;
    }

    [[nodiscard]] UnifiedAccessPattern build_pattern() {
        UnifiedAccessPattern pattern;
        if (merged_accesses_.empty()) {
            return pattern;
        }

        std::sort(merged_accesses_.begin(), merged_accesses_.end(), [](const FieldAccess& a, const FieldAccess& b) {
            if (a.offset != b.offset) {
                return a.offset < b.offset;
            }
            if (a.size != b.size) {
                return a.size < b.size;
            }
            return a.source_func_ea < b.source_func_ea;
        });

        pattern.all_accesses = merged_accesses_;
        pattern.global_min_offset = merged_accesses_.front().offset;
        pattern.global_max_offset = merged_accesses_.front().offset + merged_accesses_.front().size;

        std::unordered_map<ea_t, std::size_t> per_func_indices;
        for (const auto& access : merged_accesses_) {
            pattern.global_min_offset = std::min(pattern.global_min_offset, access.offset);
            pattern.global_max_offset = std::max(pattern.global_max_offset,
                access.offset + static_cast<sval_t>(access.size));

            if (access.is_vtable_access) {
                pattern.has_vtable = true;
                pattern.vtable_offset = access.offset;
            }

            auto [it, inserted] = per_func_indices.emplace(access.source_func_ea, pattern.per_function_patterns.size());
            if (inserted) {
                AccessPattern fn_pattern;
                fn_pattern.func_ea = access.source_func_ea;
                fn_pattern.var_name = root_name_;
                fn_pattern.var_idx = -1;
                pattern.per_function_patterns.push_back(std::move(fn_pattern));
                pattern.contributing_functions.push_back(access.source_func_ea);
                pattern.function_deltas[access.source_func_ea] = 0;
            }

            AccessPattern& fn_pattern = pattern.per_function_patterns[it->second];
            fn_pattern.add_access(FieldAccess(access));
        }

        for (auto& fn_pattern : pattern.per_function_patterns) {
            fn_pattern.sort_by_offset();
        }

        return pattern;
    }

    ea_t root_ea_ = BADADDR;
    ea_t root_head_ea_ = BADADDR;
    qstring root_name_;
    const SynthOptions& options_;
    std::unordered_set<ea_t> candidate_functions_;
    std::unordered_map<ea_t, sval_t> source_returners_;
    std::unordered_map<ea_t, sval_t> pointer_alias_globals_;
    std::unordered_set<SeedKey, SeedKeyHash> seed_keys_;
    std::unordered_set<VarKey, VarKeyHash> zero_delta_variables_;
    std::unordered_set<VarKey, VarKeyHash> var_usage_scanned_;
    qvector<FieldAccess> merged_accesses_;
};

struct ResolvedGlobalExpr {
    const RegisteredGlobalRewrite* entry = nullptr;
    bool through_pointer = false;
    ea_t obj_ea = BADADDR;
    sval_t offset = 0;

    [[nodiscard]] bool valid() const noexcept {
        return entry != nullptr && obj_ea != BADADDR;
    }
};

[[nodiscard]] static const SynthField* find_exact_field(
    const RegisteredGlobalRewrite& entry,
    sval_t offset)
{
    for (const auto& field : entry.structure.fields) {
        if (field.offset == offset && !field.is_padding) {
            return &field;
        }
    }
    return nullptr;
}

class RegisteredGlobalUseRewriter : public ctree_visitor_t {
public:
    explicit RegisteredGlobalUseRewriter(cfunc_t* cfunc)
        : ctree_visitor_t(CV_PARENTS | CV_POST)
        , cfunc_(cfunc) {}

    int idaapi visit_expr(cexpr_t* expr) override {
        if (!expr) {
            return 0;
        }

        if (expr->op == cot_ptr) {
            rewrite_dereference(expr);
        }

        return 0;
    }

    [[nodiscard]] bool modified() const noexcept {
        return modified_;
    }

private:
    [[nodiscard]] ResolvedGlobalExpr resolve_expr(const cexpr_t* expr) const {
        ResolvedGlobalExpr result;
        if (!expr) {
            return result;
        }

        while (expr && expr->op == cot_cast) {
            expr = expr->x;
        }
        if (!expr) {
            return result;
        }

        switch (expr->op) {
            case cot_obj: {
                if (const auto* entry = GlobalRewriteRegistry::instance().find_root(expr->obj_ea)) {
                    result.entry = entry;
                    result.through_pointer = false;
                    result.obj_ea = entry->root_ea;
                    result.offset = static_cast<sval_t>(expr->obj_ea - entry->root_ea);
                    return result;
                }
                if (const auto* entry = GlobalRewriteRegistry::instance().find_pointer_alias(expr->obj_ea)) {
                    result.entry = entry;
                    result.through_pointer = true;
                    result.obj_ea = expr->obj_ea;
                    result.offset = 0;
                    return result;
                }
                return result;
            }

            case cot_ref:
                return resolve_expr(expr->x);

            case cot_add: {
                ResolvedGlobalExpr left = resolve_expr(expr->x);
                if (left.valid() && expr->y && expr->y->op == cot_num) {
                    left.offset += scale_constant(expr->x, static_cast<sval_t>(expr->y->numval()));
                    return left;
                }

                ResolvedGlobalExpr right = resolve_expr(expr->y);
                if (right.valid() && expr->x && expr->x->op == cot_num) {
                    right.offset += scale_constant(expr->y, static_cast<sval_t>(expr->x->numval()));
                    return right;
                }

                return result;
            }

            case cot_sub: {
                ResolvedGlobalExpr left = resolve_expr(expr->x);
                if (left.valid() && expr->y && expr->y->op == cot_num) {
                    left.offset -= scale_constant(expr->x, static_cast<sval_t>(expr->y->numval()));
                    return left;
                }
                return result;
            }

            case cot_idx: {
                ResolvedGlobalExpr base = resolve_expr(expr->x);
                if (!base.valid() || !expr->y || expr->y->op != cot_num) {
                    return result;
                }
                base.offset += scale_constant(expr->x, static_cast<sval_t>(expr->y->numval()));
                return base;
            }

            default:
                return result;
        }
    }

    [[nodiscard]] static cexpr_t* make_obj_expr(ea_t obj_ea, const tinfo_t& type, ea_t ea) {
        cexpr_t* obj = new cexpr_t();
        obj->op = cot_obj;
        obj->obj_ea = obj_ea;
        obj->refwidth = -1;
        obj->type = type;
        obj->ea = ea;
        return obj;
    }

    void rewrite_dereference(cexpr_t* expr) {
        if (!expr || !expr->x) {
            return;
        }

        const ResolvedGlobalExpr resolved = resolve_expr(expr->x);
        if (!resolved.valid()) {
            return;
        }

        const SynthField* field = find_exact_field(*resolved.entry, resolved.offset);
        if (!field) {
            return;
        }

        if (Config::instance().options().debug_mode) {
            qstring before = utils::expr_to_string(expr, cfunc_);
            msg("Structor: rewriting global deref in %a: %s -> %s%s at offset 0x%llX\n",
                cfunc_->entry_ea,
                before.c_str(),
                resolved.entry->root_name.c_str(),
                resolved.through_pointer ? "->" : ".",
                static_cast<unsigned long long>(field->offset));
        }

        cexpr_t* replacement = new cexpr_t();
        replacement->op = resolved.through_pointer ? cot_memptr : cot_memref;
        replacement->ea = expr->ea;
        replacement->x = make_obj_expr(
            resolved.obj_ea,
            resolved.through_pointer ? resolved.entry->ptr_type : resolved.entry->struct_type,
            expr->ea);
        replacement->m = static_cast<uint32>(field->offset);
        replacement->ptrsize = get_ptr_size();
        replacement->type = field->type;
        replacement->calc_type(false);

        expr->replace_by(replacement);
        modified_ = true;
    }

    cfunc_t* cfunc_ = nullptr;
    bool modified_ = false;
};

} // namespace

GlobalObjectAnalysis GlobalObjectAnalyzer::analyze(ea_t root_ea) {
    if (root_ea == BADADDR) {
        return {};
    }

    GlobalObjectAnalysisRunner runner(root_ea, options_);
    return runner.run();
}

void register_global_rewrite_info(
    const GlobalObjectAnalysis& analysis,
    const SynthStruct& synth_struct,
    const tinfo_t& struct_type)
{
    if (analysis.root_ea == BADADDR || synth_struct.fields.empty() || struct_type.empty()) {
        return;
    }
    GlobalRewriteRegistry::instance().register_entry(analysis, synth_struct, struct_type);
}

bool rewrite_registered_global_uses(cfunc_t* cfunc) {
    if (!cfunc) {
        return false;
    }

    RegisteredGlobalUseRewriter rewriter(cfunc);
    rewriter.apply_to(&cfunc->body, nullptr);
    if (rewriter.modified()) {
        cfunc->verify(ALLOW_UNUSED_LABELS, false);
    }
    return rewriter.modified();
}

void clear_registered_global_rewrite_info() {
    GlobalRewriteRegistry::instance().clear();
}

} // namespace structor
