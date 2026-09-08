#include <structor/global_object_analyzer.hpp>

#include <structor/access_collector.hpp>
#include <structor/global_rewrite_index.hpp>
#include <structor/utils.hpp>

#include <algorithm>
#include <unordered_set>

namespace structor {

namespace {

[[nodiscard]] bool global_rewrite_thread_is_valid() noexcept {
#ifndef STRUCTOR_TESTING
    return is_main_thread();
#else
    return true;
#endif
}

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
        const auto key = current_database_key();
        if (key.has_value()) {
            databases_.erase(*key);
        }
    }

    void register_entry(const GlobalObjectAnalysis& analysis,
                        const SynthStruct& synth_struct,
                        const tinfo_t& struct_type) {
        const auto key = current_database_key();
        if (!key.has_value()) {
            return;
        }
        RegistryState& state = databases_[*key];

        RegisteredGlobalRewrite entry;
        entry.root_ea = analysis.root_ea;
        entry.root_head_ea = analysis.root_head_ea;
        entry.root_name = analysis.root_name;
        entry.structure = synth_struct;
        entry.struct_type = struct_type;
        entry.ptr_type.create_ptr(struct_type);
        entry.pointer_alias_globals = analysis.pointer_alias_globals;

        qvector<detail::GlobalRewriteIndex::address_type> zero_delta_aliases;
        zero_delta_aliases.reserve(analysis.pointer_alias_globals.size());
        for (const auto& [alias_ea, delta] : analysis.pointer_alias_globals) {
            if (delta == 0) {
                zero_delta_aliases.push_back(alias_ea);
            }
        }
        std::sort(zero_delta_aliases.begin(), zero_delta_aliases.end());

        const std::optional<detail::GlobalRewriteIndex::address_type> root_head =
            analysis.root_head_ea == BADADDR
                ? std::nullopt
                : std::optional<detail::GlobalRewriteIndex::address_type>(analysis.root_head_ea);
        const std::span<const detail::GlobalRewriteIndex::address_type> aliases =
            zero_delta_aliases.empty()
                ? std::span<const detail::GlobalRewriteIndex::address_type>()
                : std::span<const detail::GlobalRewriteIndex::address_type>(
                      zero_delta_aliases.begin(), zero_delta_aliases.size());
        const auto update = state.index.upsert(
            analysis.root_ea,
            root_head,
            aliases);

        if (update.replaced) {
            state.entries[update.index] = std::move(entry);
        } else {
            state.entries.push_back(std::move(entry));
        }
    }

    [[nodiscard]] const RegisteredGlobalRewrite* find_root(ea_t ea) const {
        const RegistryState* state = current_state();
        if (state == nullptr) {
            return nullptr;
        }
        const auto index = state->index.find_root(ea);
        return !index || *index >= state->entries.size()
            ? nullptr
            : &state->entries[*index];
    }

    [[nodiscard]] const RegisteredGlobalRewrite* find_pointer_alias(ea_t ea) const {
        const RegistryState* state = current_state();
        if (state == nullptr) {
            return nullptr;
        }
        const auto index = state->index.find_alias(ea);
        return !index || *index >= state->entries.size()
            ? nullptr
            : &state->entries[*index];
    }

private:
    struct RegistryState {
        qvector<RegisteredGlobalRewrite> entries;
        detail::GlobalRewriteIndex index;
    };

    [[nodiscard]] static std::optional<ssize_t> current_database_key() noexcept {
#ifndef STRUCTOR_TESTING
        try {
            const ssize_t key = get_dbctx_id();
            return key < 0 ? std::nullopt : std::optional<ssize_t>{key};
        } catch (...) {
            return std::nullopt;
        }
#else
        return ssize_t{0};
#endif
    }

    [[nodiscard]] const RegistryState* current_state() const noexcept {
        const auto key = current_database_key();
        if (!key.has_value()) {
            return nullptr;
        }
        const auto found = databases_.find(*key);
        return found == databases_.end() ? nullptr : &found->second;
    }

    std::unordered_map<ssize_t, RegistryState> databases_;
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

[[nodiscard]] static std::optional<sval_t> scale_constant(
    const cexpr_t* pointer_expr,
    std::uint64_t raw_value) {
    const auto value = checked_sval_from_u64(raw_value);
    if (!value.has_value()) {
        return std::nullopt;
    }
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
    if (elem_size > static_cast<size_t>(
            std::numeric_limits<sval_t>::max())) {
        return std::nullopt;
    }
    return checked_sval_mul(*value, static_cast<sval_t>(elem_size));
}

[[nodiscard]] static std::optional<sval_t> checked_ea_delta(
    ea_t value,
    ea_t base) noexcept {
    using U = std::make_unsigned_t<sval_t>;
    constexpr U kPositiveLimit =
        static_cast<U>(std::numeric_limits<sval_t>::max());
    constexpr U kNegativeLimit = kPositiveLimit + U{1};
    if (value >= base) {
        const auto magnitude = static_cast<U>(value - base);
        return magnitude <= kPositiveLimit
            ? std::optional<sval_t>{static_cast<sval_t>(magnitude)}
            : std::nullopt;
    }
    const auto magnitude = static_cast<U>(base - value);
    if (magnitude > kNegativeLimit) {
        return std::nullopt;
    }
    if (magnitude == kNegativeLimit) {
        return std::numeric_limits<sval_t>::min();
    }
    return -static_cast<sval_t>(magnitude);
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
        qvector<PointerFlowEdge> flow_edges;
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
                    const auto delta = checked_ea_delta(expr->obj_ea, root_ea_);
                    if (!delta.has_value()) return result;
                    result.delta = *delta;
                    result.origin = AliasOrigin::RootObject;
                    return result;
                }
                if (expr->obj_ea != BADADDR && get_item_head(expr->obj_ea) == root_head_ea_) {
                    const auto delta = checked_ea_delta(expr->obj_ea, root_ea_);
                    if (!delta.has_value()) return result;
                    result.delta = *delta;
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
                    const auto scaled = scale_constant(expr->x, expr->y->numval());
                    const auto combined = scaled.has_value()
                        ? checked_sval_add(result.delta, *scaled)
                        : std::nullopt;
                    if (!combined.has_value()) return AliasInfo{};
                    result.delta = *combined;
                    return result;
                }

                const AliasInfo right = extract_alias(expr->y);
                if (right.valid() && expr->x && expr->x->op == cot_num) {
                    result = right;
                    const auto scaled = scale_constant(expr->y, expr->x->numval());
                    const auto combined = scaled.has_value()
                        ? checked_sval_add(result.delta, *scaled)
                        : std::nullopt;
                    if (!combined.has_value()) return AliasInfo{};
                    result.delta = *combined;
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
                const auto scaled = scale_constant(expr->x, expr->y->numval());
                const auto combined = scaled.has_value()
                    ? checked_sval_sub(result.delta, *scaled)
                    : std::nullopt;
                if (!combined.has_value()) return AliasInfo{};
                result.delta = *combined;
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
            if (!alias.valid() || alias.delta < 0) {
                continue;
            }

            PointerFlowEdge edge;
            edge.caller_ea = cfunc_->entry_ea;
            edge.callee_ea = callee_ea;
            edge.call_site = expr->ea;
            edge.caller_var_idx = -1;
            edge.callee_param_idx = static_cast<int>(i);
            edge.delta = alias.delta;
            edge.is_direct_call = true;
            result_.flow_edges.push_back(edge);

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

        const auto member = checked_sval_from_u64(expr->m);
        const auto offset = member.has_value()
            ? checked_sval_add(alias.delta, *member)
            : std::nullopt;
        if (offset.has_value()) {
            add_direct_access(expr, *offset);
        }
    }

    void process_index_access(cexpr_t* expr) {
        if (!expr || !expr->x || !expr->y || expr->y->op != cot_num) {
            return;
        }

        const AliasInfo alias = extract_alias(expr->x);
        if (!alias.valid() || alias.origin == AliasOrigin::LocalVar) {
            return;
        }

        const auto scaled = scale_constant(expr->x, expr->y->numval());
        const auto offset = scaled.has_value()
            ? checked_sval_add(alias.delta, *scaled)
            : std::nullopt;
        if (offset.has_value()) {
            add_direct_access(expr, *offset);
        }
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

    explicit RootVarUsageScanner(int target_var_idx)
        : ctree_visitor_t(CV_FAST)
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
                    const auto scaled = scale_constant(expr->x, expr->y->numval());
                    return scaled.has_value()
                        ? checked_sval_add(*left, *scaled)
                        : std::nullopt;
                }

                auto right = resolve_delta(expr->y);
                if (right.has_value() && expr->x && expr->x->op == cot_num) {
                    const auto scaled = scale_constant(expr->y, expr->x->numval());
                    return scaled.has_value()
                        ? checked_sval_add(*right, *scaled)
                        : std::nullopt;
                }

                return std::nullopt;
            }

            case cot_sub: {
                auto left = resolve_delta(expr->x);
                if (!left.has_value() || !expr->y || expr->y->op != cot_num) {
                    return std::nullopt;
                }

                const auto scaled = scale_constant(expr->x, expr->y->numval());
                return scaled.has_value()
                    ? checked_sval_sub(*left, *scaled)
                    : std::nullopt;
            }

            case cot_memptr:
            case cot_memref: {
                auto base = resolve_delta(expr->x);
                if (!base.has_value()) {
                    return std::nullopt;
                }
                const auto member = checked_sval_from_u64(expr->m);
                return member.has_value()
                    ? checked_sval_add(*base, *member)
                    : std::nullopt;
            }

            default:
                return std::nullopt;
        }
    }

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
            if (existing.offset != access.offset || existing.size != access.size ||
                !field_access_evidence_compatible(existing, access)) {
                continue;
            }

            merge_field_access_evidence(existing, access);

            return false;
        }

        merged_accesses_.push_back(std::move(access));
        return true;
    }

    [[nodiscard]] bool merge_function_delta(ea_t func_ea, sval_t delta) {
        auto it = function_deltas_.find(func_ea);
        if (it == function_deltas_.end()) {
            function_deltas_.emplace(func_ea, delta);
            return true;
        }

        if (it->second == delta) {
            return false;
        }

        if (it->second != 0 && delta == 0) {
            it->second = 0;
            return true;
        }

        return false;
    }

    [[nodiscard]] bool merge_function_var_index(ea_t func_ea, int var_idx) {
        if (var_idx < 0) {
            return false;
        }

        auto it = function_var_indices_.find(func_ea);
        if (it == function_var_indices_.end()) {
            function_var_indices_.emplace(func_ea, var_idx);
            return true;
        }

        if (it->second == var_idx) {
            return false;
        }

        return false;
    }

    [[nodiscard]] bool merge_flow_edge(const PointerFlowEdge& edge) {
        for (const auto& existing : flow_edges_) {
            if (existing.caller_ea == edge.caller_ea &&
                existing.callee_ea == edge.callee_ea &&
                existing.call_site == edge.call_site &&
                existing.caller_var_idx == edge.caller_var_idx &&
                existing.callee_param_idx == edge.callee_param_idx &&
                existing.delta == edge.delta) {
                return false;
            }
        }

        flow_edges_.push_back(edge);
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

        RootVarUsageScanner scanner(var_idx);
        scanner.apply_to(&cfunc->body, nullptr);

        bool progress = false;
        for (const auto& [alias_ea, delta] : scanner.result().pointer_alias_globals) {
            const auto total_delta = checked_sval_add(actual_delta, delta);
            if (!total_delta.has_value() || *total_delta < 0) {
                continue;
            }

            auto [it, inserted] = pointer_alias_globals_.emplace(alias_ea, *total_delta);
            if (inserted) {
                progress = true;
            }
        }

        if (scanner.result().return_delta.has_value()) {
            const auto total_delta = checked_sval_add(
                actual_delta, *scanner.result().return_delta);
            if (total_delta.has_value() && *total_delta >= 0) {
                auto [it, inserted] = source_returners_.emplace(func_ea, *total_delta);
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
        // Preserve every attempted local scan, including an empty result.
        // These sites belong to the local ctree, independently of seed deltas.
        for (const auto& diagnostic : unified.flow_diagnostics)
            flow_diagnostics_.push_back(diagnostic);

        bool progress = false;
        for (const auto& [seed_func_ea, delta] : unified.function_deltas) {
            const auto total = checked_sval_add(seed_delta, delta);
            if (total.has_value()) {
                progress |= merge_function_delta(seed_func_ea, *total);
            }
        }

        for (const auto& fn_pattern : unified.per_function_patterns) {
            progress |= merge_function_var_index(fn_pattern.func_ea, fn_pattern.var_idx);
        }

        for (const auto& edge : unified.flow_edges) {
            progress |= merge_flow_edge(edge);
        }

        for (const auto& access : unified.all_accesses) {
            FieldAccess normalized = access;
            const auto offset = checked_sval_add(normalized.offset, seed_delta);
            if (offset.has_value()) {
                normalized.offset = *offset;
                progress |= merge_access(std::move(normalized));
            }
        }

        for (const auto& fv : analyzer.equivalence_class().variables) {
            const auto actual_delta = checked_sval_add(
                seed_delta, fv.base_delta);
            if (!actual_delta.has_value()) {
                continue;
            }
            if (*actual_delta == 0) {
                progress |= add_zero_delta_variable(fv);
            }
            progress |= scan_var_usage(fv.func_ea, fv.var_idx, *actual_delta);
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
        progress |= merge_function_delta(func_ea, 0);
        for (const auto& access : scanner.result().direct_accesses) {
            progress |= merge_access(access);
        }

        for (const auto& edge : scanner.result().flow_edges) {
            progress |= merge_flow_edge(edge);
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
        pattern.flow_diagnostics = flow_diagnostics_;
        qvector<FieldAccess> bounded_accesses;
        bounded_accesses.reserve(merged_accesses_.size());
        for (auto& access : merged_accesses_) {
            if (checked_interval_end(access.offset, access.size).has_value()) {
                bounded_accesses.push_back(std::move(access));
            }
        }
        merged_accesses_ = std::move(bounded_accesses);
        if (merged_accesses_.empty()) {
            return pattern;
        }

        std::sort(merged_accesses_.begin(), merged_accesses_.end(),
                  canonical_field_access_less);

        pattern.all_accesses = merged_accesses_;
        pattern.global_min_offset = merged_accesses_.front().offset;
        pattern.global_max_offset = *checked_interval_end(
            merged_accesses_.front().offset,
            merged_accesses_.front().size);

        std::unordered_map<ea_t, std::size_t> per_func_indices;
        for (const auto& access : merged_accesses_) {
            pattern.global_min_offset = std::min(pattern.global_min_offset, access.offset);
            const auto access_end = checked_interval_end(
                access.offset, access.size);
            if (access_end.has_value()) {
                pattern.global_max_offset = std::max(
                    pattern.global_max_offset, *access_end);
            }

            if (access.is_vtable_access) {
                pattern.has_vtable = true;
                pattern.vtable_offset = access.offset;
            }

            auto [it, inserted] = per_func_indices.emplace(access.source_func_ea, pattern.per_function_patterns.size());
            if (inserted) {
                AccessPattern fn_pattern;
                fn_pattern.func_ea = access.source_func_ea;
                fn_pattern.var_name = root_name_;
                auto var_it = function_var_indices_.find(access.source_func_ea);
                fn_pattern.var_idx = var_it != function_var_indices_.end() ? var_it->second : -1;
                pattern.per_function_patterns.push_back(std::move(fn_pattern));
                pattern.contributing_functions.push_back(access.source_func_ea);
                auto delta_it = function_deltas_.find(access.source_func_ea);
                pattern.function_deltas[access.source_func_ea] =
                    delta_it != function_deltas_.end() ? delta_it->second : 0;
            }

            AccessPattern& fn_pattern = pattern.per_function_patterns[it->second];
            fn_pattern.add_access(FieldAccess(access));
        }

        for (auto& fn_pattern : pattern.per_function_patterns) {
            fn_pattern.sort_by_offset();
        }

        std::unordered_set<ea_t> contributing(pattern.contributing_functions.begin(),
                                              pattern.contributing_functions.end());
        for (const auto& edge : flow_edges_) {
            if (!contributing.contains(edge.caller_ea) || !contributing.contains(edge.callee_ea)) {
                continue;
            }
            pattern.flow_edges.push_back(edge);
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
    qvector<FlowAnalysisDiagnostic> flow_diagnostics_;
    std::unordered_set<VarKey, VarKeyHash> zero_delta_variables_;
    std::unordered_set<VarKey, VarKeyHash> var_usage_scanned_;
    std::unordered_map<ea_t, sval_t> function_deltas_;
    std::unordered_map<ea_t, int> function_var_indices_;
    qvector<PointerFlowEdge> flow_edges_;
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

struct ResolvedFieldRef {
    const SynthField* field = nullptr;
    bool is_array_element = false;
    uint32_t array_index = 0;
    tinfo_t element_type;

    [[nodiscard]] bool valid() const noexcept {
        return field != nullptr;
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

[[nodiscard]] static ResolvedFieldRef find_field_ref(
    const RegisteredGlobalRewrite& entry,
    sval_t offset)
{
    if (const SynthField* field = find_exact_field(entry, offset)) {
        return ResolvedFieldRef{field, false, 0, field->type};
    }

    for (const auto& field : entry.structure.fields) {
        if (field.is_padding || !field.is_array || offset < field.offset) {
            continue;
        }

        const sval_t rel = offset - field.offset;
        if (rel < 0 || rel >= static_cast<sval_t>(field.size)) {
            continue;
        }

        array_type_data_t atd;
        if (!field.type.is_array() || !field.type.get_array_details(&atd)) {
            continue;
        }

        const size_t elem_size = atd.elem_type.get_size();
        if (elem_size == BADSIZE || elem_size == 0 || rel % static_cast<sval_t>(elem_size) != 0) {
            continue;
        }

        const uint32_t index = static_cast<uint32_t>(rel / static_cast<sval_t>(elem_size));
        if (index >= static_cast<uint32_t>(atd.nelems)) {
            continue;
        }

        if (atd.elem_type.is_array() || atd.elem_type.is_struct() || atd.elem_type.is_union()) {
            continue;
        }

        return ResolvedFieldRef{&field, true, index, atd.elem_type};
    }

    return {};
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
                    const auto delta = checked_ea_delta(
                        expr->obj_ea, entry->root_ea);
                    if (!delta.has_value()) {
                        return result;
                    }
                    result.entry = entry;
                    result.through_pointer = false;
                    result.obj_ea = entry->root_ea;
                    result.offset = *delta;
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
                    const auto scaled = scale_constant(expr->x, expr->y->numval());
                    const auto offset = scaled.has_value()
                        ? checked_sval_add(left.offset, *scaled)
                        : std::nullopt;
                    if (!offset.has_value()) return result;
                    left.offset = *offset;
                    return left;
                }

                ResolvedGlobalExpr right = resolve_expr(expr->y);
                if (right.valid() && expr->x && expr->x->op == cot_num) {
                    const auto scaled = scale_constant(expr->y, expr->x->numval());
                    const auto offset = scaled.has_value()
                        ? checked_sval_add(right.offset, *scaled)
                        : std::nullopt;
                    if (!offset.has_value()) return result;
                    right.offset = *offset;
                    return right;
                }

                return result;
            }

            case cot_sub: {
                ResolvedGlobalExpr left = resolve_expr(expr->x);
                if (left.valid() && expr->y && expr->y->op == cot_num) {
                    const auto scaled = scale_constant(expr->x, expr->y->numval());
                    const auto offset = scaled.has_value()
                        ? checked_sval_sub(left.offset, *scaled)
                        : std::nullopt;
                    if (!offset.has_value()) return result;
                    left.offset = *offset;
                    return left;
                }
                return result;
            }

            case cot_idx: {
                ResolvedGlobalExpr base = resolve_expr(expr->x);
                if (!base.valid() || !expr->y || expr->y->op != cot_num) {
                    return result;
                }
                const auto scaled = scale_constant(expr->x, expr->y->numval());
                const auto offset = scaled.has_value()
                    ? checked_sval_add(base.offset, *scaled)
                    : std::nullopt;
                if (!offset.has_value()) return result;
                base.offset = *offset;
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

    [[nodiscard]] cexpr_t* make_field_expr(const ResolvedGlobalExpr& resolved,
                                           const SynthField& field,
                                           ea_t ea) const {
        cexpr_t* replacement = new cexpr_t();
        replacement->op = resolved.through_pointer ? cot_memptr : cot_memref;
        replacement->ea = ea;
        replacement->x = make_obj_expr(
            resolved.obj_ea,
            resolved.through_pointer ? resolved.entry->ptr_type : resolved.entry->struct_type,
            ea);
        replacement->m = static_cast<uint32>(field.offset);
        replacement->ptrsize = get_ptr_size();
        replacement->type = field.type;
        replacement->calc_type(false);
        return replacement;
    }

    void rewrite_dereference(cexpr_t* expr) {
        if (!expr || !expr->x) {
            return;
        }

        const ResolvedGlobalExpr resolved = resolve_expr(expr->x);
        if (!resolved.valid()) {
            return;
        }

        const ResolvedFieldRef field_ref = find_field_ref(*resolved.entry, resolved.offset);
        if (!field_ref.valid()) {
            return;
        }

        if (Config::instance().options().debug_mode) {
            qstring before = utils::expr_to_string(expr, cfunc_);
            msg("Structor: rewriting global deref in 0x%llX: %s -> %s%s at offset 0x%llX\n",
                static_cast<unsigned long long>(cfunc_->entry_ea),
                before.c_str(),
                resolved.entry->root_name.c_str(),
                resolved.through_pointer ? "->" : ".",
                static_cast<unsigned long long>(field_ref.field->offset));
        }

        cexpr_t* replacement = make_field_expr(resolved, *field_ref.field, expr->ea);
        if (field_ref.is_array_element) {
            cexpr_t* index_expr = new cexpr_t();
            index_expr->ea = expr->ea;
            index_expr->put_number(cfunc_, field_ref.array_index, 4);

            cexpr_t* element_expr = new cexpr_t();
            element_expr->op = cot_idx;
            element_expr->ea = expr->ea;
            element_expr->x = replacement;
            element_expr->y = index_expr;
            element_expr->type = field_ref.element_type;
            element_expr->calc_type(false);
            replacement = element_expr;
        }

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
    if (!global_rewrite_thread_is_valid() ||
        analysis.root_ea == BADADDR || synth_struct.fields.empty() || struct_type.empty()) {
        return;
    }
    GlobalRewriteRegistry::instance().register_entry(analysis, synth_struct, struct_type);
}

bool rewrite_registered_global_uses(cfunc_t* cfunc) {
    if (!global_rewrite_thread_is_valid() || !cfunc) {
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
    if (!global_rewrite_thread_is_valid()) {
        return;
    }
    GlobalRewriteRegistry::instance().clear();
}

} // namespace structor
