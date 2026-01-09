#include "structor/z3/constraint_tracker.hpp"
#include <sstream>

namespace structor::z3 {

ConstraintTracker::ConstraintTracker(::z3::context& ctx)
    : ctx_(ctx) {
}

std::string ConstraintTracker::make_tracking_name(unsigned id) const {
    std::ostringstream ss;
    ss << "__track_" << id;
    return ss.str();
}

::z3::expr ConstraintTracker::make_tracking_literal(unsigned id) {
    std::string name = make_tracking_name(id);
    ::z3::expr lit = ctx_.bool_const(name.c_str());
    tracking_exprs_.push_back(lit);
    expr_to_id_[lit.to_string()] = id;
    return lit;
}

::z3::expr ConstraintTracker::add_tracked(
    ::z3::solver& solver,
    const ::z3::expr& constraint,
    const ConstraintProvenance& provenance)
{
    unsigned id = next_id_++;
    provenance_map_[id] = provenance;

    ::z3::expr tracking_lit = make_tracking_literal(id);

    // Create implication: tracking_lit => constraint
    // When tracking_lit is true (assumed), constraint must hold
    // When tracking_lit is false (not assumed), constraint is vacuously satisfied
    ::z3::expr guarded_constraint = ::z3::implies(tracking_lit, constraint);
    
    // Add the guarded constraint as a regular assertion
    // The constraint is activated by assuming tracking_lit during check()
    solver.add(guarded_constraint);

    if (provenance.is_soft) {
        soft_constraint_ids_.push_back(id);
    } else {
        hard_constraint_ids_.push_back(id);
    }

    return tracking_lit;
}

void ConstraintTracker::add_hard(
    ::z3::solver& solver,
    const ::z3::expr& constraint,
    const ConstraintProvenance& provenance)
{
    ConstraintProvenance hard_prov = provenance;
    hard_prov.is_soft = false;

    add_tracked(solver, constraint, hard_prov);
}

void ConstraintTracker::add_soft(
    ::z3::solver& solver,
    const ::z3::expr& constraint,
    const ConstraintProvenance& provenance,
    int weight)
{
    ConstraintProvenance soft_prov = provenance;
    soft_prov.is_soft = true;
    soft_prov.weight = weight;

    add_tracked(solver, constraint, soft_prov);
}

void ConstraintTracker::add_to_optimizer(
    ::z3::optimize& opt,
    const ::z3::expr& constraint,
    const ConstraintProvenance& provenance)
{
    unsigned id = next_id_++;
    provenance_map_[id] = provenance;

    // Add as hard constraint to optimizer
    opt.add(constraint);

    hard_constraint_ids_.push_back(id);
}

void ConstraintTracker::add_soft_to_optimizer(
    ::z3::optimize& opt,
    const ::z3::expr& constraint,
    const ConstraintProvenance& provenance,
    unsigned weight)
{
    unsigned id = next_id_++;
    ConstraintProvenance soft_prov = provenance;
    soft_prov.is_soft = true;
    soft_prov.weight = static_cast<int>(weight);
    provenance_map_[id] = soft_prov;

    // Add as soft constraint with weight
    opt.add(constraint, weight);

    soft_constraint_ids_.push_back(id);
}

qvector<ConstraintProvenance> ConstraintTracker::analyze_unsat_core(
    const ::z3::expr_vector& core) const
{
    qvector<ConstraintProvenance> result;

    for (unsigned i = 0; i < core.size(); ++i) {
        std::string expr_str = core[i].to_string();

        auto it = expr_to_id_.find(expr_str);
        if (it != expr_to_id_.end()) {
            auto prov_it = provenance_map_.find(it->second);
            if (prov_it != provenance_map_.end()) {
                // Copy provenance and add the tracking literal
                ConstraintProvenance prov = prov_it->second;
                prov.tracking_literal = core[i];
                result.push_back(std::move(prov));
            }
        }
    }

    return result;
}

::z3::expr_vector ConstraintTracker::get_soft_literals() const {
    ::z3::expr_vector result(ctx_);

    for (unsigned id : soft_constraint_ids_) {
        if (id < tracking_exprs_.size()) {
            result.push_back(tracking_exprs_[id]);
        }
    }

    return result;
}

::z3::expr_vector ConstraintTracker::get_hard_literals() const {
    ::z3::expr_vector result(ctx_);

    for (unsigned id : hard_constraint_ids_) {
        if (id < tracking_exprs_.size()) {
            result.push_back(tracking_exprs_[id]);
        }
    }

    return result;
}

::z3::expr_vector ConstraintTracker::get_all_literals() const {
    ::z3::expr_vector result(ctx_);

    // Add all tracking literals (both hard and soft)
    for (const auto& expr : tracking_exprs_) {
        result.push_back(expr);
    }

    return result;
}

const ConstraintProvenance* ConstraintTracker::get_provenance(
    const ::z3::expr& tracking_lit) const
{
    std::string expr_str = tracking_lit.to_string();
    auto it = expr_to_id_.find(expr_str);
    if (it == expr_to_id_.end()) {
        return nullptr;
    }

    auto prov_it = provenance_map_.find(it->second);
    if (prov_it == provenance_map_.end()) {
        return nullptr;
    }

    return &prov_it->second;
}

const ConstraintProvenance* ConstraintTracker::get_provenance_by_id(unsigned id) const {
    auto it = provenance_map_.find(id);
    if (it == provenance_map_.end()) {
        return nullptr;
    }
    return &it->second;
}

qvector<ConstraintProvenance> ConstraintTracker::get_by_kind(
    ConstraintProvenance::Kind kind) const
{
    qvector<ConstraintProvenance> result;

    for (const auto& [id, prov] : provenance_map_) {
        if (prov.kind == kind) {
            result.push_back(prov);
        }
    }

    return result;
}

void ConstraintTracker::clear() {
    provenance_map_.clear();
    expr_to_id_.clear();
    hard_constraint_ids_.clear();
    soft_constraint_ids_.clear();
    tracking_exprs_.clear();
    next_id_ = 0;
}

qstring ConstraintTracker::generate_report() const {
    qstring report;

    report.sprnt("Constraint Tracking Report\n");
    report.append("==========================\n\n");
    report.cat_sprnt("Total constraints: %zu\n", provenance_map_.size());
    report.cat_sprnt("  Hard: %zu\n", hard_constraint_ids_.size());
    report.cat_sprnt("  Soft: %zu\n", soft_constraint_ids_.size());
    report.append("\n");

    // Group by kind
    std::unordered_map<int, int> kind_counts;
    for (const auto& [id, prov] : provenance_map_) {
        kind_counts[static_cast<int>(prov.kind)]++;
    }

    report.append("By kind:\n");
    const char* kind_names[] = {
        "Coverage", "NonOverlap", "Alignment", "TypeMatch",
        "SizeMatch", "ArrayDetection", "Other"
    };
    for (const auto& [kind, count] : kind_counts) {
        if (kind >= 0 && kind < 7) {
            report.cat_sprnt("  %s: %d\n", kind_names[kind], count);
        }
    }
    report.append("\n");

    // List all constraints
    report.append("All constraints:\n");
    for (const auto& [id, prov] : provenance_map_) {
        report.cat_sprnt("  [%u] %s%s (weight=%d)\n",
                         id,
                         prov.description.c_str(),
                         prov.is_soft ? " [SOFT]" : "",
                         prov.weight);
        if (prov.func_ea != BADADDR) {
            report.cat_sprnt("       func=0x%llX",
                            static_cast<unsigned long long>(prov.func_ea));
            if (prov.insn_ea != BADADDR) {
                report.cat_sprnt(" insn=0x%llX",
                                static_cast<unsigned long long>(prov.insn_ea));
            }
            report.append("\n");
        }
    }

    return report;
}

} // namespace structor::z3
