#include "structor/z3/alias_analysis.hpp"
#include "structor/z3/context.hpp"
#include "structor/optimized_algorithms.hpp"
#include "structor/optimized_containers.hpp"
#include <algorithm>
#include <functional>

#ifndef STRUCTOR_TESTING
#include <pro.h>
#include <kernwin.hpp>
#include <bytes.hpp>
#include <name.hpp>
#endif

namespace structor::z3 {

// ============================================================================
// AbstractLocation implementation
// ============================================================================

AbstractLocation AbstractLocation::stack(ea_t func_ea, int var_idx) {
    AbstractLocation loc;
    loc.kind = Kind::Stack;
    loc.func_ea = func_ea;
    loc.var_idx = var_idx;
    return loc;
}

AbstractLocation AbstractLocation::heap(ea_t alloc_site) {
    AbstractLocation loc;
    loc.kind = Kind::Heap;
    loc.allocation_site = alloc_site;
    return loc;
}

AbstractLocation AbstractLocation::global(ea_t addr) {
    AbstractLocation loc;
    loc.kind = Kind::Global;
    loc.global_addr = addr;
    return loc;
}

AbstractLocation AbstractLocation::parameter(ea_t func_ea, int param_idx) {
    AbstractLocation loc;
    loc.kind = Kind::Parameter;
    loc.func_ea = func_ea;
    loc.var_idx = param_idx;
    return loc;
}

AbstractLocation AbstractLocation::unknown() {
    AbstractLocation loc;
    loc.kind = Kind::Unknown;
    return loc;
}

AbstractLocation AbstractLocation::at_offset(sval_t off, uint32_t sz) const {
    AbstractLocation derived = *this;
    
    // Combine with existing offset if present
    if (derived.offset.has_value()) {
        derived.offset = *derived.offset + off;
    } else {
        derived.offset = off;
    }
    derived.size = sz;
    
    return derived;
}

bool AbstractLocation::may_alias(const AbstractLocation& other) const {
    // Unknown may alias with anything
    if (kind == Kind::Unknown || other.kind == Kind::Unknown) {
        return true;
    }
    
    // Different kinds typically don't alias (with some exceptions)
    if (kind != other.kind) {
        // Parameters may alias with heap (passed-in pointers)
        if ((kind == Kind::Parameter && other.kind == Kind::Heap) ||
            (kind == Kind::Heap && other.kind == Kind::Parameter)) {
            return true;
        }
        // Globals may alias with heap in some cases
        if ((kind == Kind::Global && other.kind == Kind::Heap) ||
            (kind == Kind::Heap && other.kind == Kind::Global)) {
            return true;
        }
        return false;
    }
    
    // Same kind - check specific identifiers
    switch (kind) {
        case Kind::Stack:
            // Stack variables alias if same function and same variable
            // or if offsets overlap
            if (func_ea != other.func_ea) return false;
            if (var_idx != other.var_idx) return false;
            // Check field-sensitive overlap
            if (offset.has_value() && other.offset.has_value() && 
                size.has_value() && other.size.has_value()) {
                sval_t end1 = *offset + static_cast<sval_t>(*size);
                sval_t end2 = *other.offset + static_cast<sval_t>(*other.size);
                if (end1 <= *other.offset || end2 <= *offset) {
                    return false;  // Non-overlapping fields
                }
            }
            return true;
            
        case Kind::Heap:
            // Different allocation sites don't alias
            if (allocation_site != BADADDR && other.allocation_site != BADADDR &&
                allocation_site != other.allocation_site) {
                return false;
            }
            return true;
            
        case Kind::Global:
            // Different global addresses don't alias
            if (global_addr != BADADDR && other.global_addr != BADADDR &&
                global_addr != other.global_addr) {
                // Check for overlap if we have sizes
                if (size.has_value() && other.size.has_value()) {
                    ea_t end1 = global_addr + *size;
                    ea_t end2 = other.global_addr + *other.size;
                    if (end1 <= other.global_addr || end2 <= global_addr) {
                        return false;
                    }
                } else {
                    return false;
                }
            }
            return true;
            
        case Kind::Parameter:
            // Different parameters in same function don't alias
            if (func_ea == other.func_ea && var_idx != other.var_idx) {
                return false;
            }
            return true;
            
        case Kind::Unknown:
            return true;
    }
    
    return true;
}

bool AbstractLocation::must_alias(const AbstractLocation& other) const {
    // Unknown never must-alias
    if (kind == Kind::Unknown || other.kind == Kind::Unknown) {
        return false;
    }
    
    // Different kinds cannot must-alias
    if (kind != other.kind) {
        return false;
    }
    
    switch (kind) {
        case Kind::Stack:
            if (func_ea != other.func_ea || var_idx != other.var_idx) {
                return false;
            }
            // Must be same offset/size for must-alias
            if (offset != other.offset) return false;
            return true;
            
        case Kind::Heap:
            // Different allocation sites
            if (allocation_site == BADADDR || other.allocation_site == BADADDR) {
                return false;
            }
            if (allocation_site != other.allocation_site) return false;
            if (offset != other.offset) return false;
            return true;
            
        case Kind::Global:
            if (global_addr == BADADDR || other.global_addr == BADADDR) {
                return false;
            }
            if (global_addr != other.global_addr) return false;
            if (offset != other.offset) return false;
            return true;
            
        case Kind::Parameter:
            if (func_ea != other.func_ea || var_idx != other.var_idx) {
                return false;
            }
            if (offset != other.offset) return false;
            return true;
            
        case Kind::Unknown:
            return false;
    }
    
    return false;
}

bool AbstractLocation::operator==(const AbstractLocation& other) const {
    if (kind != other.kind) return false;
    if (func_ea != other.func_ea) return false;
    if (allocation_site != other.allocation_site) return false;
    if (global_addr != other.global_addr) return false;
    if (var_idx != other.var_idx) return false;
    if (offset != other.offset) return false;
    if (size != other.size) return false;
    return true;
}

std::size_t AbstractLocation::hash() const noexcept {
    std::size_t h = std::hash<int>{}(static_cast<int>(kind));
    h ^= std::hash<ea_t>{}(func_ea) << 1;
    h ^= std::hash<ea_t>{}(allocation_site) << 2;
    h ^= std::hash<ea_t>{}(global_addr) << 3;
    h ^= std::hash<int>{}(var_idx) << 4;
    if (offset.has_value()) {
        h ^= std::hash<sval_t>{}(*offset) << 5;
    }
    if (size.has_value()) {
        h ^= std::hash<uint32_t>{}(*size) << 6;
    }
    return h;
}

qstring AbstractLocation::to_string() const {
    qstring result;
    
    switch (kind) {
        case Kind::Stack:
            result.sprnt("stack[%llX:v%d", 
                        static_cast<unsigned long long>(func_ea),
                        var_idx);
            break;
        case Kind::Heap:
            result.sprnt("heap[%llX", 
                        static_cast<unsigned long long>(allocation_site));
            break;
        case Kind::Global:
            result.sprnt("global[%llX", 
                        static_cast<unsigned long long>(global_addr));
            break;
        case Kind::Parameter:
            result.sprnt("param[%llX:p%d", 
                        static_cast<unsigned long long>(func_ea),
                        var_idx);
            break;
        case Kind::Unknown:
            result = "unknown[";
            break;
    }
    
    if (offset.has_value()) {
        result.cat_sprnt("+%llX", static_cast<unsigned long long>(*offset));
    }
    if (size.has_value()) {
        result.cat_sprnt(":%u", *size);
    }
    result += "]";
    
    return result;
}

// ============================================================================
// UnionFind implementation
// ============================================================================

int UnionFind::find(int x) {
    ensure(x);
    
    // Path compression: make all nodes point directly to root
    if (parent_[x] != x) {
        parent_[x] = find(parent_[x]);
    }
    return parent_[x];
}

void UnionFind::unite(int x, int y) {
    int root_x = find(x);
    int root_y = find(y);
    
    if (root_x == root_y) {
        return;  // Already in same set
    }
    
    // Union by rank: attach smaller tree under root of larger tree
    if (rank_[root_x] < rank_[root_y]) {
        parent_[root_x] = root_y;
    } else if (rank_[root_x] > rank_[root_y]) {
        parent_[root_y] = root_x;
    } else {
        // Same rank: arbitrarily pick one and increment its rank
        parent_[root_y] = root_x;
        rank_[root_x]++;
    }
}

bool UnionFind::same_set(int x, int y) {
    return find(x) == find(y);
}

std::vector<int> UnionFind::get_set(int x) {
    std::vector<int> result;
    int root = find(x);
    
    for (const auto& [elem, parent] : parent_) {
        if (find(elem) == root) {
            result.push_back(elem);
        }
    }
    
    return result;
}

void UnionFind::ensure(int x) {
    if (parent_.find(x) == parent_.end()) {
        parent_[x] = x;
        rank_[x] = 0;
    }
}

// ============================================================================
// SteensgaardAliasAnalyzer implementation
// ============================================================================

SteensgaardAliasAnalyzer::SteensgaardAliasAnalyzer(Z3Context& ctx)
    : ctx_(ctx)
{}

void SteensgaardAliasAnalyzer::analyze(cfunc_t* cfunc) {
    if (!cfunc || !cfunc->body.cblock) {
        return;
    }
    
    // Visitor to process all expressions in the function
    struct AliasVisitor : public ctree_visitor_t {
        SteensgaardAliasAnalyzer& analyzer;
        cfunc_t* cfunc;
        
        AliasVisitor(SteensgaardAliasAnalyzer& a, cfunc_t* cf) 
            : ctree_visitor_t(CV_FAST), analyzer(a), cfunc(cf) {}
        
        int idaapi visit_expr(cexpr_t* e) override {
            analyzer.analyze_expr(e, cfunc);
            return 0;  // Continue visiting
        }
    };
    
    AliasVisitor visitor(*this, cfunc);
    visitor.apply_to(&cfunc->body, nullptr);
}

void SteensgaardAliasAnalyzer::process_assignment(int dst_id, int src_id) {
    // Steensgaard: assignment unifies the types/alias sets
    // dst = src  =>  unite(dst, src)
    union_find_.unite(dst_id, src_id);
}

void SteensgaardAliasAnalyzer::process_load(int dst_id, int ptr_id) {
    // dst = *ptr  =>  unite(dst, deref(ptr))
    int deref_id = get_deref_id(ptr_id);
    union_find_.unite(dst_id, deref_id);
}

void SteensgaardAliasAnalyzer::process_store(int ptr_id, int src_id) {
    // *ptr = src  =>  unite(deref(ptr), src)
    int deref_id = get_deref_id(ptr_id);
    union_find_.unite(deref_id, src_id);
}

void SteensgaardAliasAnalyzer::process_address_of(int dst_id, int loc_id) {
    // dst = &loc  =>  unite(deref(dst), loc)
    // Because dst now points to loc, dereferencing dst gives loc
    int deref_dst = get_deref_id(dst_id);
    union_find_.unite(deref_dst, loc_id);
}

bool SteensgaardAliasAnalyzer::may_alias(int var1_id, int var2_id) {
    // Two variables may alias if they're in the same equivalence class
    return union_find_.same_set(var1_id, var2_id);
}

std::vector<int> SteensgaardAliasAnalyzer::get_alias_set(int var_id) {
    return union_find_.get_set(var_id);
}

int SteensgaardAliasAnalyzer::get_location_id(const AbstractLocation& loc) {
    auto it = loc_to_id_.find(loc);
    if (it != loc_to_id_.end()) {
        return it->second;
    }
    
    int id = next_id_++;
    loc_to_id_[loc] = id;
    id_to_loc_[id] = loc;
    union_find_.ensure(id);
    
    return id;
}

std::optional<AbstractLocation> SteensgaardAliasAnalyzer::get_location(int id) const {
    auto it = id_to_loc_.find(id);
    if (it != id_to_loc_.end()) {
        return it->second;
    }
    return std::nullopt;
}

int SteensgaardAliasAnalyzer::get_deref_id(int ptr_id) {
    auto it = deref_.find(ptr_id);
    if (it != deref_.end()) {
        return it->second;
    }
    
    // Create a fresh "deref" node for this pointer
    int deref_id = next_id_++;
    deref_[ptr_id] = deref_id;
    union_find_.ensure(deref_id);
    
    return deref_id;
}

int SteensgaardAliasAnalyzer::analyze_expr(cexpr_t* expr, cfunc_t* cfunc) {
    if (!expr) return -1;
    
    switch (expr->op) {
        case cot_var: {
            // Local variable reference
            AbstractLocation loc = AbstractLocation::stack(cfunc->entry_ea, expr->v.idx);
            return get_location_id(loc);
        }
        
        case cot_obj: {
            // Global/static object reference
            AbstractLocation loc = AbstractLocation::global(expr->obj_ea);
            return get_location_id(loc);
        }
        
        case cot_ref: {
            // Address-of: &x
            if (expr->x) {
                int operand_id = analyze_expr(expr->x, cfunc);
                if (operand_id >= 0) {
                    // Create a location for the address-of result
                    AbstractLocation addr_loc = AbstractLocation::unknown();
                    int addr_id = get_location_id(addr_loc);
                    process_address_of(addr_id, operand_id);
                    return addr_id;
                }
            }
            break;
        }
        
        case cot_ptr: {
            // Pointer dereference: *p
            if (expr->x) {
                int ptr_id = analyze_expr(expr->x, cfunc);
                if (ptr_id >= 0) {
                    return get_deref_id(ptr_id);
                }
            }
            break;
        }
        
        case cot_asg: {
            // Assignment: dst = src
            if (expr->x && expr->y) {
                int dst_id = analyze_expr(expr->x, cfunc);
                int src_id = analyze_expr(expr->y, cfunc);
                
                if (dst_id >= 0 && src_id >= 0) {
                    // Check if this is a store (*p = x) or regular assignment
                    if (expr->x->op == cot_ptr && expr->x->x) {
                        // Store through pointer
                        int ptr_id = analyze_expr(expr->x->x, cfunc);
                        if (ptr_id >= 0) {
                            process_store(ptr_id, src_id);
                        }
                    } else if (expr->y->op == cot_ptr && expr->y->x) {
                        // Load through pointer
                        int ptr_id = analyze_expr(expr->y->x, cfunc);
                        if (ptr_id >= 0) {
                            process_load(dst_id, ptr_id);
                        }
                    } else {
                        // Direct assignment
                        process_assignment(dst_id, src_id);
                    }
                }
                return dst_id;
            }
            break;
        }
        
        case cot_call: {
            // Function call - handle return value and arguments
            // For now, create unknown location for return value
            AbstractLocation ret_loc = AbstractLocation::unknown();
            int ret_id = get_location_id(ret_loc);
            
            // Process arguments - they may affect aliasing
            if (expr->a) {
                for (size_t i = 0; i < expr->a->size(); ++i) {
                    cexpr_t* arg = &(*expr->a)[i];
                    int arg_id = analyze_expr(arg, cfunc);
                    // Arguments passed to functions may create new aliases
                    // (conservative: assume function can do anything with pointers)
                    if (arg_id >= 0 && arg->type.is_ptr()) {
                        // The function might store to or through this pointer
                        // Unite with unknown to be conservative
                        AbstractLocation unknown_loc = AbstractLocation::unknown();
                        int unknown_id = get_location_id(unknown_loc);
                        int deref_id = get_deref_id(arg_id);
                        union_find_.unite(deref_id, unknown_id);
                    }
                }
            }
            return ret_id;
        }
        
        case cot_memptr:
        case cot_memref: {
            // Member access through pointer: p->field or p.field
            if (expr->x) {
                int base_id = analyze_expr(expr->x, cfunc);
                if (base_id >= 0) {
                    // Field access at specific offset
                    auto base_loc = get_location(base_id);
                    if (base_loc.has_value()) {
                        uint32_t field_size = 0;
                        if (!expr->type.empty()) {
                            size_t sz = expr->type.get_size();
                            if (sz != BADSIZE) {
                                field_size = static_cast<uint32_t>(sz);
                            }
                        }
                        AbstractLocation field_loc = base_loc->at_offset(expr->m, field_size);
                        return get_location_id(field_loc);
                    }
                    // Fall through to deref for pointer case
                    if (expr->op == cot_memptr) {
                        return get_deref_id(base_id);
                    }
                }
            }
            break;
        }
        
        case cot_idx: {
            // Array index: arr[i]
            if (expr->x) {
                int base_id = analyze_expr(expr->x, cfunc);
                if (base_id >= 0) {
                    // Array access - treat as dereference
                    return get_deref_id(base_id);
                }
            }
            break;
        }
        
        case cot_num:
        case cot_fnum:
        case cot_str: {
            // Constants - create unique locations
            AbstractLocation const_loc = AbstractLocation::unknown();
            return get_location_id(const_loc);
        }
        
        case cot_add:
        case cot_sub: {
            // Pointer arithmetic - propagate aliasing
            if (expr->x && expr->y) {
                int lhs_id = analyze_expr(expr->x, cfunc);
                analyze_expr(expr->y, cfunc);  // Process RHS for side effects
                // Result aliases with base pointer (for add/sub to pointer)
                if (lhs_id >= 0 && expr->x->type.is_ptr()) {
                    return lhs_id;
                }
            }
            break;
        }
        
        case cot_cast: {
            // Cast - propagate aliasing through casts
            if (expr->x) {
                return analyze_expr(expr->x, cfunc);
            }
            break;
        }
        
        default:
            // For other expressions, recursively process operands
            if (expr->x) analyze_expr(expr->x, cfunc);
            if (expr->y) analyze_expr(expr->y, cfunc);
            if (expr->z) analyze_expr(expr->z, cfunc);
            break;
    }
    
    // Default: return a fresh unknown location
    AbstractLocation unknown_loc = AbstractLocation::unknown();
    return get_location_id(unknown_loc);
}

qvector<TypeConstraint> SteensgaardAliasAnalyzer::generate_type_constraints(
    const std::unordered_map<int, TypeVariable>& var_types)
{
    qvector<TypeConstraint> constraints;
    
    // For each pair of aliasing variables, generate type equality constraints
    std::unordered_set<int> processed_roots;
    
    for (const auto& [var_id, type_var] : var_types) {
        int root = union_find_.find(var_id);
        
        if (processed_roots.count(root) > 0) {
            continue;
        }
        processed_roots.insert(root);
        
        // Get all variables in this alias set
        auto alias_set = union_find_.get_set(var_id);
        
        // Generate equality constraints between all aliasing variables
        TypeVariable* prev_type = nullptr;
        for (int alias_id : alias_set) {
            auto it = var_types.find(alias_id);
            if (it != var_types.end()) {
                if (prev_type) {
                    // Type equality for aliasing variables
                    constraints.push_back(
                        TypeConstraint::make_equal(*prev_type, it->second, BADADDR)
                            .sourced_from(TypeConstraintOrigin::AliasRelation)
                            .describe("aliasing variables have same type (Steensgaard)")
                    );
                }
                prev_type = const_cast<TypeVariable*>(&it->second);
            }
        }
    }
    
    return constraints;
}

// ============================================================================
// AndersenAliasAnalyzer implementation
// ============================================================================

AndersenAliasAnalyzer::AndersenAliasAnalyzer(Z3Context& ctx)
    : ctx_(ctx)
{}

void AndersenAliasAnalyzer::analyze(cfunc_t* cfunc) {
    if (!cfunc || !cfunc->body.cblock) {
        return;
    }
    
    // Phase 1: Build initial constraints from the ctree
    struct ConstraintCollector : public ctree_visitor_t {
        AndersenAliasAnalyzer& analyzer;
        cfunc_t* cfunc;
        int next_id = 0;
        std::unordered_map<int, int> var_to_id;  // var_idx -> location ID
        
        ConstraintCollector(AndersenAliasAnalyzer& a, cfunc_t* cf)
            : ctree_visitor_t(CV_FAST), analyzer(a), cfunc(cf) {}
        
        int get_var_id(int var_idx) {
            auto it = var_to_id.find(var_idx);
            if (it != var_to_id.end()) {
                return it->second;
            }
            int id = next_id++;
            var_to_id[var_idx] = id;
            return id;
        }
        
        int get_expr_id(cexpr_t* e) {
            if (e->op == cot_var) {
                return get_var_id(e->v.idx);
            }
            // For other expressions, create fresh ID
            return next_id++;
        }
        
        int idaapi visit_expr(cexpr_t* e) override {
            switch (e->op) {
                case cot_asg: {
                    // p = q: pts(p) ⊇ pts(q)
                    if (e->x && e->y) {
                        int dst = get_expr_id(e->x);
                        int src = get_expr_id(e->y);
                        
                        if (e->y->op == cot_ref && e->y->x) {
                            // p = &x: add x to pts(p)
                            int pointee = get_expr_id(e->y->x);
                            analyzer.points_to_[dst].insert(pointee);
                        } else if (e->y->op == cot_ptr && e->y->x) {
                            // p = *q: complex constraint - handled in solve()
                            int ptr = get_expr_id(e->y->x);
                            analyzer.constraints_.push_back({ptr, dst});
                        } else if (e->x->op == cot_ptr && e->x->x) {
                            // *p = q: complex constraint - handled in solve()
                            int ptr = get_expr_id(e->x->x);
                            analyzer.constraints_.push_back({src, ptr});
                        } else {
                            // p = q: pts(p) ⊇ pts(q)
                            analyzer.constraints_.push_back({src, dst});
                        }
                    }
                    break;
                }
                
                case cot_ref: {
                    // &x creates a pointer to x
                    // Handled as part of assignment
                    break;
                }
                
                default:
                    break;
            }
            return 0;
        }
    };
    
    ConstraintCollector collector(*this, cfunc);
    collector.apply_to(&cfunc->body, nullptr);
    
    // Phase 2: Solve constraints to fixed point
    solve();
}

void AndersenAliasAnalyzer::solve() {
    // Worklist-based fixed-point iteration
    // Initialize worklist with all variables that have points-to sets
    std::unordered_set<int> in_worklist;
    for (const auto& [var, pts] : points_to_) {
        if (!pts.empty()) {
            worklist_.push_back(var);
            in_worklist.insert(var);
        }
    }
    
    int iterations = 0;
    const int max_iterations = 10000;  // Safety limit
    
    while (!worklist_.empty() && iterations < max_iterations) {
        int var = worklist_.back();
        worklist_.pop_back();
        in_worklist.erase(var);
        
        // Process all constraints involving this variable
        for (const auto& constraint : constraints_) {
            bool changed = false;
            
            // pts(constraint.src) ⊆ pts(constraint.dst)
            if (constraint.src == var) {
                // Propagate points-to set from src to dst
                for (int pointee : points_to_[var]) {
                    if (points_to_[constraint.dst].insert(pointee).second) {
                        changed = true;
                    }
                }
                
                if (changed && in_worklist.find(constraint.dst) == in_worklist.end()) {
                    worklist_.push_back(constraint.dst);
                    in_worklist.insert(constraint.dst);
                }
            }
        }
        
        ++iterations;
    }
}

void AndersenAliasAnalyzer::propagate(int var_id) {
    // Propagate points-to information to all dependents
    for (const auto& constraint : constraints_) {
        if (constraint.src == var_id) {
            for (int pointee : points_to_[var_id]) {
                points_to_[constraint.dst].insert(pointee);
            }
        }
    }
}

std::unordered_set<int> AndersenAliasAnalyzer::get_points_to(int var_id) {
    auto it = points_to_.find(var_id);
    if (it != points_to_.end()) {
        return it->second;
    }
    return {};
}

bool AndersenAliasAnalyzer::may_point_to(int ptr_id, int loc_id) {
    auto it = points_to_.find(ptr_id);
    if (it != points_to_.end()) {
        return it->second.count(loc_id) > 0;
    }
    return false;
}

bool AndersenAliasAnalyzer::may_alias(int ptr1_id, int ptr2_id) {
    // Two pointers may alias if their points-to sets intersect
    const auto& pts1 = points_to_[ptr1_id];
    const auto& pts2 = points_to_[ptr2_id];
    
    // If either is empty, conservatively return true
    if (pts1.empty() || pts2.empty()) {
        return true;
    }
    
    // Check for intersection
    for (int loc : pts1) {
        if (pts2.count(loc) > 0) {
            return true;
        }
    }
    
    return false;
}

qvector<TypeConstraint> AndersenAliasAnalyzer::generate_type_constraints(
    const std::unordered_map<int, TypeVariable>& var_types)
{
    qvector<TypeConstraint> constraints;
    
    // For each pointer and its points-to set, generate type constraints
    for (const auto& [ptr_id, pts] : points_to_) {
        auto ptr_it = var_types.find(ptr_id);
        if (ptr_it == var_types.end()) continue;
        
        const TypeVariable& ptr_type = ptr_it->second;
        
        // Pointer must be a pointer type
        constraints.push_back(
            TypeConstraint::make_is_pointer(ptr_type, BADADDR)
                .sourced_from(TypeConstraintOrigin::AliasRelation)
                .describe("variable used as pointer (Andersen)")
        );
        
        // All pointees should have compatible types
        TypeVariable* prev_pointee_type = nullptr;
        for (int pointee_id : pts) {
            auto pointee_it = var_types.find(pointee_id);
            if (pointee_it == var_types.end()) continue;
            
            if (prev_pointee_type) {
                constraints.push_back(
                    TypeConstraint::make_equal(*prev_pointee_type, pointee_it->second, BADADDR)
                        .soft(5)
                        .sourced_from(TypeConstraintOrigin::AliasRelation)
                        .describe("pointees should have compatible types (Andersen)")
                );
            }
            prev_pointee_type = const_cast<TypeVariable*>(&pointee_it->second);
        }
    }
    
    return constraints;
}

// ============================================================================
// AliasAnalyzer (unified interface) implementation
// ============================================================================

AliasAnalyzer::AliasAnalyzer(Z3Context& ctx, const AliasAnalysisConfig& config)
    : ctx_(ctx)
    , config_(config)
{
    // Initialize the appropriate analyzer based on configuration
    switch (config_.algorithm) {
        case AliasAnalysisConfig::Algorithm::Steensgaard:
            steensgaard_ = std::make_unique<SteensgaardAliasAnalyzer>(ctx_);
            break;
        case AliasAnalysisConfig::Algorithm::Andersen:
        case AliasAnalysisConfig::Algorithm::FieldSensitive:
            andersen_ = std::make_unique<AndersenAliasAnalyzer>(ctx_);
            break;
    }
}

void AliasAnalyzer::analyze(cfunc_t* cfunc) {
    current_cfunc_ = cfunc;
    
    if (steensgaard_) {
        steensgaard_->analyze(cfunc);
    }
    if (andersen_) {
        andersen_->analyze(cfunc);
    }
}

void AliasAnalyzer::reset() {
    current_cfunc_ = nullptr;
    
    // Recreate analyzers to reset state
    if (steensgaard_) {
        steensgaard_ = std::make_unique<SteensgaardAliasAnalyzer>(ctx_);
    }
    if (andersen_) {
        andersen_ = std::make_unique<AndersenAliasAnalyzer>(ctx_);
    }
}

bool AliasAnalyzer::may_alias(cexpr_t* e1, cexpr_t* e2, cfunc_t* cfunc) {
    if (!e1 || !e2) return true;  // Conservative
    
    // Quick check: same expression always aliases
    if (e1 == e2) return true;
    
    // Convert expressions to AbstractLocations
    AbstractLocation loc1, loc2;
    
    // Helper to get location from expression
    auto expr_to_location = [cfunc](cexpr_t* e) -> AbstractLocation {
        if (!e) return AbstractLocation::unknown();
        
        switch (e->op) {
            case cot_var:
                return AbstractLocation::stack(cfunc->entry_ea, e->v.idx);
            case cot_obj:
                return AbstractLocation::global(e->obj_ea);
            default:
                return AbstractLocation::unknown();
        }
    };
    
    loc1 = expr_to_location(e1);
    loc2 = expr_to_location(e2);
    
    // Use AbstractLocation's may_alias for basic cases
    if (loc1.kind != AbstractLocation::Kind::Unknown && 
        loc2.kind != AbstractLocation::Kind::Unknown) {
        // For non-unknown locations, use the location-based aliasing
        return loc1.may_alias(loc2);
    }
    
    // Check using the configured analyzer if we have IDs
    if (steensgaard_ && cfunc) {
        // Get location IDs and check alias relationship
        int id1 = steensgaard_->get_location_id(loc1);
        int id2 = steensgaard_->get_location_id(loc2);
        return steensgaard_->may_alias(id1, id2);
    }
    
    if (andersen_) {
        // For Andersen, check if the locations' points-to sets overlap
        // This is a conservative approximation
        return true;
    }
    
    // Conservative: assume may alias
    return true;
}

qvector<TypeConstraint> AliasAnalyzer::generate_type_constraints(
    const std::unordered_map<int, TypeVariable>& var_types)
{
    qvector<TypeConstraint> constraints;
    
    if (steensgaard_) {
        auto steens_constraints = steensgaard_->generate_type_constraints(var_types);
        for (auto& c : steens_constraints) {
            constraints.push_back(std::move(c));
        }
    }
    
    if (andersen_) {
        auto anders_constraints = andersen_->generate_type_constraints(var_types);
        for (auto& c : anders_constraints) {
            constraints.push_back(std::move(c));
        }
    }
    
    return constraints;
}

} // namespace structor::z3
