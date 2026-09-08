#include "structor/z3/instruction_semantics.hpp"
#include "structor/z3/memory_type_evidence.hpp"
#include <algorithm>
#include <bit>
#include <functional>
#include <limits>
#include <stdexcept>

#ifndef STRUCTOR_TESTING
#include <pro.h>
#include <kernwin.hpp>
#include <bytes.hpp>
#include <name.hpp>
#endif

namespace structor::z3 {

namespace {

std::optional<uint32_t> storage_width(const tinfo_t& type) {
    const auto size = type.get_size();
    if (size == BADSIZE || size == 0 ||
        size > std::numeric_limits<uint32_t>::max()) {
        return std::nullopt;
    }
    return static_cast<uint32_t>(size);
}

struct AbsoluteMemoryAddress {
    ea_t base;
    sval_t offset;
};

std::optional<AbsoluteMemoryAddress> resolve_memory_address(
    const cexpr_t* expression, uint32_t pointer_size, unsigned depth);

std::optional<sval_t> constant_displacement(const cexpr_t* expression) {
    if (!expression || expression->op != cot_num ||
        (!expression->type.is_signed() && !expression->type.is_unsigned()) ||
        !storage_width(expression->type) || expression->type.get_size() > 8) {
        return std::nullopt;
    }
    const auto bits = static_cast<std::uint64_t>(expression->numval());
    return expression->type.is_signed()
        ? std::optional<sval_t>(std::bit_cast<std::int64_t>(bits))
        : checked_sval_from_u64(bits);
}

std::optional<sval_t> address_stride(const tinfo_t& type, uint32_t pointer_size) {
    tinfo_t element;
    if (type.is_ptr()) element = type.get_pointed_object();
    else if (type.is_array()) {
        array_type_data_t details;
        if (!type.get_array_details(&details)) return std::nullopt;
        element = details.elem_type;
    } else if ((type.is_signed() || type.is_unsigned()) &&
               type.get_size() == pointer_size) {
        return 1;
    } else return std::nullopt;
    const auto size = storage_width(element);
    return size ? std::optional<sval_t>(*size) : std::nullopt;
}

std::optional<AbsoluteMemoryAddress> displace_address(
    std::optional<AbsoluteMemoryAddress> address, sval_t displacement,
    uint32_t pointer_size)
{
    if (!address) return std::nullopt;
    const auto offset = checked_sval_add(address->offset, displacement);
    if (!offset || !valid_memory_location(
            {address->base, *offset, 1}, pointer_size)) return std::nullopt;
    return AbsoluteMemoryAddress{address->base, *offset};
}

std::optional<AbsoluteMemoryAddress> resolve_pointer_address(
    const cexpr_t* expression, uint32_t pointer_size, unsigned depth)
{
    if (!expression || depth == 0) return std::nullopt;
    switch (expression->op) {
        case cot_ref:
            return resolve_memory_address(expression->x, pointer_size, depth - 1);
        case cot_obj:
            // Array decay is an address. A global pointer value is a load;
            // the address of its storage does not locate its pointee.
            if (expression->type.is_array() && expression->obj_ea != BADADDR &&
                valid_memory_location({expression->obj_ea, 0, 1}, pointer_size)) {
                return AbsoluteMemoryAddress{expression->obj_ea, 0};
            }
            return std::nullopt;
        case cot_num: {
            const auto size = storage_width(expression->type);
            if (!size || *size > pointer_size ||
                (!expression->type.is_signed() && !expression->type.is_unsigned() &&
                 !expression->type.is_ptr())) return std::nullopt;
            const auto address = static_cast<ea_t>(expression->numval());
            return valid_memory_location({address, 0, 1}, pointer_size)
                ? std::optional<AbsoluteMemoryAddress>({address, 0}) : std::nullopt;
        }
        case cot_cast: {
            if (!expression->x) return std::nullopt;
            const auto address_kind = [](const tinfo_t& type) {
                return type.is_ptr() || type.is_signed() || type.is_unsigned();
            };
            const auto source_size = storage_width(expression->x->type);
            if (!address_kind(expression->type) || !address_kind(expression->x->type) ||
                expression->type.get_size() != pointer_size || !source_size ||
                (*source_size != pointer_size && expression->x->op != cot_num) ||
                *source_size > pointer_size) return std::nullopt;
            return resolve_pointer_address(expression->x, pointer_size, depth - 1);
        }
        case cot_add:
        case cot_sub: {
            const cexpr_t* base = expression->x;
            const cexpr_t* index = expression->y;
            if (expression->op == cot_add && base && base->op == cot_num &&
                index && index->op != cot_num) std::swap(base, index);
            const auto constant = constant_displacement(index);
            const auto stride = base ? address_stride(base->type, pointer_size) : std::nullopt;
            if (!constant || !stride || expression->type.get_size() != pointer_size) {
                return std::nullopt;
            }
            const auto scaled = checked_sval_mul(*constant, *stride);
            if (!scaled) return std::nullopt;
            const auto displacement = expression->op == cot_sub
                ? checked_sval_sub(0, *scaled) : scaled;
            if (!displacement) return std::nullopt;
            return displace_address(resolve_pointer_address(base, pointer_size, depth - 1),
                                    *displacement, pointer_size);
        }
        default:
            return std::nullopt;
    }
}

std::optional<AbsoluteMemoryAddress> resolve_memory_address(
    const cexpr_t* expression, uint32_t pointer_size, unsigned depth)
{
    if (!expression || depth == 0) return std::nullopt;
    switch (expression->op) {
        case cot_obj:
            if (!expression->type.is_func() && expression->obj_ea != BADADDR &&
                valid_memory_location({expression->obj_ea, 0, 1}, pointer_size)) {
                return AbsoluteMemoryAddress{expression->obj_ea, 0};
            }
            return std::nullopt;
        case cot_ptr:
            return resolve_pointer_address(expression->x, pointer_size, depth - 1);
        case cot_idx: {
            const auto index = constant_displacement(expression->y);
            const auto stride = expression->x
                ? address_stride(expression->x->type, pointer_size) : std::nullopt;
            if (!index || !stride) return std::nullopt;
            const auto offset = checked_sval_mul(*index, *stride);
            return offset ? displace_address(resolve_pointer_address(
                expression->x, pointer_size, depth - 1), *offset, pointer_size) : std::nullopt;
        }
        case cot_memptr:
            return displace_address(resolve_pointer_address(expression->x, pointer_size, depth - 1),
                                    static_cast<sval_t>(expression->m), pointer_size);
        case cot_memref:
            return displace_address(resolve_memory_address(expression->x, pointer_size, depth - 1),
                                    static_cast<sval_t>(expression->m), pointer_size);
        default:
            return std::nullopt;
    }
}

// Restrict concrete observations to represented scalar/pointer types. Partial
// storage types, enums, aggregates and function prototypes need richer evidence.
std::optional<InferredType> memory_type_from_tinfo(
    const tinfo_t& type, uint32_t pointer_size, unsigned depth = 64)
{
    if (depth == 0 || type.empty() || type.is_partial() || type.is_decl_bitfield()) {
        return std::nullopt;
    }
    if (type.is_void()) return InferredType::make_base(BaseType::Void);
    if (type.is_ptr()) {
        if (type.get_size() != pointer_size) return std::nullopt;
        const auto pointed = memory_type_from_tinfo(type.get_pointed_object(), pointer_size, depth - 1);
        return pointed ? std::optional<InferredType>(InferredType::make_ptr(*pointed)) : std::nullopt;
    }
    const auto size = storage_width(type);
    if (!size) return std::nullopt;
    if (type.is_floating()) {
        if (*size == 4) return InferredType::make_base(BaseType::Float32);
        if (*size == 8) return InferredType::make_base(BaseType::Float64);
        return std::nullopt;
    }
    if (type.is_bool()) return InferredType::make_base(BaseType::Bool);
    if (!type.is_integral() || (!type.is_signed() && !type.is_unsigned())) return std::nullopt;
    const auto base = base_type_from_size(*size, type.is_signed());
    return base == BaseType::Unknown ? std::nullopt
        : std::optional<InferredType>(InferredType::make_base(base));
}

} // namespace

// ============================================================================
// TypeVariable implementation
// ============================================================================

TypeVariable TypeVariable::for_local(int id, ea_t func_ea, int var_idx, int version) {
    TypeVariable tv;
    tv.id = id;
    tv.func_ea = func_ea;
    tv.var_idx = var_idx;
    tv.ssa_version = version;
    tv.name.sprnt("local_%llX_%d_v%d", 
                  static_cast<unsigned long long>(func_ea), 
                  var_idx, version);
    return tv;
}

TypeVariable TypeVariable::for_memory(int id, ea_t base, sval_t offset, uint32_t size) {
    TypeVariable tv;
    tv.id = id;
    tv.func_ea = BADADDR;
    tv.var_idx = -1;
    tv.mem_base = base;
    tv.mem_offset = offset;
    tv.mem_size = size;
    tv.name.sprnt("mem_%llX_%llX_%u",
                  static_cast<unsigned long long>(base),
                  static_cast<unsigned long long>(offset),
                  size);
    return tv;
}

TypeVariable TypeVariable::for_temp(int id, ea_t func_ea, const char* name) {
    TypeVariable tv;
    tv.id = id;
    tv.func_ea = func_ea;
    tv.var_idx = -1;
    tv.name = name ? name : "";
    return tv;
}

// ============================================================================
// TypeConstraint factory methods
// ============================================================================

TypeConstraint TypeConstraint::make_equal(TypeVariable t1, TypeVariable t2, ea_t ea) {
    TypeConstraint c;
    c.kind = Kind::Equal;
    c.var1 = std::move(t1);
    c.var2 = std::move(t2);
    c.source_ea = ea;
    return c;
}

TypeConstraint TypeConstraint::make_subtype(TypeVariable sub, TypeVariable sup, ea_t ea) {
    TypeConstraint c;
    c.kind = Kind::Subtype;
    c.var1 = std::move(sub);
    c.var2 = std::move(sup);
    c.source_ea = ea;
    return c;
}

TypeConstraint TypeConstraint::make_is_base(TypeVariable t, BaseType base, ea_t ea) {
    TypeConstraint c;
    c.kind = Kind::IsBase;
    c.var1 = std::move(t);
    c.concrete_type = InferredType::make_base(base);
    c.source_ea = ea;
    return c;
}

TypeConstraint TypeConstraint::make_is_pointer(TypeVariable t, ea_t ea) {
    TypeConstraint c;
    c.kind = Kind::IsPointer;
    c.var1 = std::move(t);
    c.source_ea = ea;
    return c;
}

TypeConstraint TypeConstraint::make_is_pointer_to(TypeVariable t, InferredType pointee, ea_t ea) {
    TypeConstraint c;
    c.kind = Kind::IsPointerTo;
    c.var1 = std::move(t);
    c.concrete_type = InferredType::make_ptr(std::move(pointee));
    c.source_ea = ea;
    return c;
}

TypeConstraint TypeConstraint::make_is_integer(TypeVariable t, ea_t ea) {
    TypeConstraint c;
    c.kind = Kind::IsInteger;
    c.var1 = std::move(t);
    c.source_ea = ea;
    return c;
}

TypeConstraint TypeConstraint::make_is_signed(TypeVariable t, ea_t ea) {
    TypeConstraint c;
    c.kind = Kind::IsSigned;
    c.var1 = std::move(t);
    c.source_ea = ea;
    return c;
}

TypeConstraint TypeConstraint::make_is_unsigned(TypeVariable t, ea_t ea) {
    TypeConstraint c;
    c.kind = Kind::IsUnsigned;
    c.var1 = std::move(t);
    c.source_ea = ea;
    return c;
}

TypeConstraint TypeConstraint::make_is_floating(TypeVariable t, ea_t ea) {
    TypeConstraint c;
    c.kind = Kind::IsFloating;
    c.var1 = std::move(t);
    c.source_ea = ea;
    return c;
}

TypeConstraint TypeConstraint::make_has_size(TypeVariable t, uint32_t size, ea_t ea) {
    TypeConstraint c;
    c.kind = Kind::HasSize;
    c.var1 = std::move(t);
    c.size = size;
    c.source_ea = ea;
    return c;
}

TypeConstraint TypeConstraint::make_one_of(TypeVariable t, std::vector<InferredType> types, ea_t ea) {
    TypeConstraint c;
    c.kind = Kind::OneOf;
    c.var1 = std::move(t);
    c.alternatives = std::move(types);
    c.source_ea = ea;
    return c;
}

// ============================================================================
// InstructionSemanticsExtractor implementation
// ============================================================================

InstructionSemanticsExtractor::InstructionSemanticsExtractor(
    Z3Context& ctx,
    const InstructionSemanticsConfig& config)
    : ctx_(ctx)
    , encoder_(ctx)
    , config_(config)
{}

int InstructionSemanticsExtractor::allocate_diagnostic_id() {
    if (next_var_id_ == std::numeric_limits<int>::max()) {
        throw std::overflow_error("type variable diagnostic indices exhausted");
    }
    ++stats_.type_variables;
    return next_var_id_++;
}

void InstructionSemanticsExtractor::begin_expression_pass(cfunc_t* cfunc) {
    identities_.begin_expression_pass();
    expression_vars_.clear();
    observed_memory_types_.clear();
    current_cfunc_ = cfunc;
    current_func_ea_ = cfunc->entry_ea;
    stats_.expressions_analyzed = 0;
    stats_.constraints_extracted = 0;
    stats_.hard_constraints = 0;
    stats_.soft_constraints = 0;
    stats_.unresolved_memory_accesses = 0;
}

void InstructionSemanticsExtractor::end_expression_pass() {
    expression_vars_.clear();
    observed_memory_types_.clear();
    identities_.end_expression_pass();
    current_cfunc_ = nullptr;
    current_func_ea_ = BADADDR;
}

TypeConstraintSet InstructionSemanticsExtractor::extract(cfunc_t* cfunc) {
    TypeConstraintSet result(ctx_);
    if (!cfunc || !cfunc->body.cblock) {
        return result;
    }

    begin_expression_pass(cfunc);
    try {
        qvector<TypeConstraint> constraints;
        ConstraintExtractionVisitor visitor(*this, constraints);
        visitor.apply_to(&cfunc->body, nullptr);
        result.add_all(constraints);
        stats_.constraints_extracted = static_cast<int>(result.total_count());
        stats_.hard_constraints = static_cast<int>(result.hard_count());
        stats_.soft_constraints = static_cast<int>(result.soft_count());
    } catch (...) {
        end_expression_pass();
        throw;
    }
    end_expression_pass();
    return result;
}

qvector<TypeConstraint> InstructionSemanticsExtractor::extract_expr(
    cexpr_t* expr,
    cfunc_t* cfunc)
{
    qvector<TypeConstraint> constraints;
    if (!expr || !cfunc) {
        return constraints;
    }

    begin_expression_pass(cfunc);
    try {
        analyze_node(expr, constraints);
        stats_.constraints_extracted = static_cast<int>(constraints.size());
        stats_.soft_constraints = static_cast<int>(std::count_if(
            constraints.begin(), constraints.end(),
            [](const TypeConstraint& constraint) { return constraint.is_soft; }));
        stats_.hard_constraints = stats_.constraints_extracted - stats_.soft_constraints;
    } catch (...) {
        end_expression_pass();
        throw;
    }
    end_expression_pass();
    return constraints;
}

TypeVariable InstructionSemanticsExtractor::get_var_type(
    cfunc_t* cfunc,
    int var_idx,
    int version)
{
    const ea_t func_ea = cfunc ? cfunc->entry_ea : BADADDR;
    const auto identity = identities_.local(func_ea, var_idx, version);
    if (const auto found = persistent_vars_.find(identity); found != persistent_vars_.end()) {
        return found->second;
    }
    TypeVariable tv = TypeVariable::for_local(
        allocate_diagnostic_id(), func_ea, var_idx, version);
    tv.identity = identity;
    persistent_vars_.emplace(identity, tv);
    return tv;
}

TypeVariable InstructionSemanticsExtractor::get_mem_type(
    ea_t base,
    sval_t offset,
    uint32_t size)
{
    const auto identity = identities_.memory(base, offset, size);
    if (const auto found = persistent_vars_.find(identity); found != persistent_vars_.end()) {
        return found->second;
    }
    TypeVariable tv = TypeVariable::for_memory(
        allocate_diagnostic_id(), base, offset, size);
    tv.identity = identity;
    persistent_vars_.emplace(identity, tv);
    return tv;
}

TypeVariable InstructionSemanticsExtractor::get_temp_type(ea_t func_ea, const char* name) {
    const auto identity = identities_.named(func_ea, name ? name : "");
    if (const auto found = persistent_vars_.find(identity); found != persistent_vars_.end()) {
        return found->second;
    }
    TypeVariable tv = TypeVariable::for_temp(allocate_diagnostic_id(), func_ea, name);
    tv.identity = identity;
    persistent_vars_.emplace(identity, tv);
    return tv;
}

void InstructionSemanticsExtractor::analyze_node(
    cexpr_t* expr, 
    qvector<TypeConstraint>& constraints)
{
    if (!expr) return;
    
    stats_.expressions_analyzed++;
    
    switch (expr->op) {
        // Direct data loads also occur without an assignment/arithmetic parent,
        // for example `return global`. The visitor excludes address operands.
        case cot_obj:
            if (config_.extract_from_memory_ops && !expr->type.is_func() &&
                !expr->type.is_array()) {
                (void)get_expr_type(expr, constraints);
            }
            break;
        // Assignment
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
            if (config_.extract_from_arithmetic) {
                extract_from_assignment(expr, constraints);
            }
            break;
            
        // Pointer dereference
        case cot_ptr:
            if (config_.extract_from_memory_ops) {
                extract_from_ptr_deref(expr, constraints);
            }
            break;
            
        // Comparisons
        case cot_eq:
        case cot_ne:
        case cot_sge:
        case cot_uge:
        case cot_sle:
        case cot_ule:
        case cot_sgt:
        case cot_ugt:
        case cot_slt:
        case cot_ult:
            if (config_.extract_from_comparisons) {
                extract_from_comparison(expr, constraints);
            }
            break;
            
        // Arithmetic
        case cot_add:
        case cot_sub:
        case cot_mul:
        case cot_sdiv:
        case cot_udiv:
        case cot_smod:
        case cot_umod:
        case cot_bor:
        case cot_xor:
        case cot_band:
        case cot_sshr:
        case cot_ushr:
        case cot_shl:
        case cot_neg:
        case cot_bnot:
        case cot_lnot:
            if (config_.extract_from_arithmetic) {
                extract_from_arithmetic(expr, constraints);
            }
            break;
            
        // Casts
        case cot_cast:
            if (config_.extract_from_casts) {
                extract_from_cast(expr, constraints);
            }
            break;
            
        // Function calls
        case cot_call:
            if (config_.extract_from_calls) {
                extract_from_call(expr, constraints);
            }
            break;
            
        // Array access
        case cot_idx:
            if (config_.extract_from_memory_ops) {
                extract_from_array_access(expr, constraints);
            }
            break;
            
        // Member access
        case cot_memptr:
        case cot_memref:
            if (config_.extract_from_memory_ops) {
                extract_from_member_access(expr, constraints);
            }
            break;
            
        default:
            break;
    }
}

void InstructionSemanticsExtractor::extract_from_assignment(
    cexpr_t* expr, 
    qvector<TypeConstraint>& constraints)
{
    if (!expr->x || !expr->y) return;
    
    TypeVariable lhs_type = get_expr_type(expr->x, constraints);
    TypeVariable rhs_type = get_expr_type(expr->y, constraints);
    
    // Assignment implies type equality (modulo implicit conversions)
    constraints.push_back(
        TypeConstraint::make_equal(lhs_type, rhs_type, expr->ea)
            .describe("assignment type equality")
    );
    
    // If RHS has known type from decompiler, use it
    if (!rhs_type.is_memory() && !expr->y->type.empty()) {
        auto inferred = infer_from_tinfo(expr->y->type);
        if (inferred) {
            constraints.push_back(
                TypeConstraint::make_one_of(rhs_type, {*inferred}, expr->ea)
                    .soft(config_.weight_from_decompiler)
                    .describe("decompiler type hint")
            );
        }
    }
}

void InstructionSemanticsExtractor::extract_from_ptr_deref(
    cexpr_t* expr, 
    qvector<TypeConstraint>& constraints)
{
    if (!expr->x) return;
    
    // expr->x is the pointer being dereferenced
    TypeVariable ptr_type = get_expr_type(expr->x, constraints);
    TypeVariable deref_type = get_expr_type(expr, constraints);
    
    // The pointer must be a pointer type
    constraints.push_back(
        TypeConstraint::make_is_pointer(ptr_type, expr->ea)
            .describe("dereference requires pointer")
    );
    
    // The dereferenced type should match the pointee
    // ptr_type = ptr(deref_type)
    const auto pointee = ptr_type.is_memory()
        ? memory_type_from_tinfo(expr->type, ctx_.pointer_size())
        : std::optional<InferredType>(InferredType::from_tinfo(expr->type));
    if (pointee) {
        constraints.push_back(
            TypeConstraint::make_is_pointer_to(ptr_type, *pointee, expr->ea)
                .describe("dereference pointee type"));
    }
    
    // Size constraint from access
    if (const auto access_size = storage_width(expr->type)) {
        constraints.push_back(
            TypeConstraint::make_has_size(deref_type, *access_size, expr->ea)
                .describe("dereference size")
        );
    }
}

void InstructionSemanticsExtractor::extract_from_comparison(
    cexpr_t* expr, 
    qvector<TypeConstraint>& constraints)
{
    if (!expr->x || !expr->y) return;
    
    TypeVariable lhs_type = get_expr_type(expr->x, constraints);
    TypeVariable rhs_type = get_expr_type(expr->y, constraints);
    
    // Both operands should have compatible types
    constraints.push_back(
        TypeConstraint::make_equal(lhs_type, rhs_type, expr->ea)
            .soft(5)
            .describe("comparison operand compatibility")
    );
    
    // Check for signed/unsigned comparison semantics
    if (is_signed_comparison(expr->op)) {
        constraints.push_back(
            TypeConstraint::make_is_signed(lhs_type, expr->ea)
                .describe("signed comparison implies signed type")
        );
        constraints.push_back(
            TypeConstraint::make_is_signed(rhs_type, expr->ea)
                .describe("signed comparison implies signed type")
        );
    } else if (is_unsigned_comparison(expr->op)) {
        constraints.push_back(
            TypeConstraint::make_is_unsigned(lhs_type, expr->ea)
                .describe("unsigned comparison implies unsigned type")
        );
        constraints.push_back(
            TypeConstraint::make_is_unsigned(rhs_type, expr->ea)
                .describe("unsigned comparison implies unsigned type")
        );
    }
    
    // If comparing against small constant, likely integer
    if (config_.generate_soft_constraints) {
        if (expr->y->op == cot_num) {
            int64_t val = static_cast<int64_t>(expr->y->numval());
            if (val >= -0x10000 && val <= 0x10000) {
                constraints.push_back(
                    TypeConstraint::make_is_integer(lhs_type, expr->ea)
                        .soft(config_.weight_int_for_small_const)
                        .describe("small constant comparison suggests integer")
                );
            }
        }
    }
}

void InstructionSemanticsExtractor::extract_from_arithmetic(
    cexpr_t* expr, 
    qvector<TypeConstraint>& constraints)
{
    TypeVariable result_type = get_expr_type(expr, constraints);
    
    // Unary operators
    if (!expr->y) {
        if (expr->x) {
            TypeVariable operand_type = get_expr_type(expr->x, constraints);
            
            switch (expr->op) {
                case cot_neg:  // Unary minus - implies signed
                    constraints.push_back(
                        TypeConstraint::make_is_signed(operand_type, expr->ea)
                            .soft(config_.weight_signed_preference)
                            .describe("unary minus suggests signed")
                    );
                    break;
                    
                case cot_bnot:  // Bitwise NOT - implies integer
                    constraints.push_back(
                        TypeConstraint::make_is_integer(operand_type, expr->ea)
                            .describe("bitwise NOT requires integer")
                    );
                    break;
                    
                default:
                    break;
            }
        }
        return;
    }
    
    // Binary operators
    TypeVariable lhs_type = get_expr_type(expr->x, constraints);
    TypeVariable rhs_type = get_expr_type(expr->y, constraints);
    
    switch (expr->op) {
        case cot_sdiv:
        case cot_smod:
        case cot_sshr:
            // Signed division/modulo/shift - operands are signed
            constraints.push_back(
                TypeConstraint::make_is_signed(lhs_type, expr->ea)
                    .describe("signed operation implies signed operand")
            );
            constraints.push_back(
                TypeConstraint::make_is_signed(rhs_type, expr->ea)
                    .describe("signed operation implies signed operand")
            );
            break;
            
        case cot_udiv:
        case cot_umod:
        case cot_ushr:
            // Unsigned operations
            constraints.push_back(
                TypeConstraint::make_is_unsigned(lhs_type, expr->ea)
                    .describe("unsigned operation implies unsigned operand")
            );
            constraints.push_back(
                TypeConstraint::make_is_unsigned(rhs_type, expr->ea)
                    .describe("unsigned operation implies unsigned operand")
            );
            break;
            
        case cot_add:
        case cot_sub:
            // Add/sub could be pointer arithmetic
            // If adding small constant to pointer-sized value, might be pointer
            if (config_.generate_soft_constraints && expr->y->op == cot_num) {
                constraints.push_back(
                    TypeConstraint::make_is_pointer(lhs_type, expr->ea)
                        .soft(5)
                        .describe("add/sub with constant might be pointer arithmetic")
                );
            }
            break;
            
        case cot_bor:
        case cot_band:
        case cot_xor:
        case cot_shl:
            // Bitwise operations require integers
            constraints.push_back(
                TypeConstraint::make_is_integer(lhs_type, expr->ea)
                    .describe("bitwise operation requires integer")
            );
            constraints.push_back(
                TypeConstraint::make_is_integer(rhs_type, expr->ea)
                    .describe("bitwise operation requires integer")
            );
            break;
            
        default:
            break;
    }
}

void InstructionSemanticsExtractor::extract_from_cast(
    cexpr_t* expr, 
    qvector<TypeConstraint>& constraints)
{
    if (!expr->x) return;
    
    TypeVariable src_type = get_expr_type(expr->x, constraints);
    TypeVariable dst_type = get_expr_type(expr, constraints);
    
    // Cast target type is known from the expression
    if (!expr->type.empty()) {
        auto inferred = infer_from_tinfo(expr->type);
        if (inferred) {
            constraints.push_back(
                TypeConstraint::make_one_of(dst_type, {*inferred}, expr->ea)
                    .describe("cast target type")
            );
        }
    }
    
    // Source type has size from original
    if (!expr->x->type.empty()) {
        if (const auto src_size = storage_width(expr->x->type)) {
            constraints.push_back(
                TypeConstraint::make_has_size(src_type, *src_size, expr->ea)
                    .describe("cast source size")
            );
        }
    }
}

void InstructionSemanticsExtractor::extract_from_call(
    cexpr_t* expr, 
    qvector<TypeConstraint>& constraints)
{
    if (!expr->x) return;
    
    // Get called function's type
    tinfo_t func_type;
    if (expr->x->op == cot_obj) {
        // Direct call
        ea_t callee = expr->x->obj_ea;
        get_tinfo(&func_type, callee);
    } else {
        // Indirect call - function pointer
        TypeVariable fptr_type = get_expr_type(expr->x, constraints);
        constraints.push_back(
            TypeConstraint::make_is_pointer(fptr_type, expr->ea)
                .describe("indirect call target is function pointer")
        );
        func_type = expr->x->type;
    }
    
    // Extract parameter type constraints from function type
    if (!func_type.empty() && func_type.is_func()) {
        func_type_data_t ftd;
        if (func_type.get_func_details(&ftd)) {
            carglist_t* args = expr->a;
            if (args) {
                for (size_t i = 0; i < args->size() && i < ftd.size(); ++i) {
                    cexpr_t* arg = &(*args)[i];
                    TypeVariable arg_type = get_expr_type(arg, constraints);
                    
                    auto param_inferred = arg_type.is_memory()
                        ? memory_type_from_tinfo(ftd[i].type, ctx_.pointer_size())
                        : infer_from_tinfo(ftd[i].type);
                    if (param_inferred) {
                        constraints.push_back(
                            TypeConstraint::make_one_of(arg_type, {*param_inferred}, expr->ea)
                                .soft(config_.weight_from_signature)
                                .describe("function parameter type")
                        );
                    }
                }
            }
            
            // Return type constraint
            TypeVariable ret_type = get_expr_type(expr, constraints);
            auto ret_inferred = infer_from_tinfo(ftd.rettype);
            if (ret_inferred) {
                constraints.push_back(
                    TypeConstraint::make_one_of(ret_type, {*ret_inferred}, expr->ea)
                        .soft(config_.weight_from_signature)
                        .describe("function return type")
                );
            }
        }
    }
}

void InstructionSemanticsExtractor::extract_from_array_access(
    cexpr_t* expr, 
    qvector<TypeConstraint>& constraints)
{
    if (!expr->x || !expr->y) return;
    
    TypeVariable base_type = get_expr_type(expr->x, constraints);
    TypeVariable index_type = get_expr_type(expr->y, constraints);
    TypeVariable elem_type = get_expr_type(expr, constraints);
    
    // Base must be pointer or array
    constraints.push_back(
        TypeConstraint::make_is_pointer(base_type, expr->ea)
            .describe("array access base is pointer")
    );
    
    // Index must be integer
    constraints.push_back(
        TypeConstraint::make_is_integer(index_type, expr->ea)
            .describe("array index is integer")
    );
    
    // Element type from expression type
    if (!expr->type.empty()) {
        if (const auto elem_size = storage_width(expr->type)) {
            constraints.push_back(
                TypeConstraint::make_has_size(elem_type, *elem_size, expr->ea)
                    .describe("array element size")
            );
        }
    }
}

void InstructionSemanticsExtractor::extract_from_member_access(
    cexpr_t* expr, 
    qvector<TypeConstraint>& constraints)
{
    if (!expr->x) return;
    
    TypeVariable member_type = get_expr_type(expr, constraints);
    
    if (expr->op == cot_memptr) {
        // Through pointer - the pointer value is read; a direct member
        // base designates aggregate storage without loading the whole object.
        TypeVariable struct_type = get_expr_type(expr->x, constraints);
        constraints.push_back(
            TypeConstraint::make_is_pointer(struct_type, expr->ea)
                .describe("member access through pointer")
        );
    }
    
    // Member type from expression type
    if (!member_type.is_memory() && !expr->type.empty()) {
        auto inferred = infer_from_tinfo(expr->type);
        if (inferred) {
            constraints.push_back(
                TypeConstraint::make_one_of(member_type, {*inferred}, expr->ea)
                    .soft(config_.weight_from_decompiler)
                    .describe("member type")
            );
        }
    }
}

std::optional<InferredType> InstructionSemanticsExtractor::infer_from_tinfo(const tinfo_t& type) {
    if (type.empty()) return std::nullopt;
    return InferredType::from_tinfo(type);
}

TypeVariable InstructionSemanticsExtractor::get_expr_type(
    cexpr_t* expr, qvector<TypeConstraint>& constraints) {
    if (!expr) {
        // Missing operands are not a shared program variable.
        return TypeVariable::for_temp(
            allocate_diagnostic_id(), current_func_ea_, "null_expr");
    }
    if (expr->op == cot_var && current_cfunc_) {
        return get_var_type(current_cfunc_, expr->v.idx);
    }

    const auto identity = identities_.expression(expr);
    if (const auto found = expression_vars_.find(identity); found != expression_vars_.end()) {
        return found->second;
    }
    const bool memory_expression = !expr->type.is_array() &&
        (expr->op == cot_ptr || expr->op == cot_idx || expr->op == cot_memptr ||
         expr->op == cot_memref || (expr->op == cot_obj && !expr->type.is_func()));
    if (config_.extract_from_memory_ops && memory_expression) {
        const auto width = storage_width(expr->type);
        const auto address = resolve_memory_address(expr, ctx_.pointer_size(), 64);
        if (width && address && valid_memory_location(
                {address->base, address->offset, *width}, ctx_.pointer_size())) {
            TypeVariable memory = get_mem_type(address->base, address->offset, *width);
            expression_vars_.emplace(identity, memory);
            constraints.push_back(TypeConstraint::make_has_size(memory, *width, expr->ea)
                .describe("absolute-memory access width"));
            const auto observed = memory_type_from_tinfo(expr->type, ctx_.pointer_size());
            if (observed && !observed->is_unknown() &&
                config_.generate_soft_constraints && config_.weight_from_decompiler > 0) {
                auto& views = observed_memory_types_[memory.identity];
                if (std::none_of(views.begin(), views.end(),
                        [&](const InferredType& view) { return view == *observed; })) {
                    views.push_back(observed->snapshot());
                    constraints.push_back(TypeConstraint::make_one_of(memory, {*observed}, expr->ea)
                        .soft(config_.weight_from_decompiler)
                        .describe("concrete absolute-memory view"));
                }
            }
            return memory;
        }
        ++stats_.unresolved_memory_accesses;
    }
    qstring name;
    name.sprnt("expr_%llX_%d", static_cast<unsigned long long>(expr->ea), expr->op);
    TypeVariable tv = TypeVariable::for_temp(
        allocate_diagnostic_id(), current_func_ea_, name.c_str());
    tv.identity = identity;
    expression_vars_.emplace(identity, tv);
    return tv;
}

bool InstructionSemanticsExtractor::is_signed_comparison(ctype_t cmp_op) const noexcept {
    // Signed comparisons: slt, sle, sgt, sge
    return cmp_op == cot_slt || cmp_op == cot_sle || 
           cmp_op == cot_sgt || cmp_op == cot_sge;
}

bool InstructionSemanticsExtractor::is_unsigned_comparison(ctype_t cmp_op) const noexcept {
    // Unsigned comparisons: ult, ule, ugt, uge
    return cmp_op == cot_ult || cmp_op == cot_ule || 
           cmp_op == cot_ugt || cmp_op == cot_uge;
}

// ============================================================================
// TypeConstraintSet implementation
// ============================================================================

TypeConstraintSet::TypeConstraintSet(Z3Context& ctx) : ctx_(ctx) {}

void TypeConstraintSet::clear() {
    constraints_.clear();
    variables_.clear();
    var_cache_.clear();
}

void TypeConstraintSet::add(TypeConstraint constraint) {
    variables_.insert(constraint.var1);
    if (constraint.var2) {
        variables_.insert(*constraint.var2);
    }
    constraints_.push_back(std::move(constraint));
}

void TypeConstraintSet::add_all(const qvector<TypeConstraint>& constraints) {
    for (const auto& c : constraints) {
        add(c);
    }
}

::z3::expr TypeConstraintSet::get_z3_var(
    const TypeVariable& tv, 
    TypeLatticeEncoder& encoder) const
{
    auto it = var_cache_.find(tv.identity);
    if (it != var_cache_.end()) {
        return it->second;
    }
    
    const auto symbol = type_variable_solver_symbol(tv.identity);
    ::z3::expr var = encoder.make_type_var(symbol.c_str());
    var_cache_.emplace(tv.identity, var);
    return var;
}

TypeConstraintSet::ConstraintEvidence TypeConstraintSet::constraint_evidence() const {
    std::unordered_map<TypeVariableIdentity, TypeVariableIdentity,
                       TypeVariableIdentityHash> parents;
    for (const auto& variable : variables_) parents.emplace(variable.identity, variable.identity);
    const auto find_root = [&](TypeVariableIdentity identity) {
        auto root = identity;
        while (parents.at(root) != root) root = parents.at(root);
        while (parents.at(identity) != identity) {
            auto next = parents.at(identity);
            parents.at(identity) = root;
            identity = next;
        }
        return root;
    };
    for (const auto& constraint : constraints_) {
        if (!constraint.is_soft && constraint.kind == TypeConstraint::Kind::Equal && constraint.var2)
            parents.at(find_root(constraint.var1.identity)) = find_root(constraint.var2->identity);
    }
    ConcreteBindings roots;
    CandidateBindings choices;
    for (const auto& constraint : constraints_) {
        const InferredType* exact = nullptr;
        if ((constraint.kind == TypeConstraint::Kind::IsBase && constraint.concrete_type &&
             constraint.concrete_type->is_base()) ||
            (constraint.kind == TypeConstraint::Kind::IsPointerTo && constraint.concrete_type)) {
            exact = &*constraint.concrete_type;
        } else if (constraint.kind == TypeConstraint::Kind::OneOf && constraint.alternatives.size() == 1) {
            exact = &constraint.alternatives.front();
        }
        const auto root = find_root(constraint.var1.identity);
        if (exact && !constraint.is_soft) roots.emplace(root, exact->snapshot());
        const auto record_candidate = [&](const InferredType& type) {
            auto& values = choices[root];
            if (std::find(values.begin(), values.end(), type) == values.end())
                values.push_back(type.snapshot());
        };
        if (exact) record_candidate(*exact);
        if (constraint.kind == TypeConstraint::Kind::OneOf)
            for (const auto& alternative : constraint.alternatives) record_candidate(alternative);
    }
    ConstraintEvidence result;
    for (const auto& variable : variables_) {
        const auto root = find_root(variable.identity);
        auto exact = roots.find(root);
        if (exact != roots.end()) result.exact.emplace(variable.identity, exact->second);
        auto candidates = choices.find(root);
        if (candidates != choices.end()) result.candidates.emplace(variable.identity, candidates->second);
    }
    return result;
}

::z3::expr TypeConstraintSet::constraint_to_z3(
    const TypeConstraint& c,
    TypeLatticeEncoder& encoder,
    const ConcreteBindings& bindings,
    const CandidateBindings& candidates) const
{
    auto& ctx = ctx_.ctx();
    ::z3::expr t1 = get_z3_var(c.var1, encoder);
    const auto evidence_or_variable = [&](const TypeVariable& variable) {
        auto known = bindings.find(variable.identity);
        return known == bindings.end() ? get_z3_var(variable, encoder) : encoder.encode(known->second);
    };
    
    switch (c.kind) {
        case TypeConstraint::Kind::Equal:
            if (c.var2) {
                return encoder.type_eq(t1, get_z3_var(*c.var2, encoder));
            }
            return ctx.bool_val(true);
            
        case TypeConstraint::Kind::Subtype:
            if (c.var2) {
                const auto left = evidence_or_variable(c.var1), right = evidence_or_variable(*c.var2);
                auto result = encoder.subtype_of(left, right);
                const auto left_candidates = candidates.find(c.var1.identity);
                const auto right_candidates = candidates.find(c.var2->identity);
                if ((!bindings.contains(c.var1.identity) && left_candidates != candidates.end()) ||
                    (!bindings.contains(c.var2->identity) && right_candidates != candidates.end()))
                    encoder.explicit_candidate_queries_used_ = true;
                const auto t2 = get_z3_var(*c.var2, encoder);
                if (left_candidates != candidates.end()) {
                    for (const auto& candidate : left_candidates->second) {
                        auto encoded = encoder.encode(candidate);
                        result = result || (t1 == encoded && encoder.subtype_of(encoded, right));
                        if (right_candidates != candidates.end()) {
                            for (const auto& other : right_candidates->second) {
                                auto other_encoded = encoder.encode(other);
                                result = result || (t1 == encoded && t2 == other_encoded &&
                                    encoder.subtype_of(encoded, other_encoded));
                            }
                        }
                    }
                }
                if (right_candidates != candidates.end()) {
                    for (const auto& candidate : right_candidates->second) {
                        auto encoded = encoder.encode(candidate);
                        result = result || (t2 == encoded && encoder.subtype_of(left, encoded));
                    }
                }
                return result;
            }
            return ctx.bool_val(true);
            
        case TypeConstraint::Kind::IsBase:
            if (c.concrete_type && c.concrete_type->is_base()) {
                return encoder.type_eq(t1, encoder.encode(*c.concrete_type));
            }
            return ctx.bool_val(true);
            
        case TypeConstraint::Kind::IsPointer:
            return encoder.is_pointer_type(t1);
            
        case TypeConstraint::Kind::IsPointerTo:
            if (c.concrete_type) {
                return encoder.type_eq(t1, encoder.encode(*c.concrete_type));
            }
            return encoder.is_pointer_type(t1);
            
        case TypeConstraint::Kind::IsInteger:
            return encoder.is_integer_type(t1);
            
        case TypeConstraint::Kind::IsSigned:
            return encoder.is_signed_type(t1);
            
        case TypeConstraint::Kind::IsUnsigned:
            return encoder.is_unsigned_type(t1);
            
        case TypeConstraint::Kind::IsFloating:
            return encoder.is_floating_type(t1);
            
        case TypeConstraint::Kind::HasSize:
            if (c.size) {
                auto result = encoder.type_has_size(evidence_or_variable(c.var1), *c.size);
                // Soft or multi-choice evidence extends the explored domain;
                // a guarded candidate never becomes an assumed equality.
                auto explicit_types = candidates.find(c.var1.identity);
                if (explicit_types != candidates.end()) {
                    if (!bindings.contains(c.var1.identity)) encoder.explicit_candidate_queries_used_ = true;
                    for (const auto& candidate : explicit_types->second) {
                        auto encoded = encoder.encode(candidate);
                        result = result || (t1 == encoded && encoder.type_has_size(encoded, *c.size));
                    }
                }
                return result;
            }
            return ctx.bool_val(true);
            
        case TypeConstraint::Kind::OneOf: {
            if (c.alternatives.empty()) {
                return ctx.bool_val(true);
            }
            ::z3::expr_vector options(ctx);
            for (const auto& alt : c.alternatives) {
                options.push_back(encoder.type_eq(t1, encoder.encode(alt)));
            }
            return ::z3::mk_or(options);
        }
        
        default:
            return ctx.bool_val(true);
    }
}

::z3::expr_vector TypeConstraintSet::to_z3_hard(TypeLatticeEncoder& encoder) const {
    auto& ctx = ctx_.ctx();
    ::z3::expr_vector result(ctx);
    // These substitutions are entailed by hard equalities. Every original
    // equality remains below, including conflicting concrete observations.
    const auto evidence = constraint_evidence();

    for (const auto& c : constraints_) {
        if (!c.is_soft) {
            result.push_back(constraint_to_z3(c, encoder, evidence.exact, evidence.candidates));
        }
    }
    
    return result;
}

std::vector<std::pair<::z3::expr, int>> TypeConstraintSet::to_z3_soft(
    TypeLatticeEncoder& encoder, bool hard_constraints_installed) const
{
    std::vector<std::pair<::z3::expr, int>> result;
    const auto evidence = constraint_evidence();
    const auto bindings = hard_constraints_installed ? evidence.exact : ConcreteBindings{};
    
    for (const auto& c : constraints_) {
        if (c.is_soft) {
            result.emplace_back(constraint_to_z3(c, encoder, bindings, evidence.candidates), c.weight);
        }
    }
    
    return result;
}

std::size_t TypeConstraintSet::hard_count() const noexcept {
    return std::count_if(constraints_.begin(), constraints_.end(),
        [](const TypeConstraint& c) { return !c.is_soft; });
}

std::size_t TypeConstraintSet::soft_count() const noexcept {
    return std::count_if(constraints_.begin(), constraints_.end(),
        [](const TypeConstraint& c) { return c.is_soft; });
}

// ============================================================================
// ConstraintExtractionVisitor implementation
// ============================================================================

ConstraintExtractionVisitor::ConstraintExtractionVisitor(
    InstructionSemanticsExtractor& extractor,
    qvector<TypeConstraint>& constraints)
    : ctree_visitor_t(CV_PARENTS)
    , extractor_(extractor)
    , constraints_(constraints)
{}

int ConstraintExtractionVisitor::visit_expr(cexpr_t* e) {
    // The owning extract() call already established one function/pass. A
    // public extract_expr() call would start a separate pass for every node.
    const auto* parent = parent_expr();
    // Address-taking evaluates pointer/index children but does not read the
    // designated lvalue. Direct member bases likewise designate storage.
    const bool address_operand = parent && parent->x == e &&
        (parent->op == cot_ref || parent->op == cot_memref);
    if (!address_operand) extractor_.analyze_node(e, constraints_);
    return 0;  // Continue visiting
}

// ============================================================================
// SignednessInferrer implementation
// ============================================================================

SignednessInferrer::SignednessInferrer(Z3Context& ctx) : ctx_(ctx) {}

qvector<TypeConstraint> SignednessInferrer::analyze_comparison(
    cexpr_t* cmp_expr,
    TypeVariable lhs_type,
    TypeVariable rhs_type)
{
    qvector<TypeConstraint> constraints;
    
    if (!cmp_expr) return constraints;
    
    if (implies_signed(cmp_expr->op)) {
        constraints.push_back(
            TypeConstraint::make_is_signed(lhs_type, cmp_expr->ea)
                .describe("signed comparison")
        );
        constraints.push_back(
            TypeConstraint::make_is_signed(rhs_type, cmp_expr->ea)
                .describe("signed comparison")
        );
    } else if (implies_unsigned(cmp_expr->op)) {
        constraints.push_back(
            TypeConstraint::make_is_unsigned(lhs_type, cmp_expr->ea)
                .describe("unsigned comparison")
        );
        constraints.push_back(
            TypeConstraint::make_is_unsigned(rhs_type, cmp_expr->ea)
                .describe("unsigned comparison")
        );
    }
    
    return constraints;
}

qvector<TypeConstraint> SignednessInferrer::analyze_conditional(
    cexpr_t* cond_expr,
    TypeVariable cond_type)
{
    qvector<TypeConstraint> constraints;
    
    // Conditional expression result is typically boolean (int in C)
    constraints.push_back(
        TypeConstraint::make_is_integer(cond_type, cond_expr ? cond_expr->ea : BADADDR)
            .describe("conditional is integer")
    );
    
    return constraints;
}

bool SignednessInferrer::implies_signed(ctype_t op) const noexcept {
    // Signed comparisons and operations
    switch (op) {
        case cot_slt:
        case cot_sle:
        case cot_sgt:
        case cot_sge:
        case cot_sdiv:
        case cot_smod:
        case cot_sshr:
            return true;
        default:
            return false;
    }
}

bool SignednessInferrer::implies_unsigned(ctype_t op) const noexcept {
    // Unsigned comparisons and operations
    switch (op) {
        case cot_ult:
        case cot_ule:
        case cot_ugt:
        case cot_uge:
        case cot_udiv:
        case cot_umod:
        case cot_ushr:
            return true;
        default:
            return false;
    }
}

// ============================================================================
// PointerIntegerDiscriminator implementation
// ============================================================================

PointerIntegerDiscriminator::PointerIntegerDiscriminator(Z3Context& ctx) : ctx_(ctx) {}

qvector<TypeConstraint> PointerIntegerDiscriminator::analyze_usage(
    TypeVariable var,
    const qvector<cexpr_t*>& usage_sites)
{
    qvector<TypeConstraint> constraints;
    
    // Check if used as memory base
    if (used_as_memory_base(var, usage_sites)) {
        constraints.push_back(
            TypeConstraint::make_is_pointer(var, BADADDR)
                .soft(weights_.memory_base_is_pointer)
                .describe("used as memory base suggests pointer")
        );
    }
    
    // Check if compared against small constants
    if (compared_against_small_const(var, usage_sites)) {
        constraints.push_back(
            TypeConstraint::make_is_integer(var, BADADDR)
                .soft(weights_.small_const_compare_is_int)
                .describe("small constant comparison suggests integer")
        );
    }
    
    // Check if used in arithmetic with large constants
    if (arithmetic_with_large_const(var, usage_sites)) {
        constraints.push_back(
            TypeConstraint::make_is_integer(var, BADADDR)
                .soft(weights_.large_const_arithmetic_is_int)
                .describe("large constant arithmetic suggests integer")
        );
    }
    
    return constraints;
}

bool PointerIntegerDiscriminator::used_as_memory_base(
    TypeVariable var,
    const qvector<cexpr_t*>& usage_sites) const
{
    for (const auto* site : usage_sites) {
        if (!site) continue;
        
        // Check if this expression is used as base of ptr dereference
        // This would require parent analysis which we don't have here
        // Simplified: check if the expression op is cot_ptr or has cot_ptr parent
        if (site->op == cot_ptr) {
            return true;
        }
    }
    return false;
}

bool PointerIntegerDiscriminator::compared_against_small_const(
    TypeVariable var,
    const qvector<cexpr_t*>& usage_sites) const
{
    for (const auto* site : usage_sites) {
        if (!site) continue;
        
        // Check comparison operations
        bool is_cmp = (site->op >= cot_eq && site->op <= cot_ult);
        if (!is_cmp) continue;
        
        // Check if other operand is small constant
        cexpr_t* other = nullptr;
        if (site->y && site->y->op == cot_num) {
            other = site->y;
        } else if (site->x && site->x->op == cot_num) {
            other = site->x;
        }
        
        if (other) {
            int64_t val = static_cast<int64_t>(other->numval());
            if (val >= -SMALL_CONST_THRESHOLD && val <= SMALL_CONST_THRESHOLD) {
                return true;
            }
        }
    }
    return false;
}

bool PointerIntegerDiscriminator::arithmetic_with_large_const(
    TypeVariable var,
    const qvector<cexpr_t*>& usage_sites) const
{
    for (const auto* site : usage_sites) {
        if (!site) continue;
        
        // Check arithmetic operations
        bool is_arith = (site->op == cot_add || site->op == cot_sub ||
                         site->op == cot_mul || site->op == cot_sdiv ||
                         site->op == cot_udiv);
        if (!is_arith) continue;
        
        // Check if other operand is large constant
        cexpr_t* other = nullptr;
        if (site->y && site->y->op == cot_num) {
            other = site->y;
        } else if (site->x && site->x->op == cot_num) {
            other = site->x;
        }
        
        if (other) {
            int64_t val = static_cast<int64_t>(other->numval());
            if (val < -LARGE_CONST_THRESHOLD || val > LARGE_CONST_THRESHOLD) {
                return true;
            }
        }
    }
    return false;
}

} // namespace structor::z3
