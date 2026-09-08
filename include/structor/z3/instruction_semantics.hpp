#pragma once

#include <z3++.h>
#include "structor/z3/type_lattice.hpp"
#include "structor/z3/context.hpp"
#include "structor/z3/type_variable_identity.hpp"
#include "structor/synth_types.hpp"

#ifndef STRUCTOR_TESTING
#include <hexrays.hpp>
#endif

#include <optional>
#include <functional>
#include <unordered_map>
#include <unordered_set>

namespace structor::z3 {

// Forward declarations
class TypeConstraintSet;

/// A type variable representing an unknown type to be inferred
struct TypeVariable {
    int id;                      // Diagnostic index; never a semantic identity
    ea_t func_ea;                // Function containing this variable
    int var_idx;                 // Local variable index (-1 if not a local var)
    int ssa_version;             // SSA version for flow-sensitivity
    qstring name;                // Human-readable name
    TypeVariableIdentity identity; // Session identity, preserved when copied
    
    // Location info for memory variables
    std::optional<ea_t> mem_base;
    std::optional<sval_t> mem_offset;
    std::optional<uint32_t> mem_size;
    
    TypeVariable() : id(-1), func_ea(BADADDR), var_idx(-1), ssa_version(0),
                     identity(fresh_type_variable_identity()) {}
    
    /// Create an independent local variable. Copy it to share identity, or use
    /// InstructionSemanticsExtractor::get_var_type for exact key interning.
    static TypeVariable for_local(int id, ea_t func_ea, int var_idx, int version = 0);
    
    /// Create a type variable for a memory location
    static TypeVariable for_memory(int id, ea_t base, sval_t offset, uint32_t size);
    
    /// Create a type variable for a temporary expression
    static TypeVariable for_temp(int id, ea_t func_ea, const char* name);
    
    [[nodiscard]] bool is_local() const noexcept { return var_idx >= 0; }
    [[nodiscard]] bool is_memory() const noexcept { return mem_base.has_value(); }
    [[nodiscard]] bool is_temp() const noexcept { return !is_local() && !is_memory(); }
    
    bool operator==(const TypeVariable& other) const noexcept {
        return identity == other.identity;
    }
};

/// Hash for TypeVariable
struct TypeVariableHash {
    std::size_t operator()(const TypeVariable& tv) const noexcept {
        return TypeVariableIdentityHash{}(tv.identity);
    }
};

/// Origin of a generated constraint, independent of its strength or truth.
/// Caller-constructed constraints remain Unspecified unless explicitly tagged.
enum class TypeConstraintOrigin : std::uint8_t {
    Unspecified,
    InstructionUsage,
    DecompilerType,
    FunctionSignature,
    AliasRelation,
    Heuristic,
};

/// A type constraint relating one or more type variables
struct TypeConstraint {
    enum class Kind {
        // Equality constraints
        Equal,              // t1 == t2
        
        // Subtyping constraints
        Subtype,            // t1 <: t2 (t1 is subtype of t2)
        
        // Concrete type constraints
        IsBase,             // t == base_type
        IsPointer,          // t is some pointer type
        IsPointerTo,        // t == ptr(pointee_type)
        IsInteger,          // t is some integer type
        IsSigned,           // t is a signed integer
        IsUnsigned,         // t is an unsigned integer
        IsFloating,         // t is floating point
        
        // Size constraints
        HasSize,            // size(t) == n bytes
        
        // Disjunctive constraints
        OneOf,              // t in {t1, t2, ...}
        
        // Implication constraints (for path sensitivity)
        Implies,            // condition => constraint
    };
    
    Kind kind;
    TypeVariable var1;                           // Primary type variable
    std::optional<TypeVariable> var2;            // Secondary type variable (for Equal, Subtype)
    std::optional<InferredType> concrete_type;   // For IsBase, IsPointerTo, OneOf
    std::optional<uint32_t> size;                // For HasSize
    std::vector<InferredType> alternatives;      // For OneOf
    
    // Source tracking
    TypeConstraintOrigin origin = TypeConstraintOrigin::Unspecified;
    ea_t source_ea = BADADDR;
    qstring description;
    
    // Soft constraint info
    bool is_soft = false;
    int weight = 0;
    
    TypeConstraint() : kind(Kind::Equal) {}
    
    /// Factory methods
    static TypeConstraint make_equal(TypeVariable t1, TypeVariable t2, ea_t ea = BADADDR);
    static TypeConstraint make_subtype(TypeVariable sub, TypeVariable sup, ea_t ea = BADADDR);
    static TypeConstraint make_is_base(TypeVariable t, BaseType base, ea_t ea = BADADDR);
    static TypeConstraint make_is_pointer(TypeVariable t, ea_t ea = BADADDR);
    static TypeConstraint make_is_pointer_to(TypeVariable t, InferredType pointee, ea_t ea = BADADDR);
    static TypeConstraint make_is_integer(TypeVariable t, ea_t ea = BADADDR);
    static TypeConstraint make_is_signed(TypeVariable t, ea_t ea = BADADDR);
    static TypeConstraint make_is_unsigned(TypeVariable t, ea_t ea = BADADDR);
    static TypeConstraint make_is_floating(TypeVariable t, ea_t ea = BADADDR);
    static TypeConstraint make_has_size(TypeVariable t, uint32_t size, ea_t ea = BADADDR);
    static TypeConstraint make_one_of(TypeVariable t, std::vector<InferredType> types, ea_t ea = BADADDR);
    
    /// Set as a soft constraint. Nonpositive weights remain recorded but are
    /// inactive: they contribute neither an objective nor explicit candidates.
    TypeConstraint& soft(int w) {
        is_soft = true;
        weight = w;
        return *this;
    }
    
    /// Record the emission source; this does not change constraint semantics.
    TypeConstraint& sourced_from(TypeConstraintOrigin value) noexcept {
        origin = value;
        return *this;
    }

    /// Add description
    TypeConstraint& describe(const char* desc) {
        description = desc;
        return *this;
    }
};

/// Configuration for instruction semantics extraction
struct InstructionSemanticsConfig {
    bool extract_from_comparisons = true;    // Infer signedness from cmp patterns
    bool extract_from_casts = true;          // Extract constraints from type casts
    bool extract_from_arithmetic = true;     // Analyze arithmetic for int/float
    bool extract_from_memory_ops = true;     // Analyze pointer dereferences
    bool extract_from_calls = true;          // Use function signatures
    bool generate_soft_constraints = true;   // Generate preference constraints
    
    // Soft constraint weights
    int weight_from_decompiler = 10;         // Type from Hex-Rays
    int weight_from_signature = 20;          // Type from function signature
    int weight_signed_preference = 5;        // Prefer signed over unsigned
    int weight_int_for_small_const = 5;      // Small constant comparison -> int
};

/// Collects type constraints from ctree expressions
class InstructionSemanticsExtractor {
public:
    InstructionSemanticsExtractor(
        Z3Context& ctx,
        const InstructionSemanticsConfig& config = {}
    );
    
    /// Extract all type constraints in one expression-identity pass. The ctree
    /// must remain stable until this call returns; no node keys survive it.
    [[nodiscard]] TypeConstraintSet extract(cfunc_t* cfunc);
    
    /// Extract constraints for one expression in a fresh identity pass. Local,
    /// memory and named-variable identities persist for this extractor's life.
    [[nodiscard]] qvector<TypeConstraint> extract_expr(cexpr_t* expr, cfunc_t* cfunc);
    
    /// Get or create type variable for a local variable
    [[nodiscard]] TypeVariable get_var_type(cfunc_t* cfunc, int var_idx, int version = 0);
    
    /// Get or create type variable for a memory location
    [[nodiscard]] TypeVariable get_mem_type(ea_t base, sval_t offset, uint32_t size);
    
    /// Get or create type variable for a temporary expression
    [[nodiscard]] TypeVariable get_temp_type(ea_t func_ea, const char* name);
    
    /// Get the type encoder
    [[nodiscard]] TypeLatticeEncoder& type_encoder() noexcept { return encoder_; }
    
    /// Convert observed source type metadata without emitting a constraint.
    /// Unsupported observations are retained as detached diagnostics.
    [[nodiscard]] std::optional<InferredType> observe_type(const tinfo_t& type, ea_t site = BADADDR);
    [[nodiscard]] const std::vector<TypeConversionObservation>& unsupported_type_observations() const noexcept {
        return unsupported_type_observations_;
    }

    /// Get statistics
    struct Stats {
        int constraints_extracted = 0;
        int hard_constraints = 0;
        int soft_constraints = 0;
        int type_variables = 0;
        int expressions_analyzed = 0;
        int unresolved_memory_accesses = 0;
    };
    [[nodiscard]] const Stats& stats() const noexcept { return stats_; }

private:
    Z3Context& ctx_;
    TypeLatticeEncoder encoder_;
    InstructionSemanticsConfig config_;
    Stats stats_;
    std::vector<TypeConversionObservation> unsupported_type_observations_;
    
    // Type variable management
    int next_var_id_ = 0;
    TypeVariableInterner identities_;
    using VariableCache = std::unordered_map<TypeVariableIdentity, TypeVariable,
                                             TypeVariableIdentityHash>;
    VariableCache persistent_vars_;
    VariableCache expression_vars_;
    // Repeated uses of one concrete memory view do not multiply its weight.
    std::unordered_map<TypeVariableIdentity, std::vector<InferredType>,
                       TypeVariableIdentityHash> observed_memory_types_;
    
    // Current function being analyzed
    cfunc_t* current_cfunc_ = nullptr;
    ea_t current_func_ea_ = BADADDR;

    friend class ConstraintExtractionVisitor;
    [[nodiscard]] int allocate_diagnostic_id();
    void begin_expression_pass(cfunc_t* cfunc);
    void end_expression_pass();
    
    /// Analyze a specific ctree node
    void analyze_node(cexpr_t* expr, qvector<TypeConstraint>& constraints);
    
    /// Extract constraints from different expression types
    void extract_from_assignment(cexpr_t* expr, qvector<TypeConstraint>& constraints);
    void extract_from_ptr_deref(cexpr_t* expr, qvector<TypeConstraint>& constraints);
    void extract_from_comparison(cexpr_t* expr, qvector<TypeConstraint>& constraints);
    void extract_from_arithmetic(cexpr_t* expr, qvector<TypeConstraint>& constraints);
    void extract_from_cast(cexpr_t* expr, qvector<TypeConstraint>& constraints);
    void extract_from_call(cexpr_t* expr, qvector<TypeConstraint>& constraints);
    void extract_from_array_access(cexpr_t* expr, qvector<TypeConstraint>& constraints);
    void extract_from_member_access(cexpr_t* expr, qvector<TypeConstraint>& constraints);
    
    /// Infer type from expression's decompiler type
    [[nodiscard]] std::optional<InferredType> infer_from_tinfo(const tinfo_t& type, ea_t site);
    [[nodiscard]] std::optional<InferredType> observe_memory_type(const tinfo_t& type, ea_t site);
    
    /// Get type variable for an expression (creates temp if needed)
    [[nodiscard]] TypeVariable get_expr_type(cexpr_t* expr,
                                            qvector<TypeConstraint>& constraints);
    
    /// Check if comparison uses signed semantics (jl/jg vs jb/ja)
    [[nodiscard]] bool is_signed_comparison(ctype_t cmp_op) const noexcept;
    
    /// Check if comparison uses unsigned semantics
    [[nodiscard]] bool is_unsigned_comparison(ctype_t cmp_op) const noexcept;
    
};

/// Collection of type constraints for solving
class TypeConstraintSet {
public:
    TypeConstraintSet(Z3Context& ctx);
    
    /// Add a constraint
    void add(TypeConstraint constraint);
    
    /// Add multiple constraints
    void add_all(const qvector<TypeConstraint>& constraints);
    
    /// Clear all constraints
    void clear();
    
    /// Get all constraints
    [[nodiscard]] const qvector<TypeConstraint>& constraints() const noexcept {
        return constraints_;
    }
    
    /// Get all type variables referenced
    [[nodiscard]] const std::unordered_set<TypeVariable, TypeVariableHash>& variables() const noexcept {
        return variables_;
    }
    
    /// Convert to Z3 constraints
    [[nodiscard]] ::z3::expr_vector to_z3_hard(TypeLatticeEncoder& encoder) const;
    
    /// Convert soft constraints to Z3 with weights. If the caller has installed
    /// this set's hard constraints, exact hard facts may specialize predicates.
    [[nodiscard]] std::vector<std::pair<::z3::expr, int>> to_z3_soft(
        TypeLatticeEncoder& encoder, bool hard_constraints_installed = false) const;
    
    /// Get Z3 expression for a type variable
    [[nodiscard]] ::z3::expr get_z3_var(const TypeVariable& tv, TypeLatticeEncoder& encoder) const;
    
    /// Get statistics
    [[nodiscard]] std::size_t hard_count() const noexcept;
    [[nodiscard]] std::size_t soft_count() const noexcept;
    [[nodiscard]] std::size_t total_count() const noexcept { return constraints_.size(); }

private:
    Z3Context& ctx_;
    qvector<TypeConstraint> constraints_;
    std::unordered_set<TypeVariable, TypeVariableHash> variables_;
    
    mutable std::unordered_map<TypeVariableIdentity, ::z3::expr,
                               TypeVariableIdentityHash> var_cache_;
    
    using ConcreteBindings = std::unordered_map<TypeVariableIdentity,
        InferredType, TypeVariableIdentityHash>;
    using CandidateBindings = std::unordered_map<TypeVariableIdentity,
        std::vector<InferredType>, TypeVariableIdentityHash>;
    struct ConstraintEvidence {
        ConcreteBindings exact;
        CandidateBindings candidates;
    };
    [[nodiscard]] ConstraintEvidence constraint_evidence() const;

    /// Convert a single constraint to Z3
    [[nodiscard]] ::z3::expr constraint_to_z3(
        const TypeConstraint& c,
        TypeLatticeEncoder& encoder,
        const ConcreteBindings& bindings,
        const CandidateBindings& candidates
    ) const;
};

/// Visitor for extracting constraints from ctree
class ConstraintExtractionVisitor : public ctree_visitor_t {
public:
    ConstraintExtractionVisitor(
        InstructionSemanticsExtractor& extractor,
        qvector<TypeConstraint>& constraints
    );
    
    int idaapi visit_expr(cexpr_t* e) override;
    
private:
    InstructionSemanticsExtractor& extractor_;
    qvector<TypeConstraint>& constraints_;
};

/// Signedness inference from comparison patterns
/// Analyzes cmp followed by conditional jump to infer signed/unsigned
class SignednessInferrer {
public:
    SignednessInferrer(Z3Context& ctx);
    
    /// Analyze a comparison expression and infer signedness constraints
    [[nodiscard]] qvector<TypeConstraint> analyze_comparison(
        cexpr_t* cmp_expr,
        TypeVariable lhs_type,
        TypeVariable rhs_type
    );
    
    /// Analyze a conditional expression for signedness hints
    [[nodiscard]] qvector<TypeConstraint> analyze_conditional(
        cexpr_t* cond_expr,
        TypeVariable cond_type
    );
    
    /// Check if an operation implies signed semantics
    [[nodiscard]] bool implies_signed(ctype_t op) const noexcept;
    
    /// Check if an operation implies unsigned semantics
    [[nodiscard]] bool implies_unsigned(ctype_t op) const noexcept;

private:
    Z3Context& ctx_;
};

/// Pointer vs integer discriminator using heuristics
/// Generates soft constraints preferring pointer or integer based on usage patterns
class PointerIntegerDiscriminator {
public:
    PointerIntegerDiscriminator(Z3Context& ctx);
    
    /// Analyze usage of a variable and generate preference constraints
    [[nodiscard]] qvector<TypeConstraint> analyze_usage(
        TypeVariable var,
        const qvector<cexpr_t*>& usage_sites
    );
    
    /// Check if variable is used as memory base
    [[nodiscard]] bool used_as_memory_base(
        TypeVariable var,
        const qvector<cexpr_t*>& usage_sites
    ) const;
    
    /// Check if variable is compared against small constants
    [[nodiscard]] bool compared_against_small_const(
        TypeVariable var,
        const qvector<cexpr_t*>& usage_sites
    ) const;
    
    /// Check if variable is used in arithmetic with large constants
    [[nodiscard]] bool arithmetic_with_large_const(
        TypeVariable var,
        const qvector<cexpr_t*>& usage_sites
    ) const;
    
    /// Get soft constraint weights
    struct Weights {
        int memory_base_is_pointer = 15;
        int small_const_compare_is_int = 10;
        int large_const_arithmetic_is_int = 8;
    };
    void set_weights(const Weights& w) { weights_ = w; }

private:
    Z3Context& ctx_;
    Weights weights_;
    
    // Threshold for "small" constant
    static constexpr int64_t SMALL_CONST_THRESHOLD = 0x10000;
    
    // Threshold for "large" constant (likely not pointer arithmetic)
    static constexpr int64_t LARGE_CONST_THRESHOLD = 0x100000;
};

} // namespace structor::z3
