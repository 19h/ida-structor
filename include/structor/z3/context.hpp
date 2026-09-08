#pragma once

#include <z3++.h>
#include <memory>
#include <chrono>
#include <cstdint>
#include <vector>
#include <optional>

namespace structor::z3 {

// Forward declaration
class TypeEncoder;
class TypeLatticeEncoder;

/// Configuration for Z3 solver behavior
struct Z3Config {
    unsigned timeout_ms = 10000;          // Per-check limit; 0 means unlimited
    bool produce_unsat_cores = true;      // Solver setting; Optimize always enables cores
    bool produce_models = true;           // Solver setting; Optimize always enables models
    unsigned max_memory_mb = 0;           // Solver-local MiB limit; 0 means unlimited

    // Architecture-dependent settings (queried from IDA)
    uint32_t pointer_size = 8;            // 4 or 8 bytes
    uint32_t default_alignment = 8;       // Default struct alignment

    // Synthesis limits
    uint32_t max_struct_size = 0x10000;   // Maximum struct size (64KB)
    uint32_t max_candidates = 1000;       // Maximum candidate universe
    uint32_t max_fields = 4096;           // Maximum number of fields
    uint32_t max_array_elements = 1024;   // Maximum array elements to detect

    // Finite domain for recursive predicates over symbolic InferredType
    // expressions. Ground constructor terms retain exact finite semantics.
    unsigned max_symbolic_type_depth = 1;
    unsigned max_symbolic_type_list_length = 16;
    unsigned max_symbolic_type_expansions = 4096; // Type/list builder steps
};

/// RAII wrapper for Z3 context with Structor-specific configuration
class Z3Context {
public:
    explicit Z3Context(const Z3Config& config = {});
    ~Z3Context();

    // Non-copyable, movable
    Z3Context(const Z3Context&) = delete;
    Z3Context& operator=(const Z3Context&) = delete;
    Z3Context(Z3Context&&) noexcept;
    Z3Context& operator=(Z3Context&&) noexcept;

    /// Access underlying Z3 context
    [[nodiscard]] ::z3::context& ctx() noexcept { return *ctx_; }
    [[nodiscard]] const ::z3::context& ctx() const noexcept { return *ctx_; }

    /// Create a solver with all supported resource/result controls applied
    /// directly to the solver. No Z3 global parameters are modified.
    [[nodiscard]] ::z3::solver make_solver();

    /// Create an optimizer with its supported local controls applied. Bundled
    /// Z3 exposes no optimizer-local memory limit, so a nonzero configured cap
    /// is rejected rather than silently ignored.
    [[nodiscard]] ::z3::optimize make_optimizer();

    /// Common sorts used in struct synthesis (all use Int, not BitVec)
    [[nodiscard]] ::z3::sort int_sort();      // Unbounded integers for offsets/sizes
    [[nodiscard]] ::z3::sort bool_sort();     // Boolean for field selection

    /// Create bounded integer variable with explicit constraints
    /// Adds: 0 <= var <= max_struct_size
    [[nodiscard]] ::z3::expr make_offset_var(const char* name);
    [[nodiscard]] ::z3::expr make_size_var(const char* name);

    /// Create boolean variable for field selection
    [[nodiscard]] ::z3::expr make_bool_var(const char* name);

    /// Create integer constant
    [[nodiscard]] ::z3::expr int_val(int64_t v);
    [[nodiscard]] ::z3::expr uint_val(uint64_t v);

    /// Create boolean constants
    [[nodiscard]] ::z3::expr bool_val(bool v);

    /// Get configuration
    [[nodiscard]] const Z3Config& config() const noexcept { return config_; }

    /// Get max struct size constraint expression
    [[nodiscard]] ::z3::expr max_struct_size_expr();

    /// Get pointer size from config
    [[nodiscard]] uint32_t pointer_size() const noexcept { return config_.pointer_size; }

    /// Get default alignment from config
    [[nodiscard]] uint32_t default_alignment() const noexcept { return config_.default_alignment; }

    /// Get or create the shared TypeEncoder for this context
    /// This ensures enumeration sorts are only created once per context
    [[nodiscard]] TypeEncoder& type_encoder();

    /// Apply bounds constraints to an offset variable
    void add_offset_bounds(::z3::solver& solver, const ::z3::expr& var);
    void add_offset_bounds(::z3::optimize& opt, const ::z3::expr& var);

    /// Check if a result indicates timeout
    [[nodiscard]] static bool is_timeout(::z3::check_result result) noexcept {
        return result == ::z3::unknown;
    }

    /// Get reason for unknown result
    [[nodiscard]] static std::string get_unknown_reason(const ::z3::solver& s);

private:
    // Keep the immutable configuration before objects constructed from it.
    // Declaration order, not initializer-list spelling, controls construction.
    Z3Config config_;
    std::unique_ptr<::z3::context> ctx_;

    /// Shared TypeEncoder - lazily initialized to avoid circular dependency
    std::unique_ptr<TypeEncoder> type_encoder_;

    // All lattice encoders in one context share the same enum declaration.
    // Keep its owning ASTs after ctx_ so they are destroyed before the context.
    struct TypeLatticeSortCache {
        ::z3::sort base_sort;
        std::vector<::z3::expr> base_constants;
        std::optional<::z3::sort> type_sort;
        std::optional<::z3::sort> list_sort;
        std::vector<::z3::func_decl> constructors;
        std::vector<::z3::func_decl> recognizers;
        std::vector<std::vector<::z3::func_decl>> accessors;
        std::optional<::z3::func_decl> subtype;
        std::optional<::z3::func_decl> list_subtype;
        std::optional<::z3::func_decl> source_sum_subtype;
        std::optional<::z3::func_decl> target_sum_subtype;
        std::optional<::z3::func_decl> compatible;
        std::optional<::z3::func_decl> sum_compatible;
        std::optional<::z3::func_decl> same_list_length;
        std::optional<::z3::func_decl> byte_size;
        std::optional<::z3::func_decl> sum_byte_size;

        TypeLatticeSortCache(const ::z3::sort& sort,
                             const std::vector<::z3::expr>& constants)
            : base_sort(sort), base_constants(constants) {}
    };
    std::unique_ptr<TypeLatticeSortCache> type_lattice_sorts_;
    friend class TypeLatticeEncoder;

};

/// Helper to measure Z3 solving time
class SolveTimer {
public:
    SolveTimer() : start_(std::chrono::steady_clock::now()) {}

    [[nodiscard]] std::chrono::milliseconds elapsed() const {
        auto now = std::chrono::steady_clock::now();
        return std::chrono::duration_cast<std::chrono::milliseconds>(now - start_);
    }

private:
    std::chrono::steady_clock::time_point start_;
};

} // namespace structor::z3
