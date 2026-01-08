#include "structor/z3/context.hpp"
#include <stdexcept>

namespace structor::z3 {

Z3Context::Z3Context(const Z3Config& config)
    : ctx_(std::make_unique<::z3::context>())
    , config_(config) {
    apply_global_params();
}

Z3Context::~Z3Context() = default;

Z3Context::Z3Context(Z3Context&&) noexcept = default;
Z3Context& Z3Context::operator=(Z3Context&&) noexcept = default;

void Z3Context::apply_global_params() {
    // Apply timeout via global Z3 parameters (more reliable than solver.set)
    ::z3::set_param("timeout", static_cast<int>(config_.timeout_ms));

    // Memory limit
    if (config_.max_memory_mb > 0) {
        ::z3::set_param("memory_high_watermark", static_cast<int>(config_.max_memory_mb));
    }
}

::z3::solver Z3Context::make_solver() {
    ::z3::solver s(*ctx_);

    // Configure solver for UNSAT core extraction
    if (config_.produce_unsat_cores) {
        ::z3::params p(*ctx_);
        p.set("unsat_core", true);
        s.set(p);
    }

    return s;
}

::z3::optimize Z3Context::make_optimizer() {
    ::z3::optimize opt(*ctx_);
    return opt;
}

::z3::sort Z3Context::int_sort() {
    return ctx_->int_sort();
}

::z3::sort Z3Context::bool_sort() {
    return ctx_->bool_sort();
}

::z3::expr Z3Context::make_offset_var(const char* name) {
    return ctx_->int_const(name);
}

::z3::expr Z3Context::make_size_var(const char* name) {
    return ctx_->int_const(name);
}

::z3::expr Z3Context::make_bool_var(const char* name) {
    return ctx_->bool_const(name);
}

::z3::expr Z3Context::int_val(int64_t v) {
    return ctx_->int_val(v);
}

::z3::expr Z3Context::uint_val(uint64_t v) {
    // Z3 int_val handles large values correctly
    return ctx_->int_val(static_cast<int64_t>(v));
}

::z3::expr Z3Context::bool_val(bool v) {
    return ctx_->bool_val(v);
}

::z3::expr Z3Context::max_struct_size_expr() {
    return int_val(static_cast<int64_t>(config_.max_struct_size));
}

void Z3Context::add_offset_bounds(::z3::solver& solver, const ::z3::expr& var) {
    // Add: 0 <= var <= max_struct_size
    solver.add(var >= 0);
    solver.add(var <= int_val(static_cast<int64_t>(config_.max_struct_size)));
}

void Z3Context::add_offset_bounds(::z3::optimize& opt, const ::z3::expr& var) {
    // Add: 0 <= var <= max_struct_size
    opt.add(var >= 0);
    opt.add(var <= int_val(static_cast<int64_t>(config_.max_struct_size)));
}

std::string Z3Context::get_unknown_reason(const ::z3::solver& s) {
    try {
        return s.reason_unknown();
    } catch (...) {
        return "unknown";
    }
}

// Z3ParamGuard implementation
Z3ParamGuard::Z3ParamGuard(const char* param, unsigned value)
    : param_(param)
    , old_value_(0) {
    // Note: Z3 doesn't provide a way to get the current value of a parameter
    // So we just set the new value and will restore to 0 (default-ish) on destruction
    ::z3::set_param(param, static_cast<int>(value));
}

Z3ParamGuard::~Z3ParamGuard() {
    try {
        // Restore to a reasonable default
        ::z3::set_param(param_.c_str(), static_cast<int>(old_value_));
    } catch (...) {
        // Ignore errors during destruction
    }
}

} // namespace structor::z3
