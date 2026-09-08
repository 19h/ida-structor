#include "structor/z3/context.hpp"

#include <array>
#include <charconv>
#include <stdexcept>
#include <system_error>
#include "structor/z3/type_encoding.hpp"
#include <limits>
#include <stdexcept>

#ifndef STRUCTOR_TESTING
#include <pro.h>
#include <kernwin.hpp>
#endif

namespace structor::z3 {

namespace {
    // Helper for conditional logging
    inline void z3_log(const char* fmt, ...) {
#ifndef STRUCTOR_TESTING
        va_list va;
        va_start(va, fmt);
        vmsg(fmt, va);
        va_end(va);
#endif
    }
}

Z3Context::Z3Context(const Z3Config& config)
    : config_(config)
    , ctx_(std::make_unique<::z3::context>()) {
    z3_log("[Structor/Z3] Initializing Z3 context (timeout=%ums, memory=%uMiB, ptr_size=%u)\n",
           config_.timeout_ms, config_.max_memory_mb, config_.pointer_size);
}

Z3Context::~Z3Context() = default;

Z3Context::Z3Context(Z3Context&& other) noexcept
    : config_(other.config_)
    , ctx_(std::move(other.ctx_))
    , type_encoder_(std::move(other.type_encoder_))
    , type_lattice_sorts_(std::move(other.type_lattice_sorts_)) {
    if (type_encoder_) type_encoder_->ctx_ = this;
}
Z3Context& Z3Context::operator=(Z3Context&& other) noexcept {
    if (this != &other) {
        // Release context-owned AST caches before replacing their context.
        type_encoder_.reset();
        type_lattice_sorts_.reset();
        ctx_ = std::move(other.ctx_);
        config_ = other.config_;
        type_encoder_ = std::move(other.type_encoder_);
        if (type_encoder_) type_encoder_->ctx_ = this;
        type_lattice_sorts_ = std::move(other.type_lattice_sorts_);
    }
    return *this;
}

::z3::solver Z3Context::make_solver() {
    ::z3::solver s(*ctx_);
    ::z3::params p(*ctx_);

    // These are solver-instance parameters in Z3 4.15.4. Timeout is measured
    // in milliseconds. max_memory is measured in MiB and uses UINT_MAX as its
    // unlimited value. Set that value explicitly for Structor's zero sentinel
    // so a process-global Z3 default cannot reintroduce a cap.
    p.set("timeout", config_.timeout_ms);
    p.set("max_memory", config_.max_memory_mb == 0
                            ? std::numeric_limits<unsigned>::max()
                            : config_.max_memory_mb);
    p.set("unsat_core", config_.produce_unsat_cores);
    p.set("model", config_.produce_models);
    s.set(p);

    return s;
}

::z3::optimize Z3Context::make_optimizer() {
    if (config_.max_memory_mb != 0) {
        throw std::invalid_argument(
            "configured memory limit cannot be enforced by the Z3 optimizer");
    }
    ::z3::optimize opt(*ctx_);
    ::z3::params p(*ctx_);

    // Z3 4.15.4 Optimize validates against opt_context's parameter
    // descriptors. Of Structor's controls, only timeout is accepted locally.
    // Supplying max_memory, model, or unsat_core would raise Z3_INVALID_ARG;
    // using process-global parameters instead would couple independent contexts.
    p.set("timeout", config_.timeout_ms);
    opt.set(p);

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
    std::array<char, 32> decimal{};
    const auto converted = std::to_chars(
        decimal.data(), decimal.data() + decimal.size() - 1, v);
    if (converted.ec != std::errc{}) {
        throw std::runtime_error("failed to encode unsigned Z3 integer");
    }
    *converted.ptr = '\0';
    return ctx_->int_val(decimal.data());
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

TypeEncoder& Z3Context::type_encoder() {
    // Lazily initialize the TypeEncoder to avoid duplicate enumeration sort creation
    if (!type_encoder_) {
        type_encoder_ = std::make_unique<TypeEncoder>(*this);
    }
    return *type_encoder_;
}

} // namespace structor::z3
