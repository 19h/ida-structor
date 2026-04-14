#pragma once

#include "config.hpp"

#include <unordered_set>

namespace structor {

struct HostIntegrationOptions {
    bool enable_global_rewrite_callback = true;
    bool enable_auto_type_fix_callback = true;
    bool clear_global_rewrites_on_shutdown = true;
};

/// Embeddable Hex-Rays integration for hosts that want Structor's callback-driven
/// behavior without going through Structor's plugin init path.
class HostIntegration {
public:
    explicit HostIntegration(HostIntegrationOptions options = {});
    ~HostIntegration();

    HostIntegration(const HostIntegration&) = delete;
    HostIntegration& operator=(const HostIntegration&) = delete;

    [[nodiscard]] bool install_hexrays_hooks();
    void uninstall_hexrays_hooks();
    void shutdown();

    void reset_processed_functions();

    void set_auto_type_fixing_suppressed(bool suppress) noexcept {
        auto_type_fixing_suppressed_ = suppress;
    }

    [[nodiscard]] bool auto_type_fixing_suppressed() const noexcept {
        return auto_type_fixing_suppressed_;
    }

    void handle_ctree_maturity(cfunc_t* cfunc, ctree_maturity_t maturity);
    void handle_func_printed(cfunc_t* cfunc);

private:
    static ssize_t idaapi hexrays_callback(void* ud, hexrays_event_t event, va_list va);
    void process_decompilation_complete(cfunc_t* cfunc);

    HostIntegrationOptions options_;
    bool hexrays_hooked_ = false;
    bool shutdown_ = false;
    bool auto_type_fixing_suppressed_ = false;
    std::unordered_set<ea_t> processed_functions_;
};

} // namespace structor
