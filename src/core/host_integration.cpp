#include <structor/host_integration.hpp>

#include <structor/global_object_analyzer.hpp>
#include <structor/type_fixer.hpp>

namespace structor {

namespace {

void print_type_fix_messages(const TypeFixResult& result, bool include_diagnostics) {
    for (const auto& warning : result.warnings) {
        msg("Structor: %s\n", warning.c_str());
    }

    if (!include_diagnostics) {
        return;
    }

    for (const auto& diagnostic : result.diagnostics) {
        msg("Structor: diagnostic: %s\n", diagnostic.c_str());
    }
}

} // namespace

HostIntegration::HostIntegration(HostIntegrationOptions options)
    : options_(options) {}

HostIntegration::~HostIntegration() {
    shutdown();
}

bool HostIntegration::install_hexrays_hooks() {
    if (hexrays_hooked_) {
        return true;
    }

    if (!install_hexrays_callback(hexrays_callback, this)) {
        return false;
    }

    hexrays_hooked_ = true;
    return true;
}

void HostIntegration::uninstall_hexrays_hooks() {
    if (!hexrays_hooked_) {
        return;
    }

    remove_hexrays_callback(hexrays_callback, this);
    hexrays_hooked_ = false;
}

void HostIntegration::shutdown() {
    if (shutdown_) {
        return;
    }

    shutdown_ = true;
    uninstall_hexrays_hooks();
    processed_functions_.clear();

    if (options_.clear_global_rewrites_on_shutdown) {
        clear_registered_global_rewrite_info();
    }
}

void HostIntegration::reset_processed_functions() {
    processed_functions_.clear();
}

void HostIntegration::handle_ctree_maturity(cfunc_t* cfunc, ctree_maturity_t maturity) {
    if (!cfunc || maturity != CMAT_FINAL || !options_.enable_global_rewrite_callback) {
        return;
    }

    if (Config::instance().options().debug_mode) {
        qstring func_name;
        get_func_name(&func_name, cfunc->entry_ea);
        msg("Structor: hxe_maturity final for %s\n", func_name.c_str());
    }

    (void)rewrite_registered_global_uses(cfunc);
}

void HostIntegration::handle_func_printed(cfunc_t* cfunc) {
    if (!cfunc || !options_.enable_auto_type_fix_callback) {
        return;
    }

    if (!Config::instance().options().auto_fix_types || auto_type_fixing_suppressed_) {
        return;
    }

    process_decompilation_complete(cfunc);
}

ssize_t idaapi HostIntegration::hexrays_callback(void* ud, hexrays_event_t event, va_list va) {
    auto* self = static_cast<HostIntegration*>(ud);
    if (!self) {
        return 0;
    }

    switch (event) {
        case hxe_maturity: {
            cfunc_t* cfunc = va_arg(va, cfunc_t*);
            ctree_maturity_t maturity = va_argi(va, ctree_maturity_t);
            self->handle_ctree_maturity(cfunc, maturity);
            break;
        }
        case hxe_func_printed: {
            cfunc_t* cfunc = va_arg(va, cfunc_t*);
            self->handle_func_printed(cfunc);
            break;
        }
        default:
            break;
    }

    return 0;
}

void HostIntegration::process_decompilation_complete(cfunc_t* cfunc) {
    if (!cfunc) {
        return;
    }

    const ea_t func_ea = cfunc->entry_ea;
    if (processed_functions_.count(func_ea) > 0) {
        return;
    }
    processed_functions_.insert(func_ea);

    if (Config::instance().options().debug_mode) {
        qstring func_name;
        get_func_name(&func_name, func_ea);
        msg("Structor: Processing function %s (0x%llx)\n",
            func_name.c_str(), static_cast<unsigned long long>(func_ea));
    }

    TypeFixerConfig fix_config;
    fix_config.dry_run = false;
    // Function-entry type fixing must not create Local Types. Manual synthesis
    // remains responsible for creating or updating recovered structures.
    fix_config.synthesize_structures = false;
    fix_config.propagate_fixes = Config::instance().options().auto_propagate;
    fix_config.max_propagation_depth = Config::instance().options().max_propagation_depth;
    fix_config.collect_missing_argument_warnings = false;

    TypeFixer fixer(fix_config);
    TypeFixResult result = fixer.fix_function_types(cfunc);

    const bool verbose = Config::instance().options().auto_fix_verbose;
    const bool debug = Config::instance().options().debug_mode;
    if (debug) {
        msg("Structor: %s - analyzed %u vars, %u differences, %u fixed\n",
            result.func_name.c_str(),
            result.analyzed,
            result.differences_found,
            result.fixes_applied);
    }

    print_type_fix_messages(result, debug);

    if (verbose && result.fixes_applied > 0) {
        msg("Structor: Auto-fixed %u types in %s\n",
            result.fixes_applied,
            result.func_name.c_str());

        for (const auto& fix : result.variable_fixes) {
            if (fix.applied) {
                msg("  - %s: %s\n",
                    fix.var_name.c_str(),
                    fix.comparison.description.c_str());
            }
        }
    }
}

} // namespace structor
