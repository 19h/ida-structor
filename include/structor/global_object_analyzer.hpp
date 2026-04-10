#pragma once

#include "config.hpp"
#include "cross_function_analyzer.hpp"

#include <unordered_map>

namespace structor {

struct GlobalObjectAnalysis {
    ea_t root_ea = BADADDR;
    ea_t root_head_ea = BADADDR;
    qstring root_name;
    UnifiedAccessPattern pattern;
    qvector<ea_t> touched_functions;
    qvector<FunctionVariable> zero_delta_variables;
    std::unordered_map<ea_t, sval_t> pointer_alias_globals;
};

/// Recovers structure evidence rooted at a global/static storage address.
class GlobalObjectAnalyzer {
public:
    explicit GlobalObjectAnalyzer(const SynthOptions& opts = Config::instance().options())
        : options_(opts) {}

    [[nodiscard]] GlobalObjectAnalysis analyze(ea_t root_ea);

private:
    const SynthOptions& options_;
};

void register_global_rewrite_info(
    const GlobalObjectAnalysis& analysis,
    const SynthStruct& synth_struct,
    const tinfo_t& struct_type);

[[nodiscard]] bool rewrite_registered_global_uses(cfunc_t* cfunc);

void clear_registered_global_rewrite_info();

} // namespace structor
