#pragma once

#include "synth_types.hpp"
#include <cstring>
#include <fstream>
#include <filesystem>

namespace structor {

/// Access filter predicate type (adopted from Suture)
/// Returns true if the access should be included in synthesis
using AccessPredicate = std::function<bool(const FieldAccess&)>;

/// Built-in access predicates (adopted from Suture's predicate pattern)
namespace predicates {
    /// Accept all accesses
    inline bool accept_all(const FieldAccess&) { return true; }

    /// Only accept function pointer accesses
    inline bool funcptr_only(const FieldAccess& access) {
        return access.semantic_type == SemanticType::FunctionPointer ||
               access.semantic_type == SemanticType::VTablePointer ||
               access.access_type == AccessType::Call;
    }

    /// Only accept pointer accesses
    inline bool pointer_only(const FieldAccess& access) {
        return access.semantic_type == SemanticType::Pointer ||
               access.semantic_type == SemanticType::FunctionPointer ||
               access.semantic_type == SemanticType::VTablePointer;
    }

    /// Only accept non-vtable accesses
    inline bool exclude_vtable(const FieldAccess& access) {
        return !access.is_vtable_access;
    }

    /// Only accept accesses at positive offsets
    inline bool positive_offsets_only(const FieldAccess& access) {
        return access.offset >= 0;
    }

    /// Only accept accesses within a size range
    inline AccessPredicate size_range(std::uint32_t min_size, std::uint32_t max_size) {
        return [min_size, max_size](const FieldAccess& access) {
            return access.size >= min_size && access.size <= max_size;
        };
    }

    /// Only accept accesses within an offset range
    inline AccessPredicate offset_range(sval_t min_offset, sval_t max_offset) {
        return [min_offset, max_offset](const FieldAccess& access) {
            return access.offset >= min_offset && access.offset < max_offset;
        };
    }

    /// Combine predicates with AND
    inline AccessPredicate all_of(std::initializer_list<AccessPredicate> preds) {
        qvector<AccessPredicate> pred_vec;
        for (const auto& p : preds) pred_vec.push_back(p);
        return [pred_vec](const FieldAccess& access) {
            for (const auto& p : pred_vec) {
                if (!p(access)) return false;
            }
            return true;
        };
    }

    /// Combine predicates with OR
    inline AccessPredicate any_of(std::initializer_list<AccessPredicate> preds) {
        qvector<AccessPredicate> pred_vec;
        for (const auto& p : preds) pred_vec.push_back(p);
        return [pred_vec](const FieldAccess& access) {
            for (const auto& p : pred_vec) {
                if (p(access)) return true;
            }
            return false;
        };
    }
}

/// Configuration options for structure synthesis
struct SynthOptions {
    qstring         hotkey;             // Activation hotkey
    bool            auto_propagate;     // Auto-propagate types after synthesis
    bool            vtable_detection;   // Enable vtable pattern recognition
    int             min_accesses;       // Minimum access count to trigger synthesis
    int             alignment;          // Default structure alignment
    bool            interactive_mode;   // Prompt user before applying changes
    bool            highlight_changes;  // Highlight transformed expressions
    int             highlight_duration_ms;  // Duration of highlight in milliseconds
    bool            auto_open_struct;   // Auto-open structure view
    bool            generate_comments;  // Generate field comments
    int             max_propagation_depth;  // Maximum propagation depth
    bool            propagate_to_callers;   // Backward propagation
    bool            propagate_to_callees;   // Forward propagation
    bool            debug_mode;         // Enable debug logging (adopted from Suture)
    AccessPredicate access_filter;      // Filter predicate for accesses (adopted from Suture)

    SynthOptions()
        : hotkey(DEFAULT_HOTKEY)
        , auto_propagate(true)
        , vtable_detection(true)
        , min_accesses(2)
        , alignment(8)
        , interactive_mode(false)
        , highlight_changes(true)
        , highlight_duration_ms(2000)
        , auto_open_struct(true)
        , generate_comments(true)
        , max_propagation_depth(3)
        , propagate_to_callers(true)
        , propagate_to_callees(true)
        , debug_mode(false)
        , access_filter(predicates::accept_all) {}
};

/// Configuration manager for the plugin
class Config {
public:
    static Config& instance() {
        static Config cfg;
        return cfg;
    }

    /// Load configuration from IDB netnode or file
    bool load();

    /// Save configuration to IDB netnode
    bool save();

    /// Reset to defaults
    void reset();

    /// Get current options (read-only)
    [[nodiscard]] const SynthOptions& options() const noexcept {
        return options_;
    }

    /// Get mutable options for modification
    [[nodiscard]] SynthOptions& mutable_options() noexcept {
        dirty_ = true;
        return options_;
    }

    /// Check if configuration has unsaved changes
    [[nodiscard]] bool is_dirty() const noexcept {
        return dirty_;
    }

    /// Mark configuration as saved
    void mark_clean() noexcept {
        dirty_ = false;
    }

    // Convenience accessors
    [[nodiscard]] const char* hotkey() const noexcept { return options_.hotkey.c_str(); }
    [[nodiscard]] bool auto_propagate() const noexcept { return options_.auto_propagate; }
    [[nodiscard]] bool vtable_detection() const noexcept { return options_.vtable_detection; }
    [[nodiscard]] int min_accesses() const noexcept { return options_.min_accesses; }
    [[nodiscard]] int alignment() const noexcept { return options_.alignment; }
    [[nodiscard]] bool interactive_mode() const noexcept { return options_.interactive_mode; }
    [[nodiscard]] bool highlight_changes() const noexcept { return options_.highlight_changes; }
    [[nodiscard]] int highlight_duration_ms() const noexcept { return options_.highlight_duration_ms; }
    [[nodiscard]] bool auto_open_struct() const noexcept { return options_.auto_open_struct; }
    [[nodiscard]] bool generate_comments() const noexcept { return options_.generate_comments; }
    [[nodiscard]] int max_propagation_depth() const noexcept { return options_.max_propagation_depth; }
    [[nodiscard]] bool propagate_to_callers() const noexcept { return options_.propagate_to_callers; }
    [[nodiscard]] bool propagate_to_callees() const noexcept { return options_.propagate_to_callees; }

    /// Get config file path
    [[nodiscard]] static std::filesystem::path config_path() {
        const char* home = getenv("HOME");
        if (!home) home = getenv("USERPROFILE");  // Windows fallback
        if (!home) return {};
        return std::filesystem::path(home) / ".idapro" / "structor.cfg";
    }

private:
    Config() = default;
    ~Config() = default;
    Config(const Config&) = delete;
    Config& operator=(const Config&) = delete;

    static std::string trim(const std::string& s) {
        size_t start = s.find_first_not_of(" \t\r\n");
        if (start == std::string::npos) return "";
        size_t end = s.find_last_not_of(" \t\r\n");
        return s.substr(start, end - start + 1);
    }

    static bool parse_bool(const std::string& s) {
        std::string lower = s;
        for (auto& c : lower) c = static_cast<char>(std::tolower(c));
        return lower == "true" || lower == "1" || lower == "yes";
    }

    SynthOptions options_;
    bool dirty_ = false;
};

// ============================================================================
// Implementation
// ============================================================================

inline bool Config::load() {
    auto path = config_path();
    if (path.empty()) return true;

    std::ifstream file(path);
    if (!file.is_open()) {
        // No config file, use defaults
        return true;
    }

    std::string line;
    while (std::getline(file, line)) {
        line = trim(line);
        
        // Skip empty lines and comments
        if (line.empty() || line[0] == '#' || line[0] == ';' || line[0] == '[') {
            continue;
        }

        // Parse key=value
        auto eq_pos = line.find('=');
        if (eq_pos == std::string::npos) continue;

        std::string key = trim(line.substr(0, eq_pos));
        std::string value = trim(line.substr(eq_pos + 1));

        // Remove inline comments
        auto comment_pos = value.find('#');
        if (comment_pos != std::string::npos) {
            value = trim(value.substr(0, comment_pos));
        }

        // Map keys to options
        if (key == "hotkey") {
            options_.hotkey = value.c_str();
        } else if (key == "auto_propagate") {
            options_.auto_propagate = parse_bool(value);
        } else if (key == "vtable_detection") {
            options_.vtable_detection = parse_bool(value);
        } else if (key == "min_accesses") {
            options_.min_accesses = std::stoi(value);
        } else if (key == "alignment") {
            options_.alignment = std::stoi(value);
        } else if (key == "interactive_mode") {
            options_.interactive_mode = parse_bool(value);
        } else if (key == "highlight_changes") {
            options_.highlight_changes = parse_bool(value);
        } else if (key == "highlight_duration_ms") {
            options_.highlight_duration_ms = std::stoi(value);
        } else if (key == "auto_open_struct") {
            options_.auto_open_struct = parse_bool(value);
        } else if (key == "generate_comments") {
            options_.generate_comments = parse_bool(value);
        } else if (key == "max_propagation_depth") {
            options_.max_propagation_depth = std::stoi(value);
        } else if (key == "propagate_to_callers") {
            options_.propagate_to_callers = parse_bool(value);
        } else if (key == "propagate_to_callees") {
            options_.propagate_to_callees = parse_bool(value);
        } else if (key == "debug_mode") {
            options_.debug_mode = parse_bool(value);
        }
    }

    dirty_ = false;
    return true;
}

inline bool Config::save() {
    auto path = config_path();
    if (path.empty()) return false;

    // Ensure directory exists
    std::filesystem::create_directories(path.parent_path());

    std::ofstream file(path);
    if (!file.is_open()) {
        return false;
    }

    file << "# Structor Configuration\n";
    file << "# See https://github.com/AnomalyCo/structor for documentation\n\n";

    file << "[General]\n";
    file << "hotkey=" << options_.hotkey.c_str() << "\n";
    file << "interactive_mode=" << (options_.interactive_mode ? "true" : "false") << "\n";
    file << "auto_open_struct=" << (options_.auto_open_struct ? "true" : "false") << "\n";
    file << "debug_mode=" << (options_.debug_mode ? "true" : "false") << "\n";
    file << "\n";

    file << "[Synthesis]\n";
    file << "min_accesses=" << options_.min_accesses << "\n";
    file << "alignment=" << options_.alignment << "\n";
    file << "vtable_detection=" << (options_.vtable_detection ? "true" : "false") << "\n";
    file << "\n";

    file << "[Propagation]\n";
    file << "auto_propagate=" << (options_.auto_propagate ? "true" : "false") << "\n";
    file << "propagate_to_callers=" << (options_.propagate_to_callers ? "true" : "false") << "\n";
    file << "propagate_to_callees=" << (options_.propagate_to_callees ? "true" : "false") << "\n";
    file << "max_propagation_depth=" << options_.max_propagation_depth << "\n";
    file << "\n";

    file << "[UI]\n";
    file << "highlight_changes=" << (options_.highlight_changes ? "true" : "false") << "\n";
    file << "highlight_duration_ms=" << options_.highlight_duration_ms << "\n";
    file << "generate_comments=" << (options_.generate_comments ? "true" : "false") << "\n";

    dirty_ = false;
    return true;
}

inline void Config::reset() {
    options_ = SynthOptions();
    dirty_ = true;
}

} // namespace structor
