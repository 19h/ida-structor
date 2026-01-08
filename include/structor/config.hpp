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

private:
    Config() = default;
    ~Config() = default;
    Config(const Config&) = delete;
    Config& operator=(const Config&) = delete;

    SynthOptions options_;
    bool dirty_ = false;

    static constexpr const char* NETNODE_NAME = "$ structor_config";
    static constexpr nodeidx_t BLOB_TAG = 'S';
};

// ============================================================================
// Implementation
// ============================================================================

inline bool Config::load() {
    netnode node(NETNODE_NAME, 0, false);
    if (node == BADNODE) {
        // No saved config, use defaults
        return true;
    }

    // Load blob data
    size_t blob_size = 0;
    void* blob = node.getblob(nullptr, &blob_size, 0, BLOB_TAG);
    if (!blob || blob_size == 0) {
        return true;
    }

    // Parse configuration from blob
    const char* data = static_cast<const char*>(blob);
    const char* end = data + blob_size;

    auto read_bool = [&]() -> bool {
        if (data >= end) return false;
        return *data++ != 0;
    };

    auto read_int = [&]() -> int {
        if (data + 4 > end) return 0;
        int val;
        std::memcpy(&val, data, 4);
        data += 4;
        return val;
    };

    auto read_string = [&]() -> qstring {
        qstring result;
        while (data < end && *data != '\0') {
            result.append(*data++);
        }
        if (data < end) ++data; // skip null terminator
        return result;
    };

    // Read version marker
    int version = read_int();
    if (version < 1) {
        qfree(blob);
        return true;
    }

    options_.hotkey = read_string();
    options_.auto_propagate = read_bool();
    options_.vtable_detection = read_bool();
    options_.min_accesses = read_int();
    options_.alignment = read_int();
    options_.interactive_mode = read_bool();
    options_.highlight_changes = read_bool();
    options_.highlight_duration_ms = read_int();
    options_.auto_open_struct = read_bool();
    options_.generate_comments = read_bool();
    options_.max_propagation_depth = read_int();
    options_.propagate_to_callers = read_bool();
    options_.propagate_to_callees = read_bool();

    qfree(blob);
    dirty_ = false;
    return true;
}

inline bool Config::save() {
    netnode node(NETNODE_NAME, 0, true);
    if (node == BADNODE) {
        return false;
    }

    // Build blob data
    qvector<char> blob;

    auto write_bool = [&](bool val) {
        blob.push_back(val ? 1 : 0);
    };

    auto write_int = [&](int val) {
        const char* p = reinterpret_cast<const char*>(&val);
        for (int i = 0; i < 4; ++i) {
            blob.push_back(p[i]);
        }
    };

    auto write_string = [&](const qstring& str) {
        for (size_t i = 0; i < str.length(); ++i) {
            blob.push_back(str[i]);
        }
        blob.push_back('\0');
    };

    // Version marker
    write_int(1);

    write_string(options_.hotkey);
    write_bool(options_.auto_propagate);
    write_bool(options_.vtable_detection);
    write_int(options_.min_accesses);
    write_int(options_.alignment);
    write_bool(options_.interactive_mode);
    write_bool(options_.highlight_changes);
    write_int(options_.highlight_duration_ms);
    write_bool(options_.auto_open_struct);
    write_bool(options_.generate_comments);
    write_int(options_.max_propagation_depth);
    write_bool(options_.propagate_to_callers);
    write_bool(options_.propagate_to_callees);

    node.setblob(blob.begin(), blob.size(), 0, BLOB_TAG);
    dirty_ = false;
    return true;
}

inline void Config::reset() {
    options_ = SynthOptions();
    dirty_ = true;
}

} // namespace structor
