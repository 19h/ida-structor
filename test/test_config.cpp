/// @file test_config.cpp
/// @brief Unit tests for configuration system

#include <gtest/gtest.h>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <optional>
#include <string>
#include "mock_ida.hpp"

#define __HEXRAYS_HPP
#define __TYPEINF_HPP
#define __PRO_H
#define __IDA_HPP
#define __IDP_HPP
#define __LOADER_HPP
#define __KERNWIN_HPP
#define __STRUCT_HPP
#define __ENUM_HPP
#define __NAME_HPP
#define __BYTES_HPP
#define __FUNCS_HPP
#define __XREF_HPP

#include <structor/synth_types.hpp>
#include <structor/config.hpp>

namespace structor {
namespace test {

class ConfigTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Reset to defaults before each test
        Config::instance().reset();
    }
};

class ScopedHomeDirectory {
public:
    explicit ScopedHomeDirectory(const std::filesystem::path& path) {
        if (const char* current = std::getenv("HOME")) {
            previous_ = current;
        }
#ifdef _WIN32
        _putenv_s("HOME", path.string().c_str());
#else
        setenv("HOME", path.string().c_str(), 1);
#endif
    }

    ~ScopedHomeDirectory() {
#ifdef _WIN32
        _putenv_s("HOME", previous_.value_or("").c_str());
#else
        if (previous_) {
            setenv("HOME", previous_->c_str(), 1);
        } else {
            unsetenv("HOME");
        }
#endif
    }

private:
    std::optional<std::string> previous_;
};

bool has_config_save_temporary(const std::filesystem::path& directory) {
    constexpr const char* prefix = "structor.cfg.tmp.";
    for (const auto& entry : std::filesystem::directory_iterator(directory)) {
        const std::string name = entry.path().filename().string();
        if (name.rfind(prefix, 0) == 0) {
            return true;
        }
    }
    return false;
}

// ============================================================================
// Default Configuration Tests
// ============================================================================

TEST_F(ConfigTest, DefaultHotkey) {
    EXPECT_STREQ(Config::instance().hotkey(), "Shift+S");
}

TEST_F(ConfigTest, DefaultAutoPropagation) {
    EXPECT_TRUE(Config::instance().auto_propagate());
}

TEST_F(ConfigTest, DefaultVTableDetection) {
    EXPECT_TRUE(Config::instance().vtable_detection());
}

TEST_F(ConfigTest, DefaultMinAccesses) {
    EXPECT_EQ(Config::instance().min_accesses(), 2);
}

TEST_F(ConfigTest, DefaultAlignment) {
    EXPECT_EQ(Config::instance().alignment(), 8);
}

TEST_F(ConfigTest, DefaultInteractiveMode) {
    EXPECT_FALSE(Config::instance().interactive_mode());
}

TEST_F(ConfigTest, DefaultHighlightChanges) {
    EXPECT_TRUE(Config::instance().highlight_changes());
}

TEST_F(ConfigTest, DefaultHighlightDuration) {
    EXPECT_EQ(Config::instance().highlight_duration_ms(), 2000);
}

TEST_F(ConfigTest, DefaultAutoOpenStruct) {
    EXPECT_TRUE(Config::instance().auto_open_struct());
}

TEST_F(ConfigTest, DefaultGenerateComments) {
    EXPECT_TRUE(Config::instance().generate_comments());
}

TEST_F(ConfigTest, DefaultMaxPropagationDepth) {
    EXPECT_EQ(Config::instance().max_propagation_depth(), 3);
}

TEST_F(ConfigTest, DefaultSynthesisResourceLimits) {
    const auto& z3 = Config::instance().options().z3;
    EXPECT_EQ(z3.memory_limit_mb, 0u);
    EXPECT_TRUE(z3.enable_maxsmt);
    EXPECT_EQ(z3.max_accesses, 10000u);
    EXPECT_EQ(z3.max_candidates, 1000u);
    EXPECT_EQ(z3.max_fields, 4096u);
    EXPECT_EQ(z3.max_array_elements, 1024u);
    EXPECT_TRUE(z3.detect_symbolic_arrays);
    EXPECT_EQ(z3.max_array_stride, 4096u);
    EXPECT_EQ(z3.max_structure_size, 0x10000u);
    EXPECT_EQ(z3.max_constraint_pairs, 500000u);
    EXPECT_EQ(z3.max_union_alternatives, 8u);
    EXPECT_EQ(z3.max_relax_iterations, 5u);
}

TEST_F(ConfigTest, ZeroTimeoutAndMemoryMeanUnlimited) {
    SynthOptions options;
    options.z3.timeout_ms = 0;
    options.z3.memory_limit_mb = 0;
    EXPECT_EQ(options.z3.timeout_ms, 0u);
    EXPECT_EQ(options.z3.memory_limit_mb, 0u);
}

TEST_F(ConfigTest, AbiAlignmentValidationIsPowerOfTwoAndRepresentable) {
    EXPECT_FALSE(is_valid_abi_alignment(-1));
    EXPECT_FALSE(is_valid_abi_alignment(0));
    EXPECT_TRUE(is_valid_abi_alignment(1));
    EXPECT_TRUE(is_valid_abi_alignment(8));
    EXPECT_FALSE(is_valid_abi_alignment(3));
    EXPECT_TRUE(is_valid_abi_alignment(std::int64_t{1} << 30));
    EXPECT_FALSE(is_valid_abi_alignment(std::int64_t{1} << 31));
    EXPECT_FALSE(is_valid_abi_alignment(std::numeric_limits<std::int64_t>::max()));
}

TEST_F(ConfigTest, SetOptionsRejectsInvalidAlignmentAtomically) {
    Config::instance().mark_clean();
    SynthOptions invalid = Config::instance().options();
    invalid.hotkey = "Rejected";
    invalid.alignment = 6;

    EXPECT_FALSE(Config::instance().set_options(invalid));
    EXPECT_STREQ(Config::instance().hotkey(), "Shift+S");
    EXPECT_EQ(Config::instance().alignment(), 8);
    EXPECT_FALSE(Config::instance().is_dirty());
}

TEST_F(ConfigTest, SetOptionsAcceptsValidAlignmentAtomically) {
    Config::instance().mark_clean();
    SynthOptions valid = Config::instance().options();
    valid.alignment = 32;

    EXPECT_TRUE(Config::instance().set_options(valid));
    EXPECT_EQ(Config::instance().alignment(), 32);
    EXPECT_TRUE(Config::instance().is_dirty());
}

TEST_F(ConfigTest, SetOptionsRejectsEveryZeroTerminalLimit) {
    const auto assert_rejected = [](auto mutate) {
        Config::instance().reset();
        Config::instance().mark_clean();
        SynthOptions invalid = Config::instance().options();
        mutate(invalid.z3);
        EXPECT_FALSE(Config::instance().set_options(invalid));
        EXPECT_FALSE(Config::instance().is_dirty());
    };

    assert_rejected([](Z3Options& z3) { z3.max_accesses = 0; });
    assert_rejected([](Z3Options& z3) { z3.max_candidates = 0; });
    assert_rejected([](Z3Options& z3) { z3.max_fields = 0; });
    assert_rejected([](Z3Options& z3) { z3.max_array_elements = 0; });
    assert_rejected([](Z3Options& z3) { z3.max_structure_size = 0; });
    assert_rejected([](Z3Options& z3) { z3.max_constraint_pairs = 0; });
    assert_rejected([](Z3Options& z3) { z3.max_union_alternatives = 0; });
}

TEST_F(ConfigTest, SetOptionsRejectsInconsistentArrayBoundsAndNegativeWeights) {
    SynthOptions invalid = Config::instance().options();
    invalid.z3.min_array_elements = invalid.z3.max_array_elements + 1;
    EXPECT_EQ(validate_synth_options(invalid),
              SynthOptionsValidationError::InvalidArrayBounds);
    EXPECT_FALSE(Config::instance().set_options(invalid));

    invalid = Config::instance().options();
    invalid.z3.max_array_stride = 0;
    EXPECT_EQ(validate_synth_options(invalid),
              SynthOptionsValidationError::InvalidArrayBounds);
    EXPECT_FALSE(Config::instance().set_options(invalid));

    invalid = Config::instance().options();
    invalid.z3.weight_prefer_non_union = -1;
    EXPECT_EQ(validate_synth_options(invalid),
              SynthOptionsValidationError::InvalidWeight);
    EXPECT_FALSE(Config::instance().set_options(invalid));
}

TEST_F(ConfigTest, InvalidFileLoadIsTransactionalAndRejectsUnknownMode) {
    const auto nonce = std::chrono::steady_clock::now().time_since_epoch().count();
    const auto home = std::filesystem::temp_directory_path() /
        ("structor-config-test-" + std::to_string(nonce));
    const auto config_dir = home / ".idapro";
    std::filesystem::create_directories(config_dir);
    {
        std::ofstream file(config_dir / "structor.cfg");
        ASSERT_TRUE(file.is_open());
        file << "hotkey=PartiallyApplied\n";
        file << "alignment=16\n";
        file << "z3_mode=typo\n";
    }

    {
        ScopedHomeDirectory scoped_home(home);
        Config::instance().mark_clean();
        EXPECT_FALSE(Config::instance().load());
        EXPECT_STREQ(Config::instance().hotkey(), "Shift+S");
        EXPECT_EQ(Config::instance().alignment(), 8);
        EXPECT_FALSE(Config::instance().is_dirty());
    }
    std::filesystem::remove_all(home);
}

TEST_F(ConfigTest, HighBitBooleanByteIsRejectedWithoutCtypeUndefinedBehavior) {
    const auto nonce = std::chrono::steady_clock::now().time_since_epoch().count();
    const auto home = std::filesystem::temp_directory_path() /
        ("structor-config-high-byte-" + std::to_string(nonce));
    const auto config_dir = home / ".idapro";
    std::filesystem::create_directories(config_dir);
    {
        std::ofstream file(config_dir / "structor.cfg", std::ios::binary);
        ASSERT_TRUE(file.is_open());
        file << "hotkey=PartiallyApplied\n";
        file << "debug_mode=";
        file.put(static_cast<char>(0xFF));
        file << "\n";
    }

    {
        ScopedHomeDirectory scoped_home(home);
        Config::instance().mark_clean();
        EXPECT_FALSE(Config::instance().load());
        EXPECT_STREQ(Config::instance().hotkey(), "Shift+S");
        EXPECT_FALSE(Config::instance().is_dirty());
    }
    std::filesystem::remove_all(home);
}

TEST_F(ConfigTest, FirstRunLoadPersistsDefaultsAndMarksClean) {
    const auto nonce = std::chrono::steady_clock::now().time_since_epoch().count();
    const auto home = std::filesystem::temp_directory_path() /
        ("structor-config-first-run-" + std::to_string(nonce));
    std::filesystem::remove_all(home);

    {
        ScopedHomeDirectory scoped_home(home);
        Config::instance().mark_clean();
        ASSERT_FALSE(Config::instance().is_dirty());
        EXPECT_TRUE(Config::instance().load());
        EXPECT_FALSE(Config::instance().is_dirty());

        const auto path = Config::config_path();
        EXPECT_TRUE(std::filesystem::is_regular_file(path));
        EXPECT_FALSE(has_config_save_temporary(path.parent_path()));
    }
    std::filesystem::remove_all(home);
}

TEST_F(ConfigTest, MissingFileLoadReportsCreationFailureAndRetainsDirty) {
    const auto nonce = std::chrono::steady_clock::now().time_since_epoch().count();
    const auto home = std::filesystem::temp_directory_path() /
        ("structor-config-unwritable-parent-" + std::to_string(nonce));
    std::filesystem::create_directories(home);
    {
        // A regular file in place of the configuration directory makes the
        // first-run destination structurally unwritable without relying on
        // platform-specific permission behavior.
        std::ofstream blocking_parent(home / ".idapro");
        ASSERT_TRUE(blocking_parent.is_open());
        blocking_parent << "not a directory";
    }

    {
        ScopedHomeDirectory scoped_home(home);
        Config::instance().mark_clean();
        ASSERT_FALSE(Config::instance().is_dirty());
        bool loaded = true;
        EXPECT_NO_THROW(loaded = Config::instance().load());
        EXPECT_FALSE(loaded);
        EXPECT_TRUE(Config::instance().is_dirty());
    }
    std::filesystem::remove_all(home);
}

TEST_F(ConfigTest, FailedAtomicSavePreservesDestinationAndDirtyState) {
    const auto nonce = std::chrono::steady_clock::now().time_since_epoch().count();
    const auto home = std::filesystem::temp_directory_path() /
        ("structor-config-rename-failure-" + std::to_string(nonce));
    const auto config_dir = home / ".idapro";
    const auto destination = config_dir / "structor.cfg";
    std::filesystem::create_directories(destination);

    {
        ScopedHomeDirectory scoped_home(home);
        Config::instance().mutable_options().hotkey = "Unsaved";
        ASSERT_TRUE(Config::instance().is_dirty());
        bool saved = true;
        EXPECT_NO_THROW(saved = Config::instance().save());
        EXPECT_FALSE(saved);
        EXPECT_TRUE(Config::instance().is_dirty());
        EXPECT_TRUE(std::filesystem::is_directory(destination));
        EXPECT_FALSE(has_config_save_temporary(config_dir));
    }
    std::filesystem::remove_all(home);
}

TEST_F(ConfigTest, SuccessfulSaveReplacesExistingFileAfterFinalization) {
    const auto nonce = std::chrono::steady_clock::now().time_since_epoch().count();
    const auto home = std::filesystem::temp_directory_path() /
        ("structor-config-replace-success-" + std::to_string(nonce));
    const auto config_dir = home / ".idapro";
    const auto destination = config_dir / "structor.cfg";
    std::filesystem::create_directories(config_dir);
    {
        std::ofstream stale(destination);
        ASSERT_TRUE(stale.is_open());
        stale << "stale=true\n";
    }

    {
        ScopedHomeDirectory scoped_home(home);
        SynthOptions& options = Config::instance().mutable_options();
        options.hotkey = "Ctrl+Alt+S";
        options.z3.detect_symbolic_arrays = false;
        options.z3.max_array_stride = 128;
        ASSERT_TRUE(Config::instance().is_dirty());
        EXPECT_TRUE(Config::instance().save());
        EXPECT_FALSE(Config::instance().is_dirty());
        EXPECT_FALSE(has_config_save_temporary(config_dir));

        std::ifstream saved(destination);
        ASSERT_TRUE(saved.is_open());
        const std::string contents{
            std::istreambuf_iterator<char>(saved),
            std::istreambuf_iterator<char>()};
        EXPECT_NE(contents.find("hotkey=Ctrl+Alt+S"), std::string::npos);
        EXPECT_NE(contents.find("z3_detect_symbolic_arrays=false"),
                  std::string::npos);
        EXPECT_NE(contents.find("z3_max_array_stride=128"),
                  std::string::npos);
        EXPECT_EQ(contents.find("stale=true"), std::string::npos);
    }
    std::filesystem::remove_all(home);
}

// ============================================================================
// Configuration Modification Tests
// ============================================================================

TEST_F(ConfigTest, ModifyHotkey) {
    Config::instance().mutable_options().hotkey = "Ctrl+Shift+S";
    EXPECT_STREQ(Config::instance().hotkey(), "Ctrl+Shift+S");
}

TEST_F(ConfigTest, ModifyMinAccesses) {
    Config::instance().mutable_options().min_accesses = 5;
    EXPECT_EQ(Config::instance().min_accesses(), 5);
}

TEST_F(ConfigTest, ModifyAlignment) {
    Config::instance().mutable_options().alignment = 16;
    EXPECT_EQ(Config::instance().alignment(), 16);
}

TEST_F(ConfigTest, DisableAutoPropagation) {
    Config::instance().mutable_options().auto_propagate = false;
    EXPECT_FALSE(Config::instance().auto_propagate());
}

TEST_F(ConfigTest, EnableInteractiveMode) {
    Config::instance().mutable_options().interactive_mode = true;
    EXPECT_TRUE(Config::instance().interactive_mode());
}

// ============================================================================
// Dirty Flag Tests
// ============================================================================

TEST_F(ConfigTest, InitiallyNotDirty) {
    Config::instance().reset();
    Config::instance().mark_clean();
    EXPECT_FALSE(Config::instance().is_dirty());
}

TEST_F(ConfigTest, ModificationSetsDirty) {
    Config::instance().mark_clean();
    Config::instance().mutable_options().min_accesses = 10;
    EXPECT_TRUE(Config::instance().is_dirty());
}

TEST_F(ConfigTest, MarkCleanClearsDirty) {
    Config::instance().mutable_options().min_accesses = 10;
    Config::instance().mark_clean();
    EXPECT_FALSE(Config::instance().is_dirty());
}

// ============================================================================
// Reset Tests
// ============================================================================

TEST_F(ConfigTest, ResetRestoresDefaults) {
    // Modify several options
    SynthOptions& opts = Config::instance().mutable_options();
    opts.hotkey = "Alt+X";
    opts.min_accesses = 100;
    opts.alignment = 1;
    opts.auto_propagate = false;
    opts.vtable_detection = false;

    // Reset
    Config::instance().reset();

    // Verify defaults restored
    EXPECT_STREQ(Config::instance().hotkey(), "Shift+S");
    EXPECT_EQ(Config::instance().min_accesses(), 2);
    EXPECT_EQ(Config::instance().alignment(), 8);
    EXPECT_TRUE(Config::instance().auto_propagate());
    EXPECT_TRUE(Config::instance().vtable_detection());
}

// ============================================================================
// SynthOptions Direct Tests
// ============================================================================

TEST_F(ConfigTest, SynthOptionsDefaultConstruction) {
    SynthOptions opts;

    EXPECT_STREQ(opts.hotkey.c_str(), "Shift+S");
    EXPECT_TRUE(opts.auto_propagate);
    EXPECT_TRUE(opts.vtable_detection);
    EXPECT_EQ(opts.min_accesses, 2);
    EXPECT_EQ(opts.alignment, 8);
    EXPECT_FALSE(opts.interactive_mode);
}

TEST_F(ConfigTest, SynthOptionsCopy) {
    SynthOptions original;
    original.hotkey = "Custom";
    original.min_accesses = 42;

    SynthOptions copy = original;

    EXPECT_STREQ(copy.hotkey.c_str(), "Custom");
    EXPECT_EQ(copy.min_accesses, 42);
}

// ============================================================================
// Propagation Settings Tests
// ============================================================================

TEST_F(ConfigTest, PropagationToCallersDefault) {
    EXPECT_TRUE(Config::instance().propagate_to_callers());
}

TEST_F(ConfigTest, PropagationToCalleesDefault) {
    EXPECT_TRUE(Config::instance().propagate_to_callees());
}

TEST_F(ConfigTest, DisablePropagationToCallers) {
    Config::instance().mutable_options().propagate_to_callers = false;
    EXPECT_FALSE(Config::instance().propagate_to_callers());
}

TEST_F(ConfigTest, DisablePropagationToCallees) {
    Config::instance().mutable_options().propagate_to_callees = false;
    EXPECT_FALSE(Config::instance().propagate_to_callees());
}

// ============================================================================
// Singleton Tests
// ============================================================================

TEST_F(ConfigTest, SingletonIdentity) {
    Config& inst1 = Config::instance();
    Config& inst2 = Config::instance();

    EXPECT_EQ(&inst1, &inst2);
}

TEST_F(ConfigTest, SingletonModificationPersists) {
    Config::instance().mutable_options().min_accesses = 99;

    // Access through different reference
    int value = Config::instance().min_accesses();

    EXPECT_EQ(value, 99);
}

TEST_F(ConfigTest, FlowAnalysisDefaultsAndValidation) {
    SynthOptions options;
    EXPECT_EQ(options.flow.max_states, 16U);
    EXPECT_EQ(options.flow.max_steps, UINT64_C(65536));
    for (std::uint32_t cap : {0U, 1U, 2U, 3U}) {
        options.flow.max_states = cap;
        EXPECT_EQ(validate_synth_options(options), SynthOptionsValidationError::InvalidFlowLimit);
        EXPECT_FALSE(Config::instance().set_options(options));
        EXPECT_EQ(Config::instance().options().flow.max_states, 16U);
    }
    options.flow.max_states = 4;
    options.flow.max_steps = 0;
    EXPECT_EQ(validate_synth_options(options), SynthOptionsValidationError::InvalidFlowLimit);
    EXPECT_FALSE(Config::instance().set_options(options));
    for (std::uint32_t cap : {4U, 16U, 64U, UINT32_MAX}) {
        options.flow.max_states = cap;
        options.flow.max_steps = UINT64_MAX;
        EXPECT_EQ(validate_synth_options(options), SynthOptionsValidationError::None);
    }
}

TEST_F(ConfigTest, FlowAnalysisLimitsRoundTripAndRejectMalformedValuesAtomically) {
    const auto nonce = std::chrono::steady_clock::now().time_since_epoch().count();
    const auto directory = std::filesystem::temp_directory_path() /
        ("structor-flow-config-" + std::to_string(nonce));
    {
        ScopedHomeDirectory scoped_home(directory);
        auto options = Config::instance().options();
        options.flow.max_states = 64;
        options.flow.max_steps = UINT64_C(131072);
        ASSERT_TRUE(Config::instance().set_options(options));
        ASSERT_TRUE(Config::instance().save());
        Config::instance().reset();
        ASSERT_TRUE(Config::instance().load());
        EXPECT_EQ(Config::instance().options().flow.max_states, 64U);
        EXPECT_EQ(Config::instance().options().flow.max_steps, UINT64_C(131072));
        const auto path = Config::config_path();
        for (const char* entry : {
                "flow_max_states=3", "flow_max_states=0", "flow_max_states=-1",
                "flow_max_states=4294967296", "flow_max_steps=0", "flow_max_steps=-1",
                "flow_max_steps=18446744073709551616", "flow_max_steps=42junk"}) {
            std::ofstream file(path);
            ASSERT_TRUE(file.is_open());
            file << "hotkey=MustNotApply\n" << entry << '\n';
            file.close();
            EXPECT_FALSE(Config::instance().load()) << entry;
            EXPECT_STREQ(Config::instance().hotkey(), "Shift+S");
            EXPECT_EQ(Config::instance().options().flow.max_states, 64U);
            EXPECT_EQ(Config::instance().options().flow.max_steps, UINT64_C(131072));
        }
    }
    std::filesystem::remove_all(directory);
}

TEST_F(ConfigTest, FlowPrecisionMetadataSeparatesUnknownEntriesFromBudgets) {
    AccessPattern pattern;
    EXPECT_FALSE(pattern.flow_analysis.started);
    EXPECT_FALSE(pattern.flow_analysis.precision_lost());
    pattern.flow_analysis.started = true;
    pattern.flow_analysis.precision_events.push_back(
        {FlowPrecisionLoss::UnknownJumpEntry, 9, BADADDR, 2, 1, 2});
    EXPECT_TRUE(pattern.flow_analysis.precision_lost());
    EXPECT_FALSE(pattern.flow_analysis.budget_exhausted());
    auto copy = pattern;
    copy.flow_analysis.precision_events.push_back(
        {FlowPrecisionLoss::StepBudget, 10, BADADDR, -1, 1, 1});
    EXPECT_TRUE(copy.flow_analysis.budget_exhausted());
    EXPECT_FALSE(pattern.flow_analysis.budget_exhausted());
    EXPECT_EQ(pattern.flow_analysis.precision_events.size(), 1U);
}

} // namespace test
} // namespace structor
