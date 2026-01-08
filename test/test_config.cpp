/// @file test_config.cpp
/// @brief Unit tests for configuration system

#include <gtest/gtest.h>
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

} // namespace test
} // namespace structor
