/// @file test_layout_synthesizer.cpp
/// @brief Unit tests for layout synthesis

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
#include <structor/layout_synthesizer.hpp>

namespace structor {
namespace test {

class LayoutSynthesizerTest : public ::testing::Test {
protected:
    void SetUp() override {
        opts_.min_accesses = 1;
        opts_.alignment = 8;
    }

    AccessPattern create_pattern(std::initializer_list<std::pair<sval_t, std::uint32_t>> accesses) {
        AccessPattern pattern;
        pattern.func_ea = 0x401000;
        pattern.var_idx = 0;
        pattern.var_name = "test_var";

        for (const auto& [offset, size] : accesses) {
            FieldAccess access;
            access.offset = offset;
            access.size = size;
            access.access_type = AccessType::Read;
            access.semantic_type = SemanticType::Integer;
            pattern.add_access(std::move(access));
        }

        return pattern;
    }

    SynthOptions opts_;
};

// ============================================================================
// Basic Synthesis Tests
// ============================================================================

TEST_F(LayoutSynthesizerTest, EmptyPatternProducesEmptyStruct) {
    AccessPattern pattern;
    pattern.func_ea = 0x401000;

    LayoutSynthesizer synth(opts_);
    SynthStruct result = synth.synthesize(pattern);

    EXPECT_EQ(result.fields.size(), 0);
    EXPECT_EQ(result.size, 0);
}

TEST_F(LayoutSynthesizerTest, SingleFieldSynthesis) {
    auto pattern = create_pattern({{0x10, 4}});

    LayoutSynthesizer synth(opts_);
    SynthStruct result = synth.synthesize(pattern);

    // Should have padding at 0x0-0x10, then field at 0x10
    EXPECT_GE(result.fields.size(), 1);

    // Find the non-padding field
    const SynthField* main_field = nullptr;
    for (const auto& f : result.fields) {
        if (!f.is_padding && f.offset == 0x10) {
            main_field = &f;
            break;
        }
    }

    ASSERT_NE(main_field, nullptr);
    EXPECT_EQ(main_field->offset, 0x10);
    EXPECT_EQ(main_field->size, 4);
}

TEST_F(LayoutSynthesizerTest, MultipleFieldsSynthesis) {
    auto pattern = create_pattern({
        {0x00, 8},
        {0x08, 8},
        {0x10, 4},
        {0x18, 8}
    });

    LayoutSynthesizer synth(opts_);
    SynthStruct result = synth.synthesize(pattern);

    // Count non-padding fields
    int non_padding = 0;
    for (const auto& f : result.fields) {
        if (!f.is_padding) ++non_padding;
    }

    EXPECT_EQ(non_padding, 4);
}

TEST_F(LayoutSynthesizerTest, PaddingInsertion) {
    auto pattern = create_pattern({
        {0x00, 4},
        {0x10, 4}  // Gap at 0x04-0x10
    });

    LayoutSynthesizer synth(opts_);
    SynthStruct result = synth.synthesize(pattern);

    // Should have: field at 0, padding 0x04-0x10, field at 0x10
    bool has_padding = false;
    for (const auto& f : result.fields) {
        if (f.is_padding && f.offset == 0x04) {
            has_padding = true;
            EXPECT_EQ(f.size, 0x0C);  // 0x10 - 0x04
        }
    }

    EXPECT_TRUE(has_padding);
}

// ============================================================================
// Overlap and Conflict Tests
// ============================================================================

TEST_F(LayoutSynthesizerTest, OverlappingAccessesMerged) {
    AccessPattern pattern;
    pattern.func_ea = 0x401000;

    // Overlapping accesses at same offset but different sizes
    FieldAccess acc1, acc2;
    acc1.offset = 0x10;
    acc1.size = 4;
    acc2.offset = 0x10;
    acc2.size = 8;

    pattern.add_access(std::move(acc1));
    pattern.add_access(std::move(acc2));

    LayoutSynthesizer synth(opts_);
    SynthStruct result = synth.synthesize(pattern);

    EXPECT_TRUE(synth.has_conflicts());

    // Should have a field marked as union candidate
    bool has_union_candidate = false;
    for (const auto& f : result.fields) {
        if (f.is_union_candidate) {
            has_union_candidate = true;
        }
    }

    EXPECT_TRUE(has_union_candidate);
}

// ============================================================================
// Type Inference Tests
// ============================================================================

TEST_F(LayoutSynthesizerTest, PointerSizeFieldsDefaultToPointer) {
    AccessPattern pattern;
    pattern.func_ea = 0x401000;

    FieldAccess acc;
    acc.offset = 0x00;
    acc.size = 8;  // Pointer size on 64-bit
    acc.semantic_type = SemanticType::Pointer;
    pattern.add_access(std::move(acc));

    LayoutSynthesizer synth(opts_);
    SynthStruct result = synth.synthesize(pattern);

    ASSERT_GE(result.fields.size(), 1);
    EXPECT_EQ(result.fields[0].semantic, SemanticType::Pointer);
}

TEST_F(LayoutSynthesizerTest, VTablePointerDetected) {
    AccessPattern pattern;
    pattern.func_ea = 0x401000;
    pattern.has_vtable = true;
    pattern.vtable_offset = 0;

    FieldAccess acc;
    acc.offset = 0x00;
    acc.size = 8;
    acc.semantic_type = SemanticType::VTablePointer;
    acc.is_vtable_access = true;
    pattern.add_access(std::move(acc));

    LayoutSynthesizer synth(opts_);
    SynthStruct result = synth.synthesize(pattern);

    ASSERT_GE(result.fields.size(), 1);
    EXPECT_EQ(result.fields[0].semantic, SemanticType::VTablePointer);
}

// ============================================================================
// Field Naming Tests
// ============================================================================

TEST_F(LayoutSynthesizerTest, FieldNamesGenerated) {
    auto pattern = create_pattern({
        {0x00, 8},
        {0x10, 4}
    });

    LayoutSynthesizer synth(opts_);
    SynthStruct result = synth.synthesize(pattern);

    for (const auto& f : result.fields) {
        EXPECT_FALSE(f.name.empty());
    }
}

// ============================================================================
// Structure Size Tests
// ============================================================================

TEST_F(LayoutSynthesizerTest, StructureSizeAligned) {
    auto pattern = create_pattern({
        {0x00, 4},
        {0x04, 2}
    });

    opts_.alignment = 8;
    LayoutSynthesizer synth(opts_);
    SynthStruct result = synth.synthesize(pattern);

    // Size should be aligned to 8
    EXPECT_EQ(result.size % 8, 0);
}

TEST_F(LayoutSynthesizerTest, StructureSizeIncludesLastField) {
    auto pattern = create_pattern({{0x20, 4}});

    LayoutSynthesizer synth(opts_);
    SynthStruct result = synth.synthesize(pattern);

    // Size should be at least 0x24 (last field end)
    EXPECT_GE(result.size, 0x24);
}

} // namespace test
} // namespace structor
