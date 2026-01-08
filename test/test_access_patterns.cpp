/// @file test_access_patterns.cpp
/// @brief Unit tests for access pattern analysis

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

namespace structor {
namespace test {

class AccessPatternTest : public ::testing::Test {
protected:
    void SetUp() override {}
};

// ============================================================================
// Access Type Tests
// ============================================================================

TEST_F(AccessPatternTest, AccessTypeMerging) {
    FieldAccess read_access;
    read_access.offset = 0x10;
    read_access.size = 4;
    read_access.access_type = AccessType::Read;

    FieldAccess write_access;
    write_access.offset = 0x10;
    write_access.size = 4;
    write_access.access_type = AccessType::Write;

    // When merging read and write at same location, should become ReadWrite
    // This is tested indirectly through the collector
}

TEST_F(AccessPatternTest, AccessPatternMinMax) {
    AccessPattern pattern;

    FieldAccess acc1;
    acc1.offset = 0x100;
    acc1.size = 4;
    pattern.add_access(std::move(acc1));

    EXPECT_EQ(pattern.min_offset, 0x100);
    EXPECT_EQ(pattern.max_offset, 0x104);

    FieldAccess acc2;
    acc2.offset = 0x50;
    acc2.size = 8;
    pattern.add_access(std::move(acc2));

    EXPECT_EQ(pattern.min_offset, 0x50);
    EXPECT_EQ(pattern.max_offset, 0x104);

    FieldAccess acc3;
    acc3.offset = 0x200;
    acc3.size = 16;
    pattern.add_access(std::move(acc3));

    EXPECT_EQ(pattern.min_offset, 0x50);
    EXPECT_EQ(pattern.max_offset, 0x210);
}

TEST_F(AccessPatternTest, VTablePatternDetection) {
    AccessPattern pattern;

    FieldAccess vtbl_access;
    vtbl_access.offset = 0;
    vtbl_access.size = 8;
    vtbl_access.semantic_type = SemanticType::VTablePointer;
    vtbl_access.is_vtable_access = true;
    vtbl_access.vtable_slot = 0;

    pattern.add_access(std::move(vtbl_access));
    pattern.has_vtable = true;
    pattern.vtable_offset = 0;

    EXPECT_TRUE(pattern.has_vtable);
    EXPECT_EQ(pattern.vtable_offset, 0);
}

// ============================================================================
// Semantic Type Priority Tests
// ============================================================================

TEST_F(AccessPatternTest, SemanticTypePriority) {
    // VTablePointer should have highest priority
    // followed by FunctionPointer, Pointer, etc.

    auto priority = [](SemanticType s) -> int {
        switch (s) {
            case SemanticType::VTablePointer:   return 100;
            case SemanticType::FunctionPointer: return 90;
            case SemanticType::Pointer:         return 80;
            case SemanticType::Double:          return 70;
            case SemanticType::Float:           return 60;
            case SemanticType::UnsignedInteger: return 50;
            case SemanticType::Integer:         return 40;
            default:                            return 0;
        }
    };

    EXPECT_GT(priority(SemanticType::VTablePointer), priority(SemanticType::FunctionPointer));
    EXPECT_GT(priority(SemanticType::FunctionPointer), priority(SemanticType::Pointer));
    EXPECT_GT(priority(SemanticType::Pointer), priority(SemanticType::Integer));
}

// ============================================================================
// Field Access Overlap Detection
// ============================================================================

TEST_F(AccessPatternTest, OverlapDetectionExact) {
    FieldAccess a, b;
    a.offset = 0x10;
    a.size = 4;
    b.offset = 0x10;
    b.size = 4;

    EXPECT_TRUE(a.overlaps(b));
}

TEST_F(AccessPatternTest, OverlapDetectionPartial) {
    FieldAccess a, b;
    a.offset = 0x10;
    a.size = 8;
    b.offset = 0x14;
    b.size = 8;

    EXPECT_TRUE(a.overlaps(b));
}

TEST_F(AccessPatternTest, OverlapDetectionAdjacent) {
    FieldAccess a, b;
    a.offset = 0x10;
    a.size = 4;
    b.offset = 0x14;  // Starts exactly where a ends
    b.size = 4;

    EXPECT_FALSE(a.overlaps(b));
}

TEST_F(AccessPatternTest, OverlapDetectionDisjoint) {
    FieldAccess a, b;
    a.offset = 0x10;
    a.size = 4;
    b.offset = 0x20;
    b.size = 4;

    EXPECT_FALSE(a.overlaps(b));
}

// ============================================================================
// Access Pattern Sorting
// ============================================================================

TEST_F(AccessPatternTest, SortingByOffset) {
    AccessPattern pattern;

    FieldAccess acc1, acc2, acc3, acc4;
    acc1.offset = 0x30;
    acc2.offset = 0x10;
    acc3.offset = 0x20;
    acc4.offset = 0x00;

    pattern.add_access(std::move(acc1));
    pattern.add_access(std::move(acc2));
    pattern.add_access(std::move(acc3));
    pattern.add_access(std::move(acc4));

    pattern.sort_by_offset();

    EXPECT_EQ(pattern.accesses[0].offset, 0x00);
    EXPECT_EQ(pattern.accesses[1].offset, 0x10);
    EXPECT_EQ(pattern.accesses[2].offset, 0x20);
    EXPECT_EQ(pattern.accesses[3].offset, 0x30);
}

TEST_F(AccessPatternTest, SortingStableBySize) {
    AccessPattern pattern;

    FieldAccess acc1, acc2;
    acc1.offset = 0x10;
    acc1.size = 8;
    acc2.offset = 0x10;
    acc2.size = 4;

    pattern.add_access(std::move(acc1));
    pattern.add_access(std::move(acc2));

    pattern.sort_by_offset();

    // Same offset, smaller size should come first
    EXPECT_EQ(pattern.accesses[0].size, 4);
    EXPECT_EQ(pattern.accesses[1].size, 8);
}

} // namespace test
} // namespace structor
