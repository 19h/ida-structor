/// @file test_synth_types.cpp
/// @brief Unit tests for synth_types.hpp

#include <gtest/gtest.h>
#include "mock_ida.hpp"

// Override includes to use mocks
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
#include <structor/naming.hpp>

namespace structor {
namespace test {

class SynthTypesTest : public ::testing::Test {
protected:
    void SetUp() override {}
    void TearDown() override {}
};

// ============================================================================
// FieldAccess Tests
// ============================================================================

TEST_F(SynthTypesTest, FieldAccessDefaultConstruction) {
    FieldAccess access;

    EXPECT_EQ(access.insn_ea, BADADDR);
    EXPECT_EQ(access.offset, 0);
    EXPECT_EQ(access.size, 0);
    EXPECT_EQ(access.access_type, AccessType::Unknown);
    EXPECT_EQ(access.semantic_type, SemanticType::Unknown);
    EXPECT_FALSE(access.is_vtable_access);
    EXPECT_FALSE(access.is_call_argument);
    EXPECT_EQ(access.vtable_slot, -1);
}

TEST_F(SynthTypesTest, FieldAccessComparison) {
    FieldAccess a, b;

    a.offset = 0x10;
    a.size = 4;
    a.insn_ea = 0x1000;

    b.offset = 0x20;
    b.size = 4;
    b.insn_ea = 0x2000;

    EXPECT_TRUE(a < b);  // Lower offset comes first
    EXPECT_FALSE(b < a);
}

TEST_F(SynthTypesTest, FieldAccessOverlap) {
    FieldAccess a, b, c;

    a.offset = 0x10;
    a.size = 8;

    b.offset = 0x14;  // Overlaps with a
    b.size = 4;

    c.offset = 0x20;  // Does not overlap
    c.size = 4;

    EXPECT_TRUE(a.overlaps(b));
    EXPECT_TRUE(b.overlaps(a));
    EXPECT_FALSE(a.overlaps(c));
    EXPECT_FALSE(c.overlaps(a));
}

// ============================================================================
// AccessPattern Tests
// ============================================================================

TEST_F(SynthTypesTest, AccessPatternAddAccess) {
    AccessPattern pattern;

    FieldAccess acc1;
    acc1.offset = 0x10;
    acc1.size = 4;
    pattern.add_access(std::move(acc1));

    EXPECT_EQ(pattern.access_count(), 1);
    EXPECT_EQ(pattern.min_offset, 0x10);
    EXPECT_EQ(pattern.max_offset, 0x14);

    FieldAccess acc2;
    acc2.offset = 0x20;
    acc2.size = 8;
    pattern.add_access(std::move(acc2));

    EXPECT_EQ(pattern.access_count(), 2);
    EXPECT_EQ(pattern.min_offset, 0x10);
    EXPECT_EQ(pattern.max_offset, 0x28);
}

TEST_F(SynthTypesTest, AccessPatternSortByOffset) {
    AccessPattern pattern;

    FieldAccess acc1, acc2, acc3;
    acc1.offset = 0x20;
    acc2.offset = 0x10;
    acc3.offset = 0x30;

    pattern.add_access(std::move(acc1));
    pattern.add_access(std::move(acc2));
    pattern.add_access(std::move(acc3));

    pattern.sort_by_offset();

    EXPECT_EQ(pattern.accesses[0].offset, 0x10);
    EXPECT_EQ(pattern.accesses[1].offset, 0x20);
    EXPECT_EQ(pattern.accesses[2].offset, 0x30);
}

// ============================================================================
// SynthField Tests
// ============================================================================

TEST_F(SynthTypesTest, SynthFieldCreatePadding) {
    SynthField pad = SynthField::create_padding(0x10, 4);

    EXPECT_EQ(pad.offset, 0x10);
    EXPECT_EQ(pad.size, 4);
    EXPECT_TRUE(pad.is_padding);
    EXPECT_EQ(pad.semantic, SemanticType::Padding);
    EXPECT_TRUE(pad.name.c_str()[0] == '_');  // Starts with __pad_
}

// ============================================================================
// SynthStruct Tests
// ============================================================================

TEST_F(SynthTypesTest, SynthStructConstruction) {
    SynthStruct s;

    EXPECT_EQ(s.tid, BADADDR);
    EXPECT_EQ(s.size, 0);
    EXPECT_EQ(s.alignment, 8);
    EXPECT_EQ(s.source_func, BADADDR);
    EXPECT_FALSE(s.has_vtable());
    EXPECT_EQ(s.field_count(), 0);
}

TEST_F(SynthTypesTest, SynthStructAddProvenance) {
    SynthStruct s;

    s.add_provenance(0x1000);
    s.add_provenance(0x2000);
    s.add_provenance(0x1000);  // Duplicate

    EXPECT_EQ(s.provenance.size(), 2);
}

// ============================================================================
// SynthResult Tests
// ============================================================================

TEST_F(SynthTypesTest, SynthResultSuccess) {
    SynthResult result;
    result.error = SynthError::Success;
    result.struct_tid = 1;

    EXPECT_TRUE(result.success());
    EXPECT_FALSE(result.has_conflicts());
}

TEST_F(SynthTypesTest, SynthResultError) {
    SynthResult result = SynthResult::make_error(
        SynthError::NoAccessesFound,
        "No dereferences found"
    );

    EXPECT_FALSE(result.success());
    EXPECT_EQ(result.error, SynthError::NoAccessesFound);
    EXPECT_STREQ(result.error_message.c_str(), "No dereferences found");
}

// ============================================================================
// Utility Function Tests
// ============================================================================

TEST_F(SynthTypesTest, ComputeAlignment) {
    EXPECT_EQ(compute_alignment(1), 1);
    EXPECT_EQ(compute_alignment(2), 2);
    EXPECT_EQ(compute_alignment(3), 2);
    EXPECT_EQ(compute_alignment(4), 4);
    EXPECT_EQ(compute_alignment(6), 4);
    EXPECT_EQ(compute_alignment(8), 8);
    EXPECT_EQ(compute_alignment(16), 8);
}

TEST_F(SynthTypesTest, AlignOffset) {
    EXPECT_EQ(align_offset(0, 4), 0);
    EXPECT_EQ(align_offset(1, 4), 4);
    EXPECT_EQ(align_offset(4, 4), 4);
    EXPECT_EQ(align_offset(5, 4), 8);
    EXPECT_EQ(align_offset(7, 8), 8);
    EXPECT_EQ(align_offset(8, 8), 8);
}

TEST_F(SynthTypesTest, GenerateStructName) {
    qstring name = generate_struct_name(0x401000, 0);
    EXPECT_TRUE(strstr(name.c_str(), "auto_") == name.c_str());
}

TEST_F(SynthTypesTest, GenerateFieldName) {
    qstring name = generate_field_name(0x10);
    EXPECT_STREQ(name.c_str(), "u32_10");

    qstring vtbl_name = generate_field_name(0, SemanticType::VTablePointer);
    EXPECT_STREQ(vtbl_name.c_str(), "vtbl_0");

    qstring ptr_name = generate_field_name(0x20, SemanticType::Pointer);
    EXPECT_STREQ(ptr_name.c_str(), "ptr_20");

    qstring fn_name = generate_field_name(0x28, SemanticType::FunctionPointer);
    EXPECT_STREQ(fn_name.c_str(), "fn_28");
}

TEST_F(SynthTypesTest, ArrayAndSubobjectFallbackNames) {
    tinfo_t empty_type;

    EXPECT_STREQ(make_substruct_field_name(0x18).c_str(), "part_18");
    EXPECT_STREQ(make_array_field_name(0x10, empty_type, SemanticType::Unknown, 4).c_str(), "u32s_10");
    EXPECT_STREQ(make_array_element_type_name("auto_anchor", "entries_10", 0x10).c_str(),
                 "auto_anchor_entry_10");
}

TEST_F(SynthTypesTest, OverlayMemberNames) {
    EXPECT_STREQ(make_overlay_member_name("value", 8, 0, 4).c_str(), "value_lo");
    EXPECT_STREQ(make_overlay_member_name("value", 8, 4, 4).c_str(), "value_hi");
    EXPECT_STREQ(make_overlay_member_name("value", 8, 2, 2).c_str(), "value_u16");
}

TEST_F(SynthTypesTest, GeneratedNameDetectionAndAdoptionPrecedence) {
    EXPECT_TRUE(is_generated_name("u32_10"));
    EXPECT_TRUE(is_generated_name("u64_8_hi"));
    EXPECT_FALSE(is_generated_name("value_hi"));

    qstring current = "u32_10";
    NameMetadata current_meta{GeneratedNameKind::Field, NameOrigin::GeneratedFallback,
                              NameConfidence::Medium, false};
    NameMetadata adopted_meta{GeneratedNameKind::Field, NameOrigin::OriginalType,
                              NameConfidence::High, false};

    EXPECT_TRUE(adopt_preferred_name(current, current_meta, "count", adopted_meta));
    EXPECT_STREQ(current.c_str(), "count");

    NameMetadata weak_meta{GeneratedNameKind::Field, NameOrigin::GeneratedFallback,
                           NameConfidence::Low, false};
    EXPECT_FALSE(adopt_preferred_name(current, current_meta, "u32_10", weak_meta));
    EXPECT_STREQ(current.c_str(), "count");
}

TEST_F(SynthTypesTest, ApplyRoleBasedFieldNames) {
    SynthStruct structure;

    SynthField callback;
    callback.name = "fn_8";
    callback.naming = {GeneratedNameKind::Field, NameOrigin::GeneratedFallback,
                       NameConfidence::Medium, false};
    callback.offset = 8;
    callback.size = 8;
    callback.semantic = SemanticType::FunctionPointer;
    FieldAccess call_access;
    call_access.access_type = AccessType::Call;
    callback.source_accesses.push_back(call_access);
    structure.fields.push_back(callback);

    SynthField vtable;
    vtable.name = "vtbl_0";
    vtable.naming = {GeneratedNameKind::Field, NameOrigin::GeneratedFallback,
                     NameConfidence::Medium, false};
    vtable.offset = 0;
    vtable.size = 8;
    vtable.semantic = SemanticType::VTablePointer;
    structure.fields.push_back(vtable);

    SynthField kind;
    kind.name = "u32_4";
    kind.naming = {GeneratedNameKind::Field, NameOrigin::GeneratedFallback,
                   NameConfidence::Medium, false};
    kind.offset = 4;
    kind.size = 4;
    kind.semantic = SemanticType::UnsignedInteger;
    FieldAccess cmp_access;
    cmp_access.observed_constants.push_back(1);
    cmp_access.observed_constants.push_back(2);
    kind.source_accesses.push_back(cmp_access);
    structure.fields.push_back(kind);

    apply_role_based_field_names(structure);

    EXPECT_STREQ(structure.fields[0].name.c_str(), "callback");
    EXPECT_STREQ(structure.fields[1].name.c_str(), "vtable");
    EXPECT_STREQ(structure.fields[2].name.c_str(), "kind_4");
}

TEST_F(SynthTypesTest, ErrorStringConversion) {
    EXPECT_STREQ(synth_error_str(SynthError::Success), "Success");
    EXPECT_STREQ(synth_error_str(SynthError::NoVariableSelected), "No variable selected");
    EXPECT_STREQ(synth_error_str(SynthError::NoAccessesFound), "No dereferences found for variable");
}

TEST_F(SynthTypesTest, AccessTypeStringConversion) {
    EXPECT_STREQ(access_type_str(AccessType::Read), "read");
    EXPECT_STREQ(access_type_str(AccessType::Write), "write");
    EXPECT_STREQ(access_type_str(AccessType::Call), "call");
}

TEST_F(SynthTypesTest, SemanticTypeStringConversion) {
    EXPECT_STREQ(semantic_type_str(SemanticType::Integer), "int");
    EXPECT_STREQ(semantic_type_str(SemanticType::Pointer), "ptr");
    EXPECT_STREQ(semantic_type_str(SemanticType::VTablePointer), "vtbl");
}

} // namespace test
} // namespace structor
