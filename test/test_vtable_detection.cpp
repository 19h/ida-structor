/// @file test_vtable_detection.cpp
/// @brief Unit tests for vtable detection

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

class VTableDetectionTest : public ::testing::Test {
protected:
    void SetUp() override {}
};

// ============================================================================
// VTable Slot Tests
// ============================================================================

TEST_F(VTableDetectionTest, VTableSlotConstruction) {
    VTableSlot slot;

    EXPECT_EQ(slot.index, 0);
    EXPECT_EQ(slot.offset, 0);
    EXPECT_TRUE(slot.call_sites.empty());
}

TEST_F(VTableDetectionTest, VTableSlotOffset) {
    VTableSlot slot;
    slot.index = 3;
    slot.offset = 3 * 8;  // 64-bit pointers

    EXPECT_EQ(slot.offset, 24);
}

// ============================================================================
// SynthVTable Tests
// ============================================================================

TEST_F(VTableDetectionTest, SynthVTableConstruction) {
    SynthVTable vtable;

    EXPECT_EQ(vtable.tid, BADADDR);
    EXPECT_EQ(vtable.source_func, BADADDR);
    EXPECT_EQ(vtable.parent_offset, 0);
    EXPECT_EQ(vtable.slot_count(), 0);
}

TEST_F(VTableDetectionTest, SynthVTableSlotCount) {
    SynthVTable vtable;

    VTableSlot slot1, slot2, slot3;
    slot1.index = 0;
    slot2.index = 1;
    slot3.index = 2;

    vtable.slots.push_back(std::move(slot1));
    vtable.slots.push_back(std::move(slot2));
    vtable.slots.push_back(std::move(slot3));

    EXPECT_EQ(vtable.slot_count(), 3);
}

// ============================================================================
// VTable Name Generation Tests
// ============================================================================

TEST_F(VTableDetectionTest, VTableNameGeneration) {
    qstring name = generate_vtable_name(0x401000, 0);

    EXPECT_TRUE(name.c_str()[0] == 's');  // synth_vtbl_...
    EXPECT_TRUE(strstr(name.c_str(), "401000") != nullptr);
}

TEST_F(VTableDetectionTest, VTableNameUniqueness) {
    qstring name1 = generate_vtable_name(0x401000, 0);
    qstring name2 = generate_vtable_name(0x401000, 1);
    qstring name3 = generate_vtable_name(0x402000, 0);

    // Different indices or addresses should produce different names
    EXPECT_FALSE(name1 == name2);
    EXPECT_FALSE(name1 == name3);
}

// ============================================================================
// VTable Access Pattern Tests
// ============================================================================

TEST_F(VTableDetectionTest, VTableAccessMarking) {
    FieldAccess access;
    access.offset = 0;
    access.size = 8;
    access.is_vtable_access = true;
    access.vtable_slot = 0;

    EXPECT_TRUE(access.is_vtable_access);
    EXPECT_EQ(access.vtable_slot, 0);
}

TEST_F(VTableDetectionTest, VTableMultipleSlotAccesses) {
    qvector<FieldAccess> accesses;

    for (int i = 0; i < 5; ++i) {
        FieldAccess acc;
        acc.offset = 0;  // All through vtable at offset 0
        acc.size = 8;
        acc.is_vtable_access = true;
        acc.vtable_slot = i;
        acc.semantic_type = SemanticType::VTablePointer;
        accesses.push_back(std::move(acc));
    }

    EXPECT_EQ(accesses.size(), 5);

    // Verify each slot is distinct
    for (int i = 0; i < 5; ++i) {
        EXPECT_EQ(accesses[i].vtable_slot, i);
    }
}

// ============================================================================
// VTable Integration with SynthStruct Tests
// ============================================================================

TEST_F(VTableDetectionTest, SynthStructWithVTable) {
    SynthStruct s;

    // Add vtable pointer field
    SynthField vtbl_field;
    vtbl_field.name = "vtbl_0";
    vtbl_field.offset = 0;
    vtbl_field.size = 8;
    vtbl_field.semantic = SemanticType::VTablePointer;
    s.fields.push_back(std::move(vtbl_field));

    // Add vtable
    SynthVTable vtable;
    vtable.name = "synth_vtbl_test";

    VTableSlot slot0, slot1;
    slot0.index = 0;
    slot0.offset = 0;
    slot0.name = "slot_0";

    slot1.index = 1;
    slot1.offset = 8;
    slot1.name = "slot_1";

    vtable.slots.push_back(std::move(slot0));
    vtable.slots.push_back(std::move(slot1));

    s.vtable = std::move(vtable);

    EXPECT_TRUE(s.has_vtable());
    EXPECT_EQ(s.vtable->slot_count(), 2);
}

TEST_F(VTableDetectionTest, SynthStructWithoutVTable) {
    SynthStruct s;

    SynthField field;
    field.name = "field_0";
    field.offset = 0;
    field.size = 4;
    field.semantic = SemanticType::Integer;
    s.fields.push_back(std::move(field));

    EXPECT_FALSE(s.has_vtable());
}

// ============================================================================
// VTable Slot Signature Tests
// ============================================================================

TEST_F(VTableDetectionTest, VTableSlotSignatureStorage) {
    VTableSlot slot;
    slot.index = 0;
    slot.name = "destructor";

    // Create function pointer type
    func_type_data_t ftd;
    ftd.rettype.create_simple_type(BTF_VOID);

    funcarg_t this_arg;
    this_arg.name = "this";
    this_arg.type.create_simple_type(BTF_INT64);  // Actually void*
    ftd.push_back(this_arg);

    slot.func_type.create_func(ftd);

    tinfo_t ptr_type;
    ptr_type.create_ptr(slot.func_type);
    slot.func_type = ptr_type;

    EXPECT_TRUE(slot.func_type.is_ptr());
}

} // namespace test
} // namespace structor
