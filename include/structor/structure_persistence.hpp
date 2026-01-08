#pragma once

#include "synth_types.hpp"
#include "config.hpp"
#include "utils.hpp"
#include <netnode.hpp>

namespace structor {

/// Handles persistence of synthesized structures to the IDB
class StructurePersistence {
public:
    explicit StructurePersistence(const SynthOptions& opts = Config::instance().options())
        : options_(opts) {}

    /// Create a structure type in the IDB from synthesized structure
    [[nodiscard]] tid_t create_struct(SynthStruct& synth_struct);

    /// Create a vtable structure in the IDB
    [[nodiscard]] tid_t create_vtable(SynthVTable& vtable);

    /// Update an existing structure with new fields
    [[nodiscard]] bool update_struct(tid_t tid, const SynthStruct& synth_struct);

    /// Delete a synthesized structure
    [[nodiscard]] bool delete_struct(tid_t tid);

    /// Rename a structure
    [[nodiscard]] bool rename_struct(tid_t tid, const char* new_name);

    /// Get provenance info for a structure
    [[nodiscard]] qvector<ea_t> get_provenance(tid_t tid);

    /// Set provenance info for a structure
    void set_provenance(tid_t tid, const qvector<ea_t>& provenance);

    /// Check if a structure name exists
    [[nodiscard]] bool struct_exists(const char* name);

    /// Generate a unique structure name
    [[nodiscard]] qstring make_unique_name(const char* base_name);

private:
    bool add_struct_fields(tinfo_t& tif, const qvector<SynthField>& fields);
    bool add_vtable_slots(tinfo_t& tif, const qvector<VTableSlot>& slots);

    void store_provenance(tid_t tid, const qvector<ea_t>& provenance);
    qvector<ea_t> load_provenance(tid_t tid);

    const SynthOptions& options_;

    static constexpr const char* PROVENANCE_NETNODE_PREFIX = "$ structor_prov_";
    static constexpr nodeidx_t PROVENANCE_TAG = 'P';
};

// ============================================================================
// Implementation
// ============================================================================

inline tid_t StructurePersistence::create_struct(SynthStruct& synth_struct) {
    // Generate unique name if needed
    qstring name = synth_struct.name;
    if (struct_exists(name.c_str())) {
        name = make_unique_name(name.c_str());
        synth_struct.name = name;
    }

    // Create the structure type
    tinfo_t struct_type;
    udt_type_data_t udt;
    udt.is_union = false;
    udt.total_size = synth_struct.size;

    // Add fields
    for (const auto& field : synth_struct.fields) {
        udm_t udm;
        udm.name = field.name;
        udm.offset = static_cast<uint64>(field.offset) * 8;  // Convert to bits

        if (!field.type.empty()) {
            udm.type = field.type;
            udm.size = field.type.get_size() * 8;
        } else {
            // Default to bytes array for unknown types
            tinfo_t byte_type;
            byte_type.create_simple_type(BT_INT8 | BTMT_CHAR);
            if (field.size > 1) {
                udm.type.create_array(byte_type, field.size);
            } else {
                udm.type = byte_type;
            }
            udm.size = field.size * 8;
        }

        if (!field.comment.empty()) {
            udm.cmt = field.comment;
        }

        udt.push_back(udm);
    }

    // Create the struct type
    if (!struct_type.create_udt(udt)) {
        msg("Structor: Failed to create struct type\n");
        return BADADDR;
    }

    // Save to local type library
    tinfo_code_t err = struct_type.set_named_type(nullptr, name.c_str(), NTF_TYPE | NTF_REPLACE);
    if (err != TERR_OK) {
        msg("Structor: Failed to save struct type: %d\n", err);
        return BADADDR;
    }

    // Get the tid
    tid_t tid = get_named_type_tid(name.c_str());

    // Create vtable structure if present
    if (synth_struct.has_vtable()) {
        tid_t vtbl_tid = create_vtable(*synth_struct.vtable);
        if (vtbl_tid != BADADDR) {
            synth_struct.vtable->tid = vtbl_tid;
            // Note: Could update the vtable pointer field type here
        }
    }

    // Store provenance
    if (tid != BADADDR) {
        set_provenance(tid, synth_struct.provenance);
        synth_struct.tid = tid;
    }

    return tid;
}

inline tid_t StructurePersistence::create_vtable(SynthVTable& vtable) {
    qstring name = vtable.name;
    if (struct_exists(name.c_str())) {
        name = make_unique_name(name.c_str());
        vtable.name = name;
    }

    // Create vtable type
    tinfo_t vtbl_type;
    udt_type_data_t udt;
    udt.is_union = false;
    udt.set_vftable(true);

    // Add slots
    for (const auto& slot : vtable.slots) {
        udm_t udm;
        udm.name = slot.name;
        udm.offset = static_cast<uint64>(slot.offset) * 8;  // Convert to bits

        if (!slot.func_type.empty()) {
            udm.type = slot.func_type;
        } else {
            // Generic function pointer
            func_type_data_t ftd;
            ftd.rettype.create_simple_type(BTF_VOID);
            ftd.set_cc(CM_CC_UNKNOWN);
            tinfo_t func_type;
            func_type.create_func(ftd);
            udm.type.create_ptr(func_type);
        }

        udm.size = get_ptr_size() * 8;

        if (!slot.signature_hint.empty()) {
            udm.cmt = slot.signature_hint;
        }

        udt.push_back(udm);
    }

    udt.total_size = vtable.slots.empty() ? get_ptr_size() :
                     (vtable.slots.back().offset + get_ptr_size());

    if (!vtbl_type.create_udt(udt)) {
        return BADADDR;
    }

    tinfo_code_t err = vtbl_type.set_named_type(nullptr, name.c_str(), NTF_TYPE | NTF_REPLACE);
    if (err != TERR_OK) {
        return BADADDR;
    }

    tid_t tid = get_named_type_tid(name.c_str());
    vtable.tid = tid;
    return tid;
}

inline bool StructurePersistence::update_struct(tid_t tid, const SynthStruct& synth_struct) {
    // Get the type by tid
    tinfo_t tif;
    if (!tif.get_type_by_tid(tid)) {
        return false;
    }

    // Get the name
    qstring name;
    tif.get_type_name(&name);
    if (name.empty()) {
        return false;
    }

    // Recreate the structure with new fields
    udt_type_data_t udt;
    udt.is_union = false;
    udt.total_size = synth_struct.size;

    for (const auto& field : synth_struct.fields) {
        udm_t udm;
        udm.name = field.name;
        udm.offset = static_cast<uint64>(field.offset) * 8;

        if (!field.type.empty()) {
            udm.type = field.type;
            udm.size = field.type.get_size() * 8;
        } else {
            tinfo_t byte_type;
            byte_type.create_simple_type(BT_INT8 | BTMT_CHAR);
            if (field.size > 1) {
                udm.type.create_array(byte_type, field.size);
            } else {
                udm.type = byte_type;
            }
            udm.size = field.size * 8;
        }

        udt.push_back(udm);
    }

    tinfo_t new_type;
    if (!new_type.create_udt(udt)) {
        return false;
    }

    tinfo_code_t err = new_type.set_named_type(nullptr, name.c_str(), NTF_TYPE | NTF_REPLACE);
    if (err != TERR_OK) {
        return false;
    }

    // Update provenance
    set_provenance(tid, synth_struct.provenance);
    return true;
}

inline bool StructurePersistence::delete_struct(tid_t tid) {
    tinfo_t tif;
    if (!tif.get_type_by_tid(tid)) {
        return false;
    }

    qstring name;
    tif.get_type_name(&name);
    if (name.empty()) {
        return false;
    }

    // Clear provenance
    qstring node_name;
    node_name.sprnt("%s%llX", PROVENANCE_NETNODE_PREFIX, static_cast<unsigned long long>(tid));
    netnode node(node_name.c_str(), 0, false);
    if (node != BADNODE) {
        node.kill();
    }

    // Delete the named type
    return del_named_type(nullptr, name.c_str(), NTF_TYPE);
}

inline bool StructurePersistence::rename_struct(tid_t tid, const char* new_name) {
    tinfo_t tif;
    if (!tif.get_type_by_tid(tid)) {
        return false;
    }

    // Use tinfo_t::rename_type method
    tinfo_code_t err = tif.rename_type(new_name);
    return err == TERR_OK;
}

inline qvector<ea_t> StructurePersistence::get_provenance(tid_t tid) {
    return load_provenance(tid);
}

inline void StructurePersistence::set_provenance(tid_t tid, const qvector<ea_t>& provenance) {
    store_provenance(tid, provenance);
}

inline bool StructurePersistence::struct_exists(const char* name) {
    return get_named_type_tid(name) != BADADDR;
}

inline qstring StructurePersistence::make_unique_name(const char* base_name) {
    qstring name = base_name;

    if (!struct_exists(name.c_str())) {
        return name;
    }

    for (int i = 1; i < 10000; ++i) {
        qstring candidate;
        candidate.sprnt("%s_%d", base_name, i);
        if (!struct_exists(candidate.c_str())) {
            return candidate;
        }
    }

    // Fallback with timestamp
    qstring candidate;
    candidate.sprnt("%s_%llX", base_name, static_cast<unsigned long long>(time(nullptr)));
    return candidate;
}

inline void StructurePersistence::store_provenance(tid_t tid, const qvector<ea_t>& provenance) {
    qstring node_name;
    node_name.sprnt("%s%llX", PROVENANCE_NETNODE_PREFIX, static_cast<unsigned long long>(tid));

    netnode node(node_name.c_str(), 0, true);
    if (node == BADNODE) return;

    // Serialize provenance
    qvector<char> blob;
    blob.reserve(provenance.size() * sizeof(ea_t) + 4);

    // Write count
    std::uint32_t count = provenance.size();
    const char* p = reinterpret_cast<const char*>(&count);
    for (size_t i = 0; i < sizeof(count); ++i) {
        blob.push_back(p[i]);
    }

    // Write EAs
    for (ea_t ea : provenance) {
        p = reinterpret_cast<const char*>(&ea);
        for (size_t i = 0; i < sizeof(ea); ++i) {
            blob.push_back(p[i]);
        }
    }

    node.setblob(blob.begin(), blob.size(), 0, PROVENANCE_TAG);
}

inline qvector<ea_t> StructurePersistence::load_provenance(tid_t tid) {
    qvector<ea_t> result;

    qstring node_name;
    node_name.sprnt("%s%llX", PROVENANCE_NETNODE_PREFIX, static_cast<unsigned long long>(tid));

    netnode node(node_name.c_str(), 0, false);
    if (node == BADNODE) return result;

    size_t blob_size = 0;
    void* blob = node.getblob(nullptr, &blob_size, 0, PROVENANCE_TAG);
    if (!blob || blob_size < 4) {
        if (blob) qfree(blob);
        return result;
    }

    const char* data = static_cast<const char*>(blob);

    // Read count
    std::uint32_t count;
    std::memcpy(&count, data, sizeof(count));
    data += sizeof(count);

    // Validate
    size_t expected_size = sizeof(count) + count * sizeof(ea_t);
    if (blob_size < expected_size) {
        qfree(blob);
        return result;
    }

    // Read EAs
    result.reserve(count);
    for (std::uint32_t i = 0; i < count; ++i) {
        ea_t ea;
        std::memcpy(&ea, data, sizeof(ea));
        data += sizeof(ea);
        result.push_back(ea);
    }

    qfree(blob);
    return result;
}

} // namespace structor
