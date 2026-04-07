#pragma once

#include "synth_types.hpp"
#include "config.hpp"
#include "utils.hpp"
#include <netnode.hpp>
#include <tuple>

namespace structor {

/// Handles persistence of synthesized structures to the IDB
class StructurePersistence {
public:
    explicit StructurePersistence(const SynthOptions& opts = Config::instance().options())
        : options_(opts) {}

    /// Create a structure type in the IDB from synthesized structure
    [[nodiscard]] tid_t create_struct(SynthStruct& synth_struct);

    /// Create a structure with nested sub-structures
    [[nodiscard]] tid_t create_struct_with_substructs(
        SynthStruct& synth_struct,
        qvector<SubStructInfo>& sub_structs
    );

    /// Create a vtable structure in the IDB
    [[nodiscard]] tid_t create_vtable(SynthVTable& vtable);

    /// Create a union type in the IDB
    /// Returns the tid_t of the created union, or BADADDR on failure
    [[nodiscard]] tid_t create_union(
        const qstring& name,
        const qvector<SynthField>& members
    );

    /// Create a struct field that is itself an embedded union
    /// Union members are added at offset 0 within the union
    /// Returns the tid of the embedded union, or BADADDR on failure
    [[nodiscard]] tid_t add_union_field(
        udt_type_data_t& parent_udt,
        sval_t outer_offset,          // Offset of union within parent struct
        const qstring& union_name,
        const qvector<SynthField>& union_members
    );

    /// Compute union size (max of member sizes)
    [[nodiscard]] static uint32_t compute_union_size(const qvector<SynthField>& members);

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

    /// Generate a unique union name
    [[nodiscard]] qstring make_unique_union_name(const char* base_name);

private:
    bool add_struct_fields(tinfo_t& tif, const qvector<SynthField>& fields);
    bool add_vtable_slots(tinfo_t& tif, const qvector<VTableSlot>& slots);

    void store_provenance(tid_t tid, const qvector<ea_t>& provenance);
    qvector<ea_t> load_provenance(tid_t tid);

    struct FieldSignature {
        sval_t offset = 0;
        uint32_t size = 0;
        SemanticType semantic = SemanticType::Unknown;
    };

    struct StructSignature {
        qvector<FieldSignature> fields;
    };

    [[nodiscard]] std::optional<std::tuple<tid_t, qstring, double>> find_reuse_candidate(
        const SynthStruct& synth_struct,
        double threshold
    );
    [[nodiscard]] static StructSignature build_signature(const SynthStruct& synth_struct);
    [[nodiscard]] static bool build_signature_from_tinfo(const tinfo_t& tif, StructSignature& out);
    [[nodiscard]] static double compute_similarity(const StructSignature& a, const StructSignature& b);
    [[nodiscard]] static SemanticType semantic_from_type(const tinfo_t& type);

    /// Create raw bytes field type for irreconcilable regions
    [[nodiscard]] static tinfo_t create_raw_bytes_type(uint32_t size);
    [[nodiscard]] static tinfo_t create_bitfield_base_type(uint32_t size);
    [[nodiscard]] tinfo_t create_bitmask_enum_type(
        const qstring& base_name,
        sval_t offset,
        uint32_t storage_size,
        const qvector<const SynthField*>& bitfields);

    const SynthOptions& options_;

    static constexpr const char* PROVENANCE_NETNODE_PREFIX = "$ structor_prov_";
    static constexpr nodeidx_t PROVENANCE_TAG = 'P';
};

} // namespace structor
