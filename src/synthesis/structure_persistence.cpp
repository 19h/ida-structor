/// @file structure_persistence.cpp
/// @brief Structure persistence implementation

#include <structor/structure_persistence.hpp>

namespace structor {

tid_t StructurePersistence::create_struct(SynthStruct& synth_struct) {
    constexpr double kReuseThreshold = 0.85;

    if (!synth_struct.fields.empty() && synth_struct.size > 0) {
        auto reuse_candidate = find_reuse_candidate(synth_struct, kReuseThreshold);
        if (reuse_candidate.has_value()) {
            auto [reuse_tid, reuse_name, score] = *reuse_candidate;
            bool reuse = true;
            if (options_.interactive_mode) {
                qstring prompt;
                prompt.sprnt("Structor: Reuse existing struct '%s' (%.0f%% match)?",
                             reuse_name.c_str(), score * 100.0);
                reuse = ask_yn(ASKBTN_YES, "%s", prompt.c_str()) == ASKBTN_YES;
            }
            if (reuse) {
                synth_struct.name = reuse_name;
                synth_struct.tid = reuse_tid;

                if (reuse_tid != BADADDR) {
                    qvector<ea_t> merged = get_provenance(reuse_tid);
                    for (ea_t ea : synth_struct.provenance) {
                        if (std::find(merged.begin(), merged.end(), ea) == merged.end()) {
                            merged.push_back(ea);
                        }
                    }
                    set_provenance(reuse_tid, merged);
                }

                if (synth_struct.has_vtable()) {
                    tid_t vtbl_tid = create_vtable(*synth_struct.vtable);
                    if (vtbl_tid != BADADDR) {
                        synth_struct.vtable->tid = vtbl_tid;
                    }
                }

                return reuse_tid;
            }
        }
    }

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

    std::unordered_map<uint64_t, tinfo_t> bitfield_enums;
    for (const auto& field : synth_struct.fields) {
        if (!field.is_bitfield) {
            continue;
        }

        uint64_t key = (static_cast<uint64_t>(field.offset) << 32) | field.size;
        if (bitfield_enums.find(key) != bitfield_enums.end()) {
            continue;
        }

        qvector<const SynthField*> group;
        for (const auto& candidate : synth_struct.fields) {
            if (candidate.is_bitfield && candidate.offset == field.offset && candidate.size == field.size) {
                group.push_back(&candidate);
            }
        }

        tinfo_t enum_type = create_bitmask_enum_type(name, field.offset, field.size, group);
        if (!enum_type.empty()) {
            bitfield_enums.emplace(key, enum_type);
        }
    }

    // Add fields
    msg("Structor: Creating struct '%s' with %zu fields, total_size=%u\n",
        name.c_str(), synth_struct.fields.size(), synth_struct.size);
    for (const auto& field : synth_struct.fields) {
        if (field.is_union_candidate && !field.union_members.empty()) {
            qvector<SynthField> members;
            members.reserve(field.union_members.size());
            for (const auto& alt : field.union_members) {
                SynthField member;
                member.name = alt.name;
                member.size = alt.size;
                member.type = alt.type;
                member.comment = alt.comment;
                members.push_back(std::move(member));
            }

            qstring union_name = field.name.empty() ? qstring("union") : field.name;
            if (add_union_field(udt, field.offset, union_name, members) != BADADDR) {
                continue;
            }
        }

        msg("Structor:   Adding field '%s' at offset 0x%llX (bits: 0x%llX), size=%u\n",
            field.name.c_str(), static_cast<unsigned long long>(field.offset),
            static_cast<unsigned long long>(field.offset) * 8, field.size);
        udm_t udm;
        udm.name = field.name;

        if (field.is_bitfield) {
            udm.offset = static_cast<uint64>(field.offset) * 8 + field.bit_offset;
            udm.size = field.bit_size > 0 ? field.bit_size : field.size * 8;
            uint64_t key = (static_cast<uint64_t>(field.offset) << 32) | field.size;
            auto enum_it = bitfield_enums.find(key);
            if (enum_it != bitfield_enums.end()) {
                udm.type = enum_it->second;
            } else if (!field.type.empty()) {
                udm.type = field.type;
            } else {
                udm.type = create_bitfield_base_type(field.size);
            }
        } else {
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

    struct_type.set_udt_pack(1);
    struct_type.set_udt_alignment(1);

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

tid_t StructurePersistence::create_struct_with_substructs(
    SynthStruct& synth_struct,
    qvector<SubStructInfo>& sub_structs)
{
    if (!sub_structs.empty()) {
        for (auto& sub : sub_structs) {
            tid_t sub_tid = create_struct(sub.structure);
            if (sub_tid == BADADDR) {
                continue;
            }

            tinfo_t sub_type;
            if (!sub_type.get_type_by_tid(sub_tid)) {
                continue;
            }

            bool matched = false;
            for (auto& field : synth_struct.fields) {
                if (field.offset == sub.parent_offset &&
                    (field.name == sub.field_name || field.name.empty())) {
                    field.type = sub_type;
                    field.semantic = SemanticType::NestedStruct;
                    field.size = sub.structure.size;
                    if (field.name.empty()) {
                        field.name = sub.field_name;
                    }
                    matched = true;
                    break;
                }
            }

            if (!matched) {
                SynthField nested;
                nested.offset = sub.parent_offset;
                nested.size = sub.structure.size;
                nested.type = sub_type;
                nested.semantic = SemanticType::NestedStruct;
                nested.confidence = TypeConfidence::Medium;
                nested.name = sub.field_name;
                synth_struct.fields.push_back(std::move(nested));

                sval_t end = nested.offset + static_cast<sval_t>(nested.size);
                if (end > 0) {
                    synth_struct.size = std::max(synth_struct.size, static_cast<uint32_t>(end));
                }
            }
        }

        std::sort(synth_struct.fields.begin(), synth_struct.fields.end(),
                  [](const SynthField& a, const SynthField& b) {
                      if (a.offset != b.offset) return a.offset < b.offset;
                      if (a.is_bitfield != b.is_bitfield) return a.is_bitfield;
                      return a.bit_offset < b.bit_offset;
                  });
    }

    return create_struct(synth_struct);
}

tid_t StructurePersistence::create_vtable(SynthVTable& vtable) {
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

bool StructurePersistence::update_struct(tid_t tid, const SynthStruct& synth_struct) {
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

        if (field.is_bitfield) {
            udm.offset = static_cast<uint64>(field.offset) * 8 + field.bit_offset;
            udm.size = field.bit_size > 0 ? field.bit_size : field.size * 8;
            if (!field.type.empty()) {
                udm.type = field.type;
            } else {
                udm.type = create_bitfield_base_type(field.size);
            }
        } else {
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
        }

        udt.push_back(udm);
    }

    tinfo_t new_type;
    if (!new_type.create_udt(udt)) {
        return false;
    }

    new_type.set_udt_pack(1);
    new_type.set_udt_alignment(1);

    tinfo_code_t err = new_type.set_named_type(nullptr, name.c_str(), NTF_TYPE | NTF_REPLACE);
    if (err != TERR_OK) {
        return false;
    }

    // Update provenance
    set_provenance(tid, synth_struct.provenance);
    return true;
}

bool StructurePersistence::delete_struct(tid_t tid) {
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

bool StructurePersistence::rename_struct(tid_t tid, const char* new_name) {
    tinfo_t tif;
    if (!tif.get_type_by_tid(tid)) {
        return false;
    }

    // Use tinfo_t::rename_type method
    tinfo_code_t err = tif.rename_type(new_name);
    return err == TERR_OK;
}

qvector<ea_t> StructurePersistence::get_provenance(tid_t tid) {
    return load_provenance(tid);
}

void StructurePersistence::set_provenance(tid_t tid, const qvector<ea_t>& provenance) {
    store_provenance(tid, provenance);
}

bool StructurePersistence::struct_exists(const char* name) {
    return get_named_type_tid(name) != BADADDR;
}

qstring StructurePersistence::make_unique_name(const char* base_name) {
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

void StructurePersistence::store_provenance(tid_t tid, const qvector<ea_t>& provenance) {
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

qvector<ea_t> StructurePersistence::load_provenance(tid_t tid) {
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

tid_t StructurePersistence::create_union(
    const qstring& name,
    const qvector<SynthField>& members)
{
    if (members.empty()) {
        return BADADDR;
    }

    // Generate unique name if needed
    qstring union_name = name;
    if (struct_exists(union_name.c_str())) {
        union_name = make_unique_union_name(union_name.c_str());
    }

    // Create the union type
    tinfo_t union_type;
    udt_type_data_t udt;
    udt.is_union = true;
    udt.total_size = compute_union_size(members);

    // Add all members at offset 0 (union semantics)
    for (const auto& member : members) {
        udm_t udm;
        udm.name = member.name;
        udm.offset = 0;  // All union members start at offset 0

        if (!member.type.empty()) {
            udm.type = member.type;
            udm.size = member.type.get_size() * 8;  // Convert to bits
        } else {
            // Default to bytes array for unknown types
            tinfo_t byte_type;
            byte_type.create_simple_type(BT_INT8 | BTMT_CHAR);
            if (member.size > 1) {
                udm.type.create_array(byte_type, member.size);
            } else {
                udm.type = byte_type;
            }
            udm.size = member.size * 8;
        }

        if (!member.comment.empty()) {
            udm.cmt = member.comment;
        }

        udt.push_back(udm);
    }

    // Create the union type
    if (!union_type.create_udt(udt, BTF_UNION)) {
        msg("Structor: Failed to create union type\n");
        return BADADDR;
    }

    // Save to local type library
    tinfo_code_t err = union_type.set_named_type(nullptr, union_name.c_str(), NTF_TYPE | NTF_REPLACE);
    if (err != TERR_OK) {
        msg("Structor: Failed to save union type: %d\n", err);
        return BADADDR;
    }

    // Get the tid
    return get_named_type_tid(union_name.c_str());
}

tid_t StructurePersistence::add_union_field(
    udt_type_data_t& parent_udt,
    sval_t outer_offset,
    const qstring& union_name,
    const qvector<SynthField>& union_members)
{
    if (union_members.empty()) {
        return BADADDR;
    }

    // First, create the union type as a separate named type
    tid_t union_tid = create_union(union_name, union_members);
    if (union_tid == BADADDR) {
        return BADADDR;
    }

    // Get the union type info
    tinfo_t union_type;
    if (!union_type.get_type_by_tid(union_tid)) {
        return BADADDR;
    }

    // Add a field referencing the union type to the parent struct
    udm_t udm;
    udm.name = union_name;
    udm.offset = static_cast<uint64>(outer_offset) * 8;  // Convert to bits
    udm.type = union_type;
    udm.size = compute_union_size(union_members) * 8;

    parent_udt.push_back(udm);

    return union_tid;
}

uint32_t StructurePersistence::compute_union_size(const qvector<SynthField>& members) {
    uint32_t max_size = 0;

    for (const auto& member : members) {
        uint32_t member_size = member.size;

        // If type is available, use its size instead
        if (!member.type.empty()) {
            size_t type_size = member.type.get_size();
            if (type_size != BADSIZE) {
                member_size = static_cast<uint32_t>(type_size);
            }
        }

        max_size = std::max(max_size, member_size);
    }

    return max_size;
}

qstring StructurePersistence::make_unique_union_name(const char* base_name) {
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

tinfo_t StructurePersistence::create_raw_bytes_type(uint32_t size) {
    // Create uint8_t[size] type for irreconcilable regions
    tinfo_t element_type;
    element_type.create_simple_type(BT_INT8 | BTMT_USIGNED);

    tinfo_t array_type;
    array_type.create_array(element_type, size);

    return array_type;
}

tinfo_t StructurePersistence::create_bitfield_base_type(uint32_t size) {
    tinfo_t type;

    switch (size) {
        case 1:
            type.create_simple_type(BT_INT8 | BTMT_USIGNED);
            break;
        case 2:
            type.create_simple_type(BT_INT16 | BTMT_USIGNED);
            break;
        case 4:
            type.create_simple_type(BT_INT32 | BTMT_USIGNED);
            break;
        case 8:
            type.create_simple_type(BT_INT64 | BTMT_USIGNED);
            break;
        default:
            type.create_simple_type(BT_INT8 | BTMT_USIGNED);
            break;
    }

    return type;
}

tinfo_t StructurePersistence::create_bitmask_enum_type(
    const qstring& base_name,
    sval_t offset,
    uint32_t storage_size,
    const qvector<const SynthField*>& bitfields)
{
    if (bitfields.empty() || storage_size == 0 || storage_size > 8) {
        return tinfo_t();
    }

    qstring enum_name;
    enum_name.sprnt("%s_flags_%llX", base_name.c_str(),
                    static_cast<unsigned long long>(offset));
    if (struct_exists(enum_name.c_str())) {
        enum_name = make_unique_name(enum_name.c_str());
    }

    enum_type_data_t ei(BTE_ALWAYS | BTE_HEX);
    for (const auto* field : bitfields) {
        if (!field || field->bit_size == 0 || field->bit_size >= 64) {
            continue;
        }

        uint64 mask = ((uint64{1} << field->bit_size) - 1) << field->bit_offset;
        ei.push_back(edm_t(field->name.c_str(), mask));
    }

    if (ei.empty()) {
        return tinfo_t();
    }

    tid_t tid = create_enum_type(enum_name.c_str(), ei, static_cast<int>(storage_size),
                                 type_unsigned, true, "Structor recovered bitmask flags");
    if (tid == BADADDR) {
        return tinfo_t();
    }

    tinfo_t enum_type;
    enum_type.get_type_by_tid(tid);
    return enum_type;
}

SemanticType StructurePersistence::semantic_from_type(const tinfo_t& type) {
    if (type.empty()) {
        return SemanticType::Unknown;
    }

    if (type.is_funcptr()) {
        return SemanticType::FunctionPointer;
    }

    if (type.is_ptr()) {
        tinfo_t pointed = type.get_pointed_object();
        if (!pointed.empty() && pointed.is_funcptr()) {
            return SemanticType::FunctionPointer;
        }
        return SemanticType::Pointer;
    }

    if (type.is_array()) {
        return SemanticType::Array;
    }

    if (type.is_struct()) {
        return SemanticType::NestedStruct;
    }

    if (type.is_floating()) {
        return type.get_size() == 4 ? SemanticType::Float : SemanticType::Double;
    }

    if (type.is_unsigned()) {
        return SemanticType::UnsignedInteger;
    }

    if (type.is_integral()) {
        return SemanticType::Integer;
    }

    return SemanticType::Unknown;
}

StructurePersistence::StructSignature StructurePersistence::build_signature(
    const SynthStruct& synth_struct)
{
    StructSignature sig;
    sig.fields.reserve(synth_struct.fields.size());

    for (const auto& field : synth_struct.fields) {
        if (field.is_padding) {
            continue;
        }

        FieldSignature fs;
        if (field.is_bitfield) {
            fs.offset = field.offset * 8 + field.bit_offset;
            fs.size = field.bit_size;
        } else {
            fs.offset = field.offset * 8;
            fs.size = field.size * 8;
        }
        fs.semantic = field.semantic != SemanticType::Unknown
            ? field.semantic
            : semantic_from_type(field.type);

        if (fs.size == 0) {
            continue;
        }

        sig.fields.push_back(fs);
    }

    return sig;
}

bool StructurePersistence::build_signature_from_tinfo(
    const tinfo_t& tif,
    StructSignature& out)
{
    out.fields.clear();

    if (!tif.is_struct()) {
        return false;
    }

    udt_type_data_t udt;
    if (!tif.get_udt_details(&udt)) {
        return false;
    }

    out.fields.reserve(udt.size());

    for (const auto& member : udt) {
        const char* name = member.name.c_str();
        if (name && (strncmp(name, "__pad_", 6) == 0 || strncmp(name, "__raw_", 6) == 0)) {
            continue;
        }

        FieldSignature fs;
        fs.offset = static_cast<sval_t>(member.offset);
        fs.size = member.size;

        if (fs.size == 0 && !member.type.empty()) {
            size_t sz = member.type.get_size();
            if (sz != BADSIZE) {
                fs.size = static_cast<uint32_t>(sz * 8);
            }
        }

        fs.semantic = semantic_from_type(member.type);

        if (fs.size == 0) {
            continue;
        }

        out.fields.push_back(fs);
    }

    return !out.fields.empty();
}

double StructurePersistence::compute_similarity(
    const StructSignature& a,
    const StructSignature& b)
{
    if (a.fields.empty() || b.fields.empty()) {
        return 0.0;
    }

    struct Key {
        sval_t offset;
        uint32_t size;
        SemanticType semantic;
    };

    struct KeyHash {
        size_t operator()(const Key& key) const noexcept {
            size_t h1 = std::hash<int64_t>{}(static_cast<int64_t>(key.offset));
            size_t h2 = std::hash<uint32_t>{}(key.size);
            size_t h3 = std::hash<int>{}(static_cast<int>(key.semantic));
            return h1 ^ (h2 << 1) ^ (h3 << 2);
        }
    };

    struct KeyEq {
        bool operator()(const Key& lhs, const Key& rhs) const noexcept {
            return lhs.offset == rhs.offset && lhs.size == rhs.size && lhs.semantic == rhs.semantic;
        }
    };

    std::unordered_map<Key, int, KeyHash, KeyEq> counts;
    counts.reserve(a.fields.size());

    for (const auto& field : a.fields) {
        Key key{field.offset, field.size, field.semantic};
        counts[key] += 1;
    }

    int matches = 0;
    for (const auto& field : b.fields) {
        Key key{field.offset, field.size, field.semantic};
        auto it = counts.find(key);
        if (it != counts.end() && it->second > 0) {
            it->second -= 1;
            matches += 1;
        }
    }

    int total = static_cast<int>(a.fields.size() + b.fields.size() - matches);
    if (total <= 0) {
        return 0.0;
    }

    return static_cast<double>(matches) / static_cast<double>(total);
}

std::optional<std::tuple<tid_t, qstring, double>> StructurePersistence::find_reuse_candidate(
    const SynthStruct& synth_struct,
    double threshold)
{
    StructSignature synth_sig = build_signature(synth_struct);
    if (synth_sig.fields.empty()) {
        return std::nullopt;
    }

    til_t* til = get_idati();
    if (!til) {
        return std::nullopt;
    }

    uint32_t limit = get_ordinal_limit(til);
    tid_t best_tid = BADADDR;
    qstring best_name;
    double best_score = threshold;

    for (uint32_t ord = 1; ord < limit; ++ord) {
        tinfo_t tif;
        if (!tif.get_numbered_type(til, ord)) {
            continue;
        }

        if (!tif.is_struct()) {
            continue;
        }

        size_t type_size = tif.get_size();
        if (type_size == BADSIZE || type_size == 0) {
            continue;
        }

        if (synth_struct.size != 0 && type_size != synth_struct.size) {
            continue;
        }

        StructSignature sig;
        if (!build_signature_from_tinfo(tif, sig)) {
            continue;
        }

        double score = compute_similarity(synth_sig, sig);
        if (score < best_score) {
            continue;
        }

        const char* type_name = get_numbered_type_name(til, ord);
        if (!type_name || type_name[0] == '\0') {
            continue;
        }

        tid_t tid = tif.get_tid();
        if (tid == BADADDR) {
            continue;
        }

        best_score = score;
        best_tid = tid;
        best_name = type_name;
    }

    if (best_tid == BADADDR) {
        return std::nullopt;
    }

    return std::make_optional(std::make_tuple(best_tid, best_name, best_score));
}

} // namespace structor
