/// @file type_matcher.cpp
/// @brief Sparse matching of synthesized structures against existing IDA types

#include <structor/type_matcher.hpp>

#include <algorithm>
#include <cctype>
#include <string>
#include <unordered_set>

namespace structor {

namespace {

qstring render_type_decl(const tinfo_t& type) {
    qstring decl;
    if (!type.empty()) {
        type.print(&decl);
    }
    return decl;
}

std::uint32_t member_size_bytes(const udm_t& member) {
    if (member.size != 0) {
        return static_cast<std::uint32_t>((member.size + 7) / 8);
    }

    const size_t type_size = member.type.get_size();
    if (type_size != BADSIZE && type_size > 0) {
        return static_cast<std::uint32_t>(type_size);
    }

    return 1;
}

bool extract_existing_fields(const tinfo_t& type, qvector<ExistingTypeField>& out) {
    udt_type_data_t udt;
    if (!type.get_udt_details(&udt)) {
        return false;
    }

    for (const auto& member : udt) {
        ExistingTypeField field;
        field.name = member.name;
        field.offset = static_cast<sval_t>(member.offset / 8);
        field.size = member_size_bytes(member);
        field.type = member.type;
        field.type_decl = render_type_decl(member.type);
        field.is_padding = ExistingTypeMatcher::is_padding_name(field.name);
        out.push_back(std::move(field));
    }

    return true;
}

std::uint32_t count_synth_fields(const SynthStruct& synth_struct) {
    std::uint32_t count = 0;
    for (const auto& field : synth_struct.fields) {
        if (!ExistingTypeMatcher::is_effective_padding(field) && field.size != 0) {
            ++count;
        }
    }
    return count;
}

std::uint32_t count_existing_fields(const qvector<ExistingTypeField>& fields) {
    std::uint32_t count = 0;
    for (const auto& field : fields) {
        if (!field.is_padding && field.size != 0) {
            ++count;
        }
    }
    return count;
}

bool existing_field_less(const ExistingTypeField& a, const ExistingTypeField& b) {
    if (a.offset != b.offset) {
        return a.offset < b.offset;
    }
    if (a.size != b.size) {
        return a.size < b.size;
    }
    return std::string(a.name.c_str()) < std::string(b.name.c_str());
}

void uniquify_field_names(qvector<SynthField>& fields) {
    std::unordered_set<std::string> seen;
    for (auto& field : fields) {
        if (field.name.empty()) {
            field.name.sprnt("field_%X", static_cast<unsigned>(field.offset));
        }

        std::string base(field.name.c_str());
        std::string candidate = base;
        unsigned suffix = 1;
        while (seen.find(candidate) != seen.end()) {
            candidate = base + "_" + std::to_string(suffix++);
        }

        if (candidate != base) {
            field.name = candidate.c_str();
        }
        seen.insert(candidate);
    }
}

} // namespace

bool ExistingTypeMatcher::ranges_overlap(
    sval_t a_offset,
    std::uint32_t a_size,
    sval_t b_offset,
    std::uint32_t b_size) noexcept
{
    if (a_size == 0 || b_size == 0) {
        return false;
    }

    const sval_t a_end = a_offset + static_cast<sval_t>(a_size);
    const sval_t b_end = b_offset + static_cast<sval_t>(b_size);
    return a_offset < b_end && b_offset < a_end;
}

bool ExistingTypeMatcher::is_padding_name(const qstring& name) noexcept {
    if (name.empty()) {
        return false;
    }

    std::string lower(name.c_str());
    std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });

    return lower.rfind("__pad", 0) == 0 ||
           lower.rfind("_pad", 0) == 0 ||
           lower.rfind("pad_", 0) == 0 ||
           lower.rfind("padding", 0) == 0 ||
           lower.rfind("gap", 0) == 0 ||
           lower.rfind("align", 0) == 0;
}

bool ExistingTypeMatcher::is_effective_padding(const SynthField& field) noexcept {
    return field.is_padding || field.semantic == SemanticType::Padding || is_padding_name(field.name);
}

SemanticType ExistingTypeMatcher::semantic_from_type(const tinfo_t& type) noexcept {
    if (type.empty()) {
        return SemanticType::Unknown;
    }
    if (type.is_func() || type.is_funcptr()) {
        return SemanticType::FunctionPointer;
    }
    if (type.is_ptr()) {
        tinfo_t pointed = type.get_pointed_object();
        if (!pointed.empty() && pointed.is_func()) {
            return SemanticType::FunctionPointer;
        }
        return SemanticType::Pointer;
    }
    if (type.is_struct() || type.is_union()) {
        return SemanticType::NestedStruct;
    }
    if (type.is_array()) {
        return SemanticType::Array;
    }
    if (type.is_floating()) {
        return type.get_size() == 8 ? SemanticType::Double : SemanticType::Float;
    }
    if (!type.is_signed()) {
        return SemanticType::UnsignedInteger;
    }
    return SemanticType::Integer;
}

bool ExistingTypeMatcher::types_compatible(const tinfo_t& a, const tinfo_t& b) noexcept {
    if (a.empty() || b.empty()) {
        return false;
    }

    try {
        if (a.compare_with(b, TCMP_IGNMODS | TCMP_DECL)) {
            return true;
        }
    } catch (...) {
    }

    const size_t a_size = a.get_size();
    const size_t b_size = b.get_size();
    return a_size != BADSIZE && a_size == b_size && semantic_from_type(a) == semantic_from_type(b);
}

bool ExistingTypeMatcher::field_name_can_be_reused(const SynthField& field) noexcept {
    if (field.name.empty()) {
        return true;
    }

    if (field.naming.locked || field.naming.origin == NameOrigin::UserProvided) {
        return false;
    }

    return is_generated_name(field.name, &field.naming) ||
           field.naming.origin == NameOrigin::GeneratedFallback ||
           field.naming.origin == NameOrigin::HeuristicRole;
}

qvector<TypeOverlapCandidate> ExistingTypeMatcher::find_matches(
    const SynthStruct& synth_struct,
    std::size_t max_results,
    double min_score) const
{
    qvector<TypeOverlapCandidate> result;
    const std::uint32_t synth_count = count_synth_fields(synth_struct);
    if (synth_count == 0) {
        return result;
    }

#ifdef STRUCTOR_TESTING
    (void)max_results;
    (void)min_score;
    return result;
#else
    til_t* til = get_idati();
    if (!til) {
        return result;
    }

    const uint32_t limit = get_ordinal_limit(til);
    for (uint32_t ord = 1; ord < limit; ++ord) {
        tinfo_t type;
        if (!type.get_numbered_type(til, ord) || !type.is_struct()) {
            continue;
        }

        qvector<ExistingTypeField> existing_fields;
        if (!extract_existing_fields(type, existing_fields)) {
            continue;
        }

        const std::uint32_t existing_count = count_existing_fields(existing_fields);
        if (existing_count == 0) {
            continue;
        }

        TypeOverlapCandidate candidate;
        candidate.tid = type.get_tid();
        const char* type_name = get_numbered_type_name(til, ord);
        if (!type_name || type_name[0] == '\0' || candidate.tid == BADADDR) {
            continue;
        }
        candidate.name = type_name;

        const size_t type_size = type.get_size();
        candidate.size = type_size != BADSIZE ? static_cast<std::uint32_t>(type_size) : 0;
        candidate.synth_field_count = synth_count;
        candidate.existing_field_count = existing_count;
        candidate.fields = std::move(existing_fields);

        std::unordered_set<std::size_t> matched_synth_indexes;
        for (const auto& existing : candidate.fields) {
            if (existing.is_padding || existing.size == 0) {
                continue;
            }

            bool existing_matched = false;
            for (std::size_t i = 0; i < synth_struct.fields.size(); ++i) {
                const SynthField& synth = synth_struct.fields[i];
                if (is_effective_padding(synth) || synth.size == 0) {
                    continue;
                }

                if (!ranges_overlap(synth.offset, synth.size, existing.offset, existing.size)) {
                    continue;
                }

                existing_matched = true;
                matched_synth_indexes.insert(i);

                if (synth.offset == existing.offset) {
                    ++candidate.exact_offset_matches;
                }
                if (types_compatible(synth.type, existing.type)) {
                    ++candidate.type_matches;
                }
            }

            if (existing_matched) {
                ++candidate.matched_existing_fields;
            }
        }

        candidate.matched_synth_fields = static_cast<std::uint32_t>(matched_synth_indexes.size());
        if (candidate.matched_existing_fields == 0) {
            continue;
        }

        const double existing_coverage = static_cast<double>(candidate.matched_existing_fields) /
                                         static_cast<double>(candidate.existing_field_count);
        const double synth_coverage = static_cast<double>(candidate.matched_synth_fields) /
                                      static_cast<double>(candidate.synth_field_count);
        const double exact_ratio = static_cast<double>(candidate.exact_offset_matches) /
                                   static_cast<double>(candidate.matched_existing_fields);
        const double type_ratio = candidate.exact_offset_matches == 0
            ? 0.0
            : static_cast<double>(candidate.type_matches) /
              static_cast<double>(candidate.exact_offset_matches);

        candidate.score = (0.55 * existing_coverage) +
                          (0.25 * synth_coverage) +
                          (0.12 * exact_ratio) +
                          (0.08 * type_ratio);

        if (candidate.score < min_score) {
            continue;
        }

        candidate.summary.sprnt("%u/%u existing, %u/%u synthesized, %u exact, %u type",
                                candidate.matched_existing_fields,
                                candidate.existing_field_count,
                                candidate.matched_synth_fields,
                                candidate.synth_field_count,
                                candidate.exact_offset_matches,
                                candidate.type_matches);
        std::sort(candidate.fields.begin(), candidate.fields.end(), existing_field_less);
        result.push_back(std::move(candidate));
    }

    std::sort(result.begin(), result.end(), [](const TypeOverlapCandidate& a,
                                               const TypeOverlapCandidate& b) {
        if (a.score != b.score) {
            return a.score > b.score;
        }
        if (a.matched_existing_fields != b.matched_existing_fields) {
            return a.matched_existing_fields > b.matched_existing_fields;
        }
        return std::string(a.name.c_str()) < std::string(b.name.c_str());
    });

    if (result.size() > max_results) {
        result.resize(max_results);
    }

    return result;
#endif
}

TypeMergeResult ExistingTypeMatcher::merge_existing_type(
    SynthStruct& synth_struct,
    const TypeOverlapCandidate& candidate) const
{
    TypeMergeResult result;
    if (candidate.tid == BADADDR || candidate.fields.empty()) {
        result.message = "No existing type fields to merge";
        return result;
    }

    for (const auto& existing : candidate.fields) {
        if (existing.is_padding || existing.size == 0) {
            continue;
        }

        SynthField* exact = nullptr;
        for (auto& synth : synth_struct.fields) {
            if (synth.offset == existing.offset && !is_effective_padding(synth)) {
                exact = &synth;
                break;
            }
        }

        if (exact) {
            if (!existing.name.empty() && field_name_can_be_reused(*exact) && exact->name != existing.name) {
                exact->name = existing.name;
                exact->naming.kind = GeneratedNameKind::Field;
                exact->naming.origin = NameOrigin::ReusedType;
                exact->naming.confidence = NameConfidence::High;
                ++result.fields_renamed;
            }

            if (!existing.type.empty()) {
                bool type_range_conflicts = false;
                for (const auto& other : synth_struct.fields) {
                    if (&other == exact || is_effective_padding(other)) {
                        continue;
                    }
                    if (ranges_overlap(other.offset, other.size, existing.offset, existing.size)) {
                        type_range_conflicts = true;
                        break;
                    }
                }

                if (type_range_conflicts) {
                    ++result.fields_skipped;
                    continue;
                }

                exact->type = existing.type;
                exact->semantic = semantic_from_type(existing.type);
                exact->confidence = TypeConfidence::High;
                exact->size = existing.size;
                ++result.fields_retyped;
            }
            continue;
        }

        bool conflicts_with_real_field = false;
        qvector<SynthField> kept;
        kept.reserve(synth_struct.fields.size());
        for (auto& synth : synth_struct.fields) {
            if (!ranges_overlap(synth.offset, synth.size, existing.offset, existing.size)) {
                kept.push_back(std::move(synth));
                continue;
            }

            if (is_effective_padding(synth)) {
                continue;
            }

            conflicts_with_real_field = true;
            kept.push_back(std::move(synth));
        }

        if (conflicts_with_real_field) {
            ++result.fields_skipped;
            continue;
        }

        SynthField merged;
        merged.name = existing.name.empty() ? qstring() : existing.name;
        if (merged.name.empty()) {
            merged.name.sprnt("field_%X", static_cast<unsigned>(existing.offset));
        }
        merged.naming.kind = GeneratedNameKind::Field;
        merged.naming.origin = NameOrigin::ReusedType;
        merged.naming.confidence = NameConfidence::High;
        merged.offset = existing.offset;
        merged.size = existing.size;
        merged.type = existing.type;
        merged.semantic = semantic_from_type(existing.type);
        merged.confidence = TypeConfidence::High;
        merged.comment.sprnt("Merged from existing type %s", candidate.name.c_str());
        kept.push_back(std::move(merged));
        synth_struct.fields = std::move(kept);
        ++result.fields_added;
    }

    for (const auto& existing : candidate.fields) {
        if (existing.is_padding || existing.size == 0 || existing.offset < 0) {
            continue;
        }
        const sval_t end = existing.offset + static_cast<sval_t>(existing.size);
        if (end > 0) {
            synth_struct.size = std::max(synth_struct.size, static_cast<std::uint32_t>(end));
        }
    }

    std::sort(synth_struct.fields.begin(), synth_struct.fields.end(), [](const SynthField& a,
                                                                         const SynthField& b) {
        if (a.offset != b.offset) {
            return a.offset < b.offset;
        }
        if (a.is_bitfield != b.is_bitfield) {
            return a.is_bitfield;
        }
        return a.bit_offset < b.bit_offset;
    });
    uniquify_field_names(synth_struct.fields);

    result.success = true;
    result.message.sprnt("Merged %s: +%u fields, renamed %u, retyped %u, skipped %u conflicts",
                         candidate.name.c_str(),
                         result.fields_added,
                         result.fields_renamed,
                         result.fields_retyped,
                         result.fields_skipped);
    return result;
}

} // namespace structor
