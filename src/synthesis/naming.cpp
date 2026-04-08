/// @file naming.cpp
/// @brief Shared naming policy helpers

#ifdef STRUCTOR_TESTING
#include "../../test/mock_ida.hpp"
#endif

#include <structor/naming.hpp>

#include <structor/utils.hpp>

#include <array>
#include <cctype>
#include <string_view>
#include <unordered_set>

namespace structor {

namespace {

bool starts_with(const qstring& value, const char* prefix) noexcept {
    const size_t prefix_len = strlen(prefix);
    return strncmp(value.c_str(), prefix, prefix_len) == 0;
}

qstring make_qstring_slice(const char* text, size_t len) {
    std::string tmp(text, len);
    qstring out;
    out = tmp.c_str();
    return out;
}

qstring erase_qstring_range(const qstring& value, size_t pos, size_t len) {
    std::string tmp = value.c_str();
    tmp.erase(pos, len);
    qstring out;
    out = tmp.c_str();
    return out;
}

bool ends_with(const qstring& value, const char* suffix) noexcept {
    const size_t value_len = value.length();
    const size_t suffix_len = strlen(suffix);
    if (suffix_len > value_len) {
        return false;
    }

    return strcmp(value.c_str() + value_len - suffix_len, suffix) == 0;
}

bool is_c_keyword(std::string_view text) noexcept {
    constexpr std::array<std::string_view, 47> kKeywords = {
        "auto", "break", "case", "char", "const", "continue", "default",
        "do", "double", "else", "enum", "extern", "float", "for", "goto",
        "if", "inline", "int", "long", "register", "restrict", "return",
        "short", "signed", "sizeof", "static", "struct", "switch", "typedef",
        "union", "unsigned", "void", "volatile", "while", "class", "template",
        "typename", "namespace", "operator", "public", "private", "protected",
        "virtual", "this", "nullptr", "bool"
    };

    for (const auto keyword : kKeywords) {
        if (text == keyword) {
            return true;
        }
    }
    return false;
}

bool looks_like_hex_auto_name(const qstring& name) noexcept {
    if (!starts_with(name, "sub_") && !starts_with(name, "auto_")) {
        return false;
    }

    const char* text = name.c_str();
    const char* suffix = strchr(text, '_');
    if (!suffix || *(++suffix) == '\0') {
        return false;
    }

    while (*suffix != '\0') {
        if (!std::isxdigit(static_cast<unsigned char>(*suffix))) {
            return false;
        }
        ++suffix;
    }

    return true;
}

bool is_hex_suffix(const char* text) noexcept {
    if (text == nullptr || *text == '\0') {
        return false;
    }

    while (*text != '\0') {
        if (!std::isxdigit(static_cast<unsigned char>(*text))) {
            return false;
        }
        ++text;
    }

    return true;
}

bool has_offset_suffix(const qstring& name, const char* prefix) noexcept {
    if (!starts_with(name, prefix)) {
        return false;
    }

    const char* suffix = name.c_str() + strlen(prefix);
    if (strncmp(suffix, "neg_", 4) == 0) {
        return is_hex_suffix(suffix + 4);
    }

    return is_hex_suffix(suffix);
}

bool is_generated_overlay_name(const qstring& name) noexcept {
    constexpr std::array<const char*, 6> kOverlaySuffixes = {
        "_lo", "_hi", "_u8", "_u16", "_u32", "_u64"
    };

    for (const char* suffix : kOverlaySuffixes) {
        if (!ends_with(name, suffix)) {
            continue;
        }

        qstring base(name);
        base = erase_qstring_range(base, base.length() - strlen(suffix), strlen(suffix));
        return is_generated_name(base, nullptr);
    }

    if (ends_with(name, "_bytes")) {
        qstring base(name);
        base = erase_qstring_range(base, base.length() - 6, 6);
        return is_generated_name(base, nullptr);
    }

    return false;
}

const char* scalar_prefix(SemanticType semantic, std::uint32_t size, bool plural) noexcept {
    switch (semantic) {
        case SemanticType::VTablePointer:   return plural ? "vtbls" : "vtbl";
        case SemanticType::FunctionPointer: return plural ? "fns" : "fn";
        case SemanticType::Pointer:         return plural ? "ptrs" : "ptr";
        case SemanticType::Float:           return plural ? "f32s" : "f32";
        case SemanticType::Double:          return plural ? "f64s" : "f64";
        default:                            break;
    }

    switch (size) {
        case 1:  return plural ? "u8s" : "u8";
        case 2:  return plural ? "u16s" : "u16";
        case 4:  return plural ? "u32s" : "u32";
        case 8:  return plural ? "u64s" : "u64";
        default: return plural ? "bytes" : "bytes";
    }
}

} // namespace

int name_origin_priority(NameOrigin origin) noexcept {
    switch (origin) {
        case NameOrigin::Unknown:           return 0;
        case NameOrigin::GeneratedFallback: return 1;
        case NameOrigin::HeuristicRole:     return 2;
        case NameOrigin::AccessContext:     return 3;
        case NameOrigin::OriginalType:      return 4;
        case NameOrigin::PropagatedDonor:   return 5;
        case NameOrigin::ReusedType:        return 6;
        case NameOrigin::UserProvided:      return 7;
    }

    return 0;
}

int name_confidence_priority(NameConfidence confidence) noexcept {
    switch (confidence) {
        case NameConfidence::Low:     return 0;
        case NameConfidence::Medium:  return 1;
        case NameConfidence::High:    return 2;
        case NameConfidence::Certain: return 3;
    }

    return 0;
}

bool is_generated_name(const qstring& name, const NameMetadata* metadata) noexcept {
    if (metadata && metadata->is_generated()) {
        return true;
    }

    if (name.empty()) {
        return true;
    }

    if (is_generated_overlay_name(name)) {
        return true;
    }

    return starts_with(name, "field_") ||
           starts_with(name, "sub_") ||
           starts_with(name, "arr_") ||
            starts_with(name, "union_") ||
           starts_with(name, "__pad_") ||
           starts_with(name, "__raw_") ||
           starts_with(name, "bf_") ||
           has_offset_suffix(name, "part_") ||
           has_offset_suffix(name, "entry_") ||
           has_offset_suffix(name, "entries_") ||
           starts_with(name, "u8_") ||
           starts_with(name, "u16_") ||
           starts_with(name, "u32_") ||
           starts_with(name, "u64_") ||
           starts_with(name, "u8s_") ||
           starts_with(name, "u16s_") ||
           starts_with(name, "u32s_") ||
           starts_with(name, "u64s_") ||
           starts_with(name, "f32_") ||
           starts_with(name, "f64_") ||
           starts_with(name, "f32s_") ||
           starts_with(name, "f64s_") ||
           starts_with(name, "bytes_") ||
           starts_with(name, "ptrs_") ||
           starts_with(name, "fns_") ||
           starts_with(name, "ptr_") ||
           starts_with(name, "fn_") ||
           starts_with(name, "func_") ||
           starts_with(name, "vtbl_") ||
           starts_with(name, "auto_") ||
           starts_with(name, "synth_struct_") ||
           starts_with(name, "synth_vtbl_") ||
           starts_with(name, "__array_elem_") ||
           looks_like_hex_auto_name(name);
}

bool is_semantic_name(const qstring& name, const NameMetadata* metadata) noexcept {
    if (name.empty()) {
        return false;
    }

    if (metadata && metadata->is_semantic()) {
        return true;
    }

    return !is_generated_name(name, metadata);
}

qstring sanitize_identifier(const qstring& raw, const char* fallback) {
    qstring cleaned;
    const char* text = raw.c_str();
    bool last_was_underscore = false;

    for (size_t i = 0; text[i] != '\0'; ++i) {
        const unsigned char ch = static_cast<unsigned char>(text[i]);
        if (std::isalnum(ch) || ch == '_') {
            cleaned.append(static_cast<char>(std::tolower(ch)));
            last_was_underscore = false;
            continue;
        }

        if (!last_was_underscore) {
            cleaned.append('_');
            last_was_underscore = true;
        }
    }

    while (!cleaned.empty() && cleaned[0] == '_') {
        cleaned = erase_qstring_range(cleaned, 0, 1);
    }
    while (!cleaned.empty() && cleaned[cleaned.length() - 1] == '_') {
        cleaned = erase_qstring_range(cleaned, cleaned.length() - 1, 1);
    }

    if (cleaned.empty()) {
        cleaned = fallback;
    }

    if (std::isdigit(static_cast<unsigned char>(cleaned[0])) ||
        is_c_keyword(cleaned.c_str())) {
        qstring prefixed;
        prefixed.sprnt("_%s", cleaned.c_str());
        cleaned = prefixed;
    }

    return cleaned;
}

bool is_placeholder_identifier(const qstring& name) noexcept {
    if (name.empty()) {
        return true;
    }

    const qstring normalized = sanitize_identifier(name, "value");
    if (normalized.length() == 1) {
        return true;
    }
    if (normalized == "value" || normalized == "ptr" || normalized == "obj" ||
        normalized == "this" || normalized == "arg" || normalized == "ctx" ||
        normalized == "context" || normalized == "data" || normalized == "self") {
        return true;
    }

    auto is_prefix_number = [&](const char* prefix) {
        if (!starts_with(normalized, prefix)) {
            return false;
        }
        const char* suffix = normalized.c_str() + strlen(prefix);
        if (*suffix == '\0') {
            return true;
        }
        while (*suffix != '\0') {
            if (!std::isdigit(static_cast<unsigned char>(*suffix))) {
                return false;
            }
            ++suffix;
        }
        return true;
    };

    if (is_prefix_number("a") || is_prefix_number("v") || is_prefix_number("arg") ||
        is_prefix_number("var") || is_prefix_number("field") || is_prefix_number("sub")) {
        return true;
    }

    return false;
}

qstring singularize_identifier(const qstring& name) {
    const qstring normalized = sanitize_identifier(name, "item");
    if (normalized.length() > 3 && ends_with(normalized, "ies")) {
        qstring result(normalized);
        result = erase_qstring_range(result, result.length() - 3, 3);
        result.append("y");
        return result;
    }
    if (normalized.length() > 1 && ends_with(normalized, "s") && !ends_with(normalized, "ss")) {
        qstring result(normalized);
        result = erase_qstring_range(result, result.length() - 1, 1);
        return result;
    }
    return normalized;
}

qstring pluralize_identifier(const qstring& name) {
    const qstring normalized = sanitize_identifier(name, "items");
    if (ends_with(normalized, "y") && normalized.length() > 1) {
        qstring result(normalized);
        result = erase_qstring_range(result, result.length() - 1, 1);
        result.append("ies");
        return result;
    }
    if (ends_with(normalized, "s")) {
        return normalized;
    }

    qstring result(normalized);
    result.append("s");
    return result;
}

qstring make_offset_suffix(sval_t offset) {
    qstring suffix;
    const int64_t signed_offset = static_cast<int64_t>(offset);
    if (signed_offset < 0) {
        suffix.sprnt("neg_%llx", static_cast<unsigned long long>(-signed_offset));
    } else {
        suffix.sprnt("%llx", static_cast<unsigned long long>(signed_offset));
    }
    return suffix;
}

qstring strip_trailing_offset_suffix(const qstring& name) {
    const char* text = name.c_str();
    const char* last = strrchr(text, '_');
    if (last == nullptr) {
        return name;
    }

    const char* suffix = last + 1;
    if (!is_hex_suffix(suffix) && !(strncmp(suffix, "neg_", 4) == 0 && is_hex_suffix(suffix + 4))) {
        return name;
    }

    return make_qstring_slice(text, static_cast<size_t>(last - text));
}

qstring choose_root_type_stem(ea_t func_ea, const qstring& source_var) {
    if (!source_var.empty() && !is_placeholder_identifier(source_var)) {
        return sanitize_identifier(source_var, "object");
    }

    qstring func_name = utils::get_func_name(func_ea);
    if (!func_name.empty() && !is_placeholder_identifier(func_name) && !looks_like_hex_auto_name(func_name)) {
        return sanitize_identifier(func_name, "object");
    }

    return make_offset_suffix(static_cast<sval_t>(func_ea));
}

qstring make_auto_root_type_name(ea_t func_ea, const qstring& source_var, int index) {
    qstring name;
    const qstring stem = choose_root_type_stem(func_ea, source_var);
    if (index > 0) {
        name.sprnt("auto_%s_%d", stem.c_str(), index);
    } else {
        name.sprnt("auto_%s", stem.c_str());
    }
    return name;
}

qstring make_substruct_field_name(sval_t offset) {
    qstring name;
    name.sprnt("part_%s", make_offset_suffix(offset).c_str());
    return name;
}

qstring make_array_field_name(sval_t offset,
                              const tinfo_t& element_type,
                              SemanticType semantic,
                              std::uint32_t element_size) {
    qstring name;

    if ((element_type.is_struct() || element_type.is_union()) || semantic == SemanticType::NestedStruct) {
        name.sprnt("entries_%s", make_offset_suffix(offset).c_str());
        return name;
    }

    name.sprnt("%s_%s", scalar_prefix(semantic, element_size, true), make_offset_suffix(offset).c_str());
    return name;
}

qstring make_array_element_type_name(const qstring& parent_name,
                                     const qstring& field_name,
                                     sval_t offset) {
    const qstring stem = strip_trailing_offset_suffix(field_name);
    const qstring singular = singularize_identifier(stem.empty() ? qstring("entries") : stem);

    qstring name;
    if (!parent_name.empty()) {
        name.sprnt("%s_%s_%s",
                   parent_name.c_str(),
                   singular.c_str(),
                   make_offset_suffix(offset).c_str());
    } else {
        name.sprnt("%s_%s", singular.c_str(), make_offset_suffix(offset).c_str());
    }

    return name;
}

qstring make_overlay_member_name(const qstring& base_name,
                                 std::uint32_t parent_size,
                                 sval_t relative_offset,
                                 std::uint32_t member_size) {
    if (base_name.empty()) {
        return generate_field_name(relative_offset, SemanticType::Unknown, member_size);
    }

    qstring name;
    if (member_size > 0 && parent_size == member_size * 2) {
        if (relative_offset == 0) {
            name.sprnt("%s_lo", base_name.c_str());
            return name;
        }
        if (relative_offset == static_cast<sval_t>(member_size)) {
            name.sprnt("%s_hi", base_name.c_str());
            return name;
        }
    }

    name.sprnt("%s_%s", base_name.c_str(), scalar_prefix(SemanticType::Unknown, member_size, false));
    return name;
}

qstring make_internal_overlay_type_name(const qstring& base_name) {
    qstring name;
    name.sprnt("auto_%s_overlay", sanitize_identifier(base_name, "overlay").c_str());
    return name;
}

qstring make_internal_overlay_view_type_name(const qstring& union_name,
                                             const qstring& member_name,
                                             sval_t member_offset) {
    qstring name;
    name.sprnt("%s_%s_view_%s",
               make_internal_overlay_type_name(union_name).c_str(),
               sanitize_identifier(member_name, "view").c_str(),
               make_offset_suffix(member_offset).c_str());
    return name;
}

qstring make_shifted_view_type_name(const qstring& parent_name, sval_t delta) {
    qstring name;
    name.sprnt("%s_view_%s", parent_name.c_str(), make_offset_suffix(delta).c_str());
    return name;
}

qstring make_shifted_tail_type_name(const qstring& parent_name, sval_t delta) {
    qstring name;
    name.sprnt("%s_tail_%s", parent_name.c_str(), make_offset_suffix(delta).c_str());
    return name;
}

std::optional<sval_t> extract_shifted_view_delta(const qstring& type_name) {
    constexpr std::array<const char*, 3> kMarkers = {"_view_", "_window_", "_at_"};

    for (const char* marker : kMarkers) {
        const char* pos = strstr(type_name.c_str(), marker);
        if (pos == nullptr) {
            continue;
        }

        const char* suffix = pos + strlen(marker);
        if (strncmp(suffix, "neg_", 4) == 0) {
            suffix += 4;
            if (!is_hex_suffix(suffix)) {
                continue;
            }
            return -static_cast<sval_t>(strtoull(suffix, nullptr, 16));
        }

        if (!is_hex_suffix(suffix)) {
            continue;
        }

        return static_cast<sval_t>(strtoull(suffix, nullptr, 16));
    }

    return std::nullopt;
}

qstring rebase_textual_generated_name(const qstring& name, sval_t offset) {
    if (name.empty()) {
        return generate_field_name(offset, SemanticType::Unknown);
    }

    if (starts_with(name, "sub_") || starts_with(name, "part_")) {
        return make_substruct_field_name(offset);
    }

    constexpr std::array<const char*, 9> kPluralPrefixes = {
        "entries", "u8s", "u16s", "u32s", "u64s", "f32s", "f64s", "ptrs", "fns"
    };
    constexpr std::array<const char*, 10> kScalarPrefixes = {
        "field", "u8", "u16", "u32", "u64", "f32", "f64", "bytes", "ptr", "fn"
    };

    for (const char* prefix : kPluralPrefixes) {
        qstring marker;
        marker.sprnt("%s_", prefix);
        if (starts_with(name, marker.c_str())) {
            qstring rebased;
            rebased.sprnt("%s_%s", prefix, make_offset_suffix(offset).c_str());
            return rebased;
        }
    }

    for (const char* prefix : kScalarPrefixes) {
        qstring marker;
        marker.sprnt("%s_", prefix);
        if (starts_with(name, marker.c_str())) {
            qstring rebased;
            rebased.sprnt("%s_%s", prefix, make_offset_suffix(offset).c_str());
            return rebased;
        }
    }

    if (starts_with(name, "__pad_")) {
        qstring rebased;
        rebased.sprnt("__pad_%s", make_offset_suffix(offset).c_str());
        return rebased;
    }

    return name;
}

namespace {

#ifndef STRUCTOR_TESTING
size_t udt_member_size(const udm_t& member) {
    const size_t type_size = member.type.get_size();
    if (type_size != BADSIZE) {
        return type_size;
    }
    return member.size / 8;
}
#endif

GeneratedNameKind field_name_kind(const SynthField& field) {
    if (field.naming.kind != GeneratedNameKind::Unknown) {
        return field.naming.kind;
    }
    if (field.is_array) {
        return GeneratedNameKind::ArrayField;
    }
    if (field.semantic == SemanticType::NestedStruct) {
        return GeneratedNameKind::SubStructField;
    }
    if (field.is_bitfield) {
        return GeneratedNameKind::Bitfield;
    }
    if (field.is_padding) {
        return GeneratedNameKind::Padding;
    }
    return GeneratedNameKind::Field;
}

qstring extract_member_name_from_expr_text(const qstring& expr) {
    const char* text = expr.c_str();
    const size_t len = expr.length();

    for (size_t i = len; i > 0; --i) {
        if (i >= 2 && text[i - 2] == '-' && text[i - 1] == '>') {
            size_t start = i;
            size_t end = start;
            while (end < len && (std::isalnum(static_cast<unsigned char>(text[end])) || text[end] == '_')) {
                ++end;
            }
            if (end > start) {
                return make_qstring_slice(text + start, end - start);
            }
        }

        if (text[i - 1] == '.') {
            size_t start = i;
            size_t end = start;
            while (end < len && (std::isalnum(static_cast<unsigned char>(text[end])) || text[end] == '_')) {
                ++end;
            }
            if (end > start) {
                return make_qstring_slice(text + start, end - start);
            }
        }
    }

    return qstring();
}

} // namespace

bool struct_needs_name_refinement(const SynthStruct& structure) {
    for (const auto& field : structure.fields) {
        if (field.is_padding) {
            continue;
        }
        if (is_generated_name(field.name, &field.naming)) {
            return true;
        }
        if (!field.is_union_candidate) {
            continue;
        }
        for (const auto& alt : field.union_members) {
            if (is_generated_name(alt.name, &alt.naming)) {
                return true;
            }
        }
    }

    return false;
}

bool refine_struct_names_from_udt(SynthStruct& structure,
                                  const tinfo_t& donor_type,
                                  NameOrigin origin) {
#ifdef STRUCTOR_TESTING
    (void)structure;
    (void)donor_type;
    (void)origin;
    return false;
#else
    udt_type_data_t udt;
    if (!donor_type.get_udt_details(&udt) || udt.empty()) {
        return false;
    }

    bool renamed = false;
    for (auto& field : structure.fields) {
        if (field.is_padding) {
            continue;
        }

        for (const auto& member : udt) {
            if (member.offset != static_cast<uint64>(field.offset) * 8 || member.name.empty()) {
                continue;
            }
            if (udt_member_size(member) != field.size) {
                continue;
            }

            NameMetadata field_meta = field.naming;
            field_meta.kind = field_name_kind(field);
            field_meta.origin = origin;
            field_meta.confidence = NameConfidence::High;

            renamed |= adopt_preferred_name(field.name, field.naming, member.name, field_meta);
            if (field.is_union_candidate && !field.union_members.empty()) {
                auto base_meta = field_meta;
                base_meta.kind = GeneratedNameKind::UnionAlternative;
                renamed |= adopt_preferred_name(field.union_members[0].name,
                                                field.union_members[0].naming,
                                                member.name,
                                                base_meta);
                for (size_t i = 1; i < field.union_members.size(); ++i) {
                    auto& alt = field.union_members[i];
                    qstring alt_name = alt.size < field.size
                        ? make_overlay_member_name(member.name, field.size, alt.offset, alt.size)
                        : member.name;
                    auto alt_meta = base_meta;
                    alt_meta.kind = GeneratedNameKind::UnionAlternative;
                    renamed |= adopt_preferred_name(alt.name, alt.naming, alt_name, alt_meta);
                }
            }
            break;
        }
    }

    return renamed;
#endif
}

bool refine_struct_names_from_accesses(SynthStruct& structure,
                                       const qvector<FieldAccess>& accesses,
                                       NameOrigin origin) {
    bool renamed = false;

    for (auto& field : structure.fields) {
        if (field.is_padding || !is_generated_name(field.name, &field.naming)) {
            continue;
        }

        qstring candidate_name;
        for (const auto& access : accesses) {
            if (access.offset != field.offset || access.size != field.size) {
                continue;
            }

            qstring member_name = extract_member_name_from_expr_text(access.context_expr);
            if (is_generated_name(member_name, nullptr)) {
                continue;
            }

            candidate_name = member_name;
            break;
        }

        if (!candidate_name.empty()) {
            NameMetadata candidate_meta = field.naming;
            candidate_meta.kind = field_name_kind(field);
            candidate_meta.origin = origin;
            candidate_meta.confidence = NameConfidence::Medium;
            renamed |= adopt_preferred_name(field.name, field.naming, candidate_name, candidate_meta);
            if (field.is_union_candidate && !field.union_members.empty()) {
                auto base_meta = candidate_meta;
                base_meta.kind = GeneratedNameKind::UnionAlternative;
                renamed |= adopt_preferred_name(field.union_members[0].name,
                                                field.union_members[0].naming,
                                                candidate_name,
                                                base_meta);
            }
        }
    }

    for (auto& field : structure.fields) {
        if (!field.is_union_candidate || field.union_members.size() < 2) {
            continue;
        }

        for (size_t i = 1; i < field.union_members.size(); ++i) {
            auto& member = field.union_members[i];
            if (!is_generated_name(member.name, &member.naming)) {
                continue;
            }

            qstring candidate_name;
            for (const auto& access : accesses) {
                if (access.offset != field.offset + member.offset || access.size != member.size) {
                    continue;
                }

                qstring member_name = extract_member_name_from_expr_text(access.context_expr);
                if (is_generated_name(member_name, nullptr)) {
                    continue;
                }

                candidate_name = member_name;
                break;
            }

            if (!candidate_name.empty()) {
                qstring alt_name = member.size < field.size
                    ? make_overlay_member_name(candidate_name, field.size, member.offset, member.size)
                    : candidate_name;
                NameMetadata candidate_meta = member.naming;
                candidate_meta.kind = GeneratedNameKind::UnionAlternative;
                candidate_meta.origin = origin;
                candidate_meta.confidence = NameConfidence::Medium;
                renamed |= adopt_preferred_name(member.name, member.naming, alt_name, candidate_meta);
            }
        }
    }

    return renamed;
}

void apply_role_based_field_names(SynthStruct& structure) {
    int callback_count = 0;
    int vtable_count = 0;
    int kind_count = 0;

    auto is_callback_candidate = [](const SynthField& field) {
        if (field.semantic != SemanticType::FunctionPointer) {
            return false;
        }
        for (const auto& access : field.source_accesses) {
            if (access.access_type == AccessType::Call) {
                return true;
            }
        }
        return false;
    };

    auto is_kind_candidate = [](const SynthField& field) {
        if (field.size == 0 || field.size > 4 || field.is_array || field.is_union_candidate) {
            return false;
        }
        if (!(field.semantic == SemanticType::Integer ||
              field.semantic == SemanticType::UnsignedInteger ||
              field.semantic == SemanticType::Unknown)) {
            return false;
        }

        std::unordered_set<std::uint64_t> values;
        for (const auto& access : field.source_accesses) {
            for (auto value : access.observed_constants) {
                values.insert(value);
            }
        }
        if (values.size() < 2 || values.size() > 8) {
            return false;
        }
        for (auto value : values) {
            if (value > 0xFF) {
                return false;
            }
        }
        return true;
    };

    for (const auto& field : structure.fields) {
        if (field.is_padding || !is_generated_name(field.name, &field.naming)) {
            continue;
        }
        if (is_callback_candidate(field)) {
            ++callback_count;
        }
        if (field.semantic == SemanticType::VTablePointer) {
            ++vtable_count;
        }
        if (is_kind_candidate(field)) {
            ++kind_count;
        }
    }

    for (auto& field : structure.fields) {
        if (field.is_padding || !is_generated_name(field.name, &field.naming)) {
            continue;
        }

        qstring candidate_name;
        NameConfidence confidence = NameConfidence::Medium;
        if (is_callback_candidate(field)) {
            if (callback_count == 1) {
                candidate_name = "callback";
            } else {
                candidate_name.sprnt("callback_%s", make_offset_suffix(field.offset).c_str());
            }
            confidence = NameConfidence::High;
        } else if (field.semantic == SemanticType::VTablePointer) {
            if (vtable_count == 1 && field.offset == 0) {
                candidate_name = "vtable";
            } else {
                candidate_name.sprnt("vtable_%s", make_offset_suffix(field.offset).c_str());
            }
            confidence = NameConfidence::High;
        } else if (is_kind_candidate(field)) {
            if (kind_count == 1 && field.offset == 0) {
                candidate_name = "type";
            } else {
                candidate_name.sprnt("kind_%s", make_offset_suffix(field.offset).c_str());
            }
            confidence = NameConfidence::Medium;
        }

        if (candidate_name.empty()) {
            continue;
        }

        NameMetadata meta = field.naming;
        meta.kind = field_name_kind(field);
        meta.origin = NameOrigin::HeuristicRole;
        meta.confidence = confidence;
        (void)adopt_preferred_name(field.name, field.naming, candidate_name, meta);
    }
}

bool adopt_preferred_name(qstring& current_name,
                          NameMetadata& current_metadata,
                          const qstring& candidate_name,
                          const NameMetadata& candidate_metadata) {
    if (candidate_name.empty()) {
        return false;
    }

    if (current_metadata.locked && !current_name.empty() && current_name != candidate_name) {
        return false;
    }

    if (current_name.empty()) {
        current_name = candidate_name;
        current_metadata = candidate_metadata;
        return true;
    }

    if (current_name == candidate_name) {
        if (name_origin_priority(candidate_metadata.origin) >
                name_origin_priority(current_metadata.origin) ||
            name_confidence_priority(candidate_metadata.confidence) >
                name_confidence_priority(current_metadata.confidence)) {
            current_metadata = candidate_metadata;
            return true;
        }
        return false;
    }

    const int current_origin = name_origin_priority(current_metadata.origin);
    const int candidate_origin = name_origin_priority(candidate_metadata.origin);
    if (candidate_origin < current_origin) {
        return false;
    }
    if (candidate_origin == current_origin &&
        name_confidence_priority(candidate_metadata.confidence) <
            name_confidence_priority(current_metadata.confidence)) {
        return false;
    }

    current_name = candidate_name;
    current_metadata = candidate_metadata;
    return true;
}

void set_generated_name(qstring& current_name,
                        NameMetadata& current_metadata,
                        const qstring& generated_name,
                        GeneratedNameKind kind,
                        NameConfidence confidence) {
    current_name = generated_name;
    current_metadata.kind = kind;
    current_metadata.origin = NameOrigin::GeneratedFallback;
    current_metadata.confidence = confidence;
    current_metadata.locked = false;
}

void set_adopted_name(qstring& current_name,
                      NameMetadata& current_metadata,
                      const qstring& adopted_name,
                      GeneratedNameKind kind,
                      NameOrigin origin,
                      NameConfidence confidence,
                      bool lock) {
    current_name = adopted_name;
    current_metadata.kind = kind;
    current_metadata.origin = origin;
    current_metadata.confidence = confidence;
    current_metadata.locked = lock;
}

qstring generate_struct_name(ea_t func_ea, int index) {
    return make_auto_root_type_name(func_ea, qstring(), index);
}

qstring generate_vtable_name(ea_t func_ea, int index) {
    qstring name;
    const qstring stem = choose_root_type_stem(func_ea, qstring());
    if (index > 0) {
        name.sprnt("auto_%s_vtbl_%d", stem.c_str(), index);
    } else {
        name.sprnt("auto_%s_vtbl", stem.c_str());
    }
    return name;
}

qstring generate_field_name(sval_t offset, SemanticType semantic, std::uint32_t size) {
    qstring name;
    const char* prefix = nullptr;

    switch (semantic) {
        case SemanticType::VTablePointer:   prefix = "vtbl"; break;
        case SemanticType::FunctionPointer: prefix = "fn"; break;
        case SemanticType::Pointer:         prefix = "ptr"; break;
        case SemanticType::Float:           prefix = "f32"; break;
        case SemanticType::Double:          prefix = "f64"; break;
        default: break;
    }

    if (prefix == nullptr) {
        switch (size) {
            case 1:  prefix = "u8"; break;
            case 2:  prefix = "u16"; break;
            case 4:  prefix = "u32"; break;
            case 8:  prefix = "u64"; break;
            default: prefix = size > 0 ? "bytes" : "u32"; break;
        }
    }

    const int64_t signed_offset = static_cast<int64_t>(offset);
    if (signed_offset < 0) {
        name.sprnt("%s_neg_%llX", prefix,
                   static_cast<unsigned long long>(-signed_offset));
    } else {
        name.sprnt("%s_%llX", prefix,
                   static_cast<unsigned long long>(signed_offset));
    }
    return name;
}

} // namespace structor
