#pragma once

#include "synth_types.hpp"

namespace structor {

[[nodiscard]] int name_origin_priority(NameOrigin origin) noexcept;
[[nodiscard]] int name_confidence_priority(NameConfidence confidence) noexcept;
[[nodiscard]] bool is_generated_name(const qstring& name,
                                     const NameMetadata* metadata = nullptr) noexcept;
[[nodiscard]] bool is_semantic_name(const qstring& name,
                                    const NameMetadata* metadata = nullptr) noexcept;
[[nodiscard]] qstring sanitize_identifier(const qstring& raw,
                                          const char* fallback = "value");
[[nodiscard]] bool is_placeholder_identifier(const qstring& name) noexcept;
[[nodiscard]] qstring singularize_identifier(const qstring& name);
[[nodiscard]] qstring pluralize_identifier(const qstring& name);
[[nodiscard]] qstring make_offset_suffix(sval_t offset);
[[nodiscard]] qstring strip_trailing_offset_suffix(const qstring& name);
[[nodiscard]] qstring choose_root_type_stem(ea_t func_ea,
                                            const qstring& source_var);
[[nodiscard]] qstring make_auto_root_type_name(ea_t func_ea,
                                               const qstring& source_var,
                                               int index = 0);
[[nodiscard]] qstring make_substruct_field_name(sval_t offset);
[[nodiscard]] qstring make_array_field_name(sval_t offset,
                                            const tinfo_t& element_type,
                                            SemanticType semantic = SemanticType::Unknown,
                                            std::uint32_t element_size = 0);
[[nodiscard]] qstring make_array_element_type_name(const qstring& parent_name,
                                                   const qstring& field_name,
                                                   sval_t offset);
[[nodiscard]] qstring make_overlay_member_name(const qstring& base_name,
                                               std::uint32_t parent_size,
                                               sval_t relative_offset,
                                               std::uint32_t member_size);
[[nodiscard]] qstring make_internal_overlay_type_name(const qstring& base_name);
[[nodiscard]] qstring make_internal_overlay_view_type_name(const qstring& union_name,
                                                           const qstring& member_name,
                                                           sval_t member_offset);
[[nodiscard]] qstring make_shifted_view_type_name(const qstring& parent_name,
                                                  sval_t delta);
[[nodiscard]] qstring make_shifted_tail_type_name(const qstring& parent_name,
                                                  sval_t delta);
[[nodiscard]] std::optional<sval_t> extract_shifted_view_delta(const qstring& type_name);
[[nodiscard]] qstring rebase_textual_generated_name(const qstring& name,
                                                    sval_t offset);
[[nodiscard]] bool struct_needs_name_refinement(const SynthStruct& structure);
bool refine_struct_names_from_udt(SynthStruct& structure,
                                  const tinfo_t& donor_type,
                                  NameOrigin origin);
bool refine_struct_names_from_accesses(SynthStruct& structure,
                                       const qvector<FieldAccess>& accesses,
                                       NameOrigin origin = NameOrigin::AccessContext);
void apply_role_based_field_names(SynthStruct& structure);
void disambiguate_repeated_field_names(SynthStruct& structure);

bool adopt_preferred_name(qstring& current_name,
                          NameMetadata& current_metadata,
                          const qstring& candidate_name,
                          const NameMetadata& candidate_metadata);

void set_generated_name(qstring& current_name,
                        NameMetadata& current_metadata,
                        const qstring& generated_name,
                        GeneratedNameKind kind,
                        NameConfidence confidence = NameConfidence::Medium);

void set_adopted_name(qstring& current_name,
                      NameMetadata& current_metadata,
                      const qstring& adopted_name,
                      GeneratedNameKind kind,
                      NameOrigin origin,
                      NameConfidence confidence = NameConfidence::High,
                      bool lock = false);

} // namespace structor
