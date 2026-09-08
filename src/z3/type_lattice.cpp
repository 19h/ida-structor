#include "structor/z3/type_lattice.hpp"
#include "structor/z3/context.hpp"
#include <algorithm>
#include <functional>
#include <limits>

namespace structor::z3 {

// ============================================================================
// BaseType utilities
// ============================================================================

const char* base_type_name(BaseType type) noexcept {
    switch (type) {
        case BaseType::Unknown:  return "unknown";
        case BaseType::Bottom:   return "bottom";
        case BaseType::Int8:     return "int8";
        case BaseType::Int16:    return "int16";
        case BaseType::Int32:    return "int32";
        case BaseType::Int64:    return "int64";
        case BaseType::UInt8:    return "uint8";
        case BaseType::UInt16:   return "uint16";
        case BaseType::UInt32:   return "uint32";
        case BaseType::UInt64:   return "uint64";
        case BaseType::Float32:  return "float32";
        case BaseType::Float64:  return "float64";
        case BaseType::Void:     return "void";
        case BaseType::Bool:     return "bool";
        default:                 return "invalid";
    }
}

uint32_t base_type_size(BaseType type, uint32_t ptr_size) noexcept {
    switch (type) {
        case BaseType::Int8:
        case BaseType::UInt8:
        case BaseType::Bool:
            return 1;
        case BaseType::Int16:
        case BaseType::UInt16:
            return 2;
        case BaseType::Int32:
        case BaseType::UInt32:
        case BaseType::Float32:
            return 4;
        case BaseType::Int64:
        case BaseType::UInt64:
        case BaseType::Float64:
            return 8;
        case BaseType::Void:
        case BaseType::Unknown:
        case BaseType::Bottom:
        default:
            return 0;
    }
}

bool is_signed_int(BaseType type) noexcept {
    return type >= BaseType::Int8 && type <= BaseType::Int64;
}

bool is_unsigned_int(BaseType type) noexcept {
    return type >= BaseType::UInt8 && type <= BaseType::UInt64;
}

bool is_integer(BaseType type) noexcept {
    return is_signed_int(type) || is_unsigned_int(type);
}

bool is_floating(BaseType type) noexcept {
    return type == BaseType::Float32 || type == BaseType::Float64;
}

BaseType base_type_from_size(uint32_t size, bool is_signed) noexcept {
    if (is_signed) {
        switch (size) {
            case 1: return BaseType::Int8;
            case 2: return BaseType::Int16;
            case 4: return BaseType::Int32;
            case 8: return BaseType::Int64;
            default: return BaseType::Unknown;
        }
    } else {
        switch (size) {
            case 1: return BaseType::UInt8;
            case 2: return BaseType::UInt16;
            case 4: return BaseType::UInt32;
            case 8: return BaseType::UInt64;
            default: return BaseType::Unknown;
        }
    }
}

// ============================================================================
// InferredType implementation
// ============================================================================

InferredType InferredType::make_base(BaseType base) {
    InferredType t;
    t.kind_ = Kind::Base;
    t.base_type_ = base;
    return t;
}

InferredType InferredType::unknown() {
    return make_base(BaseType::Unknown);
}

InferredType InferredType::bottom() {
    return make_base(BaseType::Bottom);
}

InferredType InferredType::make_ptr(InferredType pointee) {
    InferredType t;
    t.kind_ = Kind::Pointer;
    t.pointee_ = std::make_shared<InferredType>(std::move(pointee));
    return t;
}

InferredType InferredType::make_ptr(std::shared_ptr<InferredType> pointee) {
    InferredType t;
    t.kind_ = Kind::Pointer;
    t.pointee_ = std::move(pointee);
    return t;
}

InferredType InferredType::make_func(
    InferredType return_type,
    std::vector<InferredType> param_types)
{
    InferredType t;
    t.kind_ = Kind::Function;
    t.return_type_ = std::make_shared<InferredType>(std::move(return_type));
    for (auto& p : param_types) {
        t.param_types_.push_back(std::make_shared<InferredType>(std::move(p)));
    }
    return t;
}

InferredType InferredType::make_array(InferredType element, uint32_t count) {
    InferredType t;
    t.kind_ = Kind::Array;
    t.element_type_ = std::make_shared<InferredType>(std::move(element));
    t.array_count_ = count;
    return t;
}

InferredType InferredType::make_struct(tid_t tid) {
    InferredType t;
    t.kind_ = Kind::Struct;
    t.struct_tid_ = tid;
    return t;
}

InferredType InferredType::make_sum(std::vector<InferredType> alternatives) {
    InferredType t;
    t.kind_ = Kind::Sum;
    for (auto& alt : alternatives) {
        t.sum_alternatives_.push_back(std::make_shared<InferredType>(std::move(alt)));
    }
    return t;
}

uint32_t InferredType::size(uint32_t ptr_size) const noexcept {
    switch (kind_) {
        case Kind::Base:
            return base_type_size(base_type_, ptr_size);
        case Kind::Pointer:
        case Kind::Function:
            return ptr_size;
        case Kind::Array:
            if (element_type_) {
                const std::uint64_t element_size = element_type_->size(ptr_size);
                const std::uint64_t extent = element_size * array_count_;
                return extent <= std::numeric_limits<std::uint32_t>::max()
                    ? static_cast<std::uint32_t>(extent) : 0;
            }
            return 0;
        case Kind::Struct:
            // Would need to look up struct info from IDA
            return 0;
        case Kind::Sum:
            // Size of sum is max of alternatives
            if (!sum_alternatives_.empty()) {
                uint32_t max_size = 0;
                for (const auto& alt : sum_alternatives_) {
                    const auto alternative_size = alt->size(ptr_size);
                    if (alternative_size == 0) return 0;
                    max_size = std::max(max_size, alternative_size);
                }
                return max_size;
            }
            return 0;
    }
    return 0;
}

tinfo_t InferredType::to_tinfo() const {
    tinfo_t type;
    
    switch (kind_) {
        case Kind::Base:
            switch (base_type_) {
                case BaseType::Int8:     type.create_simple_type(BTF_INT8); break;
                case BaseType::Int16:    type.create_simple_type(BTF_INT16); break;
                case BaseType::Int32:    type.create_simple_type(BTF_INT32); break;
                case BaseType::Int64:    type.create_simple_type(BTF_INT64); break;
                case BaseType::UInt8:    type.create_simple_type(BTF_UINT8); break;
                case BaseType::UInt16:   type.create_simple_type(BTF_UINT16); break;
                case BaseType::UInt32:   type.create_simple_type(BTF_UINT32); break;
                case BaseType::UInt64:   type.create_simple_type(BTF_UINT64); break;
                case BaseType::Float32:  type.create_simple_type(BTF_FLOAT); break;
                case BaseType::Float64:  type.create_simple_type(BTF_DOUBLE); break;
                case BaseType::Void:     type.create_simple_type(BTF_VOID); break;
                case BaseType::Bool:     type.create_simple_type(BTF_BOOL); break;
                default:
                    // Unknown/Bottom: create void*
                    type.create_simple_type(BTF_VOID);
                    break;
            }
            break;
            
        case Kind::Pointer:
            if (pointee_) {
                tinfo_t pointed = pointee_->to_tinfo();
                type.create_ptr(pointed);
            } else {
                tinfo_t void_type;
                void_type.create_simple_type(BTF_VOID);
                type.create_ptr(void_type);
            }
            break;
            
        case Kind::Function: {
            func_type_data_t ftd;
            if (return_type_) {
                ftd.rettype = return_type_->to_tinfo();
            } else {
                ftd.rettype.create_simple_type(BTF_VOID);
            }
            for (const auto& param : param_types_) {
                funcarg_t arg;
                arg.type = param->to_tinfo();
                ftd.push_back(arg);
            }
            ftd.set_cc(CM_CC_UNKNOWN);
            type.create_func(ftd);
            break;
        }
        
        case Kind::Array:
            if (element_type_) {
                tinfo_t elem = element_type_->to_tinfo();
                type.create_array(elem, array_count_);
            }
            break;
            
        case Kind::Struct:
            if (struct_tid_ != BADADDR) {
                type.get_type_by_tid(struct_tid_);
            }
            break;
            
        case Kind::Sum: {
            // Alternative abstract interpretations are not interchangeable.
            // A materialized C union preserves each representable object view;
            // unresolved, void, or bare-function alternatives have no such view.
            if (sum_alternatives_.empty()) break;
            udt_type_data_t members;
            members.is_union = true;
            members.pack = 1; // SDK logarithmic pack(1): preserve observed extent.
            std::size_t index = 0;
            for (const auto& alternative : sum_alternatives_) {
                if (alternative->is_unknown() || alternative->is_bottom()) return {};
                tinfo_t member_type = alternative->to_tinfo();
                const auto member_size = member_type.get_size();
                if (member_type.empty() || member_type.is_void() || member_type.is_func() ||
                    member_size == BADSIZE || member_size == 0 ||
                    member_size > std::numeric_limits<std::uint64_t>::max() / 8) return {};
                udm_t member;
                member.name.sprnt("alternative_%zu", index++);
                member.offset = 0;
                member.size = static_cast<std::uint64_t>(member_size) * 8;
                member.type = member_type;
                members.push_back(std::move(member));
                members.total_size = std::max(members.total_size, member_size);
            }
            // IDA consumes members during create_udt(); retain the expected
            // extent before handing its storage to the SDK.
            const auto expected_size = members.total_size;
            if (!type.create_udt(members, BTF_UNION) ||
                type.get_size() != expected_size) return {};
            break;
        }
    }
    
    return type;
}

InferredType InferredType::from_tinfo(const tinfo_t& type, TypeConversionIssue* issue) {
    TypeConversionIssue observed_issue = TypeConversionIssue::None;
    const auto fail = [&](TypeConversionIssue value) {
        observed_issue = value;
        return unknown();
    };
    std::function<InferredType(const tinfo_t&, unsigned)> convert;
    convert = [&](const tinfo_t& current, unsigned remaining) -> InferredType {
        if (remaining == 0) return fail(TypeConversionIssue::DepthLimit);
        if (current.empty()) return fail(TypeConversionIssue::Empty);
        if (current.is_partial()) return fail(TypeConversionIssue::PartialStorage);
        if (current.is_decl_bitfield()) return fail(TypeConversionIssue::Bitfield);
        if (current.is_enum()) return fail(TypeConversionIssue::Enumeration);
        if (current.is_ptr()) {
            auto pointed = convert(current.get_pointed_object(), remaining - 1);
            return pointed.is_unknown() ? unknown() : make_ptr(std::move(pointed));
        }
        if (current.is_func()) {
            func_type_data_t details;
            if (!current.get_func_details(&details)) return fail(TypeConversionIssue::InvalidDetails);
            auto returned = convert(details.rettype, remaining - 1);
            if (returned.is_unknown()) return unknown();
            std::vector<InferredType> parameters;
            parameters.reserve(details.size());
            for (const auto& argument : details) {
                auto parameter = convert(argument.type, remaining - 1);
                if (parameter.is_unknown()) return unknown();
                parameters.push_back(std::move(parameter));
            }
            return make_func(std::move(returned), std::move(parameters));
        }
        if (current.is_array()) {
            array_type_data_t details;
            if (!current.get_array_details(&details)) return fail(TypeConversionIssue::InvalidDetails);
            if (details.base != 0 || details.nelems == 0 ||
                static_cast<std::uint64_t>(details.nelems) > std::numeric_limits<std::uint32_t>::max()) {
                return fail(TypeConversionIssue::UnsupportedArrayBounds);
            }
            auto element = convert(details.elem_type, remaining - 1);
            return element.is_unknown() ? unknown()
                : make_array(std::move(element), static_cast<std::uint32_t>(details.nelems));
        }
        if (current.is_struct() || current.is_union()) {
            const auto tid = current.get_tid();
            return tid == BADADDR ? fail(TypeConversionIssue::AnonymousAggregate) : make_struct(tid);
        }
        if (current.is_void()) return make_base(BaseType::Void);
        const auto width = current.get_size();
        if (current.is_floating()) {
            if (width == 4) return make_base(BaseType::Float32);
            if (width == 8) return make_base(BaseType::Float64);
            return fail(TypeConversionIssue::UnsupportedFloatingWidth);
        }
        if (current.is_bool()) {
            return width == 1 ? make_base(BaseType::Bool)
                : fail(TypeConversionIssue::UnsupportedBooleanWidth);
        }
        if (!current.is_integral()) return fail(TypeConversionIssue::UnsupportedCategory);
        if (!current.is_signed() && !current.is_unsigned()) {
            return fail(TypeConversionIssue::UnknownIntegerSignedness);
        }
        if (width == BADSIZE || width > std::numeric_limits<std::uint32_t>::max()) {
            return fail(TypeConversionIssue::UnsupportedIntegerWidth);
        }
        const auto base = base_type_from_size(static_cast<std::uint32_t>(width), current.is_signed());
        return base == BaseType::Unknown ? fail(TypeConversionIssue::UnsupportedIntegerWidth) : make_base(base);
    };
    auto result = convert(type, 64);
    if (issue) *issue = observed_issue;
    return result;
}

qstring InferredType::to_string() const {
    qstring result;
    
    switch (kind_) {
        case Kind::Base:
            result = base_type_name(base_type_);
            break;
            
        case Kind::Pointer:
            if (pointee_) {
                result = pointee_->to_string();
                result += "*";
            } else {
                result = "void*";
            }
            break;
            
        case Kind::Function:
            if (return_type_) {
                result = return_type_->to_string();
            } else {
                result = "void";
            }
            result += "(";
            for (size_t i = 0; i < param_types_.size(); ++i) {
                if (i > 0) result += ", ";
                result += param_types_[i]->to_string();
            }
            result += ")";
            break;
            
        case Kind::Array:
            if (element_type_) {
                result = element_type_->to_string();
            } else {
                result = "unknown";
            }
            result.cat_sprnt("[%u]", array_count_);
            break;
            
        case Kind::Struct:
            result.sprnt("struct_%llX", static_cast<unsigned long long>(struct_tid_));
            break;
            
        case Kind::Sum:
            result = "(";
            for (size_t i = 0; i < sum_alternatives_.size(); ++i) {
                if (i > 0) result += " | ";
                result += sum_alternatives_[i]->to_string();
            }
            result += ")";
            break;
    }
    
    return result;
}

bool InferredType::operator==(const InferredType& other) const {
    if (kind_ != other.kind_) return false;
    
    switch (kind_) {
        case Kind::Base:
            return base_type_ == other.base_type_;
            
        case Kind::Pointer:
            if (!pointee_ && !other.pointee_) return true;
            if (!pointee_ || !other.pointee_) return false;
            return *pointee_ == *other.pointee_;
            
        case Kind::Function:
            if (!return_type_ && !other.return_type_) {
                // Both null returns
            } else if (!return_type_ || !other.return_type_) {
                return false;
            } else if (*return_type_ != *other.return_type_) {
                return false;
            }
            if (param_types_.size() != other.param_types_.size()) return false;
            for (size_t i = 0; i < param_types_.size(); ++i) {
                if (*param_types_[i] != *other.param_types_[i]) return false;
            }
            return true;
            
        case Kind::Array:
            if (array_count_ != other.array_count_) return false;
            if (!element_type_ && !other.element_type_) return true;
            if (!element_type_ || !other.element_type_) return false;
            return *element_type_ == *other.element_type_;
            
        case Kind::Struct:
            return struct_tid_ == other.struct_tid_;
            
        case Kind::Sum:
            if (sum_alternatives_.size() != other.sum_alternatives_.size()) return false;
            for (size_t i = 0; i < sum_alternatives_.size(); ++i) {
                if (*sum_alternatives_[i] != *other.sum_alternatives_[i]) return false;
            }
            return true;
    }
    
    return false;
}

std::size_t InferredType::hash() const noexcept {
    // Use FNV-1a inspired mixing with better avalanche properties
    constexpr std::size_t kFNVPrime = 0x100000001b3ULL;
    constexpr std::size_t kFNVOffset = 0xcbf29ce484222325ULL;
    constexpr std::size_t kGoldenRatio = 0x9e3779b97f4a7c15ULL;
    
    std::size_t h = kFNVOffset;
    
    // Mix kind into hash
    h = (h ^ static_cast<std::size_t>(kind_)) * kFNVPrime;
    
    switch (kind_) {
        case Kind::Base:
            // Combine with golden ratio for better distribution
            h ^= static_cast<std::size_t>(base_type_) + kGoldenRatio + (h << 6) + (h >> 2);
            break;
            
        case Kind::Pointer:
            if (pointee_) {
                // Use iterative unwrapping for pointer chains to avoid deep recursion
                const InferredType* curr = pointee_.get();
                unsigned depth = 0;
                while (curr && curr->is_pointer() && depth < 16) {
                    ++depth;
                    h = (h ^ depth) * kFNVPrime;
                    curr = curr->pointee();
                }
                if (curr) {
                    h ^= curr->hash() + kGoldenRatio + (h << 6) + (h >> 2);
                }
                h = (h ^ depth) * kFNVPrime;
            } else {
                h = (h ^ 0xDEADBEEFULL) * kFNVPrime;  // void*
            }
            break;
            
        case Kind::Function:
            if (return_type_) {
                h ^= return_type_->hash() + kGoldenRatio + (h << 6) + (h >> 2);
            }
            h = (h ^ param_types_.size()) * kFNVPrime;
            for (size_t i = 0; i < param_types_.size() && i < 8; ++i) {
                h ^= param_types_[i]->hash() + kGoldenRatio + (h << 6) + (h >> 2);
            }
            break;
            
        case Kind::Array:
            if (element_type_) {
                h ^= element_type_->hash() + kGoldenRatio + (h << 6) + (h >> 2);
            }
            h = (h ^ array_count_) * kFNVPrime;
            break;
            
        case Kind::Struct:
            h ^= static_cast<std::size_t>(struct_tid_) + kGoldenRatio + (h << 6) + (h >> 2);
            break;
            
        case Kind::Sum:
            h = (h ^ sum_alternatives_.size()) * kFNVPrime;
            for (size_t i = 0; i < sum_alternatives_.size() && i < 4; ++i) {
                h ^= sum_alternatives_[i]->hash() + kGoldenRatio + (h << 6) + (h >> 2);
            }
            break;
    }
    
    // Final mixing
    h ^= h >> 33;
    h *= 0xff51afd7ed558ccdULL;
    h ^= h >> 33;
    
    return h;
}

InferredType InferredType::snapshot() const {
    InferredType result = *this;
    const auto copy_child = [](const std::shared_ptr<InferredType>& child) {
        return child ? std::make_shared<InferredType>(child->snapshot()) : nullptr;
    };
    result.pointee_ = copy_child(pointee_);
    result.return_type_ = copy_child(return_type_);
    result.element_type_ = copy_child(element_type_);
    for (auto& parameter : result.param_types_) parameter = copy_child(parameter);
    for (auto& alternative : result.sum_alternatives_) alternative = copy_child(alternative);
    return result;
}

// ============================================================================
// TypeLattice implementation
// ============================================================================

TypeLattice::TypeLattice(uint32_t ptr_size) : ptr_size_(ptr_size) {}

bool TypeLattice::signed_int_subtype(BaseType a, BaseType b) const noexcept {
    // int8 <: int16 <: int32 <: int64
    if (!is_signed_int(a) || !is_signed_int(b)) return false;
    return static_cast<int>(a) <= static_cast<int>(b);
}

bool TypeLattice::unsigned_int_subtype(BaseType a, BaseType b) const noexcept {
    // uint8 <: uint16 <: uint32 <: uint64
    if (!is_unsigned_int(a) || !is_unsigned_int(b)) return false;
    return static_cast<int>(a) <= static_cast<int>(b);
}

bool TypeLattice::is_subtype(const InferredType& a, const InferredType& b) const {
    // Bottom is subtype of everything
    if (a.is_bottom()) return true;
    
    // Everything is subtype of Unknown (top)
    if (b.is_unknown()) return true;
    
    // A sum is a union of alternatives. Check the source first so two
    // sums require every source alternative to have a destination supertype.
    if (a.is_sum()) {
        return std::all_of(a.sum_alternatives().begin(), a.sum_alternatives().end(),
            [&](const auto& alternative) { return is_subtype(*alternative, b); });
    }
    if (b.is_sum()) {
        return std::any_of(b.sum_alternatives().begin(), b.sum_alternatives().end(),
            [&](const auto& alternative) { return is_subtype(a, *alternative); });
    }
    if (a.is_unknown()) return b.is_unknown();
    if (a.kind() != b.kind()) return false;

    switch (a.kind()) {
        case InferredType::Kind::Base:
            if (a.base_type() == b.base_type()) return true;
            // Integer subtyping
            if (is_signed_int(a.base_type()) && is_signed_int(b.base_type())) {
                return signed_int_subtype(a.base_type(), b.base_type());
            }
            if (is_unsigned_int(a.base_type()) && is_unsigned_int(b.base_type())) {
                return unsigned_int_subtype(a.base_type(), b.base_type());
            }
            return false;
            
        case InferredType::Kind::Pointer:
            // Pointer subtyping is covariant in pointee
            if (!a.pointee() && !b.pointee()) return true;
            if (!a.pointee() || !b.pointee()) return false;
            return is_subtype(*a.pointee(), *b.pointee());
            
        case InferredType::Kind::Function:
            // Function subtyping: contravariant in params, covariant in return
            if (a.param_types().size() != b.param_types().size()) return false;
            if (a.return_type() && b.return_type()) {
                if (!is_subtype(*a.return_type(), *b.return_type())) return false;
            }
            for (size_t i = 0; i < a.param_types().size(); ++i) {
                // Contravariant: b's param must be subtype of a's param
                if (!is_subtype(*b.param_types()[i], *a.param_types()[i])) return false;
            }
            return true;
            
        case InferredType::Kind::Array:
            if (a.array_count() != b.array_count()) return false;
            if (!a.element_type() && !b.element_type()) return true;
            if (!a.element_type() || !b.element_type()) return false;
            return is_subtype(*a.element_type(), *b.element_type());
            
        case InferredType::Kind::Struct:
            return a.struct_tid() == b.struct_tid();
            
        case InferredType::Kind::Sum:
            return false; // Handled before kind comparison.
    }
    
    return false;
}

InferredType TypeLattice::lub(const InferredType& a, const InferredType& b) const {
    // Fast path: check trivial cases first (no caching needed)
    if (a.is_unknown() || b.is_unknown()) return InferredType::unknown();
    if (a.is_bottom()) return b;
    if (b.is_bottom()) return a;
    
    // Check cache
    TypePairKey key{a, b};
    auto it = lub_cache_.find(key);
    if (it != lub_cache_.end()) {
        ++stats_.lub_hits;
        return it->second.snapshot();
    }
    
    ++stats_.lub_misses;
    InferredType result = lub_impl(a, b);
    lub_cache_.emplace(TypePairKey{a.snapshot(), b.snapshot()}, result.snapshot());
    return result;
}

namespace {
int compare_type_values(const InferredType& a, const InferredType& b) {
    const auto compare = [](const auto& left, const auto& right) {
        return left < right ? -1 : (right < left ? 1 : 0);
    };
    const auto compare_child = [&](const InferredType* left, const InferredType* right) {
        if (!left || !right) return compare(left != nullptr, right != nullptr);
        return compare_type_values(*left, *right);
    };
    const auto compare_list = [&](const auto& left, const auto& right) {
        for (std::size_t i = 0; i < std::min(left.size(), right.size()); ++i) {
            if (const auto order = compare_child(left[i].get(), right[i].get())) return order;
        }
        return compare(left.size(), right.size());
    };
    if (const auto order = compare(a.kind(), b.kind())) return order;
    switch (a.kind()) {
        case InferredType::Kind::Base: return compare(a.base_type(), b.base_type());
        case InferredType::Kind::Pointer: return compare_child(a.pointee(), b.pointee());
        case InferredType::Kind::Array:
            if (const auto order = compare(a.array_count(), b.array_count())) return order;
            return compare_child(a.element_type(), b.element_type());
        case InferredType::Kind::Struct: return compare(a.struct_tid(), b.struct_tid());
        case InferredType::Kind::Function:
            if (const auto order = compare_child(a.return_type(), b.return_type())) return order;
            return compare_list(a.param_types(), b.param_types());
        case InferredType::Kind::Sum:
            return compare_list(a.sum_alternatives(), b.sum_alternatives());
    }
    return 0;
}
} // namespace

InferredType TypeLattice::join_alternatives(std::vector<InferredType> alternatives) const {
    // Flatten finite unions and retain an antichain under the subtype order.
    // Hashes and printed names do not participate in semantic equality.
    std::vector<InferredType> flat;
    const auto append = [&](const auto& self, const InferredType& type) -> void {
        if (type.is_sum()) {
            for (const auto& alternative : type.sum_alternatives()) self(self, *alternative);
        } else if (!type.is_bottom()) {
            flat.push_back(type);
        }
    };
    for (const auto& alternative : alternatives) append(append, alternative);
    std::sort(flat.begin(), flat.end(), [](const auto& a, const auto& b) {
        return compare_type_values(a, b) < 0;
    });
    std::vector<InferredType> result;
    for (const auto& candidate : flat) {
        bool covered = false;
        for (const auto& existing : result) {
            if (is_subtype(candidate, existing)) { covered = true; break; }
        }
        if (covered) continue;
        result.erase(std::remove_if(result.begin(), result.end(),
            [&](const auto& existing) { return is_subtype(existing, candidate); }), result.end());
        result.push_back(candidate);
    }
    if (result.empty()) return InferredType::bottom();
    if (result.size() == 1) return result.front();
    return InferredType::make_sum(std::move(result));
}

InferredType TypeLattice::lub_impl(const InferredType& a, const InferredType& b) const {
    // An explicit finite union is below every common supertype. Replacing
    // incomparable signedness or pointee alternatives with one representation
    // would either discard an interpretation or fail the least-bound law.
    return join_alternatives({a, b});
}

InferredType TypeLattice::glb(const InferredType& a, const InferredType& b) const {
    // Fast path: check trivial cases first (no caching needed)
    if (a.is_bottom() || b.is_bottom()) return InferredType::bottom();
    if (a.is_unknown()) return b;
    if (b.is_unknown()) return a;
    
    // Check cache
    TypePairKey key{a, b};
    auto it = glb_cache_.find(key);
    if (it != glb_cache_.end()) {
        ++stats_.glb_hits;
        return it->second.snapshot();
    }
    
    ++stats_.glb_misses;
    InferredType result = glb_impl(a, b);
    glb_cache_.emplace(TypePairKey{a.snapshot(), b.snapshot()}, result.snapshot());
    return result;
}

InferredType TypeLattice::glb_impl(const InferredType& a, const InferredType& b) const {
    if (a.is_sum() || b.is_sum()) {
        std::vector<InferredType> alternatives;
        if (a.is_sum()) {
            for (const auto& alternative : a.sum_alternatives())
                alternatives.push_back(glb(*alternative, b));
        } else {
            for (const auto& alternative : b.sum_alternatives())
                alternatives.push_back(glb(a, *alternative));
        }
        return join_alternatives(std::move(alternatives));
    }
    if (is_subtype(a, b)) return a;
    if (is_subtype(b, a)) return b;
    if (a.kind() != b.kind()) return InferredType::bottom();
    switch (a.kind()) {
        case InferredType::Kind::Pointer:
            if (a.pointee() && b.pointee())
                return InferredType::make_ptr(glb(*a.pointee(), *b.pointee()));
            break;
        case InferredType::Kind::Array:
            if (a.array_count() == b.array_count() && a.element_type() && b.element_type())
                return InferredType::make_array(glb(*a.element_type(), *b.element_type()), a.array_count());
            break;
        case InferredType::Kind::Function:
            if (a.param_types().size() == b.param_types().size() && a.return_type() && b.return_type()) {
                std::vector<InferredType> parameters;
                parameters.reserve(a.param_types().size());
                for (std::size_t i = 0; i < a.param_types().size(); ++i)
                    parameters.push_back(lub(*a.param_types()[i], *b.param_types()[i]));
                return InferredType::make_func(glb(*a.return_type(), *b.return_type()), std::move(parameters));
            }
            break;
        default:
            break;
    }
    return InferredType::bottom();
}

bool TypeLattice::are_compatible(const InferredType& a, const InferredType& b) const {
    // Compatible if GLB is not bottom
    return !is_subtype(glb(a, b), InferredType::bottom());
}

InferredType TypeLattice::widen_to_size(const InferredType& type, uint32_t target_size) const {
    if (!type.is_base()) return type;
    
    uint32_t current_size = base_type_size(type.base_type(), ptr_size_);
    if (current_size >= target_size) return type;
    
    // Widen to target size, preserving signedness
    if (is_signed_int(type.base_type())) {
        return InferredType::make_base(base_type_from_size(target_size, true));
    } else if (is_unsigned_int(type.base_type())) {
        return InferredType::make_base(base_type_from_size(target_size, false));
    }
    
    return type;
}

InferredType TypeLattice::canonical_for_size(uint32_t size) const {
    // Default to unsigned integer of given size
    if (size == ptr_size_) {
        // Pointer-sized could be either pointer or integer
        return InferredType::unknown();
    }
    return InferredType::make_base(base_type_from_size(size, false));
}

// ============================================================================
// TypeLatticeEncoder implementation
// ============================================================================

TypeLatticeEncoder::TypeLatticeEncoder(Z3Context& ctx) 
    : ctx_(ctx)
    , lattice_(ctx.pointer_size())
{
    initialize_sorts();
}

void TypeLatticeEncoder::initialize_sorts() {
    initialize_base_sort();
    initialize_type_datatype();
}

void TypeLatticeEncoder::initialize_base_sort() {
    if (ctx_.type_lattice_sorts_) {
        base_type_sort_ = ctx_.type_lattice_sorts_->base_sort;
        base_type_consts_ = ctx_.type_lattice_sorts_->base_constants;
        return;
    }
    auto& c = ctx_.ctx();
    
    // Create enumeration sort for base types
    const unsigned num_base_types = static_cast<unsigned>(BaseType::_Count);
    const char* names[num_base_types];
    
    names[static_cast<unsigned>(BaseType::Unknown)]  = "BT_Unknown";
    names[static_cast<unsigned>(BaseType::Bottom)]   = "BT_Bottom";
    names[static_cast<unsigned>(BaseType::Int8)]     = "BT_Int8";
    names[static_cast<unsigned>(BaseType::Int16)]    = "BT_Int16";
    names[static_cast<unsigned>(BaseType::Int32)]    = "BT_Int32";
    names[static_cast<unsigned>(BaseType::Int64)]    = "BT_Int64";
    names[static_cast<unsigned>(BaseType::UInt8)]    = "BT_UInt8";
    names[static_cast<unsigned>(BaseType::UInt16)]   = "BT_UInt16";
    names[static_cast<unsigned>(BaseType::UInt32)]   = "BT_UInt32";
    names[static_cast<unsigned>(BaseType::UInt64)]   = "BT_UInt64";
    names[static_cast<unsigned>(BaseType::Float32)]  = "BT_Float32";
    names[static_cast<unsigned>(BaseType::Float64)]  = "BT_Float64";
    names[static_cast<unsigned>(BaseType::Void)]     = "BT_Void";
    names[static_cast<unsigned>(BaseType::Bool)]     = "BT_Bool";
    
    ::z3::func_decl_vector consts(c);
    ::z3::func_decl_vector testers(c);
    
    base_type_sort_ = c.enumeration_sort("BaseType", num_base_types, names, consts, testers);
    
    // Store constants
    base_type_consts_.reserve(num_base_types);
    for (unsigned i = 0; i < num_base_types; ++i) {
        base_type_consts_.push_back(consts[i]());
    }
    ctx_.type_lattice_sorts_ = std::make_unique<Z3Context::TypeLatticeSortCache>(
        *base_type_sort_, base_type_consts_);
}

namespace {
enum TypeConstructorIndex : unsigned {
    CtorBase, CtorPointer, CtorFunction, CtorArray, CtorStruct, CtorSum,
    CtorNullPointer, CtorNil, CtorCons
};
}

void TypeLatticeEncoder::initialize_type_datatype() {
    auto& cache = *ctx_.type_lattice_sorts_;
    if (cache.type_sort) {
        type_sort_ = cache.type_sort;
        return;
    }
    auto& c = ctx_.ctx();
    // Type and TypeList are declared together: list members refer to Type,
    // while function parameters and sum alternatives refer to TypeList.
    struct Constructors {
        ::z3::context& context;
        std::vector<Z3_constructor> values;
        std::vector<Z3_constructor_list> lists;
        ~Constructors() {
            for (auto list : lists) Z3_del_constructor_list(context, list);
            for (auto value : values) Z3_del_constructor(context, value);
        }
    } handles{c, {}, {}};
    std::vector<unsigned> arities;
    auto constructor = [&](const char* name, const char* recognizer,
                           std::initializer_list<const char*> fields,
                           std::initializer_list<Z3_sort> sorts,
                           std::initializer_list<unsigned> refs) {
        std::vector<Z3_symbol> names;
        for (auto field : fields) names.push_back(c.str_symbol(field));
        std::vector<Z3_sort> field_sorts(sorts);
        std::vector<unsigned> references(refs);
        handles.values.push_back(Z3_mk_constructor(c, c.str_symbol(name),
            c.str_symbol(recognizer), static_cast<unsigned>(names.size()),
            names.data(), field_sorts.data(), references.data()));
        c.check_error();
        arities.push_back(static_cast<unsigned>(names.size()));
    };
    auto count_sort = c.bv_sort(32);
    auto tid_sort = c.bv_sort(64);
    constructor("ST_Base", "ST_is_base", {"ST_base"}, {*base_type_sort_}, {0});
    constructor("ST_Ptr", "ST_is_ptr", {"ST_pointee"}, {nullptr}, {0});
    constructor("ST_Func", "ST_is_func", {"ST_return", "ST_params"},
                {nullptr, nullptr}, {0, 1});
    constructor("ST_Array", "ST_is_array", {"ST_element", "ST_count"},
                {nullptr, count_sort}, {0, 0});
    constructor("ST_Struct", "ST_is_struct", {"ST_tid"}, {tid_sort}, {0});
    constructor("ST_Sum", "ST_is_sum", {"ST_alternatives"}, {nullptr}, {1});
    // Preserve the public make_ptr(shared_ptr{}) representation distinctly
    // from an explicit pointer to Unknown or Void.
    constructor("ST_NullPtr", "ST_is_null_ptr", {}, {}, {});
    constructor("ST_Nil", "ST_is_nil", {}, {}, {});
    constructor("ST_Cons", "ST_is_cons", {"ST_head", "ST_tail"},
                {nullptr, nullptr}, {0, 1});
    handles.lists.push_back(Z3_mk_constructor_list(c, 7, handles.values.data()));
    handles.lists.push_back(Z3_mk_constructor_list(c, 2, handles.values.data() + 7));
    Z3_symbol names[] = {c.str_symbol("StructorInferredType"),
                         c.str_symbol("StructorInferredTypeList")};
    Z3_sort sorts[2] = {};
    Z3_mk_datatypes(c, 2, names, sorts, handles.lists.data());
    c.check_error();
    cache.type_sort.emplace(c, sorts[0]);
    cache.list_sort.emplace(c, sorts[1]);
    for (size_t i = 0; i < handles.values.size(); ++i) {
        Z3_func_decl ctor = nullptr, test = nullptr;
        std::vector<Z3_func_decl> access(arities[i]);
        Z3_query_constructor(c, handles.values[i], arities[i],
                             &ctor, &test, access.data());
        c.check_error();
        cache.constructors.emplace_back(c, ctor);
        cache.recognizers.emplace_back(c, test);
        auto& fields = cache.accessors.emplace_back();
        for (auto field : access) fields.emplace_back(c, field);
    }
    type_sort_ = cache.type_sort;
    initialize_type_relations();
}

void TypeLatticeEncoder::initialize_type_relations() {
    auto& c = ctx_.ctx();
    auto& cache = *ctx_.type_lattice_sorts_;
    const auto& cons = cache.constructors;
    const auto& is = cache.recognizers;
    const auto& field = cache.accessors;
    const auto& ts = *cache.type_sort;
    const auto& ls = *cache.list_sort;
    cache.subtype = c.recfun("ST_subtype", ts, ts, c.bool_sort());
    cache.list_subtype = c.recfun("ST_list_subtype", ls, ls, c.bool_sort());
    cache.source_sum_subtype = c.recfun("ST_source_sum_subtype", ls, ts, c.bool_sort());
    cache.target_sum_subtype = c.recfun("ST_target_sum_subtype", ts, ls, c.bool_sort());
    cache.compatible = c.recfun("ST_compatible", ts, ts, c.bool_sort());
    cache.sum_compatible = c.recfun("ST_sum_compatible", ls, ts, c.bool_sort());
    cache.same_list_length = c.recfun("ST_same_list_length", ls, ls, c.bool_sort());
    cache.byte_size = c.recfun("ST_byte_size", ts, c.int_sort());
    cache.sum_byte_size = c.recfun("ST_sum_byte_size", ls, c.int_sort());
    const auto& sub = *cache.subtype;
    const auto& list_sub = *cache.list_subtype;
    const auto& source_sum = *cache.source_sum_subtype;
    const auto& target_sum = *cache.target_sum_subtype;
    const auto& compatible = *cache.compatible;
    const auto& sum_compatible = *cache.sum_compatible;
    const auto& same_length = *cache.same_list_length;
    const auto& size = *cache.byte_size;
    const auto& sum_size = *cache.sum_byte_size;
    auto a = c.constant("ST_a", ts), b = c.constant("ST_b", ts);
    auto xs = c.constant("ST_xs", ls), ys = c.constant("ST_ys", ls);
    auto define = [&](const ::z3::func_decl& function,
                      std::initializer_list<::z3::expr> args,
                      const ::z3::expr& body) {
        ::z3::expr_vector parameters(c);
        for (const auto& arg : args) parameters.push_back(arg);
        c.recdef(function, parameters, body);
    };
    // Lists encode ordered function arguments. Sums use all/source and
    // any/target membership; no alternative is dropped by the representation.
    define(list_sub, {xs, ys}, ::z3::ite(is[CtorNil](xs), is[CtorNil](ys),
        is[CtorCons](ys) && sub(field[CtorCons][0](xs), field[CtorCons][0](ys)) &&
        list_sub(field[CtorCons][1](xs), field[CtorCons][1](ys))));
    define(source_sum, {xs, b}, ::z3::ite(is[CtorNil](xs), c.bool_val(true),
        sub(field[CtorCons][0](xs), b) && source_sum(field[CtorCons][1](xs), b)));
    define(target_sum, {a, ys}, ::z3::ite(is[CtorNil](ys), c.bool_val(false),
        sub(a, field[CtorCons][0](ys)) || target_sum(a, field[CtorCons][1](ys))));
    ::z3::expr scalar_sub = c.bool_val(false);
    for (unsigned i = 0; i < static_cast<unsigned>(BaseType::_Count); ++i) {
        for (unsigned j = 0; j < static_cast<unsigned>(BaseType::_Count); ++j) {
            if (lattice_.is_subtype(InferredType::make_base(static_cast<BaseType>(i)),
                                    InferredType::make_base(static_cast<BaseType>(j)))) {
                scalar_sub = scalar_sub ||
                    (a == cons[CtorBase](base_type_consts_[i]) &&
                     b == cons[CtorBase](base_type_consts_[j]));
            }
        }
    }
    auto structural_sub = scalar_sub ||
        (is[CtorPointer](a) && is[CtorPointer](b) && sub(field[CtorPointer][0](a), field[CtorPointer][0](b))) ||
        (is[CtorFunction](a) && is[CtorFunction](b) && sub(field[CtorFunction][0](a), field[CtorFunction][0](b)) &&
         list_sub(field[CtorFunction][1](b), field[CtorFunction][1](a))) ||
        (is[CtorArray](a) && is[CtorArray](b) && field[CtorArray][1](a) == field[CtorArray][1](b) &&
         sub(field[CtorArray][0](a), field[CtorArray][0](b)));
    define(sub, {a, b}, a == b ||
        a == encode_base(BaseType::Bottom) || b == encode_base(BaseType::Unknown) ||
        ::z3::ite(is[CtorSum](a), source_sum(field[CtorSum][0](a), b),
            ::z3::ite(is[CtorSum](b), target_sum(a, field[CtorSum][0](b)), structural_sub)));

    define(same_length, {xs, ys}, ::z3::ite(is[CtorNil](xs), is[CtorNil](ys),
        is[CtorCons](ys) && same_length(field[CtorCons][1](xs), field[CtorCons][1](ys))));
    define(sum_compatible, {xs, b}, ::z3::ite(is[CtorNil](xs), c.bool_val(false),
        compatible(field[CtorCons][0](xs), b) || sum_compatible(field[CtorCons][1](xs), b)));
    // Compatibility means that the lattice meet is not global Bottom.
    // Pointer/array/function meets retain their constructor even when an
    // individual component meets at Bottom; sum meets distribute pairwise.
    auto compatible_shapes = a == b ||
        a == encode_base(BaseType::Unknown) || b == encode_base(BaseType::Unknown) ||
        (is[CtorBase](a) && is[CtorBase](b) && (sub(a, b) || sub(b, a))) ||
        (is[CtorPointer](a) && is[CtorPointer](b)) ||
        (is[CtorArray](a) && is[CtorArray](b) && field[CtorArray][1](a) == field[CtorArray][1](b)) ||
        (is[CtorFunction](a) && is[CtorFunction](b) &&
         same_length(field[CtorFunction][1](a), field[CtorFunction][1](b)));
    define(compatible, {a, b},
        a != encode_base(BaseType::Bottom) && b != encode_base(BaseType::Bottom) &&
        ::z3::ite(is[CtorSum](a), sum_compatible(field[CtorSum][0](a), b),
            ::z3::ite(is[CtorSum](b), sum_compatible(field[CtorSum][0](b), a), compatible_shapes)));

    // Sizes are mathematical byte counts. -1 denotes unavailable size
    // metadata (Unknown, Bottom, or a structure requiring an IDB lookup).
    ::z3::expr scalar_size = c.int_val(-1);
    for (unsigned i = static_cast<unsigned>(BaseType::Int8);
         i < static_cast<unsigned>(BaseType::_Count); ++i) {
        scalar_size = ::z3::ite(a == cons[CtorBase](base_type_consts_[i]),
            ctx_.uint_val(base_type_size(static_cast<BaseType>(i), ctx_.pointer_size())),
            scalar_size);
    }
    auto head_size = size(field[CtorCons][0](xs));
    auto tail_size = sum_size(field[CtorCons][1](xs));
    define(sum_size, {xs}, ::z3::ite(is[CtorNil](xs), c.int_val(0),
        ::z3::ite(head_size < 0 || tail_size < 0, c.int_val(-1),
            ::z3::ite(head_size > tail_size, head_size, tail_size))));
    auto element_size = size(field[CtorArray][0](a));
    define(size, {a}, ::z3::ite(is[CtorPointer](a) || is[CtorFunction](a) || is[CtorNullPointer](a),
        ctx_.uint_val(ctx_.pointer_size()),
        ::z3::ite(is[CtorArray](a), ::z3::ite(element_size < 0, c.int_val(-1),
            element_size * ::z3::bv2int(field[CtorArray][1](a), false)),
            ::z3::ite(is[CtorSum](a), sum_size(field[CtorSum][0](a)), scalar_size))));
}

::z3::sort TypeLatticeEncoder::type_sort() { return *type_sort_; }
::z3::sort TypeLatticeEncoder::base_type_sort() { return *base_type_sort_; }

::z3::expr TypeLatticeEncoder::make_type_var(const char* name) {
    return ctx_.ctx().constant(name, type_sort());
}

::z3::expr TypeLatticeEncoder::make_type_var(ea_t func_ea, int var_idx, int version) {
    qstring name;
    name.sprnt("type_%llX_%d_%d", static_cast<unsigned long long>(func_ea), var_idx, version);
    return make_type_var(name.c_str());
}

::z3::expr TypeLatticeEncoder::make_mem_type_var(ea_t base, sval_t offset, uint32_t size) {
    qstring name;
    name.sprnt("mem_type_%llX_%llX_%u", static_cast<unsigned long long>(base),
               static_cast<unsigned long long>(offset), size);
    return make_type_var(name.c_str());
}

::z3::expr TypeLatticeEncoder::encode_base(BaseType base) {
    const auto index = static_cast<unsigned>(base);
    if (index >= base_type_consts_.size()) throw std::invalid_argument("invalid base type");
    return ctx_.type_lattice_sorts_->constructors[CtorBase](base_type_consts_[index]);
}

::z3::expr TypeLatticeEncoder::encode_list(
    const std::vector<std::shared_ptr<InferredType>>& types) {
    const auto& constructors = ctx_.type_lattice_sorts_->constructors;
    auto result = constructors[CtorNil]();
    for (auto it = types.rbegin(); it != types.rend(); ++it) {
        if (!*it) throw std::invalid_argument("null type-list member");
        result = constructors[CtorCons](encode_type(**it), result);
    }
    return result;
}

::z3::expr TypeLatticeEncoder::encode_type(const InferredType& type) {
    const auto& constructors = ctx_.type_lattice_sorts_->constructors;
    switch (type.kind()) {
        case InferredType::Kind::Base: return encode_base(type.base_type());
        case InferredType::Kind::Pointer:
            return type.pointee() ? encode_ptr(encode_type(*type.pointee()))
                                  : constructors[CtorNullPointer]();
        case InferredType::Kind::Function:
            return constructors[CtorFunction](encode_type(*type.return_type()),
                                   encode_list(type.param_types()));
        case InferredType::Kind::Array:
            return constructors[CtorArray](encode_type(*type.element_type()),
                                   ctx_.ctx().bv_val(type.array_count(), 32));
        case InferredType::Kind::Struct:
            return constructors[CtorStruct](ctx_.ctx().bv_val(static_cast<uint64_t>(type.struct_tid()), 64));
        case InferredType::Kind::Sum:
            return constructors[CtorSum](encode_list(type.sum_alternatives()));
    }
    throw std::invalid_argument("invalid inferred type kind");
}

::z3::expr TypeLatticeEncoder::encode(const InferredType& type) {
    auto it = encode_cache_.find(type);
    if (it != encode_cache_.end()) return it->second;
    auto result = encode_type(type);
    encode_cache_.emplace(type.snapshot(), result);
    return result;
}

::z3::expr TypeLatticeEncoder::encode_ptr(const ::z3::expr& pointee) {
    return ctx_.type_lattice_sorts_->constructors[CtorPointer](pointee);
}

std::vector<InferredType> TypeLatticeEncoder::decode_list(const ::z3::expr& value) {
    const auto& constructors = ctx_.type_lattice_sorts_->constructors;
    auto current = value;
    std::vector<InferredType> result;
    while (::z3::eq(current.decl(), constructors[CtorCons])) {
        result.push_back(decode_type(current.arg(0)));
        current = current.arg(1);
    }
    if (!::z3::eq(current.decl(), constructors[CtorNil]))
        throw std::invalid_argument("non-ground inferred type list");
    return result;
}

InferredType TypeLatticeEncoder::decode_type(const ::z3::expr& value) {
    const auto& constructors = ctx_.type_lattice_sorts_->constructors;
    if (::z3::eq(value.decl(), constructors[CtorBase])) {
        for (unsigned i = 0; i < base_type_consts_.size(); ++i) {
            if (::z3::eq(value.arg(0), base_type_consts_[i]))
                return InferredType::make_base(static_cast<BaseType>(i));
        }
    } else if (::z3::eq(value.decl(), constructors[CtorPointer])) {
        return InferredType::make_ptr(decode_type(value.arg(0)));
    } else if (::z3::eq(value.decl(), constructors[CtorFunction])) {
        return InferredType::make_func(decode_type(value.arg(0)), decode_list(value.arg(1)));
    } else if (::z3::eq(value.decl(), constructors[CtorArray])) {
        return InferredType::make_array(decode_type(value.arg(0)), value.arg(1).get_numeral_uint());
    } else if (::z3::eq(value.decl(), constructors[CtorStruct])) {
        return InferredType::make_struct(static_cast<tid_t>(value.arg(0).get_numeral_uint64()));
    } else if (::z3::eq(value.decl(), constructors[CtorSum])) {
        return InferredType::make_sum(decode_list(value.arg(0)));
    } else if (::z3::eq(value.decl(), constructors[CtorNullPointer])) {
        return InferredType::make_ptr(std::shared_ptr<InferredType>{});
    }
    throw std::invalid_argument("non-ground inferred type");
}

InferredType TypeLatticeEncoder::decode(const ::z3::expr& expr, const ::z3::model& model) {
    try {
        return decode_type(model.eval(expr, true));
    } catch (const ::z3::exception&) {
        return InferredType::unknown();
    } catch (const std::invalid_argument&) {
        return InferredType::unknown();
    }
}

::z3::expr TypeLatticeEncoder::type_eq(const ::z3::expr& t1, const ::z3::expr& t2) {
    return t1 == t2;
}

::z3::expr TypeLatticeEncoder::is_pointer_type(const ::z3::expr& type) {
    const auto& is = ctx_.type_lattice_sorts_->recognizers;
    return is[CtorPointer](type) || is[CtorNullPointer](type);
}

::z3::expr TypeLatticeEncoder::is_signed_type(const ::z3::expr& type) {
    auto result = ctx_.bool_val(false);
    for (unsigned i = static_cast<unsigned>(BaseType::Int8);
         i <= static_cast<unsigned>(BaseType::Int64); ++i)
        result = result || type == encode_base(static_cast<BaseType>(i));
    return result;
}

::z3::expr TypeLatticeEncoder::is_unsigned_type(const ::z3::expr& type) {
    auto result = ctx_.bool_val(false);
    for (unsigned i = static_cast<unsigned>(BaseType::UInt8);
         i <= static_cast<unsigned>(BaseType::UInt64); ++i)
        result = result || type == encode_base(static_cast<BaseType>(i));
    return result;
}

::z3::expr TypeLatticeEncoder::is_integer_type(const ::z3::expr& type) {
    return is_signed_type(type) || is_unsigned_type(type);
}

::z3::expr TypeLatticeEncoder::is_floating_type(const ::z3::expr& type) {
    return type == encode_base(BaseType::Float32) || type == encode_base(BaseType::Float64);
}

SymbolicTypeQueryBounds TypeLatticeEncoder::symbolic_query_bounds() const noexcept {
    const auto& config = ctx_.config();
    return {config.max_symbolic_type_depth, config.max_symbolic_type_list_length,
            config.max_symbolic_type_expansions};
}

void TypeLatticeEncoder::QueryBudget::consume() {
    if (remaining == 0)
        throw SymbolicTypeQueryLimit("symbolic type predicate expansion budget exhausted");
    --remaining;
}

bool TypeLatticeEncoder::is_ground_type(const ::z3::expr& type) const {
    std::vector<::z3::expr> pending{type};
    while (!pending.empty()) {
        auto current = std::move(pending.back());
        pending.pop_back();
        if (current.is_numeral()) continue;
        if (!current.is_app() || current.decl().decl_kind() != Z3_OP_DT_CONSTRUCTOR)
            return false;
        for (unsigned i = 0; i < current.num_args(); ++i)
            pending.push_back(current.arg(i));
    }
    return true;
}

int TypeLatticeEncoder::constructor_index(const ::z3::expr& type) const {
    if (!type.is_app()) return -1;
    const auto& constructors = ctx_.type_lattice_sorts_->constructors;
    for (size_t i = 0; i < constructors.size(); ++i)
        if (::z3::eq(type.decl(), constructors[i])) return static_cast<int>(i);
    return -1;
}

::z3::expr TypeLatticeEncoder::project(const ::z3::expr& type,
                                      unsigned constructor, unsigned member) const {
    if (constructor_index(type) == static_cast<int>(constructor)) return type.arg(member);
    return ctx_.type_lattice_sorts_->accessors[constructor][member](type);
}

::z3::expr TypeLatticeEncoder::bounded_byte_size(const ::z3::expr& type,
                                                unsigned depth, QueryBudget& budget) {
    budget.consume();
    const auto& cache = *ctx_.type_lattice_sorts_;
    if (is_ground_type(type)) return (*cache.byte_size)(type).simplify();
    const auto kind = constructor_index(type);
    if (kind == CtorPointer || kind == CtorNullPointer || kind == CtorFunction)
        return ctx_.uint_val(ctx_.pointer_size());
    auto result = ctx_.int_val(-1);
    for (unsigned i = static_cast<unsigned>(BaseType::Int8);
         i < static_cast<unsigned>(BaseType::_Count); ++i) {
        auto tag = static_cast<BaseType>(i);
        result = ::z3::ite(type == encode_base(tag),
            ctx_.uint_val(base_type_size(tag, ctx_.pointer_size())), result);
    }
    auto primitive = ::z3::ite(is_pointer_type(type) || cache.recognizers[CtorFunction](type),
        ctx_.uint_val(ctx_.pointer_size()), result);
    if (depth != 0) {
        auto array_size = ctx_.int_val(-1), sum_size = ctx_.int_val(-1);
        if (kind < 0 || kind == CtorArray) {
            auto element_size = bounded_byte_size(project(type, CtorArray, 0), depth - 1, budget);
            auto count = ::z3::bv2int(project(type, CtorArray, 1), false);
            array_size = ::z3::ite(element_size < 0, ctx_.int_val(-1), element_size * count);
        }
        if (kind < 0 || kind == CtorSum)
            sum_size = bounded_sum_byte_size(project(type, CtorSum, 0), depth - 1,
                symbolic_query_bounds().max_list_length, budget);
        return ::z3::ite(cache.recognizers[CtorBase](type) || is_pointer_type(type) ||
            cache.recognizers[CtorFunction](type), primitive,
            ::z3::ite(cache.recognizers[CtorArray](type), array_size,
                ::z3::ite(cache.recognizers[CtorSum](type), sum_size, ctx_.int_val(-1))));
    }
    return primitive;
}

::z3::expr TypeLatticeEncoder::bounded_sum_byte_size(const ::z3::expr& list,
                                                    unsigned depth, unsigned length,
                                                    QueryBudget& budget) {
    budget.consume();
    const auto& cache = *ctx_.type_lattice_sorts_;
    if (is_ground_type(list)) return (*cache.sum_byte_size)(list).simplify();
    const auto empty = cache.recognizers[CtorNil](list);
    if (length == 0) return ::z3::ite(empty, ctx_.int_val(0), ctx_.int_val(-1));
    auto head = bounded_byte_size(project(list, CtorCons, 0), depth, budget);
    auto tail = bounded_sum_byte_size(project(list, CtorCons, 1), depth, length - 1, budget);
    return ::z3::ite(empty, ctx_.int_val(0),
        ::z3::ite(head < 0 || tail < 0, ctx_.int_val(-1), ::z3::ite(head > tail, head, tail)));
}

::z3::expr TypeLatticeEncoder::bounded_list_subtype(const ::z3::expr& a, const ::z3::expr& b,
                                                   unsigned depth, unsigned length,
                                                   QueryBudget& budget) {
    budget.consume();
    const auto& cache = *ctx_.type_lattice_sorts_;
    const auto left_kind = constructor_index(a), right_kind = constructor_index(b);
    if (left_kind == CtorNil) return cache.recognizers[CtorNil](b);
    if (right_kind == CtorNil) return cache.recognizers[CtorNil](a);
    auto both_empty = cache.recognizers[CtorNil](a) && cache.recognizers[CtorNil](b);
    if (length == 0) return both_empty;
    auto heads = bounded_subtype(project(a, CtorCons, 0),
        project(b, CtorCons, 0), depth, budget);
    auto tails = bounded_list_subtype(project(a, CtorCons, 1),
        project(b, CtorCons, 1), depth, length - 1, budget);
    return both_empty || (cache.recognizers[CtorCons](a) && cache.recognizers[CtorCons](b) && heads && tails);
}

::z3::expr TypeLatticeEncoder::bounded_same_list_length(const ::z3::expr& a,
                                                       const ::z3::expr& b,
                                                       unsigned length, QueryBudget& budget) {
    budget.consume();
    const auto& cache = *ctx_.type_lattice_sorts_;
    const auto left_kind = constructor_index(a), right_kind = constructor_index(b);
    if (left_kind == CtorNil) return cache.recognizers[CtorNil](b);
    if (right_kind == CtorNil) return cache.recognizers[CtorNil](a);
    auto both_empty = cache.recognizers[CtorNil](a) && cache.recognizers[CtorNil](b);
    if (length == 0) return both_empty;
    auto tails = bounded_same_list_length(project(a, CtorCons, 1),
        project(b, CtorCons, 1), length - 1, budget);
    return both_empty || (cache.recognizers[CtorCons](a) && cache.recognizers[CtorCons](b) && tails);
}

::z3::expr TypeLatticeEncoder::bounded_sum_subtype(const ::z3::expr& list,
                                                  const ::z3::expr& type, bool source,
                                                  unsigned depth, unsigned length,
                                                  QueryBudget& budget) {
    budget.consume();
    const auto& cache = *ctx_.type_lattice_sorts_;
    if (constructor_index(list) == CtorNil) return ctx_.bool_val(source);
    auto empty = cache.recognizers[CtorNil](list);
    if (length == 0) return source ? empty : ctx_.bool_val(false);
    auto head = project(list, CtorCons, 0);
    auto match = source ? bounded_subtype(head, type, depth, budget)
                        : bounded_subtype(type, head, depth, budget);
    auto rest = bounded_sum_subtype(project(list, CtorCons, 1), type, source,
        depth, length - 1, budget);
    return ::z3::ite(empty, ctx_.bool_val(source), source ? match && rest : match || rest);
}

::z3::expr TypeLatticeEncoder::bounded_subtype(const ::z3::expr& a, const ::z3::expr& b,
                                              unsigned depth, QueryBudget& budget) {
    budget.consume();
    const auto& cache = *ctx_.type_lattice_sorts_;
    if (::z3::eq(a, b)) return ctx_.bool_val(true);
    if (is_ground_type(a) && is_ground_type(b)) return (*cache.subtype)(a, b).simplify();
    const auto left_kind = constructor_index(a), right_kind = constructor_index(b);
    const auto can_be = [](int known, unsigned kind) { return known < 0 || known == static_cast<int>(kind); };
    auto result = a == b || a == encode_base(BaseType::Bottom) || b == encode_base(BaseType::Unknown);
    if (can_be(left_kind, CtorBase) && can_be(right_kind, CtorBase)) {
        for (auto first : {BaseType::Int8, BaseType::UInt8}) {
            for (unsigned i = 0; i < 4; ++i) {
                for (unsigned j = i + 1; j < 4; ++j) {
                    result = result ||
                        (a == encode_base(static_cast<BaseType>(static_cast<unsigned>(first) + i)) &&
                         b == encode_base(static_cast<BaseType>(static_cast<unsigned>(first) + j)));
                }
            }
        }
    }
    if (depth == 0) return result;
    const auto length = symbolic_query_bounds().max_list_length;
    if (left_kind == CtorSum)
        return result || bounded_sum_subtype(project(a, CtorSum, 0), b, true,
            depth - 1, length, budget);
    auto structural = ctx_.bool_val(false);
    if (can_be(left_kind, CtorPointer) && can_be(right_kind, CtorPointer)) {
        auto pointees = bounded_subtype(project(a, CtorPointer, 0), project(b, CtorPointer, 0), depth - 1, budget);
        structural = structural || (cache.recognizers[CtorPointer](a) && cache.recognizers[CtorPointer](b) && pointees);
    }
    if (can_be(left_kind, CtorArray) && can_be(right_kind, CtorArray)) {
        auto elements = bounded_subtype(project(a, CtorArray, 0), project(b, CtorArray, 0), depth - 1, budget);
        structural = structural || (cache.recognizers[CtorArray](a) && cache.recognizers[CtorArray](b) &&
            project(a, CtorArray, 1) == project(b, CtorArray, 1) && elements);
    }
    if (can_be(left_kind, CtorFunction) && can_be(right_kind, CtorFunction)) {
        auto returns = bounded_subtype(project(a, CtorFunction, 0), project(b, CtorFunction, 0), depth - 1, budget);
        auto parameters = bounded_list_subtype(project(b, CtorFunction, 1), project(a, CtorFunction, 1),
            depth - 1, length, budget);
        structural = structural || (cache.recognizers[CtorFunction](a) && cache.recognizers[CtorFunction](b) && returns && parameters);
    }
    if (can_be(right_kind, CtorSum)) {
        auto list = project(b, CtorSum, 0);
        auto match = bounded_sum_subtype(list, a, false, depth - 1, length, budget) &&
            bounded_same_list_length(list, list, length, budget);
        structural = ::z3::ite(cache.recognizers[CtorSum](b), match, structural);
    }
    if (can_be(left_kind, CtorSum)) {
        auto match = bounded_sum_subtype(project(a, CtorSum, 0), b, true, depth - 1, length, budget);
        structural = ::z3::ite(cache.recognizers[CtorSum](a), match, structural);
    }
    return result || structural;
}

::z3::expr TypeLatticeEncoder::bounded_sum_compatible(const ::z3::expr& list,
                                                     const ::z3::expr& type,
                                                     unsigned depth, unsigned length,
                                                     QueryBudget& budget) {
    budget.consume();
    const auto& cache = *ctx_.type_lattice_sorts_;
    if (constructor_index(list) == CtorNil) return ctx_.bool_val(false);
    if (length == 0) return ctx_.bool_val(false);
    auto match = bounded_compatible(project(list, CtorCons, 0), type, depth, budget);
    auto rest = bounded_sum_compatible(project(list, CtorCons, 1), type,
        depth, length - 1, budget);
    return !cache.recognizers[CtorNil](list) && (match || rest);
}

::z3::expr TypeLatticeEncoder::bounded_compatible(const ::z3::expr& a, const ::z3::expr& b,
                                                 unsigned depth, QueryBudget& budget) {
    budget.consume();
    const auto& cache = *ctx_.type_lattice_sorts_;
    if (is_ground_type(a) && is_ground_type(b)) return (*cache.compatible)(a, b).simplify();
    auto result = a == b || a == encode_base(BaseType::Unknown) || b == encode_base(BaseType::Unknown) ||
        (is_signed_type(a) && is_signed_type(b)) || (is_unsigned_type(a) && is_unsigned_type(b)) ||
        (cache.recognizers[CtorPointer](a) && cache.recognizers[CtorPointer](b)) ||
        (cache.recognizers[CtorArray](a) && cache.recognizers[CtorArray](b) &&
         project(a, CtorArray, 1) == project(b, CtorArray, 1));
    const auto length = symbolic_query_bounds().max_list_length;
    auto same_arity = bounded_same_list_length(project(a, CtorFunction, 1),
        project(b, CtorFunction, 1), length, budget);
    result = result || (cache.recognizers[CtorFunction](a) && cache.recognizers[CtorFunction](b) && same_arity);
    auto any_sum = cache.recognizers[CtorSum](a) || cache.recognizers[CtorSum](b);
    if (depth == 0) {
        result = result && !any_sum;
    } else {
        auto source_list = project(a, CtorSum, 0), target_list = project(b, CtorSum, 0);
        auto source = bounded_sum_compatible(source_list, b, depth - 1, length, budget) &&
            bounded_same_list_length(source_list, source_list, length, budget);
        auto target = bounded_sum_compatible(target_list, a, depth - 1, length, budget) &&
            bounded_same_list_length(target_list, target_list, length, budget);
        result = ::z3::ite(cache.recognizers[CtorSum](a), source,
            ::z3::ite(cache.recognizers[CtorSum](b), target, result));
    }
    return a != encode_base(BaseType::Bottom) && b != encode_base(BaseType::Bottom) && result;
}

::z3::expr TypeLatticeEncoder::type_has_size(const ::z3::expr& type, uint32_t size) {
    const auto& constructors = ctx_.type_lattice_sorts_->constructors;
    if (type.is_app() &&
        (::z3::eq(type.decl(), constructors[CtorPointer]) ||
         ::z3::eq(type.decl(), constructors[CtorNullPointer]) ||
         ::z3::eq(type.decl(), constructors[CtorFunction])))
        return ctx_.bool_val(size == ctx_.pointer_size());
    if (is_ground_type(type))
        return ((*ctx_.type_lattice_sorts_->byte_size)(type) == ctx_.uint_val(size)).simplify();
    bounded_symbolic_queries_used_ = true;
    auto bounds = symbolic_query_bounds();
    QueryBudget budget{bounds.max_expansions};
    return bounded_byte_size(type, bounds.max_depth, budget) == ctx_.uint_val(size);
}

::z3::expr TypeLatticeEncoder::subtype_of(const ::z3::expr& t1, const ::z3::expr& t2) {
    if (::z3::eq(t1, t2)) return ctx_.bool_val(true);
    if (is_ground_type(t1) && is_ground_type(t2))
        return (*ctx_.type_lattice_sorts_->subtype)(t1, t2).simplify();
    bounded_symbolic_queries_used_ = true;
    auto bounds = symbolic_query_bounds();
    QueryBudget budget{bounds.max_expansions};
    return bounded_subtype(t1, t2, bounds.max_depth, budget);
}

::z3::expr TypeLatticeEncoder::types_compatible(const ::z3::expr& t1, const ::z3::expr& t2) {
    if (is_ground_type(t1) && is_ground_type(t2))
        return (*ctx_.type_lattice_sorts_->compatible)(t1, t2).simplify();
    bounded_symbolic_queries_used_ = true;
    auto bounds = symbolic_query_bounds();
    QueryBudget budget{bounds.max_expansions};
    return bounded_compatible(t1, t2, bounds.max_depth, budget);
}

// ============================================================================
// BitvectorTypeEncoder implementation
// ============================================================================

BitvectorTypeEncoder::BitvectorTypeEncoder(Z3Context& ctx) : ctx_(ctx) {
    initialize();
}

void BitvectorTypeEncoder::initialize() {
    bv_sort_ = ctx_.ctx().bv_sort(TYPE_BITS);
}

::z3::sort BitvectorTypeEncoder::type_sort() {
    return *bv_sort_;
}

::z3::expr BitvectorTypeEncoder::make_type_var(const char* name) {
    return ctx_.ctx().bv_const(name, TYPE_BITS);
}

::z3::expr BitvectorTypeEncoder::encode(const InferredType& type) {
    uint32_t encoded = 0;
    
    switch (type.kind()) {
        case InferredType::Kind::Base:
            encoded = static_cast<uint32_t>(type.base_type());
            encoded |= (base_type_size(type.base_type(), ctx_.pointer_size()) << 6);
            if (is_signed_int(type.base_type())) {
                encoded |= (1 << 15);
            }
            break;
            
        case InferredType::Kind::Pointer: {
            encoded = (1 << 14);  // Is pointer flag
            unsigned depth = 1;
            const InferredType* curr = type.pointee();
            while (curr && curr->is_pointer()) {
                ++depth;
                curr = curr->pointee();
            }
            encoded |= (depth << 16);
            encoded |= (ctx_.pointer_size() << 6);
            break;
        }
        
        default:
            encoded = static_cast<uint32_t>(type.base_type());
            break;
    }
    
    return ctx_.ctx().bv_val(encoded, TYPE_BITS);
}

::z3::expr BitvectorTypeEncoder::encode_known(
    BaseType base, 
    uint32_t size, 
    bool is_ptr, 
    unsigned ptr_depth)
{
    uint32_t encoded = static_cast<uint32_t>(base);
    encoded |= (size << 6);
    if (is_ptr) encoded |= (1 << 14);
    if (is_signed_int(base)) encoded |= (1 << 15);
    encoded |= (ptr_depth << 16);
    
    return ctx_.ctx().bv_val(encoded, TYPE_BITS);
}

InferredType BitvectorTypeEncoder::decode(const ::z3::expr& bv, const ::z3::model& model) {
    try {
        ::z3::expr val = model.eval(bv, true);
        uint64_t encoded = val.get_numeral_uint64();
        
        uint32_t base_tag = encoded & 0x3F;
        bool is_ptr = (encoded >> 14) & 1;
        unsigned ptr_depth = (encoded >> 16) & 0xFF;
        
        if (is_ptr && ptr_depth > 0) {
            InferredType inner = InferredType::make_base(static_cast<BaseType>(base_tag));
            for (unsigned i = 0; i < ptr_depth; ++i) {
                inner = InferredType::make_ptr(std::move(inner));
            }
            return inner;
        }
        
        return InferredType::make_base(static_cast<BaseType>(base_tag));
    } catch (...) {
        return InferredType::unknown();
    }
}

::z3::expr BitvectorTypeEncoder::extract_base_tag(const ::z3::expr& type) {
    return type.extract(5, 0);
}

::z3::expr BitvectorTypeEncoder::extract_size_bits(const ::z3::expr& type) {
    return type.extract(13, 6);
}

::z3::expr BitvectorTypeEncoder::extract_ptr_flag(const ::z3::expr& type) {
    return type.extract(14, 14);
}

::z3::expr BitvectorTypeEncoder::extract_signed_flag(const ::z3::expr& type) {
    return type.extract(15, 15);
}

::z3::expr BitvectorTypeEncoder::extract_ptr_depth(const ::z3::expr& type) {
    return type.extract(23, 16);
}

::z3::expr BitvectorTypeEncoder::is_pointer(const ::z3::expr& type) {
    return extract_ptr_flag(type) == ctx_.ctx().bv_val(1, 1);
}

::z3::expr BitvectorTypeEncoder::is_integer(const ::z3::expr& type) {
    auto& c = ctx_.ctx();
    ::z3::expr tag = extract_base_tag(type);
    ::z3::expr ptr_flag = extract_ptr_flag(type);
    
    return (ptr_flag == c.bv_val(0, 1)) &&
           (tag >= c.bv_val(static_cast<unsigned>(BaseType::Int8), 6)) &&
           (tag <= c.bv_val(static_cast<unsigned>(BaseType::UInt64), 6));
}

::z3::expr BitvectorTypeEncoder::is_signed(const ::z3::expr& type) {
    return extract_signed_flag(type) == ctx_.ctx().bv_val(1, 1);
}

::z3::expr BitvectorTypeEncoder::has_size(const ::z3::expr& type, uint32_t size) {
    return extract_size_bits(type) == ctx_.ctx().bv_val(size, 8);
}

::z3::expr BitvectorTypeEncoder::get_size(const ::z3::expr& type) {
    return ::z3::zext(extract_size_bits(type), TYPE_BITS - 8);
}

::z3::expr BitvectorTypeEncoder::types_compatible(const ::z3::expr& t1, const ::z3::expr& t2) {
    // Same type or same size with compatible categories
    ::z3::expr same = (t1 == t2);
    ::z3::expr same_size = (extract_size_bits(t1) == extract_size_bits(t2));
    ::z3::expr both_int = is_integer(t1) && is_integer(t2);
    ::z3::expr both_ptr = is_pointer(t1) && is_pointer(t2);
    
    return same || (same_size && (both_int || both_ptr));
}

} // namespace structor::z3
