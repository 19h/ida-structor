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

InferredType InferredType::from_tinfo(const tinfo_t& type) {
    if (type.empty()) {
        return unknown();
    }
    
    // Check for pointer types first
    if (type.is_ptr()) {
        tinfo_t pointed = type.get_pointed_object();
        if (pointed.is_func()) {
            // Function pointer
            func_type_data_t ftd;
            if (pointed.get_func_details(&ftd)) {
                std::vector<InferredType> params;
                for (const auto& arg : ftd) {
                    params.push_back(from_tinfo(arg.type));
                }
                auto func = make_func(from_tinfo(ftd.rettype), std::move(params));
                return make_ptr(std::move(func));
            }
        }
        return make_ptr(from_tinfo(pointed));
    }
    
    // Check for function (non-pointer)
    if (type.is_func()) {
        func_type_data_t ftd;
        if (type.get_func_details(&ftd)) {
            std::vector<InferredType> params;
            for (const auto& arg : ftd) {
                params.push_back(from_tinfo(arg.type));
            }
            return make_func(from_tinfo(ftd.rettype), std::move(params));
        }
    }
    
    // Check for array
    if (type.is_array()) {
        array_type_data_t atd;
        if (type.get_array_details(&atd)) {
            return make_array(from_tinfo(atd.elem_type), static_cast<uint32_t>(atd.nelems));
        }
    }
    
    // Check for struct/union
    if (type.is_struct() || type.is_union()) {
        tid_t tid = type.get_tid();
        if (tid != BADADDR) {
            return make_struct(tid);
        }
    }
    
    // Check for void
    if (type.is_void()) {
        return make_base(BaseType::Void);
    }
    
    // Check for floating point
    if (type.is_floating()) {
        size_t sz = type.get_size();
        if (sz == 4) return make_base(BaseType::Float32);
        if (sz == 8) return make_base(BaseType::Float64);
    }
    
    // Integer types
    size_t sz = type.get_size();
    bool is_signed = type.is_signed();
    return make_base(base_type_from_size(static_cast<uint32_t>(sz), is_signed));
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

void TypeLatticeEncoder::initialize_type_datatype() {
    auto& c = ctx_.ctx();
    
    // Use integer encoding for types instead of recursive datatypes
    // This is more efficient for Z3 solving and avoids API complexity
    //
    // Encoding scheme:
    // Bits 0-7:   Type kind tag (0=Base, 1=Ptr, 2=Func, 3=Array, 4=Struct, 5=Sum)
    // Bits 8-15:  Base type enum value (for Kind::Base)
    // Bits 16-23: Pointer depth or array count
    // Bits 24-31: Reserved
    //
    // For pointer types: stores the innermost pointee's base type and pointer depth
    // For example, int** has base_type=Int32, ptr_depth=2
    
    type_sort_ = c.int_sort();
}

::z3::sort TypeLatticeEncoder::type_sort() {
    return *type_sort_;
}

::z3::sort TypeLatticeEncoder::base_type_sort() {
    return *base_type_sort_;
}

::z3::expr TypeLatticeEncoder::make_type_var(const char* name) {
    return ctx_.ctx().int_const(name);
}

::z3::expr TypeLatticeEncoder::make_type_var(ea_t func_ea, int var_idx, int version) {
    qstring name;
    name.sprnt("type_%llX_%d_%d", static_cast<unsigned long long>(func_ea), var_idx, version);
    return make_type_var(name.c_str());
}

::z3::expr TypeLatticeEncoder::make_mem_type_var(ea_t base, sval_t offset, uint32_t size) {
    qstring name;
    name.sprnt("mem_type_%llX_%llX_%u", 
               static_cast<unsigned long long>(base),
               static_cast<unsigned long long>(offset),
               size);
    return make_type_var(name.c_str());
}

::z3::expr TypeLatticeEncoder::encode_base(BaseType base) {
    return ctx_.int_val(static_cast<int>(base));
}

::z3::expr TypeLatticeEncoder::encode(const InferredType& type) {
    // Check cache
    auto it = encode_cache_.find(type);
    if (it != encode_cache_.end()) {
        return it->second;
    }
    
    ::z3::expr result = ctx_.ctx().int_val(0);
    
    // Encoding scheme for integer representation:
    // Bits 0-7:   Type tag (kind)
    // Bits 8-15:  Base type (for Kind::Base)
    // Bits 16-23: Pointer depth (for Kind::Pointer)
    // Bits 24-31: Array count low bits (for Kind::Array)
    
    int encoded = 0;
    
    switch (type.kind()) {
        case InferredType::Kind::Base:
            encoded = (static_cast<int>(type.base_type()) << 8) | 0;
            break;
            
        case InferredType::Kind::Pointer: {
            int depth = 1;
            const InferredType* curr = type.pointee();
            while (curr && curr->is_pointer()) {
                ++depth;
                curr = curr->pointee();
            }
            BaseType inner_base = BaseType::Void;
            if (curr && curr->is_base()) {
                inner_base = curr->base_type();
            }
            encoded = (depth << 16) | (static_cast<int>(inner_base) << 8) | 1;
            break;
        }
        
        case InferredType::Kind::Function:
            encoded = (static_cast<int>(type.param_types().size()) << 8) | 2;
            break;
            
        case InferredType::Kind::Array:
            encoded = (static_cast<int>(type.array_count() & 0xFF) << 24) | 3;
            break;
            
        case InferredType::Kind::Struct:
            encoded = 4;
            break;
            
        case InferredType::Kind::Sum:
            encoded = 5;
            break;
    }
    
    result = ctx_.int_val(encoded);
    encode_cache_.emplace(type.snapshot(), result);
    return result;
}

::z3::expr TypeLatticeEncoder::encode_ptr(const ::z3::expr& pointee) {
    // ptr(t) = t | (1 << 16) -- add one level of pointer
    return pointee + ctx_.int_val(1 << 16);
}

InferredType TypeLatticeEncoder::decode(const ::z3::expr& expr, const ::z3::model& model) {
    try {
        ::z3::expr val = model.eval(expr, true);
        if (!val.is_numeral()) {
            return InferredType::unknown();
        }
        
        int encoded = static_cast<int>(val.get_numeral_int64());
        int kind_tag = encoded & 0xFF;
        int base_bits = (encoded >> 8) & 0xFF;
        int ptr_depth = (encoded >> 16) & 0xFF;
        
        switch (kind_tag) {
            case 0: // Base
                return InferredType::make_base(static_cast<BaseType>(base_bits));
                
            case 1: { // Pointer
                InferredType inner = InferredType::make_base(static_cast<BaseType>(base_bits));
                for (int i = 0; i < ptr_depth; ++i) {
                    inner = InferredType::make_ptr(std::move(inner));
                }
                return inner;
            }
            
            case 2: // Function
                return InferredType::make_func(
                    InferredType::make_base(BaseType::Void),
                    std::vector<InferredType>()
                );
                
            case 3: // Array
                return InferredType::make_array(
                    InferredType::unknown(),
                    (encoded >> 24) & 0xFF
                );
                
            case 4: // Struct
                return InferredType::make_struct(BADADDR);
                
            case 5: // Sum
                return InferredType::unknown();
                
            default:
                return InferredType::unknown();
        }
    } catch (...) {
        return InferredType::unknown();
    }
}

::z3::expr TypeLatticeEncoder::type_eq(const ::z3::expr& t1, const ::z3::expr& t2) {
    return t1 == t2;
}

::z3::expr TypeLatticeEncoder::is_pointer_type(const ::z3::expr& type) {
    // Check if kind tag is 1 (pointer)
    // Use mod 256 instead of bitwise & for Z3 integers
    return (type % ctx_.int_val(256)) == ctx_.int_val(1);
}

::z3::expr TypeLatticeEncoder::is_integer_type(const ::z3::expr& type) {
    // Kind tag is 0 (base) and base type is in integer range
    // Use arithmetic (div, mod) instead of bitwise ops for Z3 integers
    ::z3::expr kind = type % ctx_.int_val(256);
    ::z3::expr base = (type / ctx_.int_val(256)) % ctx_.int_val(256);
    
    ::z3::expr is_base = (kind == ctx_.int_val(0));
    ::z3::expr in_signed_range = (base >= ctx_.int_val(static_cast<int>(BaseType::Int8))) &&
                                  (base <= ctx_.int_val(static_cast<int>(BaseType::Int64)));
    ::z3::expr in_unsigned_range = (base >= ctx_.int_val(static_cast<int>(BaseType::UInt8))) &&
                                    (base <= ctx_.int_val(static_cast<int>(BaseType::UInt64)));
    
    return is_base && (in_signed_range || in_unsigned_range);
}

::z3::expr TypeLatticeEncoder::is_signed_type(const ::z3::expr& type) {
    ::z3::expr kind = type % ctx_.int_val(256);
    ::z3::expr base = (type / ctx_.int_val(256)) % ctx_.int_val(256);
    
    return (kind == ctx_.int_val(0)) &&
           (base >= ctx_.int_val(static_cast<int>(BaseType::Int8))) &&
           (base <= ctx_.int_val(static_cast<int>(BaseType::Int64)));
}

::z3::expr TypeLatticeEncoder::is_unsigned_type(const ::z3::expr& type) {
    ::z3::expr kind = type % ctx_.int_val(256);
    ::z3::expr base = (type / ctx_.int_val(256)) % ctx_.int_val(256);
    
    return (kind == ctx_.int_val(0)) &&
           (base >= ctx_.int_val(static_cast<int>(BaseType::UInt8))) &&
           (base <= ctx_.int_val(static_cast<int>(BaseType::UInt64)));
}

::z3::expr TypeLatticeEncoder::is_floating_type(const ::z3::expr& type) {
    ::z3::expr kind = type % ctx_.int_val(256);
    ::z3::expr base = (type / ctx_.int_val(256)) % ctx_.int_val(256);
    
    return (kind == ctx_.int_val(0)) &&
           ((base == ctx_.int_val(static_cast<int>(BaseType::Float32))) ||
            (base == ctx_.int_val(static_cast<int>(BaseType::Float64))));
}

::z3::expr TypeLatticeEncoder::type_has_size(const ::z3::expr& type, uint32_t size) {
    auto& c = ctx_.ctx();
    ::z3::expr kind = type % ctx_.int_val(256);
    ::z3::expr base = (type / ctx_.int_val(256)) % ctx_.int_val(256);
    
    // Build constraints for each type that has this size
    ::z3::expr_vector options(c);
    
    // Check pointer type (always pointer size)
    if (size == ctx_.pointer_size()) {
        options.push_back(is_pointer_type(type));
    }
    
    // Check base types
    for (int bt = static_cast<int>(BaseType::Int8); bt < static_cast<int>(BaseType::_Count); ++bt) {
        if (base_type_size(static_cast<BaseType>(bt), ctx_.pointer_size()) == size) {
            options.push_back((kind == ctx_.int_val(0)) && (base == ctx_.int_val(bt)));
        }
    }
    
    if (options.empty()) {
        return c.bool_val(false);
    }
    return ::z3::mk_or(options);
}

::z3::expr TypeLatticeEncoder::subtype_of(const ::z3::expr& t1, const ::z3::expr& t2) {
    // Simplified subtyping: same type or widening of integers
    ::z3::expr same = type_eq(t1, t2);
    
    ::z3::expr kind1 = t1 % ctx_.int_val(256);
    ::z3::expr kind2 = t2 % ctx_.int_val(256);
    ::z3::expr base1 = (t1 / ctx_.int_val(256)) % ctx_.int_val(256);
    ::z3::expr base2 = (t2 / ctx_.int_val(256)) % ctx_.int_val(256);
    
    // Both base types and base1 <= base2 for same signedness family
    ::z3::expr both_base = (kind1 == ctx_.int_val(0)) && (kind2 == ctx_.int_val(0));
    ::z3::expr can_widen = both_base && (base1 <= base2);
    
    return same || can_widen;
}

::z3::expr TypeLatticeEncoder::types_compatible(const ::z3::expr& t1, const ::z3::expr& t2) {
    // Compatible if same type, or both integers of compatible sizes
    ::z3::expr same = type_eq(t1, t2);
    ::z3::expr both_int = is_integer_type(t1) && is_integer_type(t2);
    ::z3::expr both_ptr = is_pointer_type(t1) && is_pointer_type(t2);
    
    return same || both_int || both_ptr;
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
