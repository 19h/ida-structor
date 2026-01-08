#include "structor/z3/type_encoding.hpp"
#include "structor/synth_types.hpp"

namespace structor::z3 {

const char* type_category_name(TypeCategory cat) noexcept {
    switch (cat) {
        case TypeCategory::Unknown:   return "unknown";
        case TypeCategory::Int8:      return "int8";
        case TypeCategory::Int16:     return "int16";
        case TypeCategory::Int32:     return "int32";
        case TypeCategory::Int64:     return "int64";
        case TypeCategory::UInt8:     return "uint8";
        case TypeCategory::UInt16:    return "uint16";
        case TypeCategory::UInt32:    return "uint32";
        case TypeCategory::UInt64:    return "uint64";
        case TypeCategory::Float32:   return "float32";
        case TypeCategory::Float64:   return "float64";
        case TypeCategory::Pointer:   return "pointer";
        case TypeCategory::FuncPtr:   return "funcptr";
        case TypeCategory::Array:     return "array";
        case TypeCategory::Struct:    return "struct";
        case TypeCategory::Union:     return "union";
        case TypeCategory::RawBytes:  return "raw_bytes";
        case TypeCategory::Void:      return "void";
        default:                      return "invalid";
    }
}

TypeEncoder::TypeEncoder(Z3Context& ctx) : ctx_(ctx) {
    initialize_type_sort();
}

void TypeEncoder::initialize_type_sort() {
    // Create enumeration sort for type categories
    const char* names[static_cast<unsigned>(TypeCategory::_Count)];
    names[static_cast<unsigned>(TypeCategory::Unknown)]  = "TypeUnknown";
    names[static_cast<unsigned>(TypeCategory::Int8)]     = "TypeInt8";
    names[static_cast<unsigned>(TypeCategory::Int16)]    = "TypeInt16";
    names[static_cast<unsigned>(TypeCategory::Int32)]    = "TypeInt32";
    names[static_cast<unsigned>(TypeCategory::Int64)]    = "TypeInt64";
    names[static_cast<unsigned>(TypeCategory::UInt8)]    = "TypeUInt8";
    names[static_cast<unsigned>(TypeCategory::UInt16)]   = "TypeUInt16";
    names[static_cast<unsigned>(TypeCategory::UInt32)]   = "TypeUInt32";
    names[static_cast<unsigned>(TypeCategory::UInt64)]   = "TypeUInt64";
    names[static_cast<unsigned>(TypeCategory::Float32)]  = "TypeFloat32";
    names[static_cast<unsigned>(TypeCategory::Float64)]  = "TypeFloat64";
    names[static_cast<unsigned>(TypeCategory::Pointer)]  = "TypePointer";
    names[static_cast<unsigned>(TypeCategory::FuncPtr)]  = "TypeFuncPtr";
    names[static_cast<unsigned>(TypeCategory::Array)]    = "TypeArray";
    names[static_cast<unsigned>(TypeCategory::Struct)]   = "TypeStruct";
    names[static_cast<unsigned>(TypeCategory::Union)]    = "TypeUnion";
    names[static_cast<unsigned>(TypeCategory::RawBytes)] = "TypeRawBytes";
    names[static_cast<unsigned>(TypeCategory::Void)]     = "TypeVoid";

    // Create enum sort
    ::z3::func_decl_vector consts(ctx_.ctx());
    ::z3::func_decl_vector testers(ctx_.ctx());

    type_sort_ = ctx_.ctx().enumeration_sort(
        "TypeCategory",
        static_cast<unsigned>(TypeCategory::_Count),
        names,
        consts,
        testers
    );

    // Store category expressions
    category_exprs_.reserve(static_cast<unsigned>(TypeCategory::_Count));
    for (unsigned i = 0; i < static_cast<unsigned>(TypeCategory::_Count); ++i) {
        category_exprs_.push_back(consts[i]());
    }
}

::z3::sort TypeEncoder::type_sort() {
    return *type_sort_;
}

::z3::expr TypeEncoder::category_expr(TypeCategory cat) {
    return category_exprs_[static_cast<unsigned>(cat)];
}

TypeCategory TypeEncoder::categorize(const tinfo_t& type) const {
    if (type.empty()) {
        return TypeCategory::Unknown;
    }

    // Check for function pointer first
    if (type.is_funcptr()) {
        return TypeCategory::FuncPtr;
    }

    // Check for pointer
    if (type.is_ptr()) {
        tinfo_t pointed = type.get_pointed_object();
        if (!pointed.empty() && pointed.is_funcptr()) {
            return TypeCategory::FuncPtr;
        }
        return TypeCategory::Pointer;
    }

    // Check for array
    if (type.is_array()) {
        return TypeCategory::Array;
    }

    // Check for struct/union
    if (type.is_struct()) {
        return TypeCategory::Struct;
    }
    if (type.is_union()) {
        return TypeCategory::Union;
    }

    // Check for void
    if (type.is_void()) {
        return TypeCategory::Void;
    }

    // Check for floating point
    if (type.is_floating()) {
        size_t sz = type.get_size();
        if (sz == 4) return TypeCategory::Float32;
        if (sz == 8) return TypeCategory::Float64;
        return TypeCategory::Unknown;
    }

    // Integer types - check signedness and size
    size_t sz = type.get_size();
    bool is_signed = type.is_signed();

    if (is_signed) {
        switch (sz) {
            case 1: return TypeCategory::Int8;
            case 2: return TypeCategory::Int16;
            case 4: return TypeCategory::Int32;
            case 8: return TypeCategory::Int64;
            default: return TypeCategory::Unknown;
        }
    } else {
        switch (sz) {
            case 1: return TypeCategory::UInt8;
            case 2: return TypeCategory::UInt16;
            case 4: return TypeCategory::UInt32;
            case 8: return TypeCategory::UInt64;
            default: return TypeCategory::Unknown;
        }
    }
}

ExtendedTypeInfo TypeEncoder::extract_extended_info(const tinfo_t& type) const {
    ExtendedTypeInfo info;
    info.category = categorize(type);

    if (!type.empty()) {
        size_t sz = type.get_size();
        info.size = (sz != BADSIZE) ? static_cast<uint32_t>(sz) : 0;
    }

    // Extract pointer target info
    if (type.is_ptr()) {
        tinfo_t pointed = type.get_pointed_object();
        if (!pointed.empty()) {
            info.pointee_category = categorize(pointed);
        }
    }

    // Extract array info
    if (type.is_array()) {
        array_type_data_t atd;
        if (type.get_array_details(&atd)) {
            info.element_count = static_cast<uint32_t>(atd.nelems);
            info.element_category = categorize(atd.elem_type);
        }
    }

    // Extract function pointer info
    if (type.is_funcptr() || (type.is_ptr() && type.get_pointed_object().is_func())) {
        tinfo_t func_type = type.is_funcptr() ? type : type.get_pointed_object();
        func_type_data_t ftd;
        if (func_type.get_func_details(&ftd)) {
            info.func_arg_count = static_cast<uint32_t>(ftd.size());
        }
    }

    // Extract UDT tid
    if (type.is_struct() || type.is_union()) {
        tid_t tid = type.get_tid();
        if (tid != BADADDR) {
            info.udt_tid = tid;
        }
    }

    return info;
}

::z3::expr TypeEncoder::encode(const tinfo_t& type) {
    TypeCategory cat = categorize(type);
    return category_expr(cat);
}

std::pair<::z3::expr, ExtendedTypeInfo> TypeEncoder::encode_extended(const tinfo_t& type) {
    ExtendedTypeInfo info = extract_extended_info(type);
    return {category_expr(info.category), info};
}

tinfo_t TypeEncoder::decode(
    TypeCategory category,
    uint32_t size,
    const ExtendedTypeInfo* extended)
{
    tinfo_t type;
    uint32_t ptr_size = ctx_.pointer_size();

    switch (category) {
        case TypeCategory::Int8:
            type.create_simple_type(BTF_INT8);
            break;
        case TypeCategory::Int16:
            type.create_simple_type(BTF_INT16);
            break;
        case TypeCategory::Int32:
            type.create_simple_type(BTF_INT32);
            break;
        case TypeCategory::Int64:
            type.create_simple_type(BTF_INT64);
            break;
        case TypeCategory::UInt8:
            type.create_simple_type(BTF_UINT8);
            break;
        case TypeCategory::UInt16:
            type.create_simple_type(BTF_UINT16);
            break;
        case TypeCategory::UInt32:
            type.create_simple_type(BTF_UINT32);
            break;
        case TypeCategory::UInt64:
            type.create_simple_type(BTF_UINT64);
            break;
        case TypeCategory::Float32:
            type.create_simple_type(BTF_FLOAT);
            break;
        case TypeCategory::Float64:
            type.create_simple_type(BTF_DOUBLE);
            break;
        case TypeCategory::Pointer: {
            tinfo_t void_type;
            void_type.create_simple_type(BTF_VOID);
            type.create_ptr(void_type);
            break;
        }
        case TypeCategory::FuncPtr: {
            // Create generic function pointer: void (*)()
            func_type_data_t ftd;
            ftd.rettype.create_simple_type(BTF_VOID);
            ftd.set_cc(CM_CC_UNKNOWN);
            tinfo_t func_type;
            func_type.create_func(ftd);
            type.create_ptr(func_type);
            break;
        }
        case TypeCategory::Array: {
            // Create byte array of given size
            tinfo_t elem_type;
            uint32_t elem_count = size;

            if (extended && extended->element_category) {
                elem_type = decode(*extended->element_category,
                                   natural_size(*extended->element_category), nullptr);
                if (extended->element_count) {
                    elem_count = *extended->element_count;
                }
            } else {
                elem_type.create_simple_type(BTF_UINT8);
            }

            type.create_array(elem_type, elem_count);
            break;
        }
        case TypeCategory::Struct:
        case TypeCategory::Union:
            // Try to get from extended info
            if (extended && extended->udt_tid) {
                type.get_type_by_tid(*extended->udt_tid);
            }
            // If that fails, create a placeholder
            if (type.empty()) {
                tinfo_t byte_type;
                byte_type.create_simple_type(BTF_UINT8);
                type.create_array(byte_type, size);
            }
            break;
        case TypeCategory::RawBytes: {
            tinfo_t byte_type;
            byte_type.create_simple_type(BTF_UINT8);
            type.create_array(byte_type, size);
            break;
        }
        case TypeCategory::Void:
            type.create_simple_type(BTF_VOID);
            break;
        case TypeCategory::Unknown:
        default:
            // Default to appropriately sized integer
            if (size == ptr_size) {
                type.create_simple_type(ptr_size == 8 ? BTF_UINT64 : BTF_UINT32);
            } else {
                switch (size) {
                    case 1: type.create_simple_type(BTF_UINT8); break;
                    case 2: type.create_simple_type(BTF_UINT16); break;
                    case 4: type.create_simple_type(BTF_UINT32); break;
                    case 8: type.create_simple_type(BTF_UINT64); break;
                    default: {
                        tinfo_t byte_type;
                        byte_type.create_simple_type(BTF_UINT8);
                        type.create_array(byte_type, size);
                        break;
                    }
                }
            }
            break;
    }

    return type;
}

std::pair<::z3::expr, bool> TypeEncoder::compatible(
    const ::z3::expr& t1,
    const ::z3::expr& t2)
{
    // Two types are compatible if they are equal or both are integral of same size
    // This is a soft constraint

    // Create expression: t1 == t2
    ::z3::expr equal = (t1 == t2);

    // Integer types of the same size are compatible
    // (e.g., int32 and uint32 at same offset is acceptable)
    auto& c = ctx_.ctx();

    ::z3::expr int8_compat =
        ((t1 == category_expr(TypeCategory::Int8)) && (t2 == category_expr(TypeCategory::UInt8))) ||
        ((t1 == category_expr(TypeCategory::UInt8)) && (t2 == category_expr(TypeCategory::Int8)));

    ::z3::expr int16_compat =
        ((t1 == category_expr(TypeCategory::Int16)) && (t2 == category_expr(TypeCategory::UInt16))) ||
        ((t1 == category_expr(TypeCategory::UInt16)) && (t2 == category_expr(TypeCategory::Int16)));

    ::z3::expr int32_compat =
        ((t1 == category_expr(TypeCategory::Int32)) && (t2 == category_expr(TypeCategory::UInt32))) ||
        ((t1 == category_expr(TypeCategory::UInt32)) && (t2 == category_expr(TypeCategory::Int32)));

    ::z3::expr int64_compat =
        ((t1 == category_expr(TypeCategory::Int64)) && (t2 == category_expr(TypeCategory::UInt64))) ||
        ((t1 == category_expr(TypeCategory::UInt64)) && (t2 == category_expr(TypeCategory::Int64)));

    // Pointer types are compatible with each other
    ::z3::expr ptr_compat =
        ((t1 == category_expr(TypeCategory::Pointer)) || (t1 == category_expr(TypeCategory::FuncPtr))) &&
        ((t2 == category_expr(TypeCategory::Pointer)) || (t2 == category_expr(TypeCategory::FuncPtr)));

    // Unknown is compatible with anything
    ::z3::expr unknown_compat =
        (t1 == category_expr(TypeCategory::Unknown)) ||
        (t2 == category_expr(TypeCategory::Unknown));

    ::z3::expr full_compat = equal || int8_compat || int16_compat || int32_compat ||
                             int64_compat || ptr_compat || unknown_compat;

    return {full_compat, false};  // Soft constraint
}

::z3::expr TypeEncoder::size_matches_type(
    const ::z3::expr& type,
    const ::z3::expr& size)
{
    auto& c = ctx_.ctx();
    uint32_t ptr_size = ctx_.pointer_size();

    ::z3::expr_vector constraints(c);

    // Add size constraints for each type category
    constraints.push_back(::z3::implies(type == category_expr(TypeCategory::Int8),
                                        size == ctx_.int_val(1)));
    constraints.push_back(::z3::implies(type == category_expr(TypeCategory::UInt8),
                                        size == ctx_.int_val(1)));
    constraints.push_back(::z3::implies(type == category_expr(TypeCategory::Int16),
                                        size == ctx_.int_val(2)));
    constraints.push_back(::z3::implies(type == category_expr(TypeCategory::UInt16),
                                        size == ctx_.int_val(2)));
    constraints.push_back(::z3::implies(type == category_expr(TypeCategory::Int32),
                                        size == ctx_.int_val(4)));
    constraints.push_back(::z3::implies(type == category_expr(TypeCategory::UInt32),
                                        size == ctx_.int_val(4)));
    constraints.push_back(::z3::implies(type == category_expr(TypeCategory::Int64),
                                        size == ctx_.int_val(8)));
    constraints.push_back(::z3::implies(type == category_expr(TypeCategory::UInt64),
                                        size == ctx_.int_val(8)));
    constraints.push_back(::z3::implies(type == category_expr(TypeCategory::Float32),
                                        size == ctx_.int_val(4)));
    constraints.push_back(::z3::implies(type == category_expr(TypeCategory::Float64),
                                        size == ctx_.int_val(8)));
    constraints.push_back(::z3::implies(type == category_expr(TypeCategory::Pointer),
                                        size == ctx_.int_val(ptr_size)));
    constraints.push_back(::z3::implies(type == category_expr(TypeCategory::FuncPtr),
                                        size == ctx_.int_val(ptr_size)));

    return ::z3::mk_and(constraints);
}

uint32_t TypeEncoder::natural_size(TypeCategory cat) const {
    uint32_t ptr_size = ctx_.pointer_size();
    return type_category_size(cat, ptr_size);
}

uint32_t TypeEncoder::natural_alignment(TypeCategory cat) const {
    uint32_t ptr_size = ctx_.pointer_size();
    return type_category_alignment(cat, ptr_size);
}

bool TypeEncoder::is_signed_int(TypeCategory cat) noexcept {
    return cat >= TypeCategory::Int8 && cat <= TypeCategory::Int64;
}

bool TypeEncoder::is_unsigned_int(TypeCategory cat) noexcept {
    return cat >= TypeCategory::UInt8 && cat <= TypeCategory::UInt64;
}

bool TypeEncoder::is_integer(TypeCategory cat) noexcept {
    return is_signed_int(cat) || is_unsigned_int(cat);
}

bool TypeEncoder::is_floating(TypeCategory cat) noexcept {
    return cat == TypeCategory::Float32 || cat == TypeCategory::Float64;
}

// Free functions

bool types_compatible(TypeCategory t1, TypeCategory t2) {
    if (t1 == t2) return true;
    if (t1 == TypeCategory::Unknown || t2 == TypeCategory::Unknown) return true;

    // Signed/unsigned of same size are compatible
    if ((t1 == TypeCategory::Int8 && t2 == TypeCategory::UInt8) ||
        (t1 == TypeCategory::UInt8 && t2 == TypeCategory::Int8)) return true;
    if ((t1 == TypeCategory::Int16 && t2 == TypeCategory::UInt16) ||
        (t1 == TypeCategory::UInt16 && t2 == TypeCategory::Int16)) return true;
    if ((t1 == TypeCategory::Int32 && t2 == TypeCategory::UInt32) ||
        (t1 == TypeCategory::UInt32 && t2 == TypeCategory::Int32)) return true;
    if ((t1 == TypeCategory::Int64 && t2 == TypeCategory::UInt64) ||
        (t1 == TypeCategory::UInt64 && t2 == TypeCategory::Int64)) return true;

    // Pointer types are compatible
    if ((t1 == TypeCategory::Pointer || t1 == TypeCategory::FuncPtr) &&
        (t2 == TypeCategory::Pointer || t2 == TypeCategory::FuncPtr)) return true;

    return false;
}

uint32_t type_category_size(TypeCategory cat, uint32_t pointer_size) {
    switch (cat) {
        case TypeCategory::Int8:
        case TypeCategory::UInt8:
            return 1;
        case TypeCategory::Int16:
        case TypeCategory::UInt16:
            return 2;
        case TypeCategory::Int32:
        case TypeCategory::UInt32:
        case TypeCategory::Float32:
            return 4;
        case TypeCategory::Int64:
        case TypeCategory::UInt64:
        case TypeCategory::Float64:
            return 8;
        case TypeCategory::Pointer:
        case TypeCategory::FuncPtr:
            return pointer_size;
        case TypeCategory::Void:
            return 0;
        default:
            return 0;
    }
}

uint32_t type_category_alignment(TypeCategory cat, uint32_t pointer_size) {
    // Alignment typically equals size for basic types, up to pointer size
    uint32_t size = type_category_size(cat, pointer_size);
    if (size == 0) return 1;
    return std::min(size, pointer_size);
}

TypeCategory semantic_to_category(int semantic_type) {
    switch (static_cast<SemanticType>(semantic_type)) {
        case SemanticType::Integer:
            return TypeCategory::Int32;  // Default to 32-bit
        case SemanticType::UnsignedInteger:
            return TypeCategory::UInt32;
        case SemanticType::Float:
            return TypeCategory::Float32;
        case SemanticType::Double:
            return TypeCategory::Float64;
        case SemanticType::Pointer:
            return TypeCategory::Pointer;
        case SemanticType::FunctionPointer:
        case SemanticType::VTablePointer:
            return TypeCategory::FuncPtr;
        case SemanticType::Array:
            return TypeCategory::Array;
        case SemanticType::NestedStruct:
            return TypeCategory::Struct;
        case SemanticType::Padding:
            return TypeCategory::RawBytes;
        default:
            return TypeCategory::Unknown;
    }
}

int category_to_semantic(TypeCategory cat) {
    switch (cat) {
        case TypeCategory::Int8:
        case TypeCategory::Int16:
        case TypeCategory::Int32:
        case TypeCategory::Int64:
            return static_cast<int>(SemanticType::Integer);
        case TypeCategory::UInt8:
        case TypeCategory::UInt16:
        case TypeCategory::UInt32:
        case TypeCategory::UInt64:
            return static_cast<int>(SemanticType::UnsignedInteger);
        case TypeCategory::Float32:
            return static_cast<int>(SemanticType::Float);
        case TypeCategory::Float64:
            return static_cast<int>(SemanticType::Double);
        case TypeCategory::Pointer:
            return static_cast<int>(SemanticType::Pointer);
        case TypeCategory::FuncPtr:
            return static_cast<int>(SemanticType::FunctionPointer);
        case TypeCategory::Array:
            return static_cast<int>(SemanticType::Array);
        case TypeCategory::Struct:
            return static_cast<int>(SemanticType::NestedStruct);
        case TypeCategory::RawBytes:
            return static_cast<int>(SemanticType::Padding);
        default:
            return static_cast<int>(SemanticType::Unknown);
    }
}

} // namespace structor::z3
