#pragma once

/// @file mock_ida.hpp
/// @brief Mock IDA SDK types and functions for unit testing

#include <cstdint>
#include <cstddef>
#include <cstdarg>
#include <cstdio>
#include <string>
#include <vector>
#include <map>
#include <memory>
#include <functional>
#include <algorithm>
#include <cstring>

// Define testing macro (guard against redefinition from build system)
#ifndef STRUCTOR_TESTING
#define STRUCTOR_TESTING
#endif

// Define idaapi macro (calling convention, empty on non-Windows)
#define idaapi

// ============================================================================
// Basic IDA Types
// ============================================================================

using ea_t = std::uint64_t;
using tid_t = std::uint64_t;
using sval_t = std::int64_t;
using uval_t = std::uint64_t;
using flags64_t = std::uint64_t;
using nodeidx_t = std::uint64_t;

// The IDA SDK defines ssize_t on every supported host. MSVC does not provide
// the POSIX spelling, so the standalone mock must supply the pointer-sized
// signed type before production headers declare callbacks that use it.
#ifdef _WIN32
using ssize_t = std::ptrdiff_t;
#endif

constexpr ea_t BADADDR = static_cast<ea_t>(-1);
constexpr tid_t BADNODE = static_cast<tid_t>(-1);
constexpr size_t BADSIZE = static_cast<size_t>(-1);

// ============================================================================
// IDA String Type
// ============================================================================

class qstring {
public:
    qstring() = default;
    qstring(const char* s) : data_(s ? s : "") {}
    qstring(const std::string& s) : data_(s) {}

    const char* c_str() const { return data_.c_str(); }
    size_t length() const { return data_.length(); }
    bool empty() const { return data_.empty(); }
    void clear() { data_.clear(); }

    qstring& operator=(const char* s) { data_ = s ? s : ""; return *this; }
    qstring& operator=(const std::string& s) { data_ = s; return *this; }

    bool operator==(const char* s) const { return data_ == s; }
    bool operator==(const qstring& other) const { return data_ == other.data_; }

    char operator[](size_t i) const { return data_[i]; }

    qstring& append(char c) { data_ += c; return *this; }
    qstring& append(const char* s) { if (s) data_ += s; return *this; }
    
    qstring& operator+=(char c) { data_ += c; return *this; }
    qstring& operator+=(const char* s) { if (s) data_ += s; return *this; }
    qstring& operator+=(const qstring& other) { data_ += other.data_; return *this; }

    void sprnt(const char* fmt, ...) {
        char buf[4096];
        va_list va;
        va_start(va, fmt);
        vsnprintf(buf, sizeof(buf), fmt, va);
        va_end(va);
        data_ = buf;
    }

    void cat_sprnt(const char* fmt, ...) {
        char buf[4096];
        va_list va;
        va_start(va, fmt);
        vsnprintf(buf, sizeof(buf), fmt, va);
        va_end(va);
        data_ += buf;
    }

    void vsprnt(const char* fmt, va_list va) {
        char buf[4096];
        vsnprintf(buf, sizeof(buf), fmt, va);
        data_ = buf;
    }

private:
    std::string data_;
};

// ============================================================================
// IDA Vector Type
// ============================================================================

template<typename T>
class qvector : public std::vector<T> {
public:
    using std::vector<T>::vector;

    void push_back(T&& val) { std::vector<T>::push_back(std::move(val)); }
    void push_back(const T& val) { std::vector<T>::push_back(val); }

    T& at(size_t i) { return std::vector<T>::at(i); }
    const T& at(size_t i) const { return std::vector<T>::at(i); }
};

// ============================================================================
// Type Information Mock
// ============================================================================

enum type_flags : std::uint32_t {
    BTF_VOID    = 0x01,
    BTF_INT8    = 0x02,
    BTF_INT16   = 0x04,
    BTF_INT32   = 0x08,
    BTF_INT64   = 0x10,
    BTF_UINT8   = 0x20,
    BTF_UINT16  = 0x40,
    BTF_UINT32  = 0x80,
    BTF_UINT64  = 0x100,
    BTF_FLOAT   = 0x200,
    BTF_DOUBLE  = 0x400,
    BTF_BOOL    = 0x800,
    BT_INT8     = BTF_INT8,
    BT_INT16    = BTF_INT16,
    BT_INT32    = BTF_INT32,
    BT_INT64    = BTF_INT64,
    BTMT_CHAR   = 0x1000,
    BTMT_USIGNED = 0x2000,
    BTMT_UNSIGNED = BTMT_USIGNED,
    BTF_STRUCT  = 0x4000,
    BTF_UNION   = 0x8000,
    BT_UNK_QWORD = 0x10000,
    BTF_ENUM_MOCK = 0x20000,
    BTF_EXTFLOAT_MOCK = 0x40000,
    BTF_BOOL4_MOCK = 0x80000,
    BTF_BITFIELD_MOCK = 0x100000,
};

constexpr int TCMP_IGNMODS = 1;
constexpr int TCMP_DECL = 0x20;

// Forward declarations
struct func_type_data_t;
struct array_type_data_t;
struct udt_type_data_t;

class tinfo_t {
public:
    tinfo_t() = default;

    bool empty() const {
        return type_flags_ == 0 && !is_ptr_ && !is_array_ &&
               !is_struct_ && !is_union_ && !is_func_;
    }
    void clear() { *this = tinfo_t(); }

    void create_simple_type(std::uint32_t bt) {
        clear();
        type_flags_ = bt;
    }
    void create_ptr(const tinfo_t& pointed) {
        const auto target = std::make_shared<tinfo_t>(pointed);
        clear();
        is_ptr_ = true;
        pointed_type_ = target;
    }
    void create_array(const tinfo_t& elem, size_t count) {
        const auto element = std::make_shared<tinfo_t>(elem);
        clear();
        is_array_ = true;
        array_count_ = count;
        pointed_type_ = element;
    }
    bool create_func(const struct func_type_data_t& ftd);
    void create_array(const struct array_type_data_t& atd);
    bool create_udt(udt_type_data_t& udt, std::uint32_t kind);
    bool get_udt_details(udt_type_data_t* out) const;

    bool is_ptr() const { return is_ptr_; }
    bool is_funcptr() const {
        return is_ptr_ && pointed_type_ && pointed_type_->is_func();
    }
    bool is_floating() const { return (type_flags_ & (BTF_FLOAT | BTF_DOUBLE)) || type_flags_ == BTF_EXTFLOAT_MOCK; }
    bool is_enum() const { return type_flags_ == BTF_ENUM_MOCK; }
    bool is_struct() const { return is_struct_; }
    bool is_array() const { return is_array_; }
    bool is_func() const { return is_func_; }
    bool is_decl_bitfield() const { return type_flags_ == BTF_BITFIELD_MOCK; }
    bool is_void() const { return type_flags_ == BTF_VOID; }
    bool is_union() const { return is_union_; }
    bool is_partial() const { return type_flags_ == BT_UNK_QWORD; }
    bool is_bool() const { return type_flags_ == BTF_BOOL || type_flags_ == BTF_BOOL4_MOCK; }
    bool is_integral() const { return is_signed() || is_unsigned() || is_bool(); }
    bool is_signed() const { 
        return !(type_flags_ & BTMT_UNSIGNED) &&
               (type_flags_ & (BTF_INT8 | BTF_INT16 | BTF_INT32 | BTF_INT64)) != 0;
    }
    bool is_unsigned() const {
        return (type_flags_ & (BTF_UINT8 | BTF_UINT16 | BTF_UINT32 | BTF_UINT64)) != 0 ||
               ((type_flags_ & BTMT_UNSIGNED) &&
                (type_flags_ & (BTF_INT8 | BTF_INT16 | BTF_INT32 | BTF_INT64)) != 0);
    }

    size_t get_size() const {
        if (is_ptr_) return 8;  // Assume 64-bit
        if (is_array_) return array_count_ * (pointed_type_ ? pointed_type_->get_size() : 1);
        if (is_struct_ || is_union_) return udt_size_;
        if (type_flags_ == BT_UNK_QWORD) return 8;
        if (type_flags_ == BTF_EXTFLOAT_MOCK) return 16;
        if (type_flags_ == BTF_ENUM_MOCK || type_flags_ == BTF_BOOL4_MOCK ||
            type_flags_ == BTF_BITFIELD_MOCK) return 4;
        if (type_flags_ & (BTF_INT8 | BTF_UINT8 | BTF_BOOL)) return 1;
        if (type_flags_ & (BTF_INT16 | BTF_UINT16)) return 2;
        if (type_flags_ & (BTF_INT32 | BTF_UINT32 | BTF_FLOAT)) return 4;
        if (type_flags_ & (BTF_INT64 | BTF_UINT64 | BTF_DOUBLE)) return 8;
        return BADSIZE;
    }

    tid_t get_tid() const { return struct_tid_; }

    bool get_pointed_object(tinfo_t* out) const {
        if (!is_ptr_ || !pointed_type_) return false;
        *out = *pointed_type_;
        return true;
    }

    tinfo_t get_pointed_object() const {
        if (!is_ptr_ || !pointed_type_) return tinfo_t();
        return *pointed_type_;
    }

    bool get_func_details(func_type_data_t* ftd) const;
    bool get_array_details(array_type_data_t* atd) const;

    bool get_type_by_tid(tid_t tid) { struct_tid_ = tid; return tid != BADADDR; }
    bool get_named_type(void*, const char* name) { return name != nullptr; }
    bool compare_with(const tinfo_t& other, int) const {
        return equals_to(other);
    }
    bool equals_to(const tinfo_t& other) const {
        if (type_flags_ != other.type_flags_ || is_ptr_ != other.is_ptr_ ||
            is_func_ != other.is_func_ || is_struct_ != other.is_struct_ ||
            is_array_ != other.is_array_ || is_union_ != other.is_union_ ||
            array_count_ != other.array_count_ ||
            struct_tid_ != other.struct_tid_) {
            return false;
        }
        if (static_cast<bool>(pointed_type_) !=
            static_cast<bool>(other.pointed_type_)) {
            return false;
        }
        return (!pointed_type_ || pointed_type_->equals_to(*other.pointed_type_)) &&
               udt_equals(other) && function_equals(other);
    }

    void print(qstring* out) const {
        if (!out) return;
        if (is_ptr_) {
            *out = "void*";
        } else if (type_flags_ & BTF_INT32) {
            *out = "int";
        } else {
            *out = "unknown";
        }
    }

private:
    std::uint32_t type_flags_ = 0;
    bool is_ptr_ = false;
    bool is_func_ = false;
    bool is_struct_ = false;
    bool is_array_ = false;
    bool is_union_ = false;
    size_t array_count_ = 0;
    std::uint32_t array_base_ = 0;
    std::shared_ptr<tinfo_t> pointed_type_;
    tid_t struct_tid_ = BADADDR;
    size_t udt_size_ = 0;
    std::shared_ptr<udt_type_data_t> udt_;
    std::shared_ptr<func_type_data_t> function_;
    bool udt_equals(const tinfo_t& other) const;
    bool function_equals(const tinfo_t& other) const;
};

struct udm_t {
    qstring name;
    std::uint64_t offset = 0;  // bits, as in the IDA SDK
    std::uint64_t size = 0;    // bits
    tinfo_t type;
    bool bitfield = false;
    bool is_bitfield() const { return bitfield; }
};

struct udt_type_data_t : public qvector<udm_t> {
    bool is_union = false;
    size_t total_size = 0;  // bytes
    unsigned pack = 0;
};

inline bool tinfo_t::create_udt(udt_type_data_t& udt, std::uint32_t kind) {
    if (kind != BTF_STRUCT && kind != BTF_UNION) return false;
    *this = tinfo_t();
    is_struct_ = kind == BTF_STRUCT;
    is_union_ = kind == BTF_UNION;
    udt_ = std::make_shared<udt_type_data_t>(udt);
    udt_->is_union = is_union_;
    udt_size_ = udt.total_size;
    for (const auto& member : udt) {
        udt_size_ = std::max(udt_size_,
            static_cast<size_t>((member.offset + member.size + 7) / 8));
    }
    udt_->total_size = udt_size_;
    // IDA's create_udt overload consumes its input, including total_size.
    udt = udt_type_data_t{};
    return true;
}

inline bool tinfo_t::get_udt_details(udt_type_data_t* out) const {
    if (!out || !udt_) return false;
    *out = *udt_;
    return true;
}

inline bool tinfo_t::udt_equals(const tinfo_t& other) const {
    if (static_cast<bool>(udt_) != static_cast<bool>(other.udt_)) return false;
    if (!udt_) return true;
    if (udt_size_ != other.udt_size_ || udt_->size() != other.udt_->size()) return false;
    for (size_t i = 0; i < udt_->size(); ++i) {
        const auto& lhs = (*udt_)[i];
        const auto& rhs = (*other.udt_)[i];
        if (lhs.offset != rhs.offset || lhs.size != rhs.size ||
            !lhs.type.equals_to(rhs.type)) return false;
    }
    return true;
}

// ============================================================================
// Function Type Data
// ============================================================================

struct funcarg_t {
    tinfo_t type;
    qstring name;
};

struct func_type_data_t : public qvector<funcarg_t> {
    tinfo_t rettype;
    int cc = 0;

    void set_cc(int calling_conv) { cc = calling_conv; }
    int get_cc() const { return cc; }
};

struct array_type_data_t {
    std::uint32_t base = 0;
    tinfo_t elem_type;
    size_t nelems = 0;
};

// Inline implementations that depend on func_type_data_t
inline bool tinfo_t::create_func(const func_type_data_t& ftd) {
    const auto signature = std::make_shared<func_type_data_t>(ftd);
    clear();
    is_func_ = true;
    function_ = signature;
    return true;
}

inline bool tinfo_t::get_func_details(func_type_data_t* ftd) const {
    if (!is_func_ || !function_ || !ftd) return false;
    *ftd = *function_;
    return true;
}

inline bool tinfo_t::function_equals(const tinfo_t& other) const {
    if (static_cast<bool>(function_) != static_cast<bool>(other.function_)) {
        return false;
    }
    if (!function_) return true;
    if (function_->cc != other.function_->cc ||
        !function_->rettype.equals_to(other.function_->rettype) ||
        function_->size() != other.function_->size()) {
        return false;
    }
    for (size_t i = 0; i < function_->size(); ++i) {
        if (!function_->at(i).type.equals_to(other.function_->at(i).type)) {
            return false;
        }
    }
    return true;
}

inline bool tinfo_t::get_array_details(array_type_data_t* atd) const {
    if (!is_array_ || !atd) return false;
    if (pointed_type_) {
        atd->elem_type = *pointed_type_;
    }
    atd->nelems = array_count_;
    atd->base = array_base_;
    return true;
}

inline void tinfo_t::create_array(const array_type_data_t& details) {
    create_array(details.elem_type, details.nelems);
    array_base_ = details.base;
}

inline bool get_tinfo(tinfo_t*, ea_t) { return false; }

// ============================================================================
// Hex-Rays Mock Types
// ============================================================================

enum ctype_t {
    cot_empty = 0,
    cot_comma,
    cot_asg,
    cot_asgbor,
    cot_asgxor,
    cot_asgband,
    cot_asgadd,
    cot_asgsub,
    cot_asgmul,
    cot_asgsshr,
    cot_asgushr,
    cot_asgshl,
    cot_asgsdiv,
    cot_asgudiv,
    cot_asgsmod,
    cot_asgumod,
    cot_tern,
    cot_lor,
    cot_land,
    cot_bor,
    cot_xor,
    cot_band,
    cot_eq,
    cot_ne,
    cot_sge,
    cot_uge,
    cot_sle,
    cot_ule,
    cot_sgt,
    cot_ugt,
    cot_slt,
    cot_ult,
    cot_sshr,
    cot_ushr,
    cot_shl,
    cot_add,
    cot_sub,
    cot_mul,
    cot_sdiv,
    cot_udiv,
    cot_smod,
    cot_umod,
    cot_fadd,
    cot_fsub,
    cot_fmul,
    cot_fdiv,
    cot_fneg,
    cot_neg,
    cot_cast,
    cot_lnot,
    cot_bnot,
    cot_ptr,
    cot_ref,
    cot_postinc,
    cot_postdec,
    cot_preinc,
    cot_predec,
    cot_call,
    cot_idx,
    cot_memref,
    cot_memptr,
    cot_num,
    cot_fnum,
    cot_str,
    cot_obj,
    cot_var,
    cot_insn,
    cot_sizeof,
    cot_helper,
    cot_type,
    cit_empty = 1000,
    cit_block,
    cit_expr,
};

struct citem_t;
struct cexpr_t;

struct var_ref_t {
    int idx = -1;
};

// Forward declarations
struct cexpr_t;
struct carglist_t;

// Base class for all c-tree items
struct citem_t {
    ctype_t op = cot_empty;
    ea_t ea = BADADDR;

    bool is_citem() const { return true; }
    bool is_expr() const { return op < cit_empty; }

    cexpr_t* cexpr();
    const cexpr_t* cexpr() const;
};

struct cexpr_t : public citem_t {
    tinfo_t type;
    cexpr_t* x = nullptr;
    cexpr_t* y = nullptr;
    cexpr_t* z = nullptr;
    var_ref_t v;
    sval_t m = 0;  // member offset for memptr
    ea_t obj_ea = BADADDR;  // for cot_obj
    carglist_t* a = nullptr;  // for cot_call
    int ptrsize = 0;

    sval_t numval() const { return num_value_; }
    void set_numval(sval_t val) { num_value_ = val; }

    void print1(qstring* out, void*) const {
        if (!out) return;
        out->sprnt("expr_%d", static_cast<int>(op));
    }

private:
    sval_t num_value_ = 0;
};

struct carglist_t : public qvector<cexpr_t> {};

// Define the cexpr() methods after cexpr_t is complete
inline cexpr_t* citem_t::cexpr() { return static_cast<cexpr_t*>(this); }
inline const cexpr_t* citem_t::cexpr() const { return static_cast<const cexpr_t*>(this); }

struct cblock_t;
struct cinsn_t : public citem_t {
    cinsn_t() { op = cit_empty; }
    cblock_t* cblock = nullptr;
    cexpr_t cexpr;
};
struct cblock_t : public qvector<cinsn_t> {};

struct lvar_locator_t {
    int mock_id = -1;
    ea_t defea = BADADDR;

    bool operator==(const lvar_locator_t&) const = default;
    bool operator<(const lvar_locator_t& other) const {
        return mock_id < other.mock_id ||
            (mock_id == other.mock_id && defea < other.defea);
    }
};

struct lvar_t : public lvar_locator_t {
    qstring name;
    bool is_arg = false;

    tinfo_t type() const { return type_; }
    void set_lvar_type(const tinfo_t& t) { type_ = t; }
    bool is_arg_var() const { return is_arg; }

private:
    tinfo_t type_;
};

struct lvars_t : public qvector<lvar_t> {
    lvar_t* find(const lvar_locator_t& locator) {
        for (auto& var : *this) {
            if (static_cast<const lvar_locator_t&>(var) == locator) {
                return &var;
            }
        }
        return nullptr;
    }
    const lvar_t* find(const lvar_locator_t& locator) const {
        for (const auto& var : *this) {
            if (static_cast<const lvar_locator_t&>(var) == locator) {
                return &var;
            }
        }
        return nullptr;
    }
};

struct cfunc_t {
    ea_t entry_ea = BADADDR;
    cinsn_t body;
    lvars_t lvars;

    lvars_t* get_lvars() { return &lvars; }

    struct pseudocode_t : public qvector<struct simpleline_t> {};
    pseudocode_t pseudo;
    pseudocode_t& get_pseudocode() { return pseudo; }

    void* user_cmts = nullptr;

    bool get_line_item(const char*, int, bool, void*, void*, void*) { return false; }
};

using cfuncptr_t = std::shared_ptr<cfunc_t>;

struct simpleline_t {
    qstring line;
    std::uint32_t bgcolor = 0;
};

// Visitor base classes
class ctree_visitor_t {
public:
    enum { CV_FAST = 0, CV_PARENTS = 1, CV_POST = 2 };

    ctree_visitor_t(int flags = 0) : flags_(flags) {}
    virtual ~ctree_visitor_t() = default;

    virtual int idaapi visit_expr(cexpr_t* e) { return 0; }
    virtual int idaapi leave_expr(cexpr_t* e) { return 0; }
    virtual int idaapi visit_insn(cinsn_t* i) { return 0; }

    int apply_to(citem_t* item, void*) {
        if (!item) return 0;
        struct ParentGuard {
            qvector<citem_t*>& stack;
            bool active;
            ParentGuard(qvector<citem_t*>& parents, citem_t* parent, bool enabled)
                : stack(parents), active(enabled) { if (active) stack.push_back(parent); }
            ~ParentGuard() { if (active) stack.pop_back(); }
        };
        if (item->is_expr()) {
            auto* expression = static_cast<cexpr_t*>(item);
            if (const int result = visit_expr(expression)) return result;
            ParentGuard guard(parents, item, (flags_ & CV_PARENTS) != 0);
            if (const int result = apply_to(expression->x, nullptr)) return result;
            if (const int result = apply_to(expression->y, nullptr)) return result;
            if (const int result = apply_to(expression->z, nullptr)) return result;
            if (expression->op == cot_call && expression->a) {
                for (auto& argument : *expression->a) {
                    if (const int result = apply_to(&argument, nullptr)) return result;
                }
            }
        } else {
            auto* instruction = static_cast<cinsn_t*>(item);
            if (const int result = visit_insn(instruction)) return result;
            ParentGuard guard(parents, item, (flags_ & CV_PARENTS) != 0);
            if (instruction->op == cit_block && instruction->cblock) {
                for (auto& child : *instruction->cblock) {
                    if (const int result = apply_to(&child, nullptr)) return result;
                }
            } else if (instruction->op == cit_expr) {
                return apply_to(&instruction->cexpr, nullptr);
            }
        }
        return 0;
    }

    const cexpr_t* parent_expr() const {
        return parents.empty() || !parents.back()->is_expr() ? nullptr :
            static_cast<const cexpr_t*>(parents.back());
    }

protected:
    int flags_;
    qvector<citem_t*> parents;
};

using hexrays_ctree_visitor_t = ctree_visitor_t;

// ============================================================================
// Mock Functions
// ============================================================================

inline bool inf_is_64bit() { return true; }
inline void msg(const char* fmt, ...) {}
inline void warning(const char* fmt, ...) {}
inline void info(const char* fmt, ...) {}
inline void qfree(void* p) { free(p); }
inline void tag_remove(qstring*) {}

inline int ask_yn(int def, const char* fmt, ...) { return def; }
constexpr int ASKBTN_YES = 1;
constexpr int ASKBTN_NO = 0;

// Structure functions
struct struc_t {
    tid_t id = BADADDR;
    size_t memqty = 0;
};

struct member_t {
    sval_t soff = 0;
};

inline tid_t add_struc(ea_t, const char*) { return 1; }
inline struc_t* get_struc(tid_t tid) {
    static struc_t s;
    s.id = tid;
    return tid != BADADDR ? &s : nullptr;
}
inline bool del_struc(struc_t*) { return true; }
inline tid_t get_struc_id(const char*) { return BADADDR; }
inline int add_struc_member(struc_t*, const char*, sval_t, flags64_t, void*, size_t) { return 0; }
inline bool del_struc_member(struc_t* s, sval_t) { if (s->memqty > 0) s->memqty--; return true; }
inline member_t* get_member(struc_t*, sval_t) { return nullptr; }
inline bool set_member_tinfo(struc_t*, member_t*, int, const tinfo_t&, int) { return true; }
inline bool set_member_cmt(member_t*, const char*, bool) { return true; }
inline void expand_struc(struc_t*, sval_t, size_t) {}
inline void set_struc_align(struc_t*, int) {}
inline bool set_struc_name(tid_t, const char*) { return true; }

constexpr int SET_MEMTI_COMPATIBLE = 0;

// Flag functions
inline flags64_t byte_flag() { return 0; }
inline flags64_t word_flag() { return 0; }
inline flags64_t dword_flag() { return 0; }
inline flags64_t qword_flag() { return 0; }
inline flags64_t off_flag() { return 0; }
inline flags64_t flt_flag() { return 0; }
inline flags64_t dbl_flag() { return 0; }

// Opinfo
struct opinfo_t {
    struct refinfo_t {
        void init(int) {}
    } ri;
};

constexpr int REF_OFF64 = 0;

// Function functions
struct func_t {
    ea_t start_ea = BADADDR;
};

inline func_t* get_func(ea_t ea) {
    static func_t f;
    f.start_ea = ea;
    return ea != BADADDR ? &f : nullptr;
}

inline void get_func_name(qstring* out, ea_t ea) {
    if (out) out->sprnt("func_%llX", static_cast<unsigned long long>(ea));
}

// Hex-Rays functions
struct hexrays_failure_t {};

inline cfuncptr_t decompile(func_t*, hexrays_failure_t*, int) {
    return std::make_shared<cfunc_t>();
}

constexpr int DECOMP_NO_WAIT = 0;

inline bool init_hexrays_plugin() { return true; }

// Netnode mock
class netnode {
public:
    netnode(const char* name, nodeidx_t, bool create) : name_(name ? name : "") {}

    operator nodeidx_t() const { return name_.empty() ? BADNODE : 1; }

    void* getblob(void*, size_t* size, int, nodeidx_t) {
        if (size) *size = 0;
        return nullptr;
    }

    void setblob(const void*, size_t, int, nodeidx_t) {}
    void kill() {}

private:
    std::string name_;
};

// Calling conventions
constexpr int CM_CC_UNKNOWN = 0;
constexpr int CM_CC_FASTCALL = 1;

// Action types
struct action_handler_t {
    virtual int idaapi activate(struct action_activation_ctx_t*) = 0;
    virtual int idaapi update(struct action_update_ctx_t*) = 0;
    virtual ~action_handler_t() = default;
};

struct action_activation_ctx_t {
    void* widget = nullptr;
};

struct action_update_ctx_t {
    void* widget = nullptr;
};

enum action_state_t { AST_ENABLE, AST_DISABLE };

struct action_desc_t {};

#define ACTION_DESC_LITERAL(name, label, handler, hotkey, tooltip, icon) action_desc_t{}

inline bool mock_register_action_result = true;
inline bool mock_unregister_action_result = true;
inline int mock_registered_action_count = 0;
inline bool register_action(const action_desc_t&) {
    if (!mock_register_action_result) return false;
    ++mock_registered_action_count;
    return true;
}
inline bool unregister_action(const char*) {
    if (!mock_unregister_action_result || mock_registered_action_count <= 0) {
        return false;
    }
    --mock_registered_action_count;
    return true;
}
inline bool attach_action_to_popup(void*, void*, const char*) { return true; }

// Widget/view types
using TWidget = void;
using TPopupMenu = void;

struct vdui_t {
    cfunc_t* cfunc = nullptr;

    struct item_t {
        citem_t* it = nullptr;
        bool is_citem() const { return it != nullptr; }
        const cexpr_t* e = nullptr;
    } item;

    void refresh_view(bool) {}
};

inline vdui_t* get_widget_vdui(void*) { return nullptr; }
inline void* get_current_widget() { return nullptr; }

// Hexrays callbacks
enum hexrays_event_t { hxe_populating_popup, hxe_double_click };

using hexrays_cb_t = ssize_t idaapi(void*, hexrays_event_t, va_list);
inline bool mock_install_hexrays_callback_result = true;
inline int mock_remove_hexrays_callback_result = 1;
inline int mock_installed_hexrays_callback_count = 0;
inline bool install_hexrays_callback(hexrays_cb_t*, void*) {
    if (!mock_install_hexrays_callback_result) return false;
    ++mock_installed_hexrays_callback_count;
    return true;
}
inline int remove_hexrays_callback(hexrays_cb_t*, void*) {
    if (mock_remove_hexrays_callback_result <= 0 ||
        mock_installed_hexrays_callback_count <= 0) {
        return mock_remove_hexrays_callback_result;
    }
    --mock_installed_hexrays_callback_count;
    return mock_remove_hexrays_callback_result;
}

// User comments
struct treeloc_t {
    ea_t ea = BADADDR;
    int itp = 0;
};

constexpr int ITP_BLOCK1 = 0;

struct citem_cmt_t {
    void set(const qstring&) {}
};

struct user_cmts_t : public std::map<treeloc_t, citem_cmt_t> {};

inline user_cmts_t* user_cmts_new() { return new user_cmts_t(); }
inline void save_user_cmts(ea_t, user_cmts_t*) {}

// Xref
struct xrefblk_t {
    ea_t from = BADADDR;
    ea_t to = BADADDR;
    bool iscode = false;
    int type = 0;

    bool first_to(ea_t, int) { return false; }
    bool next_to() { return false; }
    bool first_from(ea_t, int) { return false; }
    bool next_from() { return false; }
};

constexpr int XREF_FAR = 0;
constexpr int XREF_ALL = 0;
constexpr int fl_CN = 1;
constexpr int fl_CF = 2;
constexpr int fl_JN = 3;
constexpr int fl_JF = 4;

// func_item_iterator
struct func_item_iterator_t {
    bool set(func_t*) { return false; }
    bool next_code() { return false; }
    ea_t current() { return BADADDR; }
};

// Local var functions
struct lvar_saved_info_t {
    lvar_t ll;
    tinfo_t type;
};

constexpr int MLI_TYPE = 1;

inline bool modify_user_lvar_info(ea_t, int, const lvar_saved_info_t&) { return true; }

// Structures window
inline void open_structs_window(tid_t) {}

// Alignment
inline int compute_alignment(int a) { return a; }

// Plugin types
struct plugmod_t {
    virtual ~plugmod_t() = default;
    virtual bool idaapi run(size_t) = 0;
};

struct plugin_t {
    int version;
    int flags;
    plugmod_t* (*init)();
    void (*term)(void);
    bool (*run)(size_t);
    const char* comment;
    const char* help;
    const char* wanted_name;
    const char* wanted_hotkey;
};

constexpr int IDP_INTERFACE_VERSION = 700;
constexpr int PLUGIN_MULTI = 0;
constexpr int IDAAPI = 0;

// Less-than for treeloc_t
inline bool operator<(const treeloc_t& a, const treeloc_t& b) {
    if (a.ea != b.ea) return a.ea < b.ea;
    return a.itp < b.itp;
}
