#pragma once

/// @file mock_ida.hpp
/// @brief Mock IDA SDK types and functions for unit testing

#include <cstdint>
#include <string>
#include <vector>
#include <map>
#include <memory>
#include <functional>
#include <algorithm>
#include <cstring>

// Define testing macro
#define STRUCTOR_TESTING

// ============================================================================
// Basic IDA Types
// ============================================================================

using ea_t = std::uint64_t;
using tid_t = std::uint64_t;
using sval_t = std::int64_t;
using uval_t = std::uint64_t;
using flags64_t = std::uint64_t;
using nodeidx_t = std::uint64_t;

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
    BT_INT8     = BTF_INT8,
    BTMT_CHAR   = 0x1000,
};

class tinfo_t {
public:
    tinfo_t() = default;

    bool empty() const { return type_flags_ == 0 && !is_ptr_ && !is_array_; }
    void clear() { type_flags_ = 0; is_ptr_ = false; is_array_ = false; pointed_size_ = 0; }

    void create_simple_type(std::uint32_t bt) { type_flags_ = bt; is_ptr_ = false; }
    void create_ptr(const tinfo_t& pointed) {
        is_ptr_ = true;
        pointed_type_ = std::make_shared<tinfo_t>(pointed);
    }
    void create_array(const tinfo_t& elem, size_t count) {
        is_array_ = true;
        array_count_ = count;
        pointed_type_ = std::make_shared<tinfo_t>(elem);
    }
    bool create_func(const struct func_type_data_t& ftd) { is_func_ = true; return true; }

    bool is_ptr() const { return is_ptr_; }
    bool is_funcptr() const { return is_ptr_ && is_func_; }
    bool is_floating() const { return type_flags_ & (BTF_FLOAT | BTF_DOUBLE); }
    bool is_struct() const { return is_struct_; }
    bool is_array() const { return is_array_; }

    size_t get_size() const {
        if (is_ptr_) return 8;  // Assume 64-bit
        if (is_array_) return array_count_ * (pointed_type_ ? pointed_type_->get_size() : 1);
        if (type_flags_ & (BTF_INT8 | BTF_UINT8)) return 1;
        if (type_flags_ & (BTF_INT16 | BTF_UINT16)) return 2;
        if (type_flags_ & (BTF_INT32 | BTF_UINT32 | BTF_FLOAT)) return 4;
        if (type_flags_ & (BTF_INT64 | BTF_UINT64 | BTF_DOUBLE)) return 8;
        return BADSIZE;
    }

    bool get_pointed_object(tinfo_t* out) const {
        if (!is_ptr_ || !pointed_type_) return false;
        *out = *pointed_type_;
        return true;
    }

    bool get_type_by_tid(tid_t tid) { return tid != BADADDR; }
    bool get_named_type(void*, const char* name) { return name != nullptr; }

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
    size_t array_count_ = 0;
    std::shared_ptr<tinfo_t> pointed_type_;
    size_t pointed_size_ = 0;
};

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
};

// ============================================================================
// Hex-Rays Mock Types
// ============================================================================

enum ctype_t {
    cot_empty = 0,
    cot_var,
    cot_num,
    cot_ptr,
    cot_memptr,
    cot_memref,
    cot_idx,
    cot_add,
    cot_sub,
    cot_mul,
    cot_cast,
    cot_ref,
    cot_call,
    cot_obj,
    cot_helper,
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
    cot_preinc,
    cot_predec,
    cot_postinc,
    cot_postdec,
    cot_fadd,
    cot_fsub,
    cot_fmul,
    cot_fdiv,
    cot_ult,
    cot_ule,
    cot_ugt,
    cot_uge,
};

struct citem_t;
struct cexpr_t;

struct var_ref_t {
    int idx = -1;
};

struct carglist_t : public qvector<cexpr_t*> {};

struct cexpr_t {
    ctype_t op = cot_empty;
    ea_t ea = BADADDR;
    tinfo_t type;
    cexpr_t* x = nullptr;
    cexpr_t* y = nullptr;
    var_ref_t v;
    sval_t m = 0;  // member offset for memptr
    ea_t obj_ea = BADADDR;  // for cot_obj
    carglist_t* a = nullptr;  // for cot_call

    sval_t numval() const { return num_value_; }
    void set_numval(sval_t val) { num_value_ = val; }

    bool is_expr() const { return true; }

    void print1(qstring* out, void*) const {
        if (!out) return;
        out->sprnt("expr_%d", static_cast<int>(op));
    }

private:
    sval_t num_value_ = 0;
};

struct citem_t {
    ctype_t op = cot_empty;
    ea_t ea = BADADDR;

    bool is_citem() const { return true; }
    bool is_expr() const { return true; }

    cexpr_t* cexpr() { return reinterpret_cast<cexpr_t*>(this); }
    const cexpr_t* cexpr() const { return reinterpret_cast<const cexpr_t*>(this); }
};

struct cinsn_t : public citem_t {};

struct lvar_t {
    qstring name;
    bool is_arg = false;

    tinfo_t type() const { return type_; }
    void set_lvar_type(const tinfo_t& t) { type_ = t; }
    bool is_arg_var() const { return is_arg; }

private:
    tinfo_t type_;
};

struct lvars_t : public qvector<lvar_t> {};

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
    virtual int idaapi visit_insn(cinsn_t* i) { return 0; }

    int apply_to(citem_t* item, void*) {
        if (!item) return 0;
        if (item->is_expr()) {
            return visit_expr(static_cast<cexpr_t*>(item));
        }
        return 0;
    }

    const cexpr_t* parent_expr() const {
        return parents.empty() ? nullptr : static_cast<const cexpr_t*>(parents.back());
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

inline bool register_action(const action_desc_t&) { return true; }
inline void unregister_action(const char*) {}
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

inline bool install_hexrays_callback(void* (*)(void*, hexrays_event_t, va_list), void*) { return true; }
inline void remove_hexrays_callback(void* (*)(void*, hexrays_event_t, va_list), void*) {}

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
constexpr int fl_CN = 1;
constexpr int fl_CF = 2;

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

#define idaapi
