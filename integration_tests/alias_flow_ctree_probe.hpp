#pragma once

// Include only from a live-test hook. These trees intentionally preserve alias
// assignments that ordinary C fixtures lose during decompiler optimization.
#if !defined(STRUCTOR_LIVE_TEST_HOOKS)
#error "Alias-flow ctree probes require STRUCTOR_LIVE_TEST_HOOKS"
#endif

#include "structor/access_collector.hpp"

#include <array>
#include <functional>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>
#include <set>

namespace structor::testing {

struct AliasFlowObservation {
    std::string name;
    // True means the case expects one or more 4-byte accesses through base.
    // The case table supplies their exact offsets independently of collection.
    bool expects_base_access = false;
    bool matches_expected = false;
    bool original_body_restored = false;
    AccessPattern pattern;
    std::string error;
};

namespace alias_flow_detail {

using Expression = std::unique_ptr<cexpr_t>;
using Statement = std::unique_ptr<cinsn_t>;

// No lvars, types, saved user data, maturity, or cfunc caches are changed.
// Swap restores the original body on both success and exception unwinding.
class ScopedBodySwap {
public:
    ScopedBodySwap(cfunc_t& owner, cinsn_t& replacement)
        : owner_(owner), replacement_(replacement) {
        owner_.body.swap(replacement_);
    }
    ~ScopedBodySwap() noexcept { owner_.body.swap(replacement_); }
    ScopedBodySwap(const ScopedBodySwap&) = delete;
    ScopedBodySwap& operator=(const ScopedBodySwap&) = delete;

private:
    cfunc_t& owner_;
    cinsn_t& replacement_;
};

class Builder {
public:
    Builder(cfunc_t& owner, const std::array<int, 4>& arguments)
        : owner_(owner), arguments_(arguments) {}

    Expression variable(size_t argument) const {
        auto expression = std::make_unique<cexpr_t>(cot_var, nullptr);
        expression->v.mba = owner_.mba;
        expression->v.idx = arguments_.at(argument);
        expression->type = owner_.get_lvars()->at(expression->v.idx).type();
        expression->ea = owner_.entry_ea;
        return expression;
    }

    Expression number(uint64 value, type_sign_t sign = type_unsigned) const {
        auto expression = std::make_unique<cexpr_t>();
        expression->put_number(&owner_, value, 4, sign);
        expression->ea = owner_.entry_ea;
        return expression;
    }

    Expression number64(uint64 value, type_sign_t sign = type_unsigned) const {
        auto expression = std::make_unique<cexpr_t>();
        expression->put_number(&owner_, value, 8, sign);
        expression->ea = owner_.entry_ea;
        return expression;
    }

    Expression binary(ctype_t opcode, Expression lhs, Expression rhs,
                      const tinfo_t& type) const {
        auto expression = std::make_unique<cexpr_t>(opcode, nullptr);
        expression->x = lhs.release();
        expression->y = rhs.release();
        expression->type = type;
        expression->ea = owner_.entry_ea;
        return expression;
    }

    Expression unary(ctype_t opcode, Expression operand, const tinfo_t& type) const {
        auto expression = std::make_unique<cexpr_t>(opcode, nullptr);
        expression->x = operand.release();
        expression->type = type;
        expression->ea = owner_.entry_ea;
        return expression;
    }

    Statement block() const {
        auto statement = std::make_unique<cinsn_t>();
        statement->op = cit_block;
        statement->cblock = new cblock_t;
        statement->ea = owner_.entry_ea;
        return statement;
    }

    void append(cinsn_t& block, Statement child) const {
        block.new_insn(owner_.entry_ea).swap(*child);
    }

    Statement expression(Expression value) const {
        auto statement = std::make_unique<cinsn_t>();
        statement->op = cit_expr;
        statement->cexpr = value.release();
        statement->ea = owner_.entry_ea;
        return statement;
    }

    Statement assign_alias(size_t source_argument) const {
        auto lhs = variable(2);
        const tinfo_t type = lhs->type;
        return expression(binary(cot_asg, std::move(lhs),
                                 unary(cot_cast, variable(source_argument), type), type));
    }

    Statement assign_value(size_t argument, Expression value) const {
        auto lhs = variable(argument);
        const tinfo_t type = lhs->type;
        return expression(binary(cot_asg, std::move(lhs), unary(cot_cast, std::move(value), type), type));
    }

    Expression alias_update(ctype_t opcode, Expression value = {}) const {
        auto alias = variable(2);
        const tinfo_t type = alias->type;
        return value ? binary(opcode, std::move(alias), std::move(value), type)
                     : unary(opcode, std::move(alias), type);
    }

    Statement assign_alias_offset(size_t source_argument, uint64 offset) const {
        auto lhs = variable(2);
        const tinfo_t type = lhs->type;
        tinfo_t byte, pointer;
        byte.create_simple_type(BTF_UINT8);
        pointer.create_ptr(byte);
        auto address = binary(cot_add, unary(cot_cast, variable(source_argument), pointer),
                              number(offset), pointer);
        return expression(binary(cot_asg, std::move(lhs), unary(cot_cast, std::move(address), type), type));
    }

    Statement assign_flag(uint64 value) const {
        return assign_flag_value(number(value));
    }

    Statement assign_flag_value(Expression value, ctype_t opcode = cot_asg) const {
        auto lhs = variable(3);
        const tinfo_t type = lhs->type;
        return expression(binary(opcode, std::move(lhs), std::move(value), type));
    }

    Statement load_alias(Expression pointer_value = {}) const {
        tinfo_t byte;
        byte.create_simple_type(BTF_UINT8);
        tinfo_t byte_pointer;
        byte_pointer.create_ptr(byte);
        auto byte_address = unary(cot_cast, pointer_value ? std::move(pointer_value) : variable(2), byte_pointer);
        auto address = binary(cot_add, std::move(byte_address), number(4), byte_pointer);
        tinfo_t word;
        word.create_simple_type(BTF_UINT32);
        tinfo_t word_pointer;
        word_pointer.create_ptr(word);
        auto cast = unary(cot_cast, std::move(address), word_pointer);
        auto load = unary(cot_ptr, std::move(cast), word);
        load->ptrsize = 4;
        return expression(std::move(load));
    }

    Expression flag_condition(ctype_t relation = cot_ne, uint64 value = 0) const {
        tinfo_t boolean;
        boolean.create_simple_type(BTF_BOOL);
        return binary(relation, variable(3), number(value, type_signed), boolean);
    }

    Statement branch(Statement then_body, Statement else_body = {},
                     ctype_t relation = cot_ne, uint64 value = 0) const {
        auto statement = std::make_unique<cinsn_t>();
        statement->op = cit_if;
        statement->cif = new cif_t;
        statement->cif->expr.swap(*flag_condition(relation, value));
        statement->cif->ithen = then_body.release();
        statement->cif->ielse = else_body.release();
        statement->ea = owner_.entry_ea;
        return statement;
    }

    Statement while_loop(Statement body) const {
        auto statement = std::make_unique<cinsn_t>();
        statement->op = cit_while;
        statement->cwhile = new cwhile_t;
        statement->cwhile->expr.swap(*flag_condition(cot_sgt));
        statement->cwhile->body = body.release();
        statement->ea = owner_.entry_ea;
        return statement;
    }

    Statement do_loop(Statement body) const {
        auto statement = std::make_unique<cinsn_t>();
        statement->op = cit_do;
        statement->cdo = new cdo_t;
        statement->cdo->expr.swap(*flag_condition(cot_sgt));
        statement->cdo->body = body.release();
        statement->ea = owner_.entry_ea;
        return statement;
    }

    Statement terminal(ctype_t opcode) const {
        auto statement = std::make_unique<cinsn_t>();
        statement->op = opcode;
        statement->ea = owner_.entry_ea;
        return statement;
    }

    Statement jump(int label) const {
        auto statement = terminal(cit_goto);
        statement->cgoto = new cgoto_t;
        statement->cgoto->label_num = label;
        return statement;
    }

    Statement switch_pair(Statement first, Statement second, bool default_second = false) const {
        auto statement = terminal(cit_switch);
        statement->cswitch = new cswitch_t;
        statement->cswitch->expr.swap(*variable(3));
        statement->cswitch->cases.resize(2);
        statement->cswitch->cases[0].swap(*first);
        statement->cswitch->cases[0].values.push_back(1);
        statement->cswitch->cases[1].swap(*second);
        if (!default_second) statement->cswitch->cases[1].values.push_back(0);
        return statement;
    }

    Statement cleanup(Statement body, Statement finalizer, bool wind = false) const {
        auto statement = terminal(cit_try);
        statement->ctry = new ctry_t;
        static_cast<cblock_t*>(statement->ctry)->swap(*body->cblock);
        statement->ctry->catchs.resize(1);
        auto& handler = statement->ctry->catchs[0];
#ifdef CTRY_WIND
        handler.convert_to_finally();
        if (wind) statement->ctry->flags |= CTRY_WIND;
#else
        // Pinned legacy SDKs encode wind cleanup as a catch-all handler and
        // cannot represent a normal finally block. A live request for the
        // latter must report its unsupported setup instead of testing a
        // different control-flow construct under the same case name.
        if (!wind) throw std::runtime_error("SDK has no normal-finally ctree representation");
        statement->ctry->is_wind = true;
#endif
        static_cast<cblock_t&>(handler).swap(*finalizer->cblock);
        return statement;
    }

    Statement conditional_alias(bool expression_only = false, size_t assignment_source = 0) const {
        auto temporary = variable(2);
        const tinfo_t type = temporary->type;
        auto conditional = std::make_unique<cexpr_t>(cot_tern, nullptr);
        conditional->x = flag_condition().release();
        conditional->type = type;
        conditional->ea = owner_.entry_ea;
        if (expression_only) {
            conditional->y = binary(cot_asg, std::move(temporary),
                unary(cot_cast, variable(assignment_source), type), type).release();
            auto load = load_alias();
            conditional->z = unary(cot_cast, Expression(load->cexpr), type).release();
            load->cexpr = nullptr;
            load->op = cit_empty;
            return expression(std::move(conditional));
        }
        conditional->y = unary(cot_cast, variable(0), type).release();
        conditional->z = unary(cot_cast, variable(1), type).release();
        return expression(binary(cot_asg, std::move(temporary), std::move(conditional), type));
    }

    Statement short_circuit_alias() const {
        auto temporary = variable(2);
        const tinfo_t type = temporary->type;
        tinfo_t boolean;
        boolean.create_simple_type(BTF_BOOL);
        return expression(binary(cot_land, flag_condition(),
            binary(cot_asg, std::move(temporary), unary(cot_cast, variable(0), type), type), boolean));
    }

    Statement decrement_flag() const {
        auto flag = variable(3);
        const tinfo_t type = flag->type;
        return expression(unary(cot_predec, std::move(flag), type));
    }

    Statement return_zero() const {
        auto statement = std::make_unique<cinsn_t>();
        statement->op = cit_return;
        statement->creturn = new creturn_t;
        statement->creturn->expr.put_number(&owner_, 0, get_ptr_size(), type_unsigned);
        statement->ea = owner_.entry_ea;
        return statement;
    }

private:
    cfunc_t& owner_;
    const std::array<int, 4>& arguments_;
};

} // namespace alias_flow_detail

// Carrier contract: four distinct, actual argument locals. Arguments 0, 1,
// and 2 hold pointer-width values (base, other, temporary); temporary may be
// either an integer address or a pointer to 2-byte elements. Argument 3 is a
// 32-bit integer flag. The original carrier body must be a block statement.
// Evidence is collected from real SDK ctree objects by the production visitor.
// A mismatch is an observation, not a probe infrastructure failure.
inline std::vector<AliasFlowObservation> probe_alias_flow_ctree(
        cfunc_t* cfunc, const FlowAnalysisOptions& flow = {}, const char* selected_case = nullptr) {
    using namespace alias_flow_detail;
    if (!cfunc || !cfunc->mba || !cfunc->get_lvars() ||
        cfunc->body.op != cit_block || cfunc->argidx.size() != 4) {
        throw std::invalid_argument("alias probe requires a four-argument carrier cfunc");
    }
    std::array<int, 4> arguments{};
    for (size_t i = 0; i < arguments.size(); ++i) {
        arguments[i] = cfunc->argidx[i];
        if (arguments[i] < 0 ||
            static_cast<size_t>(arguments[i]) >= cfunc->get_lvars()->size()) {
            throw std::invalid_argument("alias carrier has an invalid argument lvar");
        }
        const size_t expected_width = i == 3 ? 4 : get_ptr_size();
        const tinfo_t& type = cfunc->get_lvars()->at(arguments[i]).type();
        if ((!type.is_integral() && !(i == 2 && type.is_ptr() &&
             type.get_pointed_object().get_size() == 2)) || type.get_size() != expected_width) {
            throw std::invalid_argument("alias carrier argument has an unexpected width");
        }
        if (i == 1 &&
            !type.equals_to(cfunc->get_lvars()->at(arguments[0]).type())) {
            throw std::invalid_argument("alias carrier pointer-width argument types differ");
        }
        for (size_t j = 0; j < i; ++j) {
            if (arguments[j] == arguments[i]) {
                throw std::invalid_argument("alias carrier arguments must be distinct");
            }
        }
    }

    Builder builder(*cfunc, arguments);
    const tinfo_t& alias_type = cfunc->get_lvars()->at(arguments[2]).type();
    const sval_t update_scale = alias_type.is_ptr() ? 2 : 1;
    struct Case {
        const char* name;
        bool expects_access;
        std::function<Statement()> make_body;
        std::set<sval_t> expected_offsets{4};
    };
    const std::vector<Case> cases{
        {"direct_alias_positive", true, [&] {
            auto body = builder.block();
            builder.append(*body, builder.assign_alias(0));
            builder.append(*body, builder.load_alias());
            return body;
        }},
        {"sibling_alias_contamination_negative", false, [&] {
            auto body = builder.block();
            builder.append(*body, builder.assign_alias(1));
            builder.append(*body, builder.branch(builder.assign_alias(0), builder.load_alias()));
            return body;
        }},
        {"sibling_incoming_alias_positive", true, [&] {
            auto body = builder.block();
            builder.append(*body, builder.assign_alias(0));
            builder.append(*body, builder.branch(builder.assign_alias(1), builder.load_alias()));
            return body;
        }},
        {"merge_possible_alias_positive", true, [&] {
            auto body = builder.block();
            builder.append(*body, builder.assign_alias(1));
            builder.append(*body, builder.branch(builder.assign_alias(0), builder.assign_alias(1)));
            builder.append(*body, builder.load_alias());
            return body;
        }},
        {"merge_identical_alias_positive", true, [&] {
            auto body = builder.block();
            builder.append(*body, builder.assign_alias(1));
            builder.append(*body, builder.branch(builder.assign_alias(0), builder.assign_alias(0)));
            builder.append(*body, builder.load_alias());
            return body;
        }},
        {"loop_carried_alias_positive", true, [&] {
            // With flag=2, the second iteration reads base + 4. A single
            // lexical pass misses that back-edge definition.
            auto body = builder.block();
            builder.append(*body, builder.assign_alias(1));
            auto loop_body = builder.block();
            builder.append(*loop_body, builder.load_alias());
            builder.append(*loop_body, builder.assign_alias(0));
            builder.append(*loop_body, builder.decrement_flag());
            builder.append(*body, builder.while_loop(std::move(loop_body)));
            return body;
        }},
        {"divergent_offset_join_positive", true, [&] {
            auto body = builder.block();
            builder.append(*body, builder.branch(builder.assign_alias_offset(0, 4), builder.assign_alias_offset(0, 8)));
            builder.append(*body, builder.load_alias());
            return body;
        }, {8, 12}},
        {"identical_offset_join_positive", true, [&] {
            auto body = builder.block();
            builder.append(*body, builder.branch(builder.assign_alias_offset(0, 8), builder.assign_alias_offset(0, 8)));
            builder.append(*body, builder.load_alias());
            return body;
        }, {12}},
        {"complementary_condition_negative", false, [&] {
            auto body = builder.block();
            builder.append(*body, builder.assign_alias(1));
            builder.append(*body, builder.branch(builder.assign_alias(0)));
            builder.append(*body, builder.branch(builder.load_alias(), {}, cot_eq));
            return body;
        }},
        {"condition_reassignment_positive", true, [&] {
            auto body = builder.block();
            builder.append(*body, builder.assign_alias(1));
            builder.append(*body, builder.branch(builder.assign_alias(0)));
            builder.append(*body, builder.assign_flag(0));
            builder.append(*body, builder.branch(builder.load_alias(), {}, cot_eq));
            return body;
        }},
        {"distinct_branch_epochs_positive", true, [&] {
            auto body = builder.block();
            auto yes = builder.block();
            builder.append(*yes, builder.assign_alias(0));
            builder.append(*yes, builder.assign_flag(0));
            auto no = builder.block();
            builder.append(*no, builder.assign_alias(1));
            builder.append(*no, builder.assign_flag(1));
            builder.append(*body, builder.branch(std::move(yes), std::move(no)));
            builder.append(*body, builder.branch(builder.load_alias(), {}, cot_eq));
            return body;
        }},
        {"distinct_branch_epochs_negative", false, [&] {
            auto body = builder.block();
            auto yes = builder.block();
            builder.append(*yes, builder.assign_alias(0));
            builder.append(*yes, builder.assign_flag(0));
            auto no = builder.block();
            builder.append(*no, builder.assign_alias(1));
            builder.append(*no, builder.assign_flag(1));
            builder.append(*body, builder.branch(std::move(yes), std::move(no)));
            builder.append(*body, builder.branch(builder.load_alias(), {}, cot_eq, 1));
            return body;
        }},
        {"same_branch_reassignment_kills_alias", false, [&] {
            auto body = builder.block();
            builder.append(*body, builder.assign_alias(0));
            auto yes = builder.block();
            builder.append(*yes, builder.assign_alias(1));
            builder.append(*yes, builder.load_alias());
            builder.append(*body, builder.branch(std::move(yes)));
            return body;
        }},
        {"returning_branch_contamination_negative", false, [&] {
            auto body = builder.block();
            builder.append(*body, builder.assign_alias(1));
            auto yes = builder.block();
            builder.append(*yes, builder.assign_alias(0));
            builder.append(*yes, builder.return_zero());
            builder.append(*body, builder.branch(std::move(yes)));
            builder.append(*body, builder.load_alias());
            return body;
        }},
        {"returning_branch_incoming_positive", true, [&] {
            auto body = builder.block();
            builder.append(*body, builder.assign_alias(0));
            auto yes = builder.block();
            builder.append(*yes, builder.assign_alias(1));
            builder.append(*yes, builder.return_zero());
            builder.append(*body, builder.branch(std::move(yes)));
            builder.append(*body, builder.load_alias());
            return body;
        }},
        {"conditional_expression_join_positive", true, [&] {
            auto body = builder.block();
            builder.append(*body, builder.conditional_alias());
            builder.append(*body, builder.load_alias());
            return body;
        }},
        {"conditional_expression_sibling_negative", false, [&] {
            auto body = builder.block();
            builder.append(*body, builder.assign_alias(1));
            builder.append(*body, builder.conditional_alias(true));
            return body;
        }},
        {"conditional_expression_incoming_positive", true, [&] {
            auto body = builder.block();
            builder.append(*body, builder.assign_alias(0));
            builder.append(*body, builder.conditional_alias(true, 1));
            return body;
        }},
        {"short_circuit_complement_negative", false, [&] {
            auto body = builder.block();
            builder.append(*body, builder.assign_alias(1));
            builder.append(*body, builder.short_circuit_alias());
            builder.append(*body, builder.branch(builder.load_alias(), {}, cot_eq));
            return body;
        }},
        {"loop_zero_iteration_incoming_positive", true, [&] {
            auto body = builder.block();
            builder.append(*body, builder.assign_alias(0));
            auto repeated = builder.block();
            builder.append(*repeated, builder.assign_alias(1));
            builder.append(*repeated, builder.decrement_flag());
            builder.append(*body, builder.while_loop(std::move(repeated)));
            builder.append(*body, builder.load_alias());
            return body;
        }},
        {"nonterminating_branch_has_no_exit_alias", false, [&] {
            auto body = builder.block();
            builder.append(*body, builder.assign_alias(1));
            builder.append(*body, builder.while_loop(builder.assign_alias(0)));
            builder.append(*body, builder.load_alias());
            return body;
        }},
        {"loop_constant_write_prevents_backedge", false, [&] {
            auto body = builder.block();
            builder.append(*body, builder.assign_alias(1));
            auto repeated = builder.block();
            builder.append(*repeated, builder.load_alias());
            builder.append(*repeated, builder.assign_alias(0));
            builder.append(*repeated, builder.assign_flag(0));
            builder.append(*body, builder.while_loop(std::move(repeated)));
            return body;
        }},
        {"loop_known_counter_prevents_backedge", false, [&] {
            auto body = builder.block();
            builder.append(*body, builder.assign_alias(1));
            builder.append(*body, builder.assign_flag(1));
            auto repeated = builder.block();
            builder.append(*repeated, builder.load_alias());
            builder.append(*repeated, builder.assign_alias(0));
            builder.append(*repeated, builder.decrement_flag());
            builder.append(*body, builder.while_loop(std::move(repeated)));
            return body;
        }},
        {"loop_compound_counter_prevents_backedge", false, [&] {
            auto body = builder.block();
            builder.append(*body, builder.assign_alias(1));
            builder.append(*body, builder.assign_flag(1));
            auto repeated = builder.block();
            builder.append(*repeated, builder.load_alias());
            builder.append(*repeated, builder.assign_alias(0));
            builder.append(*repeated, builder.assign_flag_value(builder.number(1), cot_asgsub));
            builder.append(*body, builder.while_loop(std::move(repeated)));
            return body;
        }},
        {"scalar_truncation_zero_positive", true, [&] {
            auto body = builder.block();
            builder.append(*body, builder.assign_alias(0));
            tinfo_t byte;
            byte.create_simple_type(BTF_UINT8);
            builder.append(*body, builder.assign_flag_value(builder.unary(cot_cast, builder.number(256), byte)));
            builder.append(*body, builder.branch(builder.load_alias(), {}, cot_eq));
            return body;
        }},
        {"scalar_truncation_nonzero_negative", false, [&] {
            auto body = builder.block();
            builder.append(*body, builder.assign_alias(0));
            tinfo_t byte;
            byte.create_simple_type(BTF_UINT8);
            builder.append(*body, builder.assign_flag_value(builder.unary(cot_cast, builder.number(256), byte)));
            builder.append(*body, builder.branch(builder.load_alias()));
            return body;
        }},
        {"scalar_arithmetic_zero_positive", true, [&] {
            auto body = builder.block();
            builder.append(*body, builder.assign_alias(0));
            builder.append(*body, builder.assign_flag(1));
            const tinfo_t type = builder.variable(3)->type;
            builder.append(*body, builder.assign_flag_value(builder.binary(cot_sub, builder.variable(3), builder.number(1), type)));
            builder.append(*body, builder.branch(builder.load_alias(), {}, cot_eq));
            return body;
        }},
        {"signed_operator_high_bit_negative", false, [&] {
            auto body = builder.block();
            builder.append(*body, builder.assign_alias(0));
            builder.append(*body, builder.assign_flag(UINT64_C(0x80000000)));
            builder.append(*body, builder.branch(builder.load_alias(), {}, cot_sgt));
            return body;
        }},
        {"unsigned_operator_high_bit_positive", true, [&] {
            auto body = builder.block();
            builder.append(*body, builder.assign_alias(0));
            builder.append(*body, builder.assign_flag(UINT64_C(0x80000000)));
            builder.append(*body, builder.branch(builder.load_alias(), {}, cot_ugt));
            return body;
        }},
        {"loop_break_preserves_reaching_alias", true, [&] {
            auto body = builder.block();
            builder.append(*body, builder.assign_alias(1));
            auto repeated = builder.block();
            builder.append(*repeated, builder.assign_alias(0));
            builder.append(*repeated, builder.terminal(cit_break));
            builder.append(*body, builder.while_loop(std::move(repeated)));
            builder.append(*body, builder.load_alias());
            return body;
        }},
        {"loop_continue_skips_alias_definition", false, [&] {
            auto body = builder.block();
            builder.append(*body, builder.assign_alias(1));
            auto repeated = builder.block();
            builder.append(*repeated, builder.decrement_flag());
            builder.append(*repeated, builder.terminal(cit_continue));
            builder.append(*repeated, builder.assign_alias(0));
            builder.append(*body, builder.while_loop(std::move(repeated)));
            builder.append(*body, builder.load_alias());
            return body;
        }},
        {"do_loop_first_body_positive", true, [&] {
            auto body = builder.block();
            builder.append(*body, builder.assign_alias(0));
            auto repeated = builder.block();
            builder.append(*repeated, builder.load_alias());
            builder.append(*repeated, builder.assign_alias(1));
            builder.append(*repeated, builder.assign_flag(0));
            builder.append(*body, builder.do_loop(std::move(repeated)));
            return body;
        }},
        {"do_loop_exit_definition_positive", true, [&] {
            auto body = builder.block();
            builder.append(*body, builder.assign_alias(1));
            auto repeated = builder.block();
            builder.append(*repeated, builder.assign_alias(0));
            builder.append(*repeated, builder.assign_flag(0));
            builder.append(*body, builder.do_loop(std::move(repeated)));
            builder.append(*body, builder.load_alias());
            return body;
        }},
        {"loop_offset_widening_avoids_truncated_array", true, [&] {
            auto body = builder.block();
            builder.append(*body, builder.assign_alias(0));
            auto repeated = builder.block();
            builder.append(*repeated, builder.load_alias());
            builder.append(*repeated, builder.assign_alias_offset(2, 4));
            builder.append(*repeated, builder.decrement_flag());
            builder.append(*body, builder.while_loop(std::move(repeated)));
            return body;
        }},
        {"branch_overflow_forgets_offsets", false, [&] {
            auto body = builder.block();
            auto chain = builder.assign_alias(1);
            for (unsigned i = 0; i < 18; ++i) {
                chain = builder.branch(builder.assign_alias_offset(0, i * 4), std::move(chain), cot_eq, i);
            }
            builder.append(*body, std::move(chain));
            builder.append(*body, builder.load_alias());
            return body;
        }},
        {"branch_overflow_strong_definition_recovers", true, [&] {
            auto body = builder.block();
            auto chain = builder.assign_alias(1);
            for (unsigned i = 0; i < 18; ++i) {
                chain = builder.branch(builder.assign_alias_offset(0, i * 4), std::move(chain), cot_eq, i);
            }
            builder.append(*body, std::move(chain));
            builder.append(*body, builder.assign_alias(0));
            builder.append(*body, builder.load_alias());
            return body;
        }},
        {"switch_break_isolates_sibling_alias", false, [&] {
            auto body = builder.block();
            builder.append(*body, builder.assign_alias(1));
            auto first = builder.block();
            builder.append(*first, builder.assign_alias(0));
            builder.append(*first, builder.terminal(cit_break));
            auto second = builder.block();
            builder.append(*second, builder.load_alias());
            builder.append(*second, builder.terminal(cit_break));
            builder.append(*body, builder.switch_pair(std::move(first), std::move(second)));
            return body;
        }},
        {"switch_fallthrough_alias_positive", true, [&] {
            auto body = builder.block();
            builder.append(*body, builder.assign_alias(1));
            auto first = builder.block();
            builder.append(*first, builder.assign_alias(0));
            auto second = builder.block();
            builder.append(*second, builder.load_alias());
            builder.append(*second, builder.terminal(cit_break));
            builder.append(*body, builder.switch_pair(std::move(first), std::move(second)));
            return body;
        }},
        {"switch_incoming_sibling_alias_positive", true, [&] {
            auto body = builder.block();
            builder.append(*body, builder.assign_alias(0));
            auto first = builder.block();
            builder.append(*first, builder.assign_alias(1));
            builder.append(*first, builder.terminal(cit_break));
            auto second = builder.block();
            builder.append(*second, builder.load_alias());
            builder.append(*second, builder.terminal(cit_break));
            builder.append(*body, builder.switch_pair(std::move(first), std::move(second)));
            return body;
        }},
        {"switch_case_predicate_survives_join", false, [&] {
            auto body = builder.block();
            builder.append(*body, builder.assign_alias(1));
            auto first = builder.block();
            builder.append(*first, builder.assign_alias(0));
            builder.append(*first, builder.terminal(cit_break));
            auto second = builder.block();
            builder.append(*second, builder.assign_alias(1));
            builder.append(*second, builder.terminal(cit_break));
            builder.append(*body, builder.switch_pair(std::move(first), std::move(second)));
            builder.append(*body, builder.branch(builder.load_alias(), {}, cot_eq));
            return body;
        }},
        {"switch_default_excludes_explicit_value", false, [&] {
            auto body = builder.block();
            auto first = builder.block();
            builder.append(*first, builder.assign_alias(1));
            builder.append(*first, builder.terminal(cit_break));
            auto second = builder.block();
            builder.append(*second, builder.assign_alias(0));
            builder.append(*second, builder.terminal(cit_break));
            builder.append(*body, builder.switch_pair(std::move(first), std::move(second), true));
            builder.append(*body, builder.branch(builder.load_alias(), {}, cot_eq, 1));
            return body;
        }},
        {"switch_no_default_preserves_incoming", true, [&] {
            auto body = builder.block();
            builder.append(*body, builder.assign_alias(0));
            builder.append(*body, builder.assign_flag(2));
            auto first = builder.block();
            builder.append(*first, builder.assign_alias(1));
            builder.append(*first, builder.terminal(cit_break));
            auto second = builder.block();
            builder.append(*second, builder.assign_alias(1));
            builder.append(*second, builder.terminal(cit_break));
            builder.append(*body, builder.switch_pair(std::move(first), std::move(second)));
            builder.append(*body, builder.load_alias());
            return body;
        }},
        {"goto_bypassed_definition_not_reaching", false, [&] {
            auto body = builder.block();
            builder.append(*body, builder.assign_alias(1));
            builder.append(*body, builder.jump(1));
            builder.append(*body, builder.assign_alias(0));
            auto load = builder.load_alias();
            load->label_num = 1;
            builder.append(*body, std::move(load));
            return body;
        }},
        {"goto_label_strong_definition_recovers", true, [&] {
            auto body = builder.block();
            builder.append(*body, builder.jump(1));
            auto definition = builder.assign_alias(0);
            definition->label_num = 1;
            builder.append(*body, std::move(definition));
            builder.append(*body, builder.load_alias());
            return body;
        }},
        {"goto_skips_unreachable_load", false, [&] {
            auto body = builder.block();
            builder.append(*body, builder.assign_alias(0));
            builder.append(*body, builder.jump(1));
            builder.append(*body, builder.load_alias());
            auto definition = builder.assign_alias(1);
            definition->label_num = 1;
            builder.append(*body, std::move(definition));
            return body;
        }},
        {"irreducible_goto_entries_forget_lexical_alias", false, [&] {
            auto body = builder.block();
            builder.append(*body, builder.assign_alias(1));
            builder.append(*body, builder.branch(builder.jump(2)));
            auto first_entry = builder.jump(2);
            first_entry->label_num = 1;
            builder.append(*body, std::move(first_entry));
            builder.append(*body, builder.assign_alias(0));
            auto second_entry = builder.load_alias();
            second_entry->label_num = 2;
            builder.append(*body, std::move(second_entry));
            builder.append(*body, builder.branch(builder.jump(1)));
            return body;
        }},
        {"finally_kills_alias_before_continuation", false, [&] {
            auto body = builder.block();
            auto guarded = builder.block();
            builder.append(*guarded, builder.assign_alias(0));
            auto finalizer = builder.block();
            builder.append(*finalizer, builder.assign_alias(1));
            builder.append(*body, builder.cleanup(std::move(guarded), std::move(finalizer)));
            builder.append(*body, builder.load_alias());
            return body;
        }},
        {"finally_defines_alias_for_continuation", true, [&] {
            auto body = builder.block();
            auto guarded = builder.block();
            builder.append(*guarded, builder.assign_alias(1));
            auto finalizer = builder.block();
            builder.append(*finalizer, builder.assign_alias(0));
            builder.append(*body, builder.cleanup(std::move(guarded), std::move(finalizer)));
            builder.append(*body, builder.load_alias());
            return body;
        }},
        {"finally_observes_returning_alias", true, [&] {
            auto body = builder.block();
            auto guarded = builder.block();
            builder.append(*guarded, builder.assign_alias(0));
            builder.append(*guarded, builder.return_zero());
            auto finalizer = builder.block();
            builder.append(*finalizer, builder.load_alias());
            builder.append(*body, builder.cleanup(std::move(guarded), std::move(finalizer)));
            return body;
        }},
        {"finally_return_skips_continuation", false, [&] {
            auto body = builder.block();
            auto guarded = builder.block();
            builder.append(*guarded, builder.assign_alias(0));
            auto finalizer = builder.block();
            builder.append(*finalizer, builder.return_zero());
            builder.append(*body, builder.cleanup(std::move(guarded), std::move(finalizer)));
            builder.append(*body, builder.load_alias());
            return body;
        }},
        {"wind_cleanup_does_not_replace_normal_alias", true, [&] {
            auto body = builder.block();
            auto guarded = builder.block();
            builder.append(*guarded, builder.assign_alias(0));
            auto finalizer = builder.block();
            builder.append(*finalizer, builder.assign_alias(1));
            builder.append(*body, builder.cleanup(std::move(guarded), std::move(finalizer), true));
            builder.append(*body, builder.load_alias());
            return body;
        }},
        {"shared_label_preserves_lexical_alias", true, [&] {
            auto body = builder.block();
            builder.append(*body, builder.assign_alias(1));
            builder.append(*body, builder.branch(builder.jump(1), {}, cot_eq));
            auto path = builder.block();
            builder.append(*path, builder.assign_alias(0));
            auto load = builder.load_alias();
            load->label_num = 1;
            builder.append(*path, std::move(load));
            builder.append(*body, builder.branch(std::move(path), {}, cot_eq, 1));
            return body;
        }},
        {"shared_label_excludes_jumped_definition", false, [&] {
            auto body = builder.block();
            builder.append(*body, builder.assign_alias(1));
            builder.append(*body, builder.branch(builder.jump(1), {}, cot_eq));
            auto path = builder.block();
            builder.append(*path, builder.assign_alias(0));
            builder.append(*path, builder.jump(2));
            auto load = builder.load_alias();
            load->label_num = 1;
            builder.append(*path, std::move(load));
            builder.append(*body, builder.branch(std::move(path), {}, cot_eq, 1));
            auto finish = builder.return_zero();
            finish->label_num = 2;
            builder.append(*body, std::move(finish));
            return body;
        }},
        {"shared_label_budget_widens_before_observation", false, [&] {
            auto body = builder.block();
            auto chain = builder.assign_alias(1);
            for (unsigned index = 0; index < 15; ++index) {
                chain = builder.branch(builder.assign_alias_offset(0, index * 4),
                    std::move(chain), cot_eq, index);
            }
            builder.append(*body, std::move(chain));
            auto load = builder.load_alias();
            load->label_num = 1;
            builder.append(*body, std::move(load));
            builder.append(*body, builder.return_zero());
            builder.append(*body, builder.jump(1));
            return body;
        }},
        {"compound_alias_add_uses_element_scale", true, [&] {
            auto body = builder.block();
            builder.append(*body, builder.assign_alias(0));
            builder.append(*body, builder.expression(builder.alias_update(cot_asgadd, builder.number(3))));
            builder.append(*body, builder.load_alias());
            return body;
        }, {4 + 3 * update_scale}},
        {"compound_alias_sub_uses_element_scale", true, [&] {
            auto body = builder.block();
            builder.append(*body, builder.assign_alias_offset(0, 16));
            builder.append(*body, builder.expression(builder.alias_update(cot_asgsub, builder.number(3))));
            builder.append(*body, builder.load_alias());
            return body;
        }, {20 - 3 * update_scale}},
        {"compound_alias_signed_negative_delta", true, [&] {
            auto body = builder.block();
            builder.append(*body, builder.assign_alias_offset(0, 16));
            builder.append(*body, builder.expression(builder.alias_update(cot_asgadd,
                builder.number64(static_cast<uint64>(-2), type_signed))));
            builder.append(*body, builder.load_alias());
            return body;
        }, {20 - 2 * update_scale}},
        {"compound_alias_delta_cast_is_preserved", true, [&] {
            auto body = builder.block();
            builder.append(*body, builder.assign_alias(0));
            tinfo_t byte;
            byte.create_simple_type(BTF_UINT8);
            builder.append(*body, builder.expression(builder.alias_update(cot_asgadd,
                builder.unary(cot_cast, builder.number(256), byte))));
            builder.append(*body, builder.load_alias());
            return body;
        }},
        {"compound_alias_rhs_read_precedes_kill", true, [&] {
            auto body = builder.block();
            builder.append(*body, builder.assign_alias(0));
            auto load = builder.load_alias();
            auto value = Expression(load->cexpr);
            load->cexpr = nullptr;
            load->op = cit_empty;
            builder.append(*body, builder.expression(builder.alias_update(cot_asgadd, std::move(value))));
            builder.append(*body, builder.load_alias());
            return body;
        }},
        {"compound_alias_overflow_discards_offset", false, [&] {
            auto body = builder.block();
            builder.append(*body, builder.assign_alias_offset(0, 8));
            builder.append(*body, builder.expression(builder.alias_update(cot_asgadd,
                builder.number64(UINT64_C(0x7ffffffffffffff8), type_signed))));
            builder.append(*body, builder.load_alias());
            return body;
        }},
        {"compound_alias_minimum_subtraction_rejected", false, [&] {
            auto body = builder.block();
            builder.append(*body, builder.assign_alias(0));
            builder.append(*body, builder.expression(builder.alias_update(cot_asgsub,
                builder.number64(UINT64_C(0x8000000000000000), type_signed))));
            builder.append(*body, builder.load_alias());
            return body;
        }},
        {"postincrement_load_observes_old_address", true, [&] {
            auto body = builder.block();
            builder.append(*body, builder.assign_alias(0));
            builder.append(*body, builder.load_alias(builder.alias_update(cot_postinc)));
            builder.append(*body, builder.load_alias());
            return body;
        }, {4, 4 + update_scale}},
        {"preincrement_load_observes_new_address", true, [&] {
            auto body = builder.block();
            builder.append(*body, builder.assign_alias(0));
            builder.append(*body, builder.load_alias(builder.alias_update(cot_preinc)));
            builder.append(*body, builder.load_alias());
            return body;
        }, {4 + update_scale}},
        {"postdecrement_load_observes_old_address", true, [&] {
            auto body = builder.block();
            builder.append(*body, builder.assign_alias_offset(0, 8));
            builder.append(*body, builder.load_alias(builder.alias_update(cot_postdec)));
            builder.append(*body, builder.load_alias());
            return body;
        }, {12, 12 - update_scale}},
        {"predecrement_load_observes_new_address", true, [&] {
            auto body = builder.block();
            builder.append(*body, builder.assign_alias_offset(0, 8));
            builder.append(*body, builder.load_alias(builder.alias_update(cot_predec)));
            builder.append(*body, builder.load_alias());
            return body;
        }, {12 - update_scale}},
        {"postincrement_assignment_preserves_old_result", true, [&] {
            auto body = builder.block();
            builder.append(*body, builder.assign_alias(0));
            builder.append(*body, builder.assign_value(1, builder.alias_update(cot_postinc)));
            builder.append(*body, builder.load_alias(builder.variable(1)));
            builder.append(*body, builder.load_alias());
            return body;
        }, {4, 4 + update_scale}},
        {"preincrement_assignment_preserves_new_result", true, [&] {
            auto body = builder.block();
            builder.append(*body, builder.assign_alias(0));
            builder.append(*body, builder.assign_value(1, builder.alias_update(cot_preinc)));
            builder.append(*body, builder.load_alias(builder.variable(1)));
            builder.append(*body, builder.load_alias());
            return body;
        }, {4 + update_scale}},
        {"compound_assignment_result_preserves_new_address", true, [&] {
            auto body = builder.block();
            builder.append(*body, builder.assign_alias(0));
            builder.append(*body, builder.assign_value(1, builder.alias_update(cot_asgadd, builder.number(2))));
            builder.append(*body, builder.load_alias(builder.variable(1)));
            builder.append(*body, builder.load_alias());
            return body;
        }, {4 + 2 * update_scale}},
        {"postincrement_loop_recomputes_expression_value", true, [&] {
            auto body = builder.block();
            builder.append(*body, builder.assign_alias(0));
            builder.append(*body, builder.assign_flag(2));
            auto repeated = builder.block();
            builder.append(*repeated, builder.load_alias(builder.alias_update(cot_postinc)));
            builder.append(*repeated, builder.decrement_flag());
            builder.append(*body, builder.while_loop(std::move(repeated)));
            return body;
        }, {4, 4 + update_scale}},
        {"narrowed_postincrement_result_discards_alias", false, [&] {
            auto body = builder.block();
            builder.append(*body, builder.assign_alias(0));
            tinfo_t narrow;
            narrow.create_simple_type(BTF_UINT32);
            builder.append(*body, builder.assign_value(1,
                builder.unary(cot_cast, builder.alias_update(cot_postinc), narrow)));
            builder.append(*body, builder.load_alias(builder.variable(1)));
            return body;
        }},
        {"narrowed_conditional_update_discards_alias", false, [&] {
            auto body = builder.block();
            builder.append(*body, builder.assign_alias(0));
            auto conditional = std::make_unique<cexpr_t>(cot_tern, nullptr);
            conditional->x = builder.flag_condition().release();
            conditional->y = builder.alias_update(cot_postinc).release();
            conditional->z = builder.alias_update(cot_preinc).release();
            conditional->type = builder.variable(2)->type;
            tinfo_t narrow;
            narrow.create_simple_type(BTF_UINT32);
            builder.append(*body, builder.assign_value(1,
                builder.unary(cot_cast, std::move(conditional), narrow)));
            builder.append(*body, builder.load_alias(builder.variable(1)));
            return body;
        }},
    };

    std::vector<AliasFlowObservation> observations;
    observations.reserve(cases.size());
    const cblock_t* original_body = cfunc->body.cblock;
    for (const auto& test : cases) {
        if (selected_case && std::string(test.name) != selected_case) continue;
        AliasFlowObservation observation;
        observation.name = test.name;
        observation.expects_base_access = test.expects_access;
        try {
            auto replacement = test.make_body();
            builder.append(*replacement, builder.return_zero());
            {
                ScopedBodySwap restore(*cfunc, *replacement);
                SynthOptions options;
                options.min_accesses = 1;
                options.vtable_detection = false;
                options.flow = flow;
                AccessCollector collector(options);
                observation.pattern = collector.collect(cfunc, arguments[0]);
            }
            std::set<sval_t> offsets;
            bool widths_match = true;
            for (const auto& access : observation.pattern.accesses) {
                offsets.insert(access.offset);
                widths_match &= access.size == 4;
            }
            observation.matches_expected = test.expects_access
                ? widths_match && offsets == test.expected_offsets
                : observation.pattern.accesses.empty();
        } catch (const std::exception& exception) {
            observation.error = exception.what();
        } catch (...) {
            observation.error = "unknown exception while collecting alias probe";
        }
        observation.original_body_restored =
            cfunc->body.op == cit_block && cfunc->body.cblock == original_body;
        observations.push_back(std::move(observation));
    }
    return observations;
}

} // namespace structor::testing
