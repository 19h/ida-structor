#pragma once

namespace structor::detail {

// The pinned 9.3 SDKs expose ctry_t::is_wind as a Boolean member. Later
// SDKs expose it as a method and represent normal finally handlers explicitly.
template <typename TryStatement>
[[nodiscard]] bool is_wind_statement(const TryStatement& statement) {
    if constexpr (requires { statement.is_wind(); }) {
        return statement.is_wind();
    } else {
        return statement.is_wind;
    }
}

template <typename TryStatement, typename Handler>
[[nodiscard]] bool is_cleanup_handler(
    const TryStatement& statement, const Handler& handler) {
    // Wind handlers run on exceptional exit and cannot resume the normal
    // continuation. The older SDK represents these as catch-all handlers.
    if (is_wind_statement(statement)) return true;
    if constexpr (requires { handler.is_finally(); }) {
        return handler.is_finally();
    } else {
        // Older ccatch_t has no distinct normal-finally representation.
        return false;
    }
}

} // namespace structor::detail
