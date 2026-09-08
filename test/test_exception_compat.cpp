#include <gtest/gtest.h>
#include <structor/analysis/exception_compat.hpp>

namespace {
struct LegacyTry { bool is_wind; };
struct LegacyCatch { bool is_catch_all() const { return true; } };
struct CurrentTry {
    bool wind;
    bool is_wind() const { return wind; }
};
struct CurrentCatch {
    bool finally;
    bool is_finally() const { return finally; }
};
} // namespace

TEST(ExceptionCompatibilityTest, LegacyWindIsExceptionalCleanup) {
    EXPECT_TRUE(structor::detail::is_wind_statement(LegacyTry{true}));
    EXPECT_TRUE(structor::detail::is_cleanup_handler(LegacyTry{true}, LegacyCatch{}));
}

TEST(ExceptionCompatibilityTest, LegacyOrdinaryCatchAllIsNotFinally) {
    EXPECT_FALSE(structor::detail::is_wind_statement(LegacyTry{false}));
    EXPECT_FALSE(structor::detail::is_cleanup_handler(LegacyTry{false}, LegacyCatch{}));
}

TEST(ExceptionCompatibilityTest, CurrentFinallyAndWindRetainSeparateRoles) {
    EXPECT_FALSE(structor::detail::is_wind_statement(CurrentTry{false}));
    EXPECT_TRUE(structor::detail::is_wind_statement(CurrentTry{true}));
    EXPECT_TRUE(structor::detail::is_cleanup_handler(CurrentTry{false}, CurrentCatch{true}));
    EXPECT_FALSE(structor::detail::is_cleanup_handler(CurrentTry{false}, CurrentCatch{false}));
    EXPECT_TRUE(structor::detail::is_cleanup_handler(CurrentTry{true}, CurrentCatch{true}));
}
