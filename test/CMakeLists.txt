cmake_minimum_required(VERSION 3.20)

# Test configuration
enable_testing()

# Find or fetch GoogleTest
include(FetchContent)
FetchContent_Declare(
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG v1.14.0
)
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

# Test sources
set(TEST_SOURCES
    test_synth_types.cpp
    test_layout_synthesizer.cpp
    test_access_patterns.cpp
    test_vtable_detection.cpp
    test_config.cpp
    mock_ida.cpp
)

# Create test executable
add_executable(structor_tests ${TEST_SOURCES})

target_include_directories(structor_tests PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/test
)

target_link_libraries(structor_tests PRIVATE
    gtest
    gtest_main
    gmock
)

target_compile_definitions(structor_tests PRIVATE
    STRUCTOR_TESTING
)

# Register tests with CTest
include(GoogleTest)
gtest_discover_tests(structor_tests)

# Add test target
add_custom_target(check
    COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure
    DEPENDS structor_tests
)
