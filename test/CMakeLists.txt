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

# Test sources (mock IDA tests)
# Note: test_layout_synthesizer.cpp is tested via Z3 integration tests
# as it requires the full LayoutSynthesizer with Z3 dependencies
set(TEST_SOURCES
    test_synth_types.cpp
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

# ============================================================================
# Z3-specific tests (standalone, no IDA dependency)
# ============================================================================

# Helper function to add Z3 test targets
function(add_z3_test TEST_NAME TEST_SOURCE)
    add_executable(${TEST_NAME} ${TEST_SOURCE})
    target_include_directories(${TEST_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/include)
    target_compile_definitions(${TEST_NAME} PRIVATE STRUCTOR_TESTING)

    if(Z3_USE_SYSTEM)
        target_link_libraries(${TEST_NAME} PRIVATE z3::libz3)
    else()
        target_include_directories(${TEST_NAME} PRIVATE
            ${z3_SOURCE_DIR}/src/api
            ${z3_SOURCE_DIR}/src/api/c++
            ${z3_BINARY_DIR}/src/api
        )
        target_link_libraries(${TEST_NAME} PRIVATE libz3)
    endif()
endfunction()

# Z3 Context Tests
add_z3_test(test_z3_context test_z3_context.cpp)
add_test(NAME z3_context COMMAND test_z3_context)

# Z3 Type Encoding Tests
add_z3_test(test_z3_type_encoding test_type_encoding.cpp)
add_test(NAME z3_type_encoding COMMAND test_z3_type_encoding)

# Z3 Array Detection Tests
add_z3_test(test_z3_array_detection test_array_detection.cpp)
add_test(NAME z3_array_detection COMMAND test_z3_array_detection)

# Z3 Layout Constraints Tests
add_z3_test(test_z3_layout_constraints test_layout_constraints.cpp)
add_test(NAME z3_layout_constraints COMMAND test_z3_layout_constraints)

# Z3 Cross-Function Tests
add_z3_test(test_z3_cross_function test_cross_function.cpp)
add_test(NAME z3_cross_function COMMAND test_z3_cross_function)

# Z3 Integration Tests
add_z3_test(test_z3_synthesis_integration test_z3_synthesis_integration.cpp)
add_test(NAME z3_synthesis_integration COMMAND test_z3_synthesis_integration)

# End-to-End Synthesis Tests (exercises full pipeline with constraint tracking)
add_z3_test(test_e2e_synthesis test_e2e_synthesis.cpp)
add_test(NAME e2e_synthesis COMMAND test_e2e_synthesis)

# Add combined test target
add_custom_target(check
    COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure
    DEPENDS structor_tests
            test_z3_context
            test_z3_type_encoding
            test_z3_array_detection
            test_z3_layout_constraints
            test_z3_cross_function
            test_z3_synthesis_integration
            test_e2e_synthesis
)

# Add z3-only test target for quick Z3 testing
# Run tests matching z3_ or e2e_ pattern
add_custom_target(check_z3
    COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure -R "^z3_|^e2e_"
    DEPENDS test_z3_context
            test_z3_type_encoding
            test_z3_array_detection
            test_z3_layout_constraints
            test_z3_cross_function
            test_z3_synthesis_integration
            test_e2e_synthesis
    VERBATIM
)
