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
    ${CMAKE_SOURCE_DIR}/src/synthesis/naming.cpp
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

set(LIVE_TYPE_FIX_DEPS "")
find_program(IDUMP_EXECUTABLE NAMES idump)
if(IDUMP_EXECUTABLE
   AND APPLE
   AND CMAKE_SYSTEM_PROCESSOR MATCHES "arm64|aarch64"
   AND EXISTS "$ENV{HOME}/.idapro/ida.reg")
    find_package(Python3 COMPONENTS Interpreter REQUIRED)
    add_test(
        NAME type_fixer_regressions_live
        COMMAND ${Python3_EXECUTABLE}
                ${CMAKE_SOURCE_DIR}/integration_tests/check_type_fixer_regressions.py
                --repo-root ${CMAKE_SOURCE_DIR}
                --plugin ${CMAKE_BINARY_DIR}/structor${PLUGIN_EXT}
                --idump ${IDUMP_EXECUTABLE}
    )
    set_tests_properties(type_fixer_regressions_live PROPERTIES TIMEOUT 240)
    add_test(
        NAME global_recovery_regressions_live
        COMMAND ${Python3_EXECUTABLE}
                ${CMAKE_SOURCE_DIR}/integration_tests/check_global_recovery_regressions.py
                --repo-root ${CMAKE_SOURCE_DIR}
                --plugin ${CMAKE_BINARY_DIR}/structor${PLUGIN_EXT}
                --idump ${IDUMP_EXECUTABLE}
    )
    set_tests_properties(global_recovery_regressions_live PROPERTIES TIMEOUT 240)
    set(LIVE_TYPE_FIX_DEPS structor${IDA_SUFFIX})
endif()

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

# Type Lattice Tests (needs type_lattice.cpp implementation)
add_executable(test_type_lattice
    test_type_lattice.cpp
    ${CMAKE_SOURCE_DIR}/src/z3/type_lattice.cpp
    ${CMAKE_SOURCE_DIR}/src/z3/context.cpp
    ${CMAKE_SOURCE_DIR}/src/z3/type_encoding.cpp
)
target_include_directories(test_type_lattice PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/test
)
target_compile_definitions(test_type_lattice PRIVATE STRUCTOR_TESTING)
if(Z3_CUSTOM)
    target_link_libraries(test_type_lattice PRIVATE z3_custom)
elseif(Z3_USE_SYSTEM)
    target_link_libraries(test_type_lattice PRIVATE z3::libz3)
else()
    target_include_directories(test_type_lattice PRIVATE
        ${z3_SOURCE_DIR}/src/api
        ${z3_SOURCE_DIR}/src/api/c++
        ${z3_BINARY_DIR}/src/api
    )
    target_link_libraries(test_type_lattice PRIVATE libz3)
endif()
add_test(NAME type_lattice COMMAND test_type_lattice)

# Add combined test target
add_custom_target(check
    COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure
    DEPENDS structor_tests
            ${LIVE_TYPE_FIX_DEPS}
            test_z3_context
            test_z3_type_encoding
            test_z3_array_detection
            test_z3_layout_constraints
            test_z3_cross_function
            test_z3_synthesis_integration
            test_e2e_synthesis
            test_type_lattice
)

# Add z3-only test target for quick Z3 testing
# Run tests matching z3_ or e2e_ or type_ pattern
add_custom_target(check_z3
    COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure -R "^z3_|^e2e_|^type_"
    DEPENDS test_z3_context
            test_z3_type_encoding
            test_z3_array_detection
            test_z3_layout_constraints
            test_z3_cross_function
            test_z3_synthesis_integration
            test_e2e_synthesis
            test_type_lattice
    VERBATIM
)
