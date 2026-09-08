cmake_minimum_required(VERSION 3.20)

# Test configuration
enable_testing()

# Find or fetch GoogleTest
include(FetchContent)
FetchContent_Declare(
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG f8d7d77c06936315286eb55f8de22cd23c188571
)
set(gtest_force_shared_crt OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)
find_package(Python3 COMPONENTS Interpreter REQUIRED)

# The standalone solver tests intentionally use assert() as their failure
# mechanism. Release builds define NDEBUG globally, which would otherwise turn
# those tests into no-op executables that always pass.
function(structor_enable_test_assertions TARGET_NAME)
    if(MSVC)
        target_compile_options(${TARGET_NAME} PRIVATE /UNDEBUG)
    else()
        target_compile_options(${TARGET_NAME} PRIVATE -UNDEBUG)
    endif()
endfunction()

# Test sources that can execute against the IDA mocks. The legacy
# test_layout_synthesizer.cpp target is intentionally not listed: it cannot
# link the current production synthesizer against these mocks. Production
# layout behavior is covered by the licensed live contract suite below.
set(TEST_SOURCES
    test_synth_types.cpp
    test_access_patterns.cpp
    test_access_type_inference.cpp
    test_field_fragment_type.cpp
    test_signature_and_abi.cpp
    test_optimized_algorithms.cpp
    test_persistence_invariants.cpp
    test_lifecycle_and_registry.cpp
    test_vtable_detection.cpp
    test_config.cpp
    test_type_matcher.cpp
    ${PROJECT_SOURCE_DIR}/src/synthesis/naming.cpp
    ${PROJECT_SOURCE_DIR}/src/synthesis/type_matcher.cpp
    mock_ida.cpp
)

# Create test executable
add_executable(structor_tests ${TEST_SOURCES})

target_include_directories(structor_tests PRIVATE
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/test
)

target_link_libraries(structor_tests PRIVATE
    gtest
    gtest_main
    gmock
)

target_compile_definitions(structor_tests PRIVATE
    STRUCTOR_TESTING
)
structor_enable_test_assertions(structor_tests)

# Register tests with CTest
include(GoogleTest)
gtest_discover_tests(structor_tests)

add_test(
    NAME fixture_contract_parser
    COMMAND ${Python3_EXECUTABLE}
            ${PROJECT_SOURCE_DIR}/test/test_fixture_contract_parser.py
)

add_executable(structor_embed_consumer_smoke test_embed_consumer.cpp)
target_link_libraries(structor_embed_consumer_smoke PRIVATE structor_core)
# IDA SDK libraries are host stubs and cannot be executed outside IDA. This
# smoke check therefore validates that an embedding consumer compiles and links
# without trying to launch the resulting host-dependent executable.
add_test(
    NAME embed_consumer_build_smoke
    COMMAND ${CMAKE_COMMAND}
            --build ${PROJECT_BINARY_DIR}
            --target structor_embed_consumer_smoke
            --config $<CONFIG>
)

set(STRUCTOR_LIVE_TEST_DEPS "")
find_program(IDUMP_EXECUTABLE NAMES idump)
file(GLOB STRUCTOR_IDA_LICENSE_FILES LIST_DIRECTORIES FALSE
    "$ENV{HOME}/.idapro/ida.reg"
    "$ENV{HOME}/.idapro/*.hexlic"
    "$ENV{HOME}/.idapro/*.lic"
)

set(STRUCTOR_LIVE_TEST_ARCH_SUPPORTED FALSE)
if(APPLE)
    if(CMAKE_OSX_ARCHITECTURES)
        list(FIND CMAKE_OSX_ARCHITECTURES "arm64" STRUCTOR_ARM64_ARCH_INDEX)
        if(NOT STRUCTOR_ARM64_ARCH_INDEX EQUAL -1)
            set(STRUCTOR_LIVE_TEST_ARCH_SUPPORTED TRUE)
        endif()
    elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "arm64|aarch64")
        set(STRUCTOR_LIVE_TEST_ARCH_SUPPORTED TRUE)
    endif()
endif()

if(TARGET structor${IDA_SUFFIX}
   AND IDUMP_EXECUTABLE
   AND STRUCTOR_LIVE_TEST_ARCH_SUPPORTED
   AND STRUCTOR_IDA_LICENSE_FILES
   AND STRUCTOR_ENABLE_LIVE_TEST_HOOKS)
    add_test(
        NAME full_integrity_suite_live
        COMMAND ${Python3_EXECUTABLE}
                ${PROJECT_SOURCE_DIR}/integration_tests/check_full_integrity_suite.py
                --repo-root ${PROJECT_SOURCE_DIR}
                --plugin ${PROJECT_BINARY_DIR}/structor${PLUGIN_EXT}
                --idump ${IDUMP_EXECUTABLE}
    )
    set_tests_properties(full_integrity_suite_live PROPERTIES
        TIMEOUT 1800
        RUN_SERIAL TRUE
        LABELS "live;ida;integration"
    )
    set(STRUCTOR_LIVE_TEST_DEPS structor${IDA_SUFFIX})
endif()

# ============================================================================
# Standalone Z3 model tests (no IDA dependency)
#
# These exercise IDA-independent test models from test_ir.hpp. They are useful
# solver checks but are not substitutes for the production-linked and live
# contract tests.
# ============================================================================

# Helper function to add Z3 test targets
function(add_z3_test TEST_NAME TEST_SOURCE)
    add_executable(${TEST_NAME} ${TEST_SOURCE})
    target_include_directories(${TEST_NAME} PRIVATE
        ${PROJECT_SOURCE_DIR}/include
        ${STRUCTOR_Z3_INCLUDE_DIRS}
    )
    target_compile_definitions(${TEST_NAME} PRIVATE STRUCTOR_TESTING)
    target_link_libraries(${TEST_NAME} PRIVATE structor_z3)
    structor_enable_test_assertions(${TEST_NAME})
endfunction()

# Z3 Context Tests
add_z3_test(test_z3_context test_z3_context.cpp)
target_sources(test_z3_context PRIVATE
    ${PROJECT_SOURCE_DIR}/src/z3/context.cpp
    ${PROJECT_SOURCE_DIR}/src/z3/type_encoding.cpp
)
target_include_directories(test_z3_context PRIVATE ${PROJECT_SOURCE_DIR}/test)
add_test(NAME z3_context COMMAND test_z3_context)

# Production UNSAT metadata must remain safe after the owning context expires.
add_z3_test(test_constraint_diagnostics test_constraint_diagnostics.cpp)
target_sources(test_constraint_diagnostics PRIVATE
    ${PROJECT_SOURCE_DIR}/src/z3/constraint_tracker.cpp
)
target_include_directories(test_constraint_diagnostics PRIVATE ${PROJECT_SOURCE_DIR}/test)
add_test(NAME z3_constraint_diagnostics COMMAND test_constraint_diagnostics)

# Z3 Type Encoding Tests
add_z3_test(test_z3_type_encoding test_type_encoding.cpp)
add_test(NAME z3_type_encoding COMMAND test_z3_type_encoding)

# Z3 Array Detection Tests
add_z3_test(test_z3_array_detection test_array_detection.cpp)
add_test(NAME z3_array_detection COMMAND test_z3_array_detection)

# Exercise the production detector, with only IDA's type-system boundary mocked.
add_z3_test(test_production_array_detection test_production_array_detection.cpp)
target_sources(test_production_array_detection PRIVATE
    ${PROJECT_SOURCE_DIR}/src/z3/array_constraints.cpp
    ${PROJECT_SOURCE_DIR}/src/z3/context.cpp
    ${PROJECT_SOURCE_DIR}/src/z3/type_encoding.cpp
)
target_include_directories(test_production_array_detection PRIVATE ${PROJECT_SOURCE_DIR}/test)
add_test(NAME z3_production_array_detection COMMAND test_production_array_detection)

# Z3 Layout Constraints Tests
add_z3_test(test_z3_layout_constraints test_layout_constraints.cpp)
add_test(NAME z3_layout_constraints COMMAND test_z3_layout_constraints)

# Production union-domain/cardinality helper tests
add_z3_test(test_z3_union_constraints test_union_constraints.cpp)
add_test(NAME z3_union_constraints COMMAND test_z3_union_constraints)

# Production field/array resource helper tests with IDA mocks.
add_z3_test(test_z3_resource_helpers test_resource_helpers.cpp)
target_include_directories(test_z3_resource_helpers PRIVATE ${PROJECT_SOURCE_DIR}/test)
add_test(NAME z3_resource_helpers COMMAND test_z3_resource_helpers)

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
    ${PROJECT_SOURCE_DIR}/src/z3/type_lattice.cpp
    ${PROJECT_SOURCE_DIR}/src/z3/context.cpp
    ${PROJECT_SOURCE_DIR}/src/z3/type_encoding.cpp
)
target_include_directories(test_type_lattice PRIVATE
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/test
    ${STRUCTOR_Z3_INCLUDE_DIRS}
)
target_compile_definitions(test_type_lattice PRIVATE STRUCTOR_TESTING)
target_link_libraries(test_type_lattice PRIVATE structor_z3)
structor_enable_test_assertions(test_type_lattice)
add_test(NAME type_lattice COMMAND test_type_lattice)

add_z3_test(test_type_lattice_laws test_type_lattice_laws.cpp)
target_sources(test_type_lattice_laws PRIVATE
    ${PROJECT_SOURCE_DIR}/src/z3/type_lattice.cpp
    ${PROJECT_SOURCE_DIR}/src/z3/context.cpp
    ${PROJECT_SOURCE_DIR}/src/z3/type_encoding.cpp
)
target_include_directories(test_type_lattice_laws PRIVATE ${PROJECT_SOURCE_DIR}/test)
add_test(NAME type_lattice_laws COMMAND test_type_lattice_laws)

add_z3_test(test_type_variable_identity test_type_variable_identity.cpp)
add_test(NAME type_variable_identity COMMAND test_type_variable_identity)

add_z3_test(test_instruction_semantics_identity test_instruction_semantics_identity.cpp)
target_include_directories(test_instruction_semantics_identity PRIVATE ${PROJECT_SOURCE_DIR}/test)
target_sources(test_instruction_semantics_identity PRIVATE
    ${PROJECT_SOURCE_DIR}/src/z3/instruction_semantics.cpp
    ${PROJECT_SOURCE_DIR}/src/z3/type_lattice.cpp
    ${PROJECT_SOURCE_DIR}/src/z3/context.cpp
    ${PROJECT_SOURCE_DIR}/src/z3/type_encoding.cpp
)
add_test(NAME type_instruction_semantics_identity COMMAND test_instruction_semantics_identity)

# Add combined test target
add_custom_target(check
    COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure --no-tests=error
    DEPENDS structor_tests
            structor_embed_consumer_smoke
            ${STRUCTOR_LIVE_TEST_DEPS}
            test_z3_context
            test_constraint_diagnostics
            test_z3_type_encoding
            test_z3_array_detection
            test_production_array_detection
            test_z3_layout_constraints
            test_z3_union_constraints
            test_z3_resource_helpers
            test_z3_cross_function
            test_z3_synthesis_integration
            test_e2e_synthesis
            test_type_lattice
            test_type_lattice_laws
            test_type_variable_identity
            test_instruction_semantics_identity
)

# Add z3-only test target for quick Z3 testing
# Run tests matching z3_ or e2e_ or type_ pattern
add_custom_target(check_z3
    COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure --no-tests=error -R "^z3_|^e2e_|^type_"
    DEPENDS test_z3_context
            test_constraint_diagnostics
            test_z3_type_encoding
            test_z3_array_detection
            test_production_array_detection
            test_z3_layout_constraints
            test_z3_union_constraints
            test_z3_resource_helpers
            test_z3_cross_function
            test_z3_synthesis_integration
            test_e2e_synthesis
            test_type_lattice
            test_type_lattice_laws
            test_type_variable_identity
            test_instruction_semantics_identity
    VERBATIM
)
