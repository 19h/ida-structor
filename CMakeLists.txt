cmake_minimum_required(VERSION 3.20)

# Toolchain-affecting defaults must be established before project() enables a
# compiler. The deployment target remains caller-configurable; the static MSVC
# runtime is verified after compiler detection.
if(CMAKE_HOST_APPLE OR CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    if(NOT DEFINED CMAKE_OSX_DEPLOYMENT_TARGET OR
       CMAKE_OSX_DEPLOYMENT_TARGET STREQUAL "")
        set(CMAKE_OSX_DEPLOYMENT_TARGET "12.0" CACHE STRING
            "Minimum supported macOS version" FORCE)
    endif()
endif()
if(POLICY CMP0091)
    cmake_policy(SET CMP0091 NEW)
endif()
set(CMAKE_MSVC_RUNTIME_LIBRARY
    "MultiThreaded$<$<CONFIG:Debug>:Debug>"
    CACHE STRING "MSVC runtime linkage")

project(structor VERSION 2.2.0 LANGUAGES CXX)

if(MSVC AND NOT CMAKE_MSVC_RUNTIME_LIBRARY STREQUAL
        "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    message(FATAL_ERROR
        "Structor production builds require the static MSVC runtime")
endif()

file(READ "${CMAKE_CURRENT_SOURCE_DIR}/include/structor/synth_types.hpp"
    STRUCTOR_SYNTH_TYPES_HEADER)
string(REGEX MATCH
    "PLUGIN_VERSION = \"([0-9]+\\.[0-9]+\\.[0-9]+)\""
    STRUCTOR_PLUGIN_VERSION_MATCH
    "${STRUCTOR_SYNTH_TYPES_HEADER}")
if(NOT STRUCTOR_PLUGIN_VERSION_MATCH OR
   NOT "${CMAKE_MATCH_1}" STREQUAL "${PROJECT_VERSION}")
    message(FATAL_ERROR
        "Runtime PLUGIN_VERSION '${CMAKE_MATCH_1}' must equal CMake project version '${PROJECT_VERSION}'")
endif()

option(BUILD_TESTS "Build unit tests" OFF)
option(STRUCTOR_ENABLE_LIVE_TEST_HOOKS
    "Compile fault-injection hooks required by licensed live integration tests"
    OFF)
if(STRUCTOR_ENABLE_LIVE_TEST_HOOKS AND NOT BUILD_TESTS)
    message(FATAL_ERROR
        "STRUCTOR_ENABLE_LIVE_TEST_HOOKS requires BUILD_TESTS=ON")
endif()

find_package(Threads REQUIRED)
include(FetchContent)
option(FETCHCONTENT_UPDATES_DISCONNECTED
    "Do not contact remotes while populating pinned FetchContent dependencies"
    OFF)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Build type
if(NOT CMAKE_CONFIGURATION_TYPES AND NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# ============================================================================
# Z3 Theorem Prover Integration
# ============================================================================

# Allow specifying custom Z3 location. By default, Structor builds and links a
# static bundled Z3 so plugin artifacts do not depend on a sidecar libz3.
option(Z3_USE_CUSTOM "Use custom Z3 library instead of bundled static Z3" OFF)
set(Z3_CUSTOM_INCLUDE_DIR "" CACHE PATH "Custom Z3 include directory")
set(Z3_CUSTOM_LIBRARY "" CACHE FILEPATH "Custom Z3 library path")
set(Z3_CUSTOM_IMPLIB "" CACHE FILEPATH
    "Unsupported legacy dynamic Z3 import-library path")

if(Z3_USE_CUSTOM)
    if(NOT Z3_CUSTOM_INCLUDE_DIR OR NOT IS_DIRECTORY "${Z3_CUSTOM_INCLUDE_DIR}")
        message(FATAL_ERROR
            "Z3_USE_CUSTOM=ON requires an existing Z3_CUSTOM_INCLUDE_DIR")
    endif()
    if(NOT Z3_CUSTOM_LIBRARY OR NOT EXISTS "${Z3_CUSTOM_LIBRARY}")
        message(FATAL_ERROR
            "Z3_USE_CUSTOM=ON requires an existing static Z3_CUSTOM_LIBRARY")
    endif()
    if(Z3_CUSTOM_IMPLIB)
        message(FATAL_ERROR
            "Dynamic custom Z3 import libraries are unsupported; provide one static Z3_CUSTOM_LIBRARY")
    endif()
    if(WIN32)
        if(NOT Z3_CUSTOM_LIBRARY MATCHES "\\.[Ll][Ii][Bb]$")
            message(FATAL_ERROR "Custom Windows Z3 must be a static .lib archive")
        endif()
    elseif(NOT Z3_CUSTOM_LIBRARY MATCHES "\\.[Aa]$")
        message(FATAL_ERROR "Custom Unix Z3 must be a static .a archive")
    endif()

    message(STATUS "Using custom Z3: ${Z3_CUSTOM_LIBRARY}")
    set(Z3_CUSTOM TRUE)

    set(STRUCTOR_Z3_INCLUDE_DIRS "${Z3_CUSTOM_INCLUDE_DIR}")
    if(IS_DIRECTORY "${Z3_CUSTOM_INCLUDE_DIR}/c++")
        list(APPEND STRUCTOR_Z3_INCLUDE_DIRS "${Z3_CUSTOM_INCLUDE_DIR}/c++")
    endif()
    add_library(z3_custom STATIC IMPORTED GLOBAL)
    set_target_properties(z3_custom PROPERTIES
        IMPORTED_LOCATION "${Z3_CUSTOM_LIBRARY}"
        INTERFACE_INCLUDE_DIRECTORIES "${STRUCTOR_Z3_INCLUDE_DIRS}"
    )

    add_library(structor_z3 INTERFACE)
    target_link_libraries(structor_z3 INTERFACE z3_custom)
    target_include_directories(structor_z3 INTERFACE ${STRUCTOR_Z3_INCLUDE_DIRS})
else()
    set(Z3_CUSTOM FALSE)
    message(STATUS "Building bundled static Z3 from source")

    # Z3 Theorem Prover - use release tag for reproducibility
    FetchContent_Declare(
        z3
        GIT_REPOSITORY https://github.com/Z3Prover/z3.git
        GIT_TAG        745087e237e669d709ae35694728a0c479e572b3
    )

    # Z3 build options - produce a static library that is linked into Structor.
    set(Z3_BUILD_LIBZ3_SHARED OFF CACHE BOOL "" FORCE)
    set(Z3_BUILD_LIBZ3_MSVC_STATIC ON CACHE BOOL "" FORCE)
    set(Z3_BUILD_EXECUTABLE OFF CACHE BOOL "" FORCE)
    set(Z3_BUILD_TEST_EXECUTABLES OFF CACHE BOOL "" FORCE)
    set(Z3_ENABLE_EXAMPLE_TARGETS OFF CACHE BOOL "" FORCE)
    set(Z3_BUILD_DOCUMENTATION OFF CACHE BOOL "" FORCE)
    set(Z3_BUILD_JAVA_BINDINGS OFF CACHE BOOL "" FORCE)
    set(Z3_BUILD_PYTHON_BINDINGS OFF CACHE BOOL "" FORCE)
    set(Z3_BUILD_DOTNET_BINDINGS OFF CACHE BOOL "" FORCE)
    set(WARNINGS_AS_ERRORS OFF CACHE BOOL "" FORCE)

    FetchContent_MakeAvailable(z3)

    if(NOT TARGET libz3)
        message(FATAL_ERROR "Expected bundled Z3 target 'libz3' was not created")
    endif()

    if(MSVC)
        target_compile_options(libz3 PRIVATE $<$<CONFIG:Release>:/O2>)
    elseif(CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
        target_compile_options(libz3 PRIVATE $<$<CONFIG:Release>:-O3>)
    endif()

    add_library(structor_z3 ALIAS libz3)
    set(STRUCTOR_Z3_INCLUDE_DIRS
        "${z3_SOURCE_DIR}/src/api"
        "${z3_SOURCE_DIR}/src/api/c++"
        "${z3_BINARY_DIR}/src/api"
    )
endif()

# Verify exceptions are enabled (required for Z3 C++ API)
if(CMAKE_CXX_FLAGS MATCHES "-fno-exceptions")
    message(FATAL_ERROR "Z3 C++ API requires exceptions. Remove -fno-exceptions.")
endif()

option(STRUCTOR_BUILD_PLUGIN "Build the standalone Structor IDA plugin wrapper" ON)

# IDA SDK configuration
if(NOT DEFINED IDA_SDK_DIR)
    if(DEFINED ENV{IDA_SDK_DIR})
        set(IDA_SDK_DIR $ENV{IDA_SDK_DIR})
    else()
        message(FATAL_ERROR "IDA_SDK_DIR must be set to the IDA SDK directory")
    endif()
endif()

# Platform detection
if(WIN32)
    set(IDA_PLATFORM "win")
    set(IDA_LIB_SUFFIX ".lib")
    set(PLUGIN_EXT ".dll")
elseif(APPLE)
    set(IDA_PLATFORM "mac")
    set(IDA_LIB_SUFFIX ".dylib")
    set(PLUGIN_EXT ".dylib")
else()
    set(IDA_PLATFORM "linux")
    set(IDA_LIB_SUFFIX ".so")
    set(PLUGIN_EXT ".so")
endif()

# Architecture
option(IDA_EA64 "Build for 64-bit IDA (ida64)" ON)
if(NOT IDA_EA64)
    message(FATAL_ERROR
        "IDA_EA64=OFF is unsupported by the bundled IDA SDK import-library layout")
endif()
set(IDA_SUFFIX "64")

# IDA SDK paths
set(IDA_INCLUDE_DIR "${IDA_SDK_DIR}/include")

# Detect architecture for library path
# On macOS, check CMAKE_OSX_ARCHITECTURES for cross-compilation
message(STATUS "CMAKE_OSX_ARCHITECTURES: ${CMAKE_OSX_ARCHITECTURES}")
message(STATUS "CMAKE_SYSTEM_PROCESSOR: ${CMAKE_SYSTEM_PROCESSOR}")

if(APPLE)
    if(CMAKE_OSX_ARCHITECTURES)
        list(LENGTH CMAKE_OSX_ARCHITECTURES STRUCTOR_MAC_ARCH_COUNT)
        if(NOT STRUCTOR_MAC_ARCH_COUNT EQUAL 1)
            message(FATAL_ERROR
                "Universal/multi-architecture macOS builds are unsupported; configure exactly one of arm64 or x86_64")
        endif()
        if(CMAKE_OSX_ARCHITECTURES STREQUAL "arm64")
            set(IDA_ARCH "arm64")
        elseif(CMAKE_OSX_ARCHITECTURES STREQUAL "x86_64")
            set(IDA_ARCH "x64")
        else()
            message(FATAL_ERROR
                "Unsupported macOS architecture: ${CMAKE_OSX_ARCHITECTURES}")
        endif()
    elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "^(arm64|aarch64)$")
        set(IDA_ARCH "arm64")
    elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86_64|amd64|AMD64)$")
        set(IDA_ARCH "x64")
    else()
        message(FATAL_ERROR
            "Cannot map macOS processor '${CMAKE_SYSTEM_PROCESSOR}' to an IDA SDK architecture")
    endif()
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "^(arm64|aarch64|ARM64)$")
    set(IDA_ARCH "arm64")
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86_64|amd64|AMD64|x64)$")
    set(IDA_ARCH "x64")
else()
    message(FATAL_ERROR
        "Cannot map processor '${CMAKE_SYSTEM_PROCESSOR}' to an IDA SDK architecture")
endif()

message(STATUS "IDA_ARCH: ${IDA_ARCH}")

if(WIN32)
    set(IDA_LIB_DIR "${IDA_SDK_DIR}/lib/${IDA_ARCH}_win_${IDA_SUFFIX}")
elseif(APPLE)
    set(IDA_LIB_DIR "${IDA_SDK_DIR}/lib/${IDA_ARCH}_mac_${IDA_SUFFIX}")
else()
    set(IDA_LIB_DIR "${IDA_SDK_DIR}/lib/${IDA_ARCH}_linux_${IDA_SUFFIX}")
endif()

# Find IDA libraries - on Mac they're libida.dylib, not libida64.dylib
if(IDA_LIB AND NOT EXISTS "${IDA_LIB}")
    message(STATUS "Discarding stale cached IDA library path: ${IDA_LIB}")
    unset(IDA_LIB CACHE)
    unset(IDA_LIB)
endif()
find_library(IDA_LIB NAMES ida libida PATHS ${IDA_LIB_DIR} NO_DEFAULT_PATH)

# Hex-Rays doesn't ship as separate library on Mac - it's loaded dynamically
set(HEXRAYS_LIB "")

if(NOT IDA_LIB AND WIN32 AND STRUCTOR_BUILD_PLUGIN)
    message(FATAL_ERROR "IDA import library not found at ${IDA_LIB_DIR}; Windows plugin builds require ida.lib")
elseif(NOT IDA_LIB)
    message(WARNING "IDA library not found at ${IDA_LIB_DIR}, proceeding anyway for header-only development")
endif()

# Common compile definitions
set(STRUCTOR_PUBLIC_COMPILE_DEFINITIONS
    __IDP__
    USE_STANDARD_FILE_FUNCTIONS
    USE_DANGEROUS_FUNCTIONS
)

if(WIN32)
    list(APPEND STRUCTOR_PUBLIC_COMPILE_DEFINITIONS __NT__)
elseif(APPLE)
    list(APPEND STRUCTOR_PUBLIC_COMPILE_DEFINITIONS __MAC__)
else()
    list(APPEND STRUCTOR_PUBLIC_COMPILE_DEFINITIONS __LINUX__)
endif()

if(IDA_EA64)
    list(APPEND STRUCTOR_PUBLIC_COMPILE_DEFINITIONS __EA64__)
endif()

add_compile_definitions(${STRUCTOR_PUBLIC_COMPILE_DEFINITIONS})

# Compiler flags
if(MSVC)
    add_compile_options(/W4 /WX- /permissive- /Zc:__cplusplus)
else()
    add_compile_options(
        -Wall -Wextra -Wpedantic
        -Wno-unused-parameter
        -Wno-sign-compare
        -fPIC
        -fvisibility=hidden
        $<$<CONFIG:Debug>:-g>
        $<$<CONFIG:Debug>:-O0>
        $<$<CONFIG:Release>:-O3>
    )
endif()

# Include directories (structor include only - IDA includes added per-target)
include_directories(
    ${PROJECT_SOURCE_DIR}/include
)

# Source files - organized by module
set(STRUCTOR_CORE_SOURCES
    # Core module
    src/core/config.cpp
    src/core/host_integration.cpp
    
    # Analysis module
    src/analysis/access_collector.cpp
    src/analysis/cross_function_analyzer.cpp
    src/analysis/global_object_analyzer.cpp
    src/analysis/vtable_detector.cpp
    
    # Synthesis module
    src/synthesis/naming.cpp
    src/synthesis/layout_synthesizer.cpp
    src/synthesis/structure_persistence.cpp
    src/synthesis/type_matcher.cpp
    src/synthesis/type_propagator.cpp
    
    # Rewriter module
    src/ui/pseudocode_rewriter.cpp
    
    # Z3 module
    src/z3/context.cpp
    src/z3/type_encoding.cpp
    src/z3/constraint_tracker.cpp
    src/z3/field_candidates.cpp
    src/z3/array_constraints.cpp
    src/z3/layout_constraints.cpp
    src/z3/type_lattice.cpp
    src/z3/instruction_semantics.cpp
    src/z3/memory_type_evidence.cpp
    src/z3/type_inference_engine.cpp
    src/z3/alias_analysis.cpp
    src/z3/type_applicator.cpp
)

set(STRUCTOR_CORE_HEADERS
    include/structor/synth_types.hpp
    include/structor/config.hpp
    include/structor/host_integration.hpp
    include/structor/host_lifecycle.hpp
    include/structor/access_collector.hpp
    include/structor/access_type_inference.hpp
    include/structor/function_variable_key.hpp
    include/structor/field_fragment_type.hpp
    include/structor/layout_synthesizer.hpp
    include/structor/vtable_detector.hpp
    include/structor/global_object_analyzer.hpp
    include/structor/global_rewrite_index.hpp
    include/structor/global_tinfo_transaction.hpp
    include/structor/type_propagator.hpp
    include/structor/type_matcher.hpp
    include/structor/pseudocode_rewriter.hpp
    include/structor/structure_persistence.hpp
    include/structor/persistence_transaction.hpp
    include/structor/ui_integration.hpp
    include/structor/api.hpp
    include/structor/utils.hpp
    include/structor/cross_function_analyzer.hpp
    include/structor/call_graph.hpp
    include/structor/z3/context.hpp
    include/structor/z3/type_encoding.hpp
    include/structor/z3/constraint_tracker.hpp
    include/structor/z3/result.hpp
    include/structor/z3/field_candidates.hpp
    include/structor/z3/array_constraints.hpp
    include/structor/z3/union_constraints.hpp
    include/structor/z3/layout_constraints.hpp
    include/structor/z3/test_ir.hpp
    include/structor/z3/type_lattice.hpp
    include/structor/z3/instruction_semantics.hpp
    include/structor/z3/type_variable_identity.hpp
    include/structor/z3/alias_analysis.hpp
    include/structor/z3/type_inference_engine.hpp
    include/structor/z3/memory_type_evidence.hpp
    include/structor/z3/signature_argument_map.hpp
    include/structor/z3/calling_convention_model.hpp
    include/structor/z3/type_applicator.hpp
)

set(STRUCTOR_PLUGIN_SOURCES
    src/ui/plugin.cpp
    src/ui/ui_integration.cpp
)

set(STRUCTOR_PLUGIN_HEADERS
    include/structor/ui_integration.hpp
    src/ui/type_matcher_live_checks.hpp
    src/ui/type_application_live_checks.hpp
)

# Embeddable Structor core library
add_library(structor_core STATIC ${STRUCTOR_CORE_SOURCES} ${STRUCTOR_CORE_HEADERS})
add_library(structor::core ALIAS structor_core)

set_target_properties(structor_core PROPERTIES POSITION_INDEPENDENT_CODE ON)

target_include_directories(structor_core
    PUBLIC
        ${PROJECT_SOURCE_DIR}/include
        ${STRUCTOR_Z3_INCLUDE_DIRS}
)
target_include_directories(structor_core SYSTEM PUBLIC ${IDA_INCLUDE_DIR})

target_compile_definitions(structor_core
    PUBLIC
        ${STRUCTOR_PUBLIC_COMPILE_DEFINITIONS}
)
if(STRUCTOR_ENABLE_LIVE_TEST_HOOKS)
    # Test hooks are never propagated to embedding consumers.
    target_compile_definitions(structor_core PRIVATE STRUCTOR_LIVE_TEST_HOOKS=1)
endif()

if(IDA_LIB)
    target_link_libraries(structor_core PUBLIC ${IDA_LIB})
endif()

target_link_libraries(structor_core PUBLIC Threads::Threads)

if(HEXRAYS_LIB)
    target_link_libraries(structor_core PUBLIC ${HEXRAYS_LIB})
endif()

# Link Z3 into the actual Structor libraries/plugins instead of shipping it as
# a separate runtime dependency.
target_link_libraries(structor_core PUBLIC structor_z3)

if(STRUCTOR_BUILD_PLUGIN)
    # Plugin shared library wrapper
    add_library(structor${IDA_SUFFIX} SHARED ${STRUCTOR_PLUGIN_SOURCES} ${STRUCTOR_PLUGIN_HEADERS})
    add_library(structor::plugin ALIAS structor${IDA_SUFFIX})

    target_link_libraries(structor${IDA_SUFFIX} PRIVATE structor_core)

    target_include_directories(structor${IDA_SUFFIX} SYSTEM PRIVATE ${IDA_INCLUDE_DIR})
    target_compile_definitions(structor${IDA_SUFFIX} PRIVATE ${STRUCTOR_PUBLIC_COMPILE_DEFINITIONS})
    if(STRUCTOR_ENABLE_LIVE_TEST_HOOKS)
        target_compile_definitions(structor${IDA_SUFFIX} PRIVATE STRUCTOR_LIVE_TEST_HOOKS=1)
    endif()

    if(APPLE)
        # IDA plugins resolve IDA/Hex-Rays host symbols from the loading process.
        target_link_options(structor${IDA_SUFFIX} PRIVATE -Wl,-undefined,dynamic_lookup)
    elseif(MSVC)
        target_link_options(structor${IDA_SUFFIX} PRIVATE /SUBSYSTEM:WINDOWS)
    endif()

    # Set plugin output name and properties
    set_target_properties(structor${IDA_SUFFIX} PROPERTIES
        OUTPUT_NAME "structor"
        SUFFIX ${PLUGIN_EXT}
        PREFIX ""
        SKIP_BUILD_RPATH ON
        BUILD_RPATH ""
        INSTALL_RPATH ""
        INSTALL_RPATH_USE_LINK_PATH FALSE
    )

    # A relative destination makes --prefix/DESTDIR staging deterministic and
    # prevents packaging from writing into a developer's IDA installation.
    set(STRUCTOR_PLUGIN_INSTALL_DIR "plugins" CACHE STRING
        "Relative directory below CMAKE_INSTALL_PREFIX for the IDA plugin")
    if(IS_ABSOLUTE "${STRUCTOR_PLUGIN_INSTALL_DIR}")
        message(FATAL_ERROR "STRUCTOR_PLUGIN_INSTALL_DIR must be relative")
    endif()
    install(TARGETS structor${IDA_SUFFIX}
        LIBRARY DESTINATION "${STRUCTOR_PLUGIN_INSTALL_DIR}" COMPONENT Runtime
        RUNTIME DESTINATION "${STRUCTOR_PLUGIN_INSTALL_DIR}" COMPONENT Runtime
    )
    install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/THIRD_PARTY_NOTICES.md"
        DESTINATION "share/structor"
        COMPONENT Runtime
    )
endif()

# Tests
if(BUILD_TESTS)
    enable_testing()
    add_subdirectory(test)
endif()

# Export compile commands for IDE integration
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Print configuration summary
message(STATUS "")
message(STATUS "Structor Plugin Configuration:")
message(STATUS "  IDA SDK: ${IDA_SDK_DIR}")
message(STATUS "  Platform: ${IDA_PLATFORM}")
message(STATUS "  64-bit build: ${IDA_EA64}")
message(STATUS "  Live test hooks: ${STRUCTOR_ENABLE_LIVE_TEST_HOOKS}")
message(STATUS "  Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "")
