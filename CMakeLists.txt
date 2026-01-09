cmake_minimum_required(VERSION 3.20)
project(structor VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# ============================================================================
# Z3 Theorem Prover Integration
# ============================================================================

# Allow specifying custom Z3 location
option(Z3_USE_CUSTOM "Use custom Z3 library instead of system" OFF)
set(Z3_CUSTOM_INCLUDE_DIR "" CACHE PATH "Custom Z3 include directory")
set(Z3_CUSTOM_LIBRARY "" CACHE FILEPATH "Custom Z3 library path")
set(Z3_CUSTOM_IMPLIB "" CACHE FILEPATH "Custom Z3 import library path (Windows only)")

if(Z3_USE_CUSTOM AND Z3_CUSTOM_INCLUDE_DIR AND Z3_CUSTOM_LIBRARY)
    message(STATUS "Using custom Z3: ${Z3_CUSTOM_LIBRARY}")
    set(Z3_USE_SYSTEM TRUE)
    set(Z3_CUSTOM TRUE)

    # Create imported target for custom Z3
    add_library(z3_custom SHARED IMPORTED)
    if(WIN32)
        # On Windows, we need the import library (.lib) for linking
        if(Z3_CUSTOM_IMPLIB)
            set_target_properties(z3_custom PROPERTIES
                IMPORTED_LOCATION "${Z3_CUSTOM_LIBRARY}"
                IMPORTED_IMPLIB "${Z3_CUSTOM_IMPLIB}"
                INTERFACE_INCLUDE_DIRECTORIES "${Z3_CUSTOM_INCLUDE_DIR}"
            )
        else()
            # Try to find .lib next to .dll or in lib/ directory
            get_filename_component(Z3_LIB_DIR "${Z3_CUSTOM_LIBRARY}" DIRECTORY)
            get_filename_component(Z3_LIB_DIR_PARENT "${Z3_LIB_DIR}" DIRECTORY)
            find_file(Z3_IMPLIB_FOUND
                NAMES libz3.lib z3.lib
                PATHS "${Z3_LIB_DIR}" "${Z3_LIB_DIR_PARENT}/lib"
                NO_DEFAULT_PATH
            )
            if(Z3_IMPLIB_FOUND)
                message(STATUS "Found Z3 import library: ${Z3_IMPLIB_FOUND}")
                set_target_properties(z3_custom PROPERTIES
                    IMPORTED_LOCATION "${Z3_CUSTOM_LIBRARY}"
                    IMPORTED_IMPLIB "${Z3_IMPLIB_FOUND}"
                    INTERFACE_INCLUDE_DIRECTORIES "${Z3_CUSTOM_INCLUDE_DIR}"
                )
            else()
                message(FATAL_ERROR "Z3_CUSTOM_IMPLIB not set and could not find import library (.lib) for Z3")
            endif()
        endif()
    else()
        set_target_properties(z3_custom PROPERTIES
            IMPORTED_LOCATION "${Z3_CUSTOM_LIBRARY}"
            INTERFACE_INCLUDE_DIRECTORIES "${Z3_CUSTOM_INCLUDE_DIR}"
        )
    endif()
else()
    # Try to find system Z3 first (much faster than building from source)
    find_package(Z3 CONFIG QUIET)

    if(Z3_FOUND)
        message(STATUS "Found system Z3: ${Z3_VERSION}")
        set(Z3_USE_SYSTEM TRUE)
        set(Z3_CUSTOM FALSE)
    else()
    message(STATUS "System Z3 not found, building from source (this takes 15+ minutes)...")
    include(FetchContent)

    # Z3 Theorem Prover - use release tag for reproducibility
    FetchContent_Declare(
        z3
        GIT_REPOSITORY https://github.com/Z3Prover/z3.git
        GIT_TAG        z3-4.13.0
        GIT_SHALLOW    TRUE
    )

    # Z3 build options - disable unnecessary components for faster builds
    set(Z3_BUILD_LIBZ3_SHARED OFF CACHE BOOL "" FORCE)
    set(Z3_BUILD_EXECUTABLE OFF CACHE BOOL "" FORCE)
    set(Z3_BUILD_TEST_EXECUTABLES OFF CACHE BOOL "" FORCE)
    set(Z3_ENABLE_EXAMPLE_TARGETS OFF CACHE BOOL "" FORCE)
    set(Z3_BUILD_DOCUMENTATION OFF CACHE BOOL "" FORCE)
    set(Z3_BUILD_JAVA_BINDINGS OFF CACHE BOOL "" FORCE)
    set(Z3_BUILD_PYTHON_BINDINGS OFF CACHE BOOL "" FORCE)
    set(Z3_BUILD_DOTNET_BINDINGS OFF CACHE BOOL "" FORCE)

        FetchContent_MakeAvailable(z3)
        set(Z3_USE_SYSTEM FALSE)
        set(Z3_CUSTOM FALSE)
    endif()
endif()

# Verify exceptions are enabled (required for Z3 C++ API)
if(CMAKE_CXX_FLAGS MATCHES "-fno-exceptions")
    message(FATAL_ERROR "Z3 C++ API requires exceptions. Remove -fno-exceptions.")
endif()

# macOS deployment target (12.0 = Monterey, matches IDA SDK requirement)
if(APPLE)
    if(NOT CMAKE_OSX_DEPLOYMENT_TARGET OR CMAKE_OSX_DEPLOYMENT_TARGET STREQUAL "")
        set(CMAKE_OSX_DEPLOYMENT_TARGET "12.0" CACHE STRING "Minimum macOS version" FORCE)
    endif()
endif()

# Build type
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# IDA SDK configuration
if(NOT DEFINED IDA_SDK_DIR)
    if(DEFINED ENV{IDA_SDK_DIR})
        set(IDA_SDK_DIR $ENV{IDA_SDK_DIR})
    else()
        message(FATAL_ERROR "IDA_SDK_DIR must be set to the IDA SDK directory")
    endif()
endif()

if(NOT DEFINED IDA_INSTALL_DIR)
    if(DEFINED ENV{IDA_INSTALL_DIR})
        set(IDA_INSTALL_DIR $ENV{IDA_INSTALL_DIR})
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
if(IDA_EA64)
    set(IDA_SUFFIX "64")
    add_compile_definitions(__EA64__)
else()
    set(IDA_SUFFIX "")
endif()

# IDA SDK paths
set(IDA_INCLUDE_DIR "${IDA_SDK_DIR}/include")

# Detect architecture for library path
# On macOS, check CMAKE_OSX_ARCHITECTURES for cross-compilation
message(STATUS "CMAKE_OSX_ARCHITECTURES: ${CMAKE_OSX_ARCHITECTURES}")
message(STATUS "CMAKE_SYSTEM_PROCESSOR: ${CMAKE_SYSTEM_PROCESSOR}")

if(APPLE)
    # Check target architecture - CMAKE_OSX_ARCHITECTURES takes precedence
    if(CMAKE_OSX_ARCHITECTURES STREQUAL "arm64")
        set(IDA_ARCH "arm64")
    elseif(CMAKE_OSX_ARCHITECTURES STREQUAL "x86_64")
        set(IDA_ARCH "x64")
    elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "arm64|aarch64")
        set(IDA_ARCH "arm64")
    else()
        set(IDA_ARCH "x64")
    endif()
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "arm64|aarch64")
    set(IDA_ARCH "arm64")
else()
    set(IDA_ARCH "x64")
endif()

message(STATUS "IDA_ARCH: ${IDA_ARCH}")

if(WIN32)
    set(IDA_LIB_DIR "${IDA_SDK_DIR}/lib/x64_win_vc_64")
elseif(APPLE)
    set(IDA_LIB_DIR "${IDA_SDK_DIR}/lib/${IDA_ARCH}_mac_clang_64")
else()
    set(IDA_LIB_DIR "${IDA_SDK_DIR}/lib/x64_linux_gcc_64")
endif()

# Find IDA libraries - on Mac they're libida.dylib, not libida64.dylib
find_library(IDA_LIB NAMES ida libida PATHS ${IDA_LIB_DIR} NO_DEFAULT_PATH)

# Hex-Rays doesn't ship as separate library on Mac - it's loaded dynamically
set(HEXRAYS_LIB "")

if(NOT IDA_LIB)
    message(WARNING "IDA library not found at ${IDA_LIB_DIR}, proceeding anyway for header-only development")
endif()

# Common compile definitions
add_compile_definitions(
    __IDP__
    USE_STANDARD_FILE_FUNCTIONS
    USE_DANGEROUS_FUNCTIONS
)

if(WIN32)
    add_compile_definitions(__NT__)
elseif(APPLE)
    add_compile_definitions(__MAC__)
else()
    add_compile_definitions(__LINUX__)
endif()

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
    )
    if(CMAKE_BUILD_TYPE STREQUAL "Debug")
        add_compile_options(-g -O0)
    else()
        add_compile_options(-O3)
    endif()
endif()

# Include directories (structor include only - IDA includes added per-target)
include_directories(
    ${CMAKE_SOURCE_DIR}/include
)

# Source files
set(STRUCTOR_SOURCES
    src/plugin.cpp
    src/config.cpp
    src/access_collector.cpp
    src/layout_synthesizer.cpp
    src/vtable_detector.cpp
    src/type_propagator.cpp
    src/pseudocode_rewriter.cpp
    src/structure_persistence.cpp
    src/ui_integration.cpp
    src/z3/context.cpp
    src/z3/type_encoding.cpp
    src/z3/constraint_tracker.cpp
    src/z3/field_candidates.cpp
    src/z3/array_constraints.cpp
    src/z3/layout_constraints.cpp
    src/cross_function_analyzer.cpp
)

set(STRUCTOR_HEADERS
    include/structor/synth_types.hpp
    include/structor/config.hpp
    include/structor/access_collector.hpp
    include/structor/layout_synthesizer.hpp
    include/structor/vtable_detector.hpp
    include/structor/type_propagator.hpp
    include/structor/pseudocode_rewriter.hpp
    include/structor/structure_persistence.hpp
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
    include/structor/z3/layout_constraints.hpp
    include/structor/z3/test_ir.hpp
)

# Plugin shared library
add_library(structor${IDA_SUFFIX} SHARED ${STRUCTOR_SOURCES} ${STRUCTOR_HEADERS})

# Add IDA SDK includes to structor target (not globally, to avoid contaminating tests)
target_include_directories(structor${IDA_SUFFIX} PRIVATE ${IDA_INCLUDE_DIR})

if(IDA_LIB)
    target_link_libraries(structor${IDA_SUFFIX} PRIVATE ${IDA_LIB})
endif()

if(HEXRAYS_LIB)
    target_link_libraries(structor${IDA_SUFFIX} PRIVATE ${HEXRAYS_LIB})
endif()

# Link Z3 to structor
if(Z3_CUSTOM)
    target_link_libraries(structor${IDA_SUFFIX} PRIVATE z3_custom)
elseif(Z3_USE_SYSTEM)
    target_link_libraries(structor${IDA_SUFFIX} PRIVATE z3::libz3)
    # System Z3 includes are handled by the imported target
else()
    target_link_libraries(structor${IDA_SUFFIX} PRIVATE libz3)
    target_include_directories(structor${IDA_SUFFIX} PRIVATE
        ${z3_SOURCE_DIR}/src/api      # C API headers (z3.h)
        ${z3_SOURCE_DIR}/src/api/c++  # C++ API headers (z3++.h)
        ${z3_BINARY_DIR}/src/api      # Generated headers
    )
endif()

# Set plugin output name and properties
set_target_properties(structor${IDA_SUFFIX} PROPERTIES
    OUTPUT_NAME "structor"
    SUFFIX ${PLUGIN_EXT}
    PREFIX ""
)

# Install target
if(IDA_INSTALL_DIR)
    install(TARGETS structor${IDA_SUFFIX}
        LIBRARY DESTINATION "${IDA_INSTALL_DIR}/plugins"
        RUNTIME DESTINATION "${IDA_INSTALL_DIR}/plugins"
    )
endif()

# Tests
option(BUILD_TESTS "Build unit tests" OFF)
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
message(STATUS "  Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "")
