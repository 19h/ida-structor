cmake_minimum_required(VERSION 3.20)
project(structor VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

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
if(APPLE AND CMAKE_OSX_ARCHITECTURES)
    if(CMAKE_OSX_ARCHITECTURES MATCHES "arm64")
        set(IDA_ARCH "arm64")
    else()
        set(IDA_ARCH "x64")
    endif()
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "arm64|aarch64")
    set(IDA_ARCH "arm64")
else()
    set(IDA_ARCH "x64")
endif()

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

# Include directories
include_directories(
    ${CMAKE_SOURCE_DIR}/include
    ${IDA_INCLUDE_DIR}
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
)

# Plugin shared library
add_library(structor${IDA_SUFFIX} SHARED ${STRUCTOR_SOURCES} ${STRUCTOR_HEADERS})

if(IDA_LIB)
    target_link_libraries(structor${IDA_SUFFIX} PRIVATE ${IDA_LIB})
endif()

if(HEXRAYS_LIB)
    target_link_libraries(structor${IDA_SUFFIX} PRIVATE ${HEXRAYS_LIB})
endif()

# Set plugin output name and properties
set_target_properties(structor${IDA_SUFFIX} PROPERTIES
    OUTPUT_NAME "structor${IDA_SUFFIX}"
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
