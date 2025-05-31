cmake_minimum_required(VERSION 3.16)

# Vcpkg Config
if(DEFINED ENV{VCPKG_ROOT} AND NOT DEFINED CMAKE_TOOLCHAIN_FILE)
    set(CMAKE_TOOLCHAIN_FILE "$ENV{VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake" CACHE STRING "")
endif()

# Project Config
project(VulneraTestX
    VERSION 0.1.0
    DESCRIPTION "Modern C++ Binary Fuzzing and Analysis Tool"
    LANGUAGES CXX
)

# Standard Config
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# GCC Config
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Wpedantic")
    set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -g -O0 -fsanitize=address,undefined -fno-omit-frame-pointer")
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O3 -DNDEBUG")
endif()


# Output Directories
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# Include Directories
include_directories(inc)

# Find Packages
find_package(GTest CONFIG REQUIRED)

# Core Library
file(GLOB_RECURSE LIB_SOURCES "src/*.cpp")
list(REMOVE_ITEM LIB_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/src/main.cpp")

add_library(VulneraTestXLib ${LIB_SOURCES})
target_include_directories(VulneraTestXLib
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/inc>
        $<INSTALL_INTERFACE:inc>
)

# Main Executable
add_executable(VulneraTestX src/main.cpp)
target_link_libraries(VulneraTestX VulneraTestXLib)

# Testing
enable_testing()

file(GLOB_RECURSE TEST_SOURCES "tests/*.cpp")
if(TEST_SOURCES)
    add_executable(VulneraTestXTests ${TEST_SOURCES})
    target_link_libraries(VulneraTestXTests
        VulneraTestXLib
        GTest::gtest
        GTest::gtest_main
    )

    # Discover tests
    include(GoogleTest)
    gtest_discover_tests(VulneraTestXTests)
endif()

# Target Binaries
file(GLOB TARGET_SOURCES "targets/*.cpp")
foreach(TARGET_SOURCE ${TARGET_SOURCES})
    get_filename_component(TARGET_NAME ${TARGET_SOURCE} NAME_WE)
    add_executable(${TARGET_NAME} ${TARGET_SOURCE})
    set_target_properties(${TARGET_NAME}
        PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/Targets
    )
endforeach()

# Installation

install(TARGETS VulneraTestX VulneraTestXLib
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
)

install(DIRECTORY inc/ DESTINATION inc)

# CPack Config
set(CPACK_PACKAGE_NAME "VulneraTestX")
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY ${PROJECT_DESCRIPTION})
include(CPack)
