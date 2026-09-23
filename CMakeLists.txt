cmake_minimum_required(VERSION 3.25)
project(xc3 VERSION 1.0.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Global compiler definitions & flags
if(MSVC)
    add_compile_options(
        /permissive-
        /Zc:inline
        /Zc:forScope
        /Zc:wchar_t
        /EHsc
    )
    add_compile_definitions(
        _UNICODE
        UNICODE
        WIN32_LEAN_AND_MEAN
        PHNT_NO_INLINE_INIT_STRING
    )
endif()

# Output directories
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)

# Include directories
set(DEPS_DIR ${CMAKE_SOURCE_DIR}/deps)
set(DOCTEST_INCLUDE_DIR ${DEPS_DIR}/doctest)
set(PHNT_INCLUDE_DIR ${DEPS_DIR}/systeminformer/phnt/include)
set(XORSTR_INCLUDE_DIR ${DEPS_DIR}/xorstr)
set(NIRVANA_INCLUDE_DIR ${DEPS_DIR}/nirvana)
set(VMP_INCLUDE_DIR ${DEPS_DIR}/vmp)
set(SCOPE_GUARD_INCLUDE_DIR ${DEPS_DIR}/neargye/scope_guard/include)
set(MAGIC_ENUM_INCLUDE_DIR ${DEPS_DIR}/neargye/magic_enum/include)

# ------------------------------------------------------------------------------
# 1. Target: bin2header (Binary header encoder tool + tests)
# ------------------------------------------------------------------------------
add_executable(bin2header
    src/tools/bin2header/bin2header.cpp
    deps/doctest/doctest.h
)

target_include_directories(bin2header PRIVATE
    src/tools/bin2header
    ${DEPS_DIR}
    ${DOCTEST_INCLUDE_DIR}
)

# ------------------------------------------------------------------------------
# 2. Target: xc3_api (Core static library)
# ------------------------------------------------------------------------------
add_library(xc3_api STATIC
    src/xc3_api/xc3api.h
    src/xc3_api/error.hpp
    src/xc3_api/xc3api.cpp
    src/xc3_api/util.hpp
    src/xc3_api/xhunter1_sys_bin.h
)

target_include_directories(xc3_api
    PUBLIC
        src/xc3_api
    PRIVATE
        ${PHNT_INCLUDE_DIR}
        ${XORSTR_INCLUDE_DIR}
        ${NIRVANA_INCLUDE_DIR}
        ${VMP_INCLUDE_DIR}
        ${SCOPE_GUARD_INCLUDE_DIR}
        ${MAGIC_ENUM_INCLUDE_DIR}
        ${DEPS_DIR}
)

target_link_libraries(xc3_api PUBLIC
    ntdll
    bcrypt
    advapi32
    kernel32
    user32
)

# ------------------------------------------------------------------------------
# 3. Target: xc3_cli (Sample / Integration Harness)
# ------------------------------------------------------------------------------
add_executable(xc3_cli
    src/xc3_cli/Main.cpp
)

target_include_directories(xc3_cli PRIVATE
    ${PHNT_INCLUDE_DIR}
)

target_link_libraries(xc3_cli PRIVATE
    xc3_api
)

# ------------------------------------------------------------------------------
# 4. Target: test_lifecycle (Integration test for service lifecycle)
# ------------------------------------------------------------------------------
add_executable(test_lifecycle
    tests/test_lifecycle.cpp
)

target_include_directories(test_lifecycle PRIVATE
    ${PHNT_INCLUDE_DIR}
    ${XORSTR_INCLUDE_DIR}
    ${NIRVANA_INCLUDE_DIR}
    ${VMP_INCLUDE_DIR}
    ${SCOPE_GUARD_INCLUDE_DIR}
    ${MAGIC_ENUM_INCLUDE_DIR}
    ${DEPS_DIR}
)

target_link_libraries(test_lifecycle PRIVATE
    xc3_api
)
