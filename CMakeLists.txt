cmake_minimum_required(VERSION 3.25)
project(xhunter_sdk VERSION 1.0.0 LANGUAGES C CXX)

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
set(PHNT_INCLUDE_DIR ${DEPS_DIR}/systeminformer/phnt/include)
set(XORSTR_INCLUDE_DIR ${DEPS_DIR}/xorstr)
set(NIRVANA_INCLUDE_DIR ${DEPS_DIR}/nirvana)
set(VMP_INCLUDE_DIR ${DEPS_DIR}/vmp)
set(NEARGYE_INCLUDE_DIR ${DEPS_DIR}/neargye)

# ------------------------------------------------------------------------------
# 1. Target: enc_dec (Binary header encoder tool + tests)
# ------------------------------------------------------------------------------
add_executable(enc_dec
    enc_dec/enc_dec.cpp
    enc_dec/doctest.h
)

target_include_directories(enc_dec PRIVATE
    enc_dec
)

# ------------------------------------------------------------------------------
# 2. Target: xhunter_sdk_lib (Core static library)
# ------------------------------------------------------------------------------
add_library(xhunter_sdk_lib STATIC
    xhunter_sdk_lib/xhunterapi.cpp
    xhunter_sdk_lib/xhunterapi.h
    xhunter_sdk_lib/util.hpp
    xhunter_sdk_lib/error.hpp
    xhunter_sdk_lib/xhunter1_sys_bin.h
)

target_include_directories(xhunter_sdk_lib PUBLIC
    xhunter_sdk_lib
    ${PHNT_INCLUDE_DIR}
    ${XORSTR_INCLUDE_DIR}
    ${NIRVANA_INCLUDE_DIR}
    ${VMP_INCLUDE_DIR}
    ${NEARGYE_INCLUDE_DIR}
)

target_link_libraries(xhunter_sdk_lib PUBLIC
    ntdll
    bcrypt
    advapi32
    kernel32
    user32
)

# ------------------------------------------------------------------------------
# 3. Target: xhunter_sdk (Sample / Integration Harness)
# ------------------------------------------------------------------------------
add_executable(xhunter_sdk
    xhunter_sdk/Main.cpp
)

target_include_directories(xhunter_sdk PRIVATE
    ${PHNT_INCLUDE_DIR}
    xhunter_sdk_lib
)

target_link_libraries(xhunter_sdk PRIVATE
    xhunter_sdk_lib
)
