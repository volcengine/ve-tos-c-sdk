cmake_minimum_required(VERSION 3.1)

PROJECT(ve_tos_c_sdk
        VERSION 2.1.0
        LANGUAGES C)


if(CMAKE_HOST_WIN32)

else()
    set(CMAKE_C_FLAGS " -g -ggdb -O0 -Wall -fpic -fPIC -D_LARGEFILE64_SOURCE")
    set(CMAKE_CXX_FLAGS " -g -ggdb -O0 -Wall -fpic -fPIC -D_LARGEFILE64_SOURCE")

    set(CMAKE_C_FLAGS_DEBUG " -g -ggdb -O0 -Wall -fpic -fPIC -D_LARGEFILE64_SOURCE")
    set(CMAKE_CXX_FLAGS_DEBUG " -g -ggdb -O0 -Wall -fpic -fPIC -D_LARGEFILE64_SOURCE")

    set(CMAKE_C_FLAGS_RELEASE " -O3 -Wall -fpic -fPIC -D_LARGEFILE64_SOURCE")
    set(CMAKE_CXX_FLAGS_RELEASE " -O3 -Wall -fpic -fPIC -D_LARGEFILE64_SOURCE")

    set(CMAKE_C_FLAGS_MINSIZEREF " -Os -Wall  -fpic -fPIC -D_LARGEFILE64_SOURCE")
    set(CMAKE_CXX_FLAGS_MINSIZEREF " -Os -Wall -fpic -fPIC -D_LARGEFILE64_SOURCE")

    set(CMAKE_C_FLAGS_RELWITHDEBINFO " -O2 -Wall -fpic -fPIC -D_LARGEFILE64_SOURCE")
    set(CMAKE_CXX_FLAGS_RELWITHDEBINFO " -O2 -Wall -fpic -fPIC -D_LARGEFILE64_SOURCE")

    set(CMAKE_C_FLAGS_COVERAGE " ${CMAKE_C_FLAGS_DEBUG} -fprofile-arcs -ftest-coverage")
    set(CMAKE_CXX_FLAGS_COVERAGE " ${CMAKE_C_FLAGS_DEBUG} -fprofile-arcs -ftest-coverage")
endif()


set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/build/${CMAKE_BUILD_TYPE}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/build/${CMAKE_BUILD_TYPE}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/build/${CMAKE_BUILD_TYPE}/bin)
set(CMAKE_C_OUTPUT_EXTENSION_REPLACE 1)
set(CMAKE_CXX_OUTPUT_EXTENSION_REPLACE 1)

FIND_PROGRAM(APR_CONFIG_BIN NAMES apr-config apr-1-config PATHS /usr/bin /usr/local/bin /usr/local/apr/bin/)
FIND_PROGRAM(APU_CONFIG_BIN NAMES apu-config apu-1-config PATHS /usr/bin /usr/local/bin /usr/local/apr/bin/)
FIND_PROGRAM(CURL_CONFIG_BIN NAMES curl-config)


IF (APR_CONFIG_BIN)
    EXECUTE_PROCESS(
            COMMAND ${APR_CONFIG_BIN} --includedir
            OUTPUT_VARIABLE APR_INCLUDE_DIR
            OUTPUT_STRIP_TRAILING_WHITESPACE
    )
ELSE()
    MESSAGE(FATAL_ERROR "Could not find apr-config/apr-1-config")
ENDIF()

IF (APU_CONFIG_BIN)
    EXECUTE_PROCESS(
            COMMAND ${APU_CONFIG_BIN} --includedir
            OUTPUT_VARIABLE APR_UTIL_INCLUDE_DIR
            OUTPUT_STRIP_TRAILING_WHITESPACE
    )
ELSE()
    MESSAGE(FATAL_ERROR "Could not find apu-config/apu-1-config")
ENDIF()


message(STATUS "APR_INCLUDE_DIR: ${APR_INCLUDE_DIR}")
message(STATUS "APR_UTIL_INCLUDE_DIR: ${APR_UTIL_INCLUDE_DIR}")


# options
option(BUILD_TEST_DEMO "Build test demo" OFF)

file(GLOB_RECURSE SRC_LIST "tos_c_sdk/*.c")

add_library(${CMAKE_PROJECT_NAME}_static STATIC ${SRC_LIST})
add_library(${CMAKE_PROJECT_NAME} SHARED ${SRC_LIST})


include_directories(
        ${APR_INCLUDE_DIR}
        ${APR_UTIL_INCLUDE_DIR}
        "tos_c_sdk/include"
)


INSTALL(TARGETS ${CMAKE_PROJECT_NAME}_static DESTINATION lib)
INSTALL(TARGETS ${CMAKE_PROJECT_NAME} DESTINATION lib)
INSTALL(DIRECTORY tos_c_sdk/include/ DESTINATION include/ve_tos_c_sdk FILES_MATCHING PATTERN "*.h")

if (BUILD_TEST_DEMO)
    add_subdirectory(tos_c_sdk_test)
endif ()