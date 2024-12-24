cmake_minimum_required(VERSION 3.1)
project (tos_c_sdk_test)

include_directories(${CMAKE_SOURCE_DIR})

set(TEST_OBJECT_BASE_SOURCE_FILES src/tos_demo.c)


include_directories (${APR_INCLUDE_DIR})
include_directories (${APR_UTIL_INCLUDE_DIR})
include_directories (${MINIXML_INCLUDE_DIR})
include_directories (${CURL_INCLUDE_DIR})
include_directories ("${CMAKE_SOURCE_DIR}/tos_c_sdk/include")

find_library(APR_LIBRARY apr-1 PATHS /usr/local/apr/lib/)
find_library(APR_UTIL_LIBRARY aprutil-1 PATHS /usr/local/apr/lib/)
find_library(MINIXML_LIBRARY mxml)
find_library(CURL_LIBRARY curl)
find_library(CJSON_LIBRARY cjson)

find_package(Threads REQUIRED)

add_executable(object_base ${TEST_OBJECT_BASE_SOURCE_FILES})

target_link_libraries(object_base ve_tos_c_sdk ${APR_UTIL_LIBRARY} ${APR_LIBRARY} ${MINIXML_LIBRARY} ${CURL_LIBRARY} ${CJSON_LIBRARY} ${CMAKE_THREAD_LIBS_INIT})


