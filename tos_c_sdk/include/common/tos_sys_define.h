// Copyright (c) 2024 Beijing Volcano Engine Technology Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef LIBTOS_SYS_DEFINE_H
#define LIBTOS_SYS_DEFINE_H

#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <ctype.h>
#include <time.h>

#include <apr_portable.h>
#include <apr_time.h>
#include <apr_strings.h>
#include <apr_pools.h>
#include <apr_tables.h>
#include <apr_file_io.h>

#include <curl/curl.h>

#ifdef __cplusplus
# define TOS_CPP_START extern "C" {
# define TOS_CPP_END }
#else
# define TOS_CPP_START
# define TOS_CPP_END
#endif

typedef enum {
    HTTP_GET,
    HTTP_HEAD,
    HTTP_PUT,
    HTTP_POST,
    HTTP_DELETE
} http_method_e;

typedef enum {
    TOSE_OK = 0,
    TOSE_OUT_MEMORY = -10000,
    TOSE_INVALID_ARGUMENT = -9999,
    TOSE_INTERNAL_ERROR = -9998,
    TOSE_CREATE_TRANSPORT_FAILED = -9997,
    TOSE_WRITE_BODY_ERROR = -9996,
    TOSE_READ_BODY_ERROR = -9995,
    TOSE_OPEN_FILE_ERROR = -9994,
    TOSE_FILE_READ_ERROR = -9993,
    TOSE_FILE_WRITE_ERROR = -9992,
    TOSE_FILE_INFO_ERROR = -9991,
} tos_error_code_e;

typedef apr_pool_t tos_pool_t;
typedef apr_table_t tos_table_t;
typedef apr_table_entry_t tos_table_entry_t;
typedef apr_array_header_t tos_array_header_t;

#define tos_table_elts(t) apr_table_elts(t)
#define tos_is_empty_table(t) apr_is_empty_table(t)
#define tos_table_make(p, n) apr_table_make(p, n)
#define tos_table_add(t, key, value) apr_table_add(t, key, value)
#define tos_table_add_int(t, key, value) do {       \
        char value_str[64];                             \
        apr_snprintf(value_str, sizeof(value_str), "%d", value);\
        apr_table_add(t, key, value_str);               \
    } while(0)

#define tos_table_add_int64(t, key, value) do {       \
        char value_str[64];                             \
        apr_snprintf(value_str, sizeof(value_str), "%" APR_INT64_T_FMT, value);\
        apr_table_add(t, key, value_str);               \
    } while(0)

#define tos_table_add_float(t, key, value) do {       \
        char value_str[64];                             \
        apr_snprintf(value_str, sizeof(value_str), "%f", value);\
        apr_table_add(t, key, value_str);               \
    } while(0)

#define tos_table_set_int64(t, key, value) do {       \
        char value_str[64];                             \
        apr_snprintf(value_str, sizeof(value_str), "%" APR_INT64_T_FMT, value);\
        apr_table_set(t, key, value_str);               \
    } while(0)

#define tos_pool_create(n, p) apr_pool_create(n, p)
#define tos_pool_destroy(p) apr_pool_destroy(p)
#define tos_palloc(p, s) apr_palloc(p, s)
#define tos_pcalloc(p, s) apr_pcalloc(p, s)

#define TOS_RETRY_TIME 2

#define TOS_INIT_WINSOCK 1
#define TOS_MD5_STRING_LEN 32
#define TOS_MAX_URI_LEN 2048
#define TOS_MAX_HEADER_LEN 8192
#define TOS_MAX_QUERY_ARG_LEN 2048
#define TOS_MAX_GMT_TIME_LEN 128

#define TOS_MAX_XML_NODE_VALUE_LEN 1024
#define TOS_MAX_INT64_STRING_LEN 64
#define TOS_MAX_UINT64_STRING_LEN 64

#define TOS_CONNECT_TIMEOUT 10
#define TOS_DNS_CACHE_TIMOUT 60
#define TOS_MIN_SOCKET_TIMEOUT 120
#define TOS_MAX_MEMORY_SIZE 1024*1024*1024L
#define TOS_MAX_PART_SIZE 512*1024*1024L
#define TOS_DEFAULT_PART_SIZE 1024*1024L
#define TOS_SHA256_HASH_LEN 32
#define TOS_MAX_SHORT_TIME_LEN 10

#define TOS_REQUEST_STACK_SIZE 32

#define tos_abs(value)       (((value) >= 0) ? (value) : - (value))
#define tos_max(val1, val2)  (((val1) < (val2)) ? (val2) : (val1))
#define tos_min(val1, val2)  (((val1) > (val2)) ? (val2) : (val1))

#define LF     (char) 10
#define CR     (char) 13
#define CRLF   "\x0d\x0a"

#define TOS_VERSION    "v2.1.0"
#define TOS_VER        "ve-tos-c-sdk/" TOS_VERSION

#define TOS_HTTP_PREFIX   "http://"
#define TOS_HTTPS_PREFIX  "https://"
#define TOS_RTMP_PREFIX   "rtmp://"

#define TOS_TEMP_FILE_SUFFIX  ".tmp"

#define TOS_FALSE     0
#define TOS_TRUE      1

#endif
