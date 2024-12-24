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

#ifndef LIBTOS_TRANSPORT_H
#define LIBTOS_TRANSPORT_H

#include "../common/tos_sys_define.h"
#include "../common/tos_buf.h"


TOS_CPP_START

typedef struct tos_http_request_s tos_http_request_t;
typedef struct tos_http_response_s tos_http_response_t;
typedef struct tos_http_transport_s tos_http_transport_t;
typedef struct tos_http_controller_s tos_http_controller_t;

typedef struct tos_http_request_options_s tos_http_request_options_t;
typedef struct tos_http_transport_options_s tos_http_transport_options_t;
typedef struct tos_curl_http_transport_s tos_curl_http_transport_t;

typedef int (*tos_read_http_body_pt)(tos_http_request_t *req, char *buffer, int len);
typedef int (*tos_write_http_body_pt)(tos_http_response_t *resp, const char *buffer, int len);

typedef void (*tos_progress_callback)(int64_t consumed_bytes, int64_t total_bytes);

void tos_curl_response_headers_parse(tos_pool_t *p, tos_table_t *headers, char *buffer, int len);
tos_http_transport_t *tos_curl_http_transport_create(tos_pool_t *p);
int tos_curl_http_transport_perform(tos_http_transport_t *t);

struct tos_http_request_options_s {
    int socket_timeout;
    int dns_cache_timeout;
    int connect_timeout;
    int64_t max_memory_size;
    int enable_crc;
    char *proxy_host;
    char *proxy_auth;
    char *host_ip;
    int host_port;
};

struct tos_http_transport_options_s {
    char *user_agent;
    char *cacerts_path;
    uint32_t ssl_verification_disabled:1;
};

#define TOS_HTTP_BASE_CONTROLLER_DEFINE         \
    tos_http_request_options_t *options;        \
    tos_pool_t *pool;                           \
    int64_t start_time;                         \
    int64_t first_byte_time;                    \
    int64_t finish_time;                        \
    uint32_t owner:1;                           \
    void *user_data;

struct tos_http_controller_s {
    TOS_HTTP_BASE_CONTROLLER_DEFINE
};

typedef struct tos_http_controller_ex_s {
    TOS_HTTP_BASE_CONTROLLER_DEFINE
    // private
    int error_code;
    char *reason; // can't modify
} tos_http_controller_ex_t;

typedef enum {
    BODY_IN_MEMORY = 0,
    BODY_IN_FILE,
    BODY_IN_CALLBACK
} tos_http_body_type_e;

struct tos_http_request_s {
    char *host;
    char *proto;
    char *signed_url;
    
    http_method_e method;
    char *uri;
    char *resource;
    tos_table_t *headers;
    tos_table_t *query_params;
    
    tos_list_t body;
    int64_t body_len;
    char *file_path;
    tos_file_buf_t *file_buf;

    tos_pool_t *pool;
    void *user_data;
    tos_read_http_body_pt read_body;

    tos_http_body_type_e type;

    tos_progress_callback progress_callback;
    uint64_t crc64;
    int64_t  consumed_bytes;
    int clear_body;
};

struct tos_http_response_s {
    int status;
    tos_table_t *headers;

    tos_list_t body;
    int64_t body_len;
    char *file_path;
    tos_file_buf_t* file_buf;
    int64_t content_length;

    tos_pool_t *pool;
    void *user_data;
    tos_write_http_body_pt write_body;

    tos_http_body_type_e type;

    tos_progress_callback progress_callback;
    uint64_t crc64;
};

typedef enum {
    TRANS_STATE_INIT,
    TRANS_STATE_HEADER,
    TRANS_STATE_BODY_IN,
    TRANS_STATE_BODY_OUT,
    TRANS_STATE_ABORT,
    TRANS_STATE_DONE
} tos_transport_state_e;

#define TOS_HTTP_BASE_TRANSPORT_DEFINE           \
    tos_http_request_t *req;                     \
    tos_http_response_t *resp;                   \
    tos_pool_t *pool;                            \
    tos_transport_state_e state;                 \
    tos_array_header_t *cleanup;                 \
    tos_http_transport_options_t *options;       \
    tos_http_controller_ex_t *controller;
    
struct tos_http_transport_s {
    TOS_HTTP_BASE_TRANSPORT_DEFINE
};

struct tos_curl_http_transport_s {
    TOS_HTTP_BASE_TRANSPORT_DEFINE
    CURL *curl;
    CURLcode curl_code;
    char *url;
    struct curl_slist *headers;
    curl_read_callback header_callback;
    curl_read_callback read_callback;
    curl_write_callback write_callback;
};

TOS_CPP_END

#endif
