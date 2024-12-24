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

#ifndef TOS_ERROR_H
#define TOS_ERROR_H

#include "transport/tos_transport.h"
#include "common/tos_string.h"
#include <stdbool.h>

TOS_CPP_START

extern const char ERR_MSG_INVALID_EXPIRES[];
extern const char ERR_MSG_INVALID_SSEC_ALGORITHM[];
extern const char ERR_MSG_BOTH_SSEC_AND_SSE_ARE_SET[];
extern const char ERR_MSG_EMPTY_SSEC_KEY_OR_KEY_MD5[];
extern const char ERR_MSG_INVALID_ENCRYPTION_DECRYPTION_ALGORITHM[];
extern const char ERR_MSG_INVALID_META_KEY_OR_VALUE[];

typedef struct tos_error_s tos_error_t;

struct tos_error_s {
    tos_string_t request_id;
    tos_string_t id2; // 定位问题的特殊符号
    int status_code; // http code
    tos_table_t *headers;
    tos_string_t ec;
    tos_string_t host_id;
    tos_string_t resource;
    tos_string_t code; // 服务端返回的 Code
    tos_string_t message;

    int client_error_code;
    bool is_curl_error;

    bool is_client_error;
};

#define tos_error_set_client_error_code(s, c)                                    \
    do {                                                                        \
        (s)->client_error_code = (c);                                          \
        (s)->is_curl_error = ((c) > 0);                                        \
    } while (0)

#define tos_error_set_message(s, msg)                                    \
    do {                                                                \
        tos_str_set(&(s)->message,msg);                                   \
    } while (0)

#define tos_error_set_is_client_error(s, ice)               \
    do {                                                                \
        (s)->is_client_error = (ice);                      \
    } while (0)


tos_error_t *tos_error_create(tos_pool_t *p);

tos_error_t *tos_client_error_create(tos_pool_t *p, int client_error_code, const char *error_msg);

tos_error_t *tos_server_error_create(tos_pool_t *p, const tos_http_response_t *resp, const char *error_msg);

tos_error_t *tos_error_parse_from_resp(tos_pool_t *p, tos_http_response_t *resp, tos_error_t *tos_error);

TOS_CPP_END

#endif //TOS_ERROR_H
