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

#ifndef CREATE_MULTIPART_UPLOAD_INPUT_H
#define CREATE_MULTIPART_UPLOAD_INPUT_H
#include "common/tos_string.h"
#include "common/tos_define.h"
#include "tos_error.h"
#include "transport/tos_transport.h"

TOS_CPP_START
typedef struct  create_multipart_upload_input_s create_multipart_upload_input_t;
struct create_multipart_upload_input_s
{
    tos_string_t bucket;
    tos_string_t key;
    storage_class_type storage_class;
    tos_string_t encoding_type;
    tos_string_t cache_control;

    int64_t content_length;
    tos_string_t content_disposition;
    tos_string_t content_encoding;
    tos_string_t content_language;
    tos_string_t content_type;

    apr_time_t expires;
    acl_type acl;

    tos_string_t grant_full_control;
    tos_string_t grant_read;
    tos_string_t grant_read_acp;
    tos_string_t grant_write;
    tos_string_t grant_write_acp;

    tos_string_t ssec_algorithm;
    tos_string_t ssec_key;
    tos_string_t ssec_key_md5;
    tos_string_t server_side_encryption;

    tos_table_t* meta;
    tos_string_t website_redirect_location;
    tos_string_t tagging;
};

int create_multipart_upload_input_new(tos_pool_t *p,create_multipart_upload_input_t **input);

typedef struct  create_multipart_upload_output_s create_multipart_upload_output_t;

struct  create_multipart_upload_output_s{
    tos_string_t request_id;
    tos_string_t id2; // 定位问题的特殊符号
    int status_code; // http code
    tos_table_t *headers;

    tos_string_t bucket;
    tos_string_t key;
    tos_string_t upload_id;
    tos_string_t ssec_algorithm;
    tos_string_t ssec_key_md5;
    tos_string_t encoding_type;
    tos_string_t server_side_encryption;
    tos_string_t server_side_encryption_key_id;
};

tos_error_t *create_multipart_upload_output_parse_from_resp(tos_pool_t *p, tos_http_response_t *resp, create_multipart_upload_output_t** output);

TOS_CPP_END

#endif //CREATE_MULTIPART_UPLOAD_INPUT_H
