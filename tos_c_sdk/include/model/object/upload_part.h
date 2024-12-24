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

#ifndef VE_TOS_C_SDK_UPLOAD_PART_H
#define VE_TOS_C_SDK_UPLOAD_PART_H
#include "common/tos_string.h"
#include "tos_error.h"
#include "transport/tos_transport.h"

// upload_part_from_file
typedef struct upload_part_from_file_input_s upload_part_from_file_input_t;

struct upload_part_from_file_input_s {
    tos_string_t bucket;
    tos_string_t key;
    tos_string_t upload_id;
    int part_number;
    tos_string_t content_md5;

    tos_string_t ssec_algorithm;
    tos_string_t ssec_key;
    tos_string_t ssec_key_md5;

    tos_string_t file_path;
    int64_t  offset;
    int64_t part_size;
};

typedef struct upload_part_from_file_output_s upload_part_from_file_output_t;
struct upload_part_from_file_output_s{
    tos_string_t request_id;
    tos_string_t ec;
    tos_string_t code;
    tos_string_t id2; // 定位问题的特殊符号
    int status_code; // http code
    tos_table_t *headers;

    int part_number;
    tos_string_t etag;
    tos_string_t ssec_algorithm;
    tos_string_t ssec_key_md5;
    uint64_t hash_crc64ecma;
};


// upload_part_from_buffer
typedef struct upload_part_from_buffer_input_s upload_part_from_buffer_input_t;
struct upload_part_from_buffer_input_s {
    tos_string_t bucket;
    tos_string_t key;
    tos_string_t upload_id;
    int part_number;
    tos_string_t content_md5;

    tos_string_t ssec_algorithm;
    tos_string_t ssec_key;
    tos_string_t ssec_key_md5;

    tos_list_t *content;
    int64_t content_length;
};

typedef struct upload_part_from_buffer_output_s upload_part_from_buffer_output_t;
struct upload_part_from_buffer_output_s{
    tos_string_t request_id;
    tos_string_t id2; // 定位问题的特殊符号
    int status_code; // http code
    tos_table_t *headers;

    int part_number;
    tos_string_t etag;
    tos_string_t ssec_algorithm;
    tos_string_t ssec_key_md5;
    uint64_t hash_crc64ecma;
};

// func
int upload_part_from_file_input_new(tos_pool_t *p,upload_part_from_file_input_t **input);
tos_error_t *upload_part_from_file_output_parse_from_resp(tos_pool_t *p, tos_http_response_t *resp, upload_part_from_file_output_t **output);

int upload_part_from_buffer_input_new(tos_pool_t *p,upload_part_from_buffer_input_t **input);
tos_error_t *upload_part_from_buffer_output_parse_from_resp(tos_pool_t *p, tos_http_response_t *resp, upload_part_from_buffer_output_t **output);

#endif //VE_TOS_C_SDK_UPLOAD_PART_H
