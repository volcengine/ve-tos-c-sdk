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

#ifndef VE_TOS_C_SDK_COMPLETE_MULTIPART_UPLOAD_H
#define VE_TOS_C_SDK_COMPLETE_MULTIPART_UPLOAD_H
#include "common/tos_string.h"
#include <stdbool.h>
#include "common/tos_define.h"
#include "tos_error.h"


typedef struct complete_multipart_upload_input_s complete_multipart_upload_input_t;
struct complete_multipart_upload_input_s{
    tos_string_t bucket;
    tos_string_t key;
    tos_string_t upload_id;
    tos_list_t parts;
};

typedef struct complete_multipart_upload_output_s complete_multipart_upload_output_t;

struct complete_multipart_upload_output_s{
    tos_string_t request_id;
    tos_string_t id2; // 定位问题的特殊符号
    int status_code; // http code
    tos_table_t *headers;

    tos_string_t bucket;
    tos_string_t key;
    tos_string_t etag;
    tos_string_t location;
    tos_string_t version_id;
    uint64_t hash_crc64ecma;
};
char *build_complete_multipart_upload_json(tos_pool_t *p, tos_list_t *bc);
tos_error_t* complete_multipart_upload_body_create(tos_pool_t *p, tos_list_t *part_list, tos_list_t *body);
tos_error_t *complete_multipart_upload_output_parse_from_resp(tos_pool_t *p, tos_http_response_t *resp, complete_multipart_upload_output_t** output);
int complete_multipart_upload_input_new(tos_pool_t *p,complete_multipart_upload_input_t **input);

#endif //VE_TOS_C_SDK_COMPLETE_MULTIPART_UPLOAD_H
