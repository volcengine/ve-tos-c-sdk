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

#ifndef VE_TOS_C_SDK_ABORT_MULTIPART_UPLOAD_H
#define VE_TOS_C_SDK_ABORT_MULTIPART_UPLOAD_H
#include "common/tos_string.h"
#include "tos_error.h"
#include "transport/tos_transport.h"

// abort_multipart_upload
typedef struct abort_multipart_upload_input_s abort_multipart_upload_input_t;
struct abort_multipart_upload_input_s{
    tos_string_t bucket;
    tos_string_t key;
    tos_string_t upload_id;
};

typedef struct abort_multipart_upload_output_s abort_multipart_upload_output_t;
struct abort_multipart_upload_output_s {
    tos_string_t request_id;
    tos_string_t id2; // 定位问题的特殊符号
    int status_code; // http code
    tos_table_t *headers;
};

tos_error_t *abort_multipart_upload_output_parse_from_resp(tos_pool_t *p, tos_http_response_t *resp, abort_multipart_upload_output_t** output);

int abort_multipart_upload_input_new(tos_pool_t *p, abort_multipart_upload_input_t **input);
int abort_multipart_upload_output_new(tos_pool_t *p, abort_multipart_upload_output_t **output);

#endif //VE_TOS_C_SDK_ABORT_MULTIPART_UPLOAD_H

