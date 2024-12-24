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

#ifndef VE_TOS_C_SDK_LIST_PART_INPUT_H
#define VE_TOS_C_SDK_LIST_PART_INPUT_H
#include "common/tos_string.h"
#include "tos_error.h"
#include "transport/tos_transport.h"
#include <stdbool.h>
#include "common/tos_define.h"

typedef struct {
    tos_string_t bucket;
    tos_string_t key;
    tos_string_t upload_id;
    int part_number_marker;
    int max_parts;
}list_parts_input_t;


typedef struct  {
    tos_list_t node;
    int part_number;
    tos_string_t etag;
    int64_t size;
    tos_string_t last_modified;
}upload_part_t;


typedef struct{
    tos_string_t id;
    tos_string_t display_name;
} owner_t;


typedef struct  {
    tos_string_t request_id;
    tos_string_t id2; // 定位问题的特殊符号
    int status_code; // http code
    tos_table_t *headers;

    tos_string_t bucket;
    tos_string_t key;
    tos_string_t upload_id;
    int part_number_marker;
    int max_parts;
    bool is_truncated;

    int next_part_number_marker;
    storage_class_type storage_class;
    owner_t owner;
    tos_list_t parts;
}list_parts_output_t;

tos_error_t *list_parts_output_parse_from_resp(tos_pool_t *p, tos_http_response_t *resp, list_parts_output_t** output);

int list_parts_input_new(tos_pool_t *p, list_parts_input_t **input);
int list_part_output_new(tos_pool_t *p, list_parts_output_t **output);
upload_part_t *create_list_parts_content(tos_pool_t *p);

#endif //VE_TOS_C_SDK_LIST_PART_INPUT_H
