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

#ifndef TOS_JSON_H
#define TOS_JSON_H

#include <cjson/cJSON.h>
#include "../common/tos_string.h"
#include "../transport/tos_transport.h"
#include "../common/tos_define.h"


TOS_CPP_START



char *get_json_node_value_string(tos_pool_t *p, cJSON * root, const char *json_path);
int tos_upload_id_parse_from_body(tos_pool_t *p, tos_list_t *bc, tos_string_t *upload_id);
int get_json_node_value_int(cJSON* root,const char* json_path);
bool get_json_node_value_bool(cJSON* root,const char* json_path);
int64_t get_json_node_value_int64(cJSON* root,const char* json_path);

TOS_CPP_END

#endif //TOS_JSON_H
