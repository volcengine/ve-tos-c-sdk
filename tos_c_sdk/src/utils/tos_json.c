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

#include "../../include/common/tos_string.h"
#include "../../include/common/tos_list.h"
#include "../../include/common/tos_buf.h"

#include "../../include/common/tos_log.h"
#include "../../include/utils/tos_utility.h"
#include "../../include/auth/tos_auth.h"
#include "../../include/utils/tos_json.h"
#include "../../include/common/tos_define.h"
#include "../../include/common/tos_string.h"
#include "../../include/common/tos_list.h"
#include "../../include/utils/tos_sys_util.h"


char *get_json_node_value_string(tos_pool_t *p,cJSON* root,const char* json_path)
{
    char *value = NULL;
    cJSON *node;
    node = cJSON_GetObjectItem(root,json_path);
    if(node&&cJSON_IsString(node)&&node->valuestring!=NULL)
    {
        value = apr_pstrdup(p,node->valuestring);
    }
    return value;
}

int get_json_node_value_int(cJSON* root,const char* json_path){
    cJSON *node;
    node = cJSON_GetObjectItem(root,json_path);
    return node->valueint;
}

bool get_json_node_value_bool(cJSON* root,const char* json_path){
    cJSON *node;
    node = cJSON_GetObjectItem(root,json_path);
    return cJSON_IsTrue(node);
}

int64_t get_json_node_value_int64(cJSON* root,const char* json_path){
    cJSON *node;
    node = cJSON_GetObjectItem(root,json_path);
    return (int64_t)cJSON_GetNumberValue(node);
}


int tos_upload_id_parse_from_body(tos_pool_t *p, tos_list_t *bc, tos_string_t *upload_id)
{
    int res;
    cJSON *root;
    char *value=NULL;
    res = tos_parse_json_body(bc,&root);

    if(res == TOSE_OK)
    {
        value = get_json_node_value_string(p,root,"UploadId");
        if(value)
        {
            tos_str_set(upload_id,value);
        }
        cJSON_Delete(root);
    }
    return res;
}