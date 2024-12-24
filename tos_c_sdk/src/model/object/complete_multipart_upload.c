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

#include "model/object/complete_multipart_upload.h"
#include "model/object/list_parts.h"
#include "cjson/cJSON.h"
#include "utils/tos_sys_util.h"
#include "utils/tos_json.h"


char *build_complete_multipart_upload_json(tos_pool_t *p, tos_list_t *bc){
    char *json_buff;
    char *complete_part_json;
    tos_string_t json_doc;
    cJSON *root_node;
    cJSON *parts_array;
    upload_part_t *content;

    root_node = cJSON_CreateObject();
    if (root_node == NULL){
        return NULL;
    }
    parts_array = cJSON_CreateArray();
    if (parts_array == NULL) {
        cJSON_Delete(root_node);
        return NULL;
    }

    tos_list_for_each_entry(upload_part_t, content, bc, node){
        cJSON *part = cJSON_CreateObject();
        if (part == NULL) {
            cJSON_Delete(parts_array);
            cJSON_Delete(root_node);
            return NULL;
        }
        cJSON_AddItemToObject(part, "PartNumber", cJSON_CreateNumber(content->part_number));
        cJSON_AddItemToObject(part, "ETag", cJSON_CreateString(content->etag.data));
        cJSON_AddItemToArray(parts_array, part);
    }

    cJSON_AddItemToObject(root_node, "Parts", parts_array);

    json_buff = cJSON_Print(root_node);
    if (json_buff == NULL) {
        cJSON_Delete(root_node);
        return NULL;
    }

    tos_str_set(&json_doc,json_buff);

    complete_part_json = tos_pstrdup(p,&json_doc);


    free(json_buff);
    cJSON_Delete(root_node);

    return complete_part_json;
}

tos_error_t* complete_multipart_upload_body_create(tos_pool_t *p, tos_list_t *part_list, tos_list_t *body){
    char *complete_multipart_upload_json;
    tos_buf_t *b;

    complete_multipart_upload_json = build_complete_multipart_upload_json(p,part_list);
    tos_list_init(body);
    b = tos_buf_pack(p, complete_multipart_upload_json, strlen(complete_multipart_upload_json));
    tos_list_add_tail(&b->node, body);
    return NULL;
}

tos_error_t *complete_multipart_upload_output_parse_from_resp(tos_pool_t *p, tos_http_response_t *resp, complete_multipart_upload_output_t** output){
    int res = TOSE_OK;
    cJSON *root;
    char *value=NULL;
    tos_error_t *tos_error = NULL;

    if (resp->status >= 300 || resp->status == 203)
    {
        res = tos_parse_json_body(&resp->body,&root);
        if (res != TOSE_OK){
            tos_error = tos_server_error_create(p,resp,apr_psprintf(p, "unexpected status code: %d", resp->status));
            return tos_error;
        }

        value = get_json_node_value_string(p,root,"Message");
        tos_error = tos_server_error_create(p,resp,apr_psprintf(p, "%s", value));

        value = get_json_node_value_string(p,root,"Code");
        tos_str_set(&tos_error->code,value);

        value = get_json_node_value_string(p,root,"EC");
        tos_str_set(&tos_error->ec,value);

        value = get_json_node_value_string(p,root,"HostId");
        tos_str_set(&tos_error->host_id,value);

        value = get_json_node_value_string(p,root,"Resource");
        tos_str_set(&tos_error->resource,value);

        cJSON_Delete(root);

        return tos_error;
    }

    if ((*output)==NULL){
        *output = (complete_multipart_upload_output_t *)tos_pcalloc(p, sizeof(complete_multipart_upload_output_t));
        if ((*output)==NULL){
            tos_error = tos_client_error_create(p, TOSE_OUT_MEMORY, "complete_multipart_upload_output_t init by tos_pcalloc failed");
            return tos_error;
        }
    }

    (*output)->status_code = resp->status;
    (*output)->headers = resp->headers;
    tos_str_set(&(*output)->id2,apr_table_get(resp->headers, HEADER_ID_2));
    tos_str_set(&(*output)->request_id,apr_table_get(resp->headers, HEADER_REQUEST_ID));

    res = tos_parse_json_body(&resp->body,&root);
    if (res != TOSE_OK){
        tos_error = tos_server_error_create(p,resp,apr_psprintf(p, "parse json from response body failed"));
        return tos_error;
    }

    value = get_json_node_value_string(p,root,"ETag");
    tos_str_set(&(*output)->etag,value);

    value = get_json_node_value_string(p,root,"Key");
    tos_str_set(&(*output)->key,value);

    value = get_json_node_value_string(p,root,"Bucket");
    tos_str_set(&(*output)->bucket,value);

    value = get_json_node_value_string(p,root,"Location");
    tos_str_set(&(*output)->location,value);

    cJSON_Delete(root);

    value = apr_pstrdup(p,(char*)apr_table_get(resp->headers, HEADER_VERSION_ID));
    if (value)
    {
        tos_str_set(&(*output)->version_id, value);
    }

    value = apr_pstrdup(p,(char*)apr_table_get(resp->headers, HEADER_HASH_CRC64_ECMA));
    if (value)
    {
        (*output)->hash_crc64ecma = strtoull(value, NULL, 10);
    }

    return NULL;
}

int complete_multipart_upload_input_new(tos_pool_t *p,complete_multipart_upload_input_t **input){
    *input = (complete_multipart_upload_input_t *)tos_pcalloc(p, sizeof(complete_multipart_upload_input_t));
    tos_list_init(&(*input)->parts);
    if(*input){
        return TOSE_OK;
    }
    return TOSE_OUT_MEMORY;
}