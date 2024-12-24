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

#include "model/object/list_parts.h"
#include "tos_error.h"
#include "transport/tos_http_io.h"
#include "utils/tos_sys_util.h"
#include "utils/tos_json.h"
#include "utils/tos_utility.h"


int list_parts_input_new(tos_pool_t *p, list_parts_input_t **input){
    *input = (list_parts_input_t *)tos_pcalloc(p, sizeof(list_parts_input_t));
    if(*input){
        return TOSE_OK;
    }
    return TOSE_OUT_MEMORY;
}

upload_part_t *create_list_parts_content(tos_pool_t *p){
    upload_part_t *part = NULL;
    part = (upload_part_t*)tos_create_api_result_content(p, sizeof(upload_part_t));
    return part;
}

int list_part_output_new(tos_pool_t *p, list_parts_output_t **output){
    *output = (list_parts_output_t *)tos_pcalloc(p, sizeof(list_parts_output_t));
    if (!(*output)){
        return TOSE_OUT_MEMORY;
    }
    tos_list_init(&(*output)->parts);
    tos_str_set(&(*output)->bucket,"");
    tos_str_set(&(*output)->key,"");
    tos_str_set(&(*output)->upload_id,"");
    tos_str_set(&(*output)->owner.id,"");
    tos_str_set(&(*output)->owner.display_name,"");
    (*output)->storage_class = STORAGE_CLASS_UNKNOWN;

    (*output)->part_number_marker = 0;
    (*output)->next_part_number_marker = 0;
    (*output)->max_parts = 1000;
    (*output)->is_truncated = true;
    return TOSE_OK;

}

tos_error_t *list_parts_output_parse_from_resp(tos_pool_t *p, tos_http_response_t *resp, list_parts_output_t** output){
    int res = TOSE_OK;
    cJSON *root;
    char *value=NULL;
    tos_error_t *tos_error = NULL;

    if (resp->status >= 300)
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

    if (list_part_output_new(p,output)!=TOSE_OK){
        tos_error = tos_client_error_create(p, TOSE_OUT_MEMORY, "list_part_output init by tos_pcalloc failed");
        return tos_error;
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

    value = get_json_node_value_string(p,root,"Bucket");
    tos_str_set(&(*output)->bucket,value);

    value = get_json_node_value_string(p,root,"Key");
    tos_str_set(&(*output)->key,value);

    value = get_json_node_value_string(p,root,"UploadId");
    tos_str_set(&(*output)->upload_id,value);

    value = get_json_node_value_string(p,root,"StorageClass");
    (*output)->storage_class = string_to_storage_class(value);

    (*output)->part_number_marker = get_json_node_value_int(root,"PartNumberMarker");
    (*output)->next_part_number_marker = get_json_node_value_int(root,"NextPartNumberMarker");
    (*output)->max_parts = get_json_node_value_int(root,"MaxParts");
    (*output)->is_truncated = get_json_node_value_bool(root,"IsTruncated");

    cJSON *owner = cJSON_GetObjectItem(root, "Owner");
    value = get_json_node_value_string(p,owner,"ID");
    tos_str_set(&(*output)->owner.id,value);

    cJSON *parts = cJSON_GetObjectItem(root, "Parts");
    int parts_count = cJSON_GetArraySize(parts);
    upload_part_t *upload_part = NULL;

    for (int i = 0; i < parts_count; i++) {
        upload_part = create_list_parts_content(p);
        cJSON *part = cJSON_GetArrayItem(parts, i);
        upload_part->part_number = get_json_node_value_int(part,"PartNumber");
        upload_part->size = get_json_node_value_int64(part, "Size");
        tos_str_set(&upload_part->etag,get_json_node_value_string(p,part,"ETag"));
        tos_str_set(&upload_part->last_modified,get_json_node_value_string(p,part,"LastModified"));
        tos_list_add_tail(&upload_part->node,&(*output)->parts);
    }
    cJSON_Delete(root);

    return NULL;
}