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

#include "model/object/upload_part.h"
#include "tos_error.h"
#include "transport/tos_http_io.h"
#include "utils/tos_sys_util.h"
#include "utils/tos_json.h"

int upload_part_from_file_input_new(tos_pool_t *p,upload_part_from_file_input_t **input){
    *input = (upload_part_from_file_input_t *)tos_pcalloc(p, sizeof(upload_part_from_file_input_t));
    if(*input){
        (*input)->part_size = -1;
        return TOSE_OK;
    }
    return TOSE_OUT_MEMORY;
}

tos_error_t *upload_part_from_file_output_parse_from_resp(tos_pool_t *p, tos_http_response_t *resp, upload_part_from_file_output_t **output){
    int res = TOSE_OK;
    cJSON *root;
    char *value=NULL;
    tos_error_t *tos_error = NULL;
    char* etag = NULL;
    char* ssec_algorithm = NULL;
    char* ssec_key_md5 = NULL;
    char* crc64 = NULL;

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

    if ((*output)==NULL)
    {
        *output = (upload_part_from_file_output_t *)tos_pcalloc(p, sizeof(upload_part_from_file_output_t));
        if ((*output)==NULL){
            tos_error = tos_client_error_create(p, TOSE_OUT_MEMORY, "upload_part_from_file_output_t init by tos_pcalloc failed");
            return tos_error;
        }
    }

    (*output)->status_code = resp->status;
    (*output)->headers = resp->headers;
    tos_str_set(&(*output)->id2,apr_table_get(resp->headers, HEADER_ID_2));
    tos_str_set(&(*output)->request_id,apr_table_get(resp->headers, HEADER_REQUEST_ID));

    etag = apr_pstrdup(p,(char*)apr_table_get(resp->headers, HEADER_ETAG));
    tos_str_set(&(*output)->etag, etag);

    ssec_algorithm = apr_pstrdup(p,(char*)apr_table_get(resp->headers, HEADER_SSEC_ALGORITHM));
    tos_str_set(&(*output)->ssec_algorithm, ssec_algorithm);

    ssec_key_md5 = apr_pstrdup(p,(char*)apr_table_get(resp->headers, HEADER_SSEC_KEY_MD5));
    tos_str_set(&(*output)->ssec_key_md5, ssec_key_md5);

    crc64 = apr_pstrdup(p,(char*)apr_table_get(resp->headers, HEADER_HASH_CRC64_ECMA));
    if (crc64) (*output)->hash_crc64ecma =  strtoull(crc64, NULL, 10);

    return NULL;
}

int upload_part_from_buffer_input_new(tos_pool_t *p,upload_part_from_buffer_input_t **input)
{
    *input = (upload_part_from_buffer_input_t *)tos_pcalloc(p, sizeof(upload_part_from_buffer_input_t));
    if(*input){
        (*input)->content_length = -1;
        return TOSE_OK;
    }
    return TOSE_OUT_MEMORY;
}

tos_error_t *upload_part_from_buffer_output_parse_from_resp(tos_pool_t *p, tos_http_response_t *resp, upload_part_from_buffer_output_t **output)
{
    int res = TOSE_OK;
    cJSON *root;
    char *value=NULL;
    char* etag = NULL;
    char* ssec_algorithm = NULL;
    char* ssec_key_md5 = NULL;
    char* crc64 = NULL;
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

    if ((*output)==NULL)
    {
        *output = (upload_part_from_buffer_output_t *)tos_pcalloc(p, sizeof(upload_part_from_buffer_output_t));
        if ((*output)==NULL){
            tos_error = tos_client_error_create(p, TOSE_OUT_MEMORY, "upload_part_from_buffer_output_t init by tos_pcalloc failed");
            return tos_error;
        }
    }

    (*output)->status_code = resp->status;
    (*output)->headers = resp->headers;
    tos_str_set(&(*output)->id2,apr_table_get(resp->headers, HEADER_ID_2));
    tos_str_set(&(*output)->request_id,apr_table_get(resp->headers, HEADER_REQUEST_ID));

    etag = apr_pstrdup(p,(char*)apr_table_get(resp->headers, HEADER_ETAG));
    tos_str_set(&(*output)->etag, etag);

    ssec_algorithm = apr_pstrdup(p,(char*)apr_table_get(resp->headers, HEADER_SSEC_ALGORITHM));
    tos_str_set(&(*output)->ssec_algorithm, ssec_algorithm);

    ssec_key_md5 = apr_pstrdup(p,(char*)apr_table_get(resp->headers, HEADER_SSEC_KEY_MD5));
    tos_str_set(&(*output)->ssec_key_md5, ssec_key_md5);

    crc64 = apr_pstrdup(p,(char*)apr_table_get(resp->headers, HEADER_HASH_CRC64_ECMA));
    if (crc64) (*output)->hash_crc64ecma =  strtoull(crc64, NULL, 10);

    return NULL;
}
