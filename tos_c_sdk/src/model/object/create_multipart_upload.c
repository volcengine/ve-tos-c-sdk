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

#include "model/object/create_multipart_upload.h"
#include "tos_error.h"
#include "utils/tos_sys_util.h"
#include "utils/tos_json.h"

int create_multipart_upload_input_new(tos_pool_t *p,create_multipart_upload_input_t **input){
    *input = (create_multipart_upload_input_t *)tos_pcalloc(p, sizeof(create_multipart_upload_input_t));
    if(*input){
        (*input)->content_length = -1;
        return TOSE_OK;
    }
    return TOSE_OUT_MEMORY;
}


tos_error_t *create_multipart_upload_output_parse_from_resp(tos_pool_t *p, tos_http_response_t *resp, create_multipart_upload_output_t** output){
    int res = TOSE_OK;
    cJSON *root;
    char *value=NULL;
    char *bucket=NULL;
    char *key=NULL;
    char *upload_id=NULL;
    char *encoding_type=NULL;
    char *ssec_algorithm=NULL;
    char *ssec_key_md5=NULL;
    char *server_side_encryption=NULL;
    char *server_side_encryption_key_id=NULL;
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
        *output = (create_multipart_upload_output_t *)tos_pcalloc(p, sizeof(create_multipart_upload_output_t));
        if ((*output)==NULL){
            tos_error = tos_client_error_create(p, TOSE_OUT_MEMORY, "create_multipart_upload_output_t init by tos_pcalloc failed");
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

    bucket = get_json_node_value_string(p,root,"Bucket");
    if (bucket){
        tos_str_set(&(*output)->bucket,bucket);
    }
    key = get_json_node_value_string(p,root,"Key");
    if (key){
        tos_str_set(&(*output)->key,key);
    }
    upload_id = get_json_node_value_string(p,root,"UploadId");
    if (upload_id){
        tos_str_set(&(*output)->upload_id,upload_id);
    }
    encoding_type = get_json_node_value_string(p,root,"EncodingType");
    if (encoding_type){
        tos_str_set(&(*output)->encoding_type,encoding_type);
    }

    ssec_algorithm = apr_pstrdup(p,(char*)apr_table_get(resp->headers, HEADER_SSEC_ALGORITHM));
    if (ssec_algorithm != NULL)
    {
        tos_str_set(&(*output)->ssec_algorithm, ssec_algorithm);
    }
    ssec_key_md5 = apr_pstrdup(p,(char*)apr_table_get(resp->headers, HEADER_SSEC_KEY_MD5));
    if (ssec_algorithm != NULL)
    {
        tos_str_set(&(*output)->ssec_key_md5, ssec_key_md5);
    }
    server_side_encryption = apr_pstrdup(p,(char*)apr_table_get(resp->headers, HEADER_SERVER_SIDE_ENCRYPTION));
    if (server_side_encryption != NULL)
    {
        tos_str_set(&(*output)->server_side_encryption, server_side_encryption);
    }
    server_side_encryption_key_id = apr_pstrdup(p,(char*)apr_table_get(resp->headers, HEADER_SERVER_SIDE_ENCRYPTION_KMS_KEY_ID));
    if (server_side_encryption_key_id != NULL)
    {
        tos_str_set(&(*output)->server_side_encryption_key_id, server_side_encryption_key_id);
    }

    cJSON_Delete(root);

    return NULL;
}