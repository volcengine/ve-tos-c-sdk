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

#include "model/object/abort_multipart_upload.h"
#include "tos_error.h"
#include "transport/tos_http_io.h"
#include "utils/tos_sys_util.h"
#include "utils/tos_json.h"

int abort_multipart_upload_input_new(tos_pool_t *p,abort_multipart_upload_input_t **input){
    *input = (abort_multipart_upload_input_t *)tos_pcalloc(p, sizeof(abort_multipart_upload_input_t));
    if(*input){
        return TOSE_OK;
    }
    return TOSE_OUT_MEMORY;
}

tos_error_t *abort_multipart_upload_output_parse_from_resp(tos_pool_t *p, tos_http_response_t *resp, abort_multipart_upload_output_t **output){
    cJSON *root;
    char *value=NULL;
    tos_error_t *tos_error = NULL;
    int res = TOSE_OK;

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

    if ((*output) == NULL)
    {
        *output = (abort_multipart_upload_output_t *)tos_pcalloc(p, sizeof(abort_multipart_upload_output_t));
        if ((*output) == NULL)
        {
            tos_error = tos_client_error_create(p, TOSE_OUT_MEMORY, "abort_multipart_upload_output_t init by tos_pcalloc failed");
            return tos_error;
        }
    }

    (*output)->status_code = resp->status;
    (*output)->headers = resp->headers;
    tos_str_set(&(*output)->id2,apr_table_get(resp->headers, HEADER_ID_2));
    tos_str_set(&(*output)->request_id,apr_table_get(resp->headers, HEADER_REQUEST_ID));

    return NULL;
}
