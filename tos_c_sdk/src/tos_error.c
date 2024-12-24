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

#include "tos_error.h"
#include "transport/tos_http_io.h"
#include "utils/tos_sys_util.h"
#include "utils/tos_json.h"

const char ERR_MSG_INVALID_EXPIRES[] = "invalid expires value";
const char ERR_MSG_INVALID_SSEC_ALGORITHM[] = "invalid encryption-decryption algorithm";
const char ERR_MSG_BOTH_SSEC_AND_SSE_ARE_SET[] = "both ssec and server side encryption are set";
const char ERR_MSG_EMPTY_SSEC_KEY_OR_KEY_MD5[] = "empty ssec key or ssec key md5";
const char ERR_MSG_INVALID_ENCRYPTION_DECRYPTION_ALGORITHM[] = "invalid encryption-decryption algorithm";
const char ERR_MSG_INVALID_META_KEY_OR_VALUE[] = "invalid meta key or value";

tos_error_t *tos_error_create(tos_pool_t *p)
{
    return (tos_error_t *)tos_pcalloc(p, sizeof(tos_error_t));
}

tos_error_t *tos_client_error_create(tos_pool_t *p, int client_error_code, const char* error_msg)
{
    tos_error_t* error = tos_error_create(p);
    tos_error_set_is_client_error(error,true);
    tos_error_set_client_error_code(error, client_error_code);
    tos_error_set_message(error, error_msg);
    return error;
}

tos_error_t *tos_server_error_create(tos_pool_t *p, const tos_http_response_t* resp, const char* error_msg)
{
    tos_error_t* error = tos_error_create(p);
    tos_error_set_is_client_error(error,false);
    tos_error_set_message(error, error_msg);

    if (resp != NULL)
    {
        error->status_code = resp->status;
        error->headers = resp->headers;
        tos_str_set(&error->id2,apr_table_get(resp->headers, HEADER_ID_2));
        tos_str_set(&error->request_id,apr_table_get(resp->headers, HEADER_REQUEST_ID));
    }

    return error;
}

tos_error_t *tos_error_parse_from_resp(tos_pool_t *p, tos_http_response_t *resp, tos_error_t *tos_error){
    cJSON *root;
    char *value=NULL;

    if (tos_error == NULL) {
        tos_error = tos_error_create(p);
    }
    tos_error->status_code = resp->status;
    tos_error->headers = resp->headers;
    tos_str_set(&tos_error->request_id,apr_table_get(resp->headers, HEADER_REQUEST_ID));
    tos_str_set(&tos_error->ec,apr_table_get(resp->headers, HEADER_EC));
    tos_error_set_is_client_error(tos_error,false);

    if (tos_list_empty(&resp->body))
    {
        return tos_error;
    }

    if (tos_parse_json_body(&resp->body, &root) != TOSE_OK)
    {
        return tos_error;
    }

    value = get_json_node_value_string(p,root,"Code");
    if (value != NULL)
    {
        tos_str_set(&tos_error->code, value);
    }


    value = get_json_node_value_string(p,root,"Message");
    if (value != NULL)
    {
        tos_str_set(&tos_error->message,value);
    }

    value = get_json_node_value_string(p,root,"EC");
    if (value != NULL)
    {
        tos_str_set(&tos_error->ec,value);
    }

    value = get_json_node_value_string(p,root,"HostId");
    if (value != NULL)
    {
        tos_str_set(&tos_error->host_id,value);
    }

    value = get_json_node_value_string(p,root,"Resource");
    if (value != NULL)
    {
        tos_str_set(&tos_error->resource,value);
    }

    cJSON_Delete(root);

    return tos_error;
}