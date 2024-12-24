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

#include "../include/tos_client_impl.h"
#include "../include/utils/tos_utility.h"
#include "../include/common/tos_sys_define.h"
#include "../include/utils/tos_sys_util.h"
#include "../include/utils/tos_utility.h"

tos_error_t* create_multipart_upload(const tos_client_t* client, const create_multipart_upload_input_t* input,
                                     create_multipart_upload_output_t** output)
{
    // 声明公共结构
    tos_error_t* tos_error = NULL;
    tos_http_request_t* req = NULL;
    tos_http_response_t* resp = NULL;
    tos_table_t* query_params = NULL;
    tos_table_t* headers = NULL;
    char* content_length_str = NULL;
    const char* acl_str = NULL;
    const char* storage_class_str = NULL;
    const tos_array_header_t* arr;
    const tos_table_entry_t* elts;
    char key_buf[3 * TOS_MAX_HEADER_LEN + 1];
    char value_buf[3 * TOS_MAX_HEADER_LEN + 1];
    int res;

    // set basic header
    if ((headers = tos_table_create_if_null(client, headers, 10)) == NULL)
    {
        tos_error = tos_client_error_create(client->pool, TOSE_OUT_MEMORY, "header init by tos_table_create_if_null failed");
        return tos_error;
    }

    if (input->content_length >= 0)
    {
        content_length_str = apr_psprintf(client->pool, "%" APR_INT64_T_FMT, input->content_length);
        tos_table_add(headers, HEADER_CONTENT_LENGTH, content_length_str);
    }

    if (tos_string_valid(input->cache_control))
    {
        tos_table_add(headers, HEADER_CACHE_CONTROL, input->cache_control.data);
    }

    if (tos_string_valid(input->content_type))
    {
        tos_table_add(headers, HEADER_CONTENT_TYPE, input->content_type.data);
    }

    if (tos_string_valid(input->content_language))
    {
        tos_table_add(headers, HEADER_CONTENT_LANGUAGE, input->content_language.data);
    }

    if (tos_string_valid(input->content_encoding))
    {
        tos_table_add(headers, HEADER_CONTENT_ENCODING, input->content_encoding.data);
    }

    if (tos_string_valid(input->content_disposition))
    {
        tos_chinese_url_encode(value_buf, input->content_disposition.data,input->content_disposition.len);
        tos_table_add(headers, HEADER_CONTENT_ENCODING, value_buf);
    }

    if (input->expires > 0)
    {
        char expires_str[APR_RFC822_DATE_LEN];
        if (apr_rfc822_date(expires_str, input->expires) != APR_SUCCESS)
        {
            tos_error = tos_client_error_create(client->pool,TOSE_INVALID_ARGUMENT, ERR_MSG_INVALID_EXPIRES);
            return tos_error;
        }

        tos_table_add(headers, HEADER_EXPIRES, expires_str);
    }

    // set acl header
    if (input->acl > 0)
    {
        acl_str = acl_type_to_string(input->acl);
        if (acl_str != NULL)
        {
            tos_table_add(headers, HEADER_ACL, acl_str);
        }
    }

    if (tos_string_valid(input->grant_full_control))
    {
        tos_table_add(headers, HEADER_GRANT_FULL_CONTROL, input->grant_full_control.data);
    }

    if (tos_string_valid(input->grant_read))
    {
        tos_table_add(headers, HEADER_GRANT_READ, input->grant_read.data);
    }

    if (tos_string_valid(input->grant_read_acp))
    {
        tos_table_add(headers, HEADER_GRANT_READ_ACP, input->grant_read_acp.data);
    }

    if (tos_string_valid(input->grant_write))
    {
        tos_table_add(headers, HEADER_GRANT_WRITE, input->grant_write.data);
    }

    if (tos_string_valid(input->grant_write_acp))
    {
        tos_table_add(headers, HEADER_GRANT_WRITE_ACP, input->grant_write_acp.data);
    }

    // sse headers
    if (tos_string_valid(input->ssec_algorithm))
    {
        if (!tos_string_equal(input->ssec_algorithm.data, ALGORITHM_AES_256))
        {
            return tos_client_error_create(client->pool,TOSE_INVALID_ARGUMENT,  ERR_MSG_INVALID_SSEC_ALGORITHM);
        }
        if (tos_string_valid(input->server_side_encryption))
        {
            return tos_client_error_create(client->pool, TOSE_INVALID_ARGUMENT, ERR_MSG_BOTH_SSEC_AND_SSE_ARE_SET);
        }
        if (!tos_string_valid(input->ssec_key) || !tos_string_valid(input->ssec_key_md5))
        {
            return tos_client_error_create(client->pool, TOSE_INVALID_ARGUMENT, ERR_MSG_EMPTY_SSEC_KEY_OR_KEY_MD5);
        }

        tos_table_add(headers, HEADER_SSEC_ALGORITHM, input->ssec_algorithm.data);
        tos_table_add(headers, HEADER_SSEC_KEY, input->ssec_key.data);
        tos_table_add(headers, HEADER_SSEC_KEY_MD5, input->ssec_key_md5.data);
    }
    else if (tos_string_valid(input->server_side_encryption))
    {
        if (!tos_string_equal(input->server_side_encryption.data, ALGORITHM_AES_256))
        {
            return tos_client_error_create(client->pool, TOSE_INVALID_ARGUMENT, ERR_MSG_INVALID_ENCRYPTION_DECRYPTION_ALGORITHM);
        }

        tos_table_add(headers, HEADER_SERVER_SIDE_ENCRYPTION, input->server_side_encryption.data);
    }

    // meta headers
    arr = tos_table_elts(input->meta);
    if (arr && arr->nelts > 0)
    {
        elts = (tos_table_entry_t*)arr->elts;
        for (int pos = 0; pos < arr->nelts; ++pos)
        {
            if (strlen(elts[pos].key) <= 0)
            {
                continue;
            }

            key_buf[0] = '\0';
            res = tos_url_encode(key_buf, elts[pos].key, TOS_MAX_HEADER_LEN);
            if (res != TOSE_OK)
            {
                return tos_client_error_create(client->pool, res, ERR_MSG_INVALID_META_KEY_OR_VALUE);
            }

            value_buf[0] = '\0';
            res = tos_url_encode(value_buf, elts[pos].val, TOS_MAX_HEADER_LEN);
            if (res != TOSE_OK)
            {
                return tos_client_error_create(client->pool, res, ERR_MSG_INVALID_META_KEY_OR_VALUE);
            }

            if (!starts_with(key_buf, HEADER_META_PREFIX))
            {
                char* tmp_buf = apr_pstrndup(client->pool, key_buf, strlen(key_buf));
                apr_snprintf(key_buf, sizeof(key_buf), "%s", HEADER_META_PREFIX);
                snprintf(key_buf + strlen(key_buf), sizeof(key_buf) - strlen(key_buf), "%s", tmp_buf);
            }
            tos_table_add(headers, key_buf, value_buf);
        }
    }

    // misc header
    if (input->storage_class > 0)
    {
        storage_class_str = storage_class_to_string(input->storage_class);
        if (storage_class_str != NULL)
            tos_table_add(headers, HEADER_STORAGE_CLASS, storage_class_str);
    }
    if (tos_string_valid(input->website_redirect_location))
    {
        tos_table_add(headers, HEADER_WEBSITE_REDIRECT_LOCATION, input->website_redirect_location.data);
    }
    if (tos_string_valid(input->tagging))
    {
        tos_table_add(headers, HEADER_TAGGING, input->tagging.data);
    }

    // init query_params
    if ((query_params = tos_table_create_if_null(client, query_params, 2)) ==NULL)
    {
        tos_error = tos_client_error_create(client->pool, TOSE_OUT_MEMORY, "query init by tos_table_create_if_null failed");
        return tos_error;
    }
    if (tos_string_valid(input->encoding_type))
    {
        tos_table_add(query_params, QUERY_ENCODING_TYPE, input->encoding_type.data);
    }
    tos_table_add(query_params, QUERY_UPLOADS, "");

    if ((tos_error = tos_init_object_request(client, &input->bucket, &input->key, HTTP_POST,
                                             &req, query_params, headers, NULL, 0, &resp)) != NULL)
    {
        return tos_error;
    }

    // 发送一个请求
    if ((tos_error = tos_process_request(client, req, resp, NULL, "CreateMultipartUpload",
                                         client->config->max_retry_time)) != NULL)
    {
        return tos_error;
    }

    // 处理resp
    tos_error = create_multipart_upload_output_parse_from_resp(client->pool, resp, output);

    return tos_error;
}

tos_error_t* upload_part_from_file(const tos_client_t* client, const upload_part_from_file_input_t* input,
                                   upload_part_from_file_output_t** output)
{
    tos_error_t* tos_error = NULL;
    tos_http_request_t* req = NULL;
    tos_http_response_t* resp = NULL;
    tos_table_t* query_params = NULL;
    tos_table_t* headers = NULL;
    tos_upload_file_t* upload_file = NULL;
    apr_finfo_t finfo;

    int res = TOSE_OK;
    if (tos_string_valid(input->file_path))
    {
        res = tos_does_file_exist(&input->file_path, client->pool);
        if (!res)
        {
            tos_error = tos_client_error_create(client->pool, TOSE_INVALID_ARGUMENT, "the specified file path does not exist");
            return tos_error;
        }
    }
    else
    {
        tos_error = tos_client_error_create(client->pool, TOSE_INVALID_ARGUMENT, "empty file path");
        return tos_error;
    }

    res = tos_get_file_info(&input->file_path, client->pool, &finfo);
    if (res != TOSE_OK)
    {
        tos_error = tos_client_error_create(client->pool, TOSE_INVALID_ARGUMENT, "get file info failed");
        return tos_error;
    }

    if (input->offset < 0 || input->offset > finfo.size)
    {
        tos_error = tos_client_error_create(client->pool, TOSE_INVALID_ARGUMENT, "invalid offset for upload part");
        return tos_error;
    }

    //init headers
    headers = tos_table_create_if_null(client, headers, 10);
    if (tos_string_valid(input->content_md5))
    {
        tos_table_add(headers, HEADER_CONTENT_MD5, input->content_md5.data);
    }

    // sse headers
    if (tos_string_valid(input->ssec_algorithm))
    {
        if (!tos_string_equal(input->ssec_algorithm.data, ALGORITHM_AES_256))
        {
            return tos_client_error_create(client->pool,TOSE_INVALID_ARGUMENT,  ERR_MSG_INVALID_SSEC_ALGORITHM);
        }
        if (!tos_string_valid(input->ssec_key) || !tos_string_valid(input->ssec_key_md5))
        {
            return tos_client_error_create(client->pool, TOSE_INVALID_ARGUMENT, ERR_MSG_EMPTY_SSEC_KEY_OR_KEY_MD5);
        }

        tos_table_add(headers, HEADER_SSEC_ALGORITHM, input->ssec_algorithm.data);
        tos_table_add(headers, HEADER_SSEC_KEY, input->ssec_key.data);
        tos_table_add(headers, HEADER_SSEC_KEY_MD5, input->ssec_key_md5.data);
    }

    if (input->part_size >= 0)
    {
        tos_table_add(headers, HEADER_CONTENT_LENGTH,
                      apr_psprintf(client->pool, "%" APR_INT64_T_FMT, input->part_size));
    }
    else
    {
        tos_table_add(headers, HEADER_CONTENT_LENGTH,
                      apr_psprintf(client->pool, "%" APR_INT64_T_FMT, finfo.size-input->offset));
    }

    //init query_params
    query_params = tos_table_create_if_null(client, query_params, 2);
    if (input->part_number < 0)
    {
        tos_error = tos_client_error_create(client->pool, TOSE_INVALID_ARGUMENT, "invalid part number");
        return tos_error;
    }
    tos_table_add(query_params, QUERY_UPLOAD_ID, input->upload_id.data);
    tos_table_add_int(query_params, QUERY_PART_NUMBER, input->part_number);

    if ((tos_error = tos_init_object_request(client, &input->bucket, &input->key, HTTP_PUT,
                                             &req, query_params, headers, NULL, 0, &resp)) != NULL)
    {
        return tos_error;
    }

    upload_file = tos_create_upload_file(client->pool);
    tos_str_set(&upload_file->filename, input->file_path.data);
    upload_file->file_pos = input->offset;
    upload_file->file_last = input->offset + input->part_size;

    // 发送一个请求
    if ((tos_error = tos_process_request(client, req, resp, upload_file, "UploadPartFromFile",
                                         client->config->max_retry_time)) != NULL)
    {
        return tos_error;
    }

    tos_error = upload_part_from_file_output_parse_from_resp(client->pool, resp, output);
    if (*output) (*output)->part_number = input->part_number;
    return tos_error;
}

tos_error_t* upload_part_from_buffer(const tos_client_t* client, const upload_part_from_buffer_input_t* input,
                                     upload_part_from_buffer_output_t** output)
{
    tos_error_t* tos_error = NULL;
    tos_http_request_t* req = NULL;
    tos_http_response_t* resp = NULL;
    tos_table_t* query_params = NULL;
    tos_table_t* headers = NULL;
    int64_t input_content_len = 0;

    //init headers
    headers = tos_table_create_if_null(client, headers, 10);
    if (tos_string_valid(input->content_md5))
    {
        tos_table_add(headers, HEADER_CONTENT_MD5, input->content_md5.data);
    }

    // sse headers
    if (tos_string_valid(input->ssec_algorithm))
    {
        if (!tos_string_equal(input->ssec_algorithm.data, ALGORITHM_AES_256))
        {
            return tos_client_error_create(client->pool,TOSE_INVALID_ARGUMENT,  ERR_MSG_INVALID_SSEC_ALGORITHM);
        }
        if (!tos_string_valid(input->ssec_key) || !tos_string_valid(input->ssec_key_md5))
        {
            return tos_client_error_create(client->pool, TOSE_INVALID_ARGUMENT, ERR_MSG_EMPTY_SSEC_KEY_OR_KEY_MD5);
        }

        tos_table_add(headers, HEADER_SSEC_ALGORITHM, input->ssec_algorithm.data);
        tos_table_add(headers, HEADER_SSEC_KEY, input->ssec_key.data);
        tos_table_add(headers, HEADER_SSEC_KEY_MD5, input->ssec_key_md5.data);
    }

    if (input->content_length >= 0)
    {
        tos_table_add(headers, HEADER_CONTENT_LENGTH,
                      apr_psprintf(client->pool, "%" APR_INT64_T_FMT, input->content_length));

        set_tos_buf_list_to_specific_len(input->content,input->content_length);
    }
    else if (input->content)
    {
        tos_table_add(headers, HEADER_CONTENT_LENGTH,
                      apr_psprintf(client->pool, "%" APR_INT64_T_FMT, tos_buf_list_len(input->content)));
    }

    //init query_params
    query_params = tos_table_create_if_null(client, query_params, 2);
    if (input->part_number < 0)
    {
        tos_error = tos_client_error_create(client->pool, TOSE_INVALID_ARGUMENT, "invalid part number");
        return tos_error;
    }
    tos_table_add(query_params, QUERY_UPLOAD_ID, input->upload_id.data);
    tos_table_add_int(query_params, QUERY_PART_NUMBER, input->part_number);

    if ((tos_error = tos_init_object_request(client, &input->bucket, &input->key, HTTP_PUT,
                                             &req, query_params, headers, NULL, 0, &resp)) != NULL)
    {
        return tos_error;
    }

    tos_write_request_body_from_buffer(input->content, req);

    // 发送一个请求
    if ((tos_error = tos_process_request(client, req, resp, NULL, "UploadPart", client->config->max_retry_time)) != NULL)
    {
        return tos_error;
    }

    tos_error = upload_part_from_buffer_output_parse_from_resp(client->pool, resp, output);
    if (*output) (*output)->part_number = input->part_number;

    return tos_error;
}

tos_error_t* list_parts(const tos_client_t* client, const list_parts_input_t* input, list_parts_output_t** output)
{
    tos_error_t* tos_error = NULL;
    tos_http_request_t* req = NULL;
    tos_http_response_t* resp = NULL;
    tos_table_t* query_params = NULL;
    tos_table_t* headers = NULL;

    //init query_params
    query_params = tos_table_create_if_null(client, query_params, 3);
    if (tos_string_valid(input->upload_id))
    {
        tos_table_add(query_params, QUERY_UPLOAD_ID, input->upload_id.data);
    }
    else
    {
        tos_error = tos_client_error_create(client->pool, TOSE_INVALID_ARGUMENT, "empty upload id");
        return tos_error;
    }

    if (input->part_number_marker >= 0)
    {
        tos_table_add_int(query_params, TOS_PART_NUMBER_MARKER, input->part_number_marker);
    }

    if (input->max_parts >= 0)
    {
        tos_table_add_int(query_params, TOS_MAX_PARTS, input->max_parts);
    }

    //init headers
    headers = tos_table_create_if_null(client, headers, 0);

    if ((tos_error = tos_init_object_request(client, &input->bucket, &input->key, HTTP_GET,
                                             &req, query_params, headers, NULL, 0, &resp)) != NULL)
    {
        return tos_error;
    }

    // 发送一个请求
    if ((tos_error = tos_process_request(client, req, resp, NULL, "ListParts", client->config->max_retry_time)) != NULL)
    {
        return tos_error;
    }

    tos_error = list_parts_output_parse_from_resp(client->pool, resp, output);

    return tos_error;
}


tos_error_t* complete_multipart_upload(const tos_client_t* client, const complete_multipart_upload_input_t* input,
                                       complete_multipart_upload_output_t** output)
{
    tos_error_t* tos_error = NULL;
    tos_http_request_t* req = NULL;
    tos_http_response_t* resp = NULL;
    tos_table_t* query_params = NULL;
    tos_table_t* headers = NULL;
    tos_list_t body;

    if (tos_list_empty((tos_list_t*)&input->parts))
    {
        tos_error = tos_client_error_create(client->pool, TOSE_INVALID_ARGUMENT, "empty parts for complete multipart upload");
        return tos_error;
    }

    //init query_params
    query_params = tos_table_create_if_null(client, query_params, 1);
    if (tos_string_valid(input->upload_id))
    {
        tos_table_add(query_params, QUERY_UPLOAD_ID, input->upload_id.data);
    }
    else
    {
        tos_error = tos_client_error_create(client->pool, TOSE_INVALID_ARGUMENT, "empty upload id");
        return tos_error;
    }

    //init headers
    headers = tos_table_create_if_null(client, headers, 1);

    if ((tos_error = tos_init_object_request(client, &input->bucket, &input->key, HTTP_POST,
                                             &req, query_params, headers, NULL, 0, &resp)) != NULL)
    {
        return tos_error;
    }

    complete_multipart_upload_body_create(client->pool, (tos_list_t*)&input->parts, &body);
    tos_write_request_body_from_buffer(&body, req);

    if ((tos_error = tos_process_request(client, req, resp, NULL, "CompleteMultipartUpload",
                                         client->config->max_retry_time)) != NULL)
    {
        return tos_error;
    }

    tos_error = complete_multipart_upload_output_parse_from_resp(client->pool, resp, output);

    return tos_error;
}

tos_error_t* abort_multipart_upload(const tos_client_t* client, const abort_multipart_upload_input_t* input,
                                    abort_multipart_upload_output_t** output)
{
    tos_error_t* tos_error = NULL;
    tos_http_request_t* req = NULL;
    tos_http_response_t* resp = NULL;
    tos_table_t* query_params = NULL;
    tos_table_t* headers = NULL;

    //init query_params
    query_params = tos_table_create_if_null(client, query_params, 1);
    if (tos_string_valid(input->upload_id))
    {
        tos_table_add(query_params, QUERY_UPLOAD_ID, input->upload_id.data);
    }
    else
    {
        tos_error = tos_client_error_create(client->pool,TOSE_INVALID_ARGUMENT, "empty upload id");
        return tos_error;
    }

    //init headers
    headers = tos_table_create_if_null(client, headers, 0);

    if ((tos_error = tos_init_object_request(client, &input->bucket, &input->key, HTTP_DELETE,
                                             &req, query_params, headers, NULL, 0, &resp)) != NULL)
    {
        return tos_error;
    }

    if ((tos_error = tos_process_request(client, req, resp, NULL, "AbortMultipartUpload",
                                         client->config->max_retry_time)) != NULL)
    {
        return tos_error;
    }

    tos_error = abort_multipart_upload_output_parse_from_resp(client->pool, resp, output);

    return tos_error;
}
