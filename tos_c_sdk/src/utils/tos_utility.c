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
#include "../../include/utils/tos_sys_util.h"
#include "../../include/common/tos_log.h"
#include "../../include/auth/tos_auth.h"
#include "../../include/utils/tos_utility.h"

#ifndef WIN32

#include<sys/socket.h>
#include<netinet/in.h>
#include<arpa/inet.h>

#endif

static char *default_content_type = "application/octet-stream";

#ifdef MOCK_IS_SHOULD_RETRY

#else

#endif

char *check_bucket(const tos_string_t *bucket) {
    char *err_msg = NULL;

    if (!tos_string_valid(*bucket) || bucket->len < 3 || bucket->len > 63) {
        return "invalid bucket name, the length must be [3, 63]";
    }

    if (bucket->data[0] == '-' || bucket->data[bucket->len - 1] == '-') {
        return "invalid bucket name, the bucket name can be neither starting with '-' nor ending with '-'";
    }

    char *idx = bucket->data;
    while (*idx) {
        if (*idx == '-' || (*idx >= 'a' && *idx <= 'z') || (*idx >= '0' && *idx <= '9')) {
            idx++;
            continue;
        }
        return "invalid bucket name, the character set is illegal";
    }

    return err_msg;
}

static tos_error_t *is_config_params_valid(const tos_client_t *options,
                                           const tos_string_t *bucket) {
    tos_error_t *tos_error = NULL;
    char *err_msg = NULL;

    if ((err_msg = check_bucket(bucket)) != NULL) {
        tos_error = tos_client_error_create(options->pool, TOSE_INVALID_ARGUMENT, err_msg);
        return tos_error;
    }

    if (!tos_string_valid((*options).config->endpoint)) {
        tos_error = tos_client_error_create(options->pool, TOSE_INVALID_ARGUMENT, "empty endpoint");
        return tos_error;
    }
    if (!tos_string_valid((*options).config->region)) {
        tos_error = tos_client_error_create(options->pool, TOSE_INVALID_ARGUMENT, "empty region");
        return tos_error;
    }

    return NULL;
}

int starts_with(const char *str, const char *prefix) {
    uint32_t i;
    if (NULL != str && prefix && strlen(str) && strlen(prefix)) {
        for (i = 0; str[i] != '\0' && prefix[i] != '\0'; i++) {
            if (prefix[i] != str[i]) return 0;
        }
        return 1;
    }
    return 0;
}

int tos_string_starts_with(const tos_string_t *str, const char *prefix) {
    uint32_t i;
    if (NULL != str && prefix && str->len > 0 && strlen(prefix)) {
        for (i = 0; str->data[i] != '\0' && prefix[i] != '\0'; i++) {
            if (prefix[i] != str->data[i]) return 0;
        }
        return 1;
    }
    return 0;
}

static void generate_proto(const tos_client_t *options,
                           tos_http_request_t *req) {
    const char *proto;
    proto = tos_string_starts_with(&options->config->endpoint, TOS_HTTP_PREFIX) ? TOS_HTTP_PREFIX : "";
    proto = tos_string_starts_with(&options->config->endpoint, TOS_HTTPS_PREFIX) ? TOS_HTTPS_PREFIX : proto;
    req->proto = apr_psprintf(options->pool, "%.*s", (int) strlen(proto), proto);
}

#if 0
static void generate_rtmp_proto(const tos_request_options_t *options,
                           tos_http_request_t *req)
{
    const char *proto = TOS_RTMP_PREFIX;
    req->proto = apr_psprintf(options->pool, "%.*s", (int)strlen(proto), proto);
}
#endif

int is_valid_ip(const char *str) {
    if (INADDR_NONE == inet_addr(str) || INADDR_ANY == inet_addr(str)) {
        return 0;
    }
    return 1;
}

tos_config_t *tos_config_create(tos_pool_t *p) {
    return (tos_config_t *) tos_pcalloc(p, sizeof(tos_config_t));
}

#if 0
void tos_config_resolve(tos_pool_t *pool, tos_config_t *config, tos_http_controller_t *ctl)
{
    if(!tos_is_null_string(&config->proxy_host)) {
        // proxy host:port
        if (config->proxy_port == 0) {
            ctl->options->proxy_host = apr_psprintf(pool, "%.*s", config->proxy_host.len, config->proxy_host.data);
        } else {
            ctl->options->proxy_host = apr_psprintf(pool, "%.*s:%d", config->proxy_host.len, config->proxy_host.data,
                config->proxy_port);
        }
        // authorize user:passwd
        if (!tos_is_null_string(&config->proxy_user) && !tos_is_null_string(&config->proxy_passwd)) {
            ctl->options->proxy_auth = apr_psprintf(pool, "%.*s:%.*s", config->proxy_user.len,
                config->proxy_user.data, config->proxy_passwd.len, config->proxy_passwd.data);
        }
    }
}
#endif

tos_client_t *tos_client_create(tos_pool_t *p) {
    int s;
    tos_client_t *options;

    if (p == NULL) {
        if ((s = tos_pool_create(&p, NULL)) != APR_SUCCESS) {
            tos_fatal_log("tos_pool_create failure.");
            return NULL;
        }
    }

    options = (tos_client_t *) tos_pcalloc(p, sizeof(tos_client_t));
    options->pool = p;

    return options;
}

tos_error_t *tos_get_object_uri(const tos_client_t *client,
                                const tos_string_t *bucket,
                                const tos_string_t *object,
                                tos_http_request_t *req) {
    uint32_t proto_len;
    const char *raw_endpoint_str;
    tos_string_t raw_endpoint;
    tos_error_t *tos_error = NULL;

    // check params
    if ((tos_error = is_config_params_valid(client, bucket)) != NULL) {
        return tos_error;
    }

    generate_proto(client, req);

    proto_len = strlen(req->proto);
    raw_endpoint_str = tos_pstrdup(client->pool, &client->config->endpoint) + proto_len;
    raw_endpoint.len = client->config->endpoint.len - proto_len;
    raw_endpoint.data = client->config->endpoint.data + proto_len;

    req->resource = apr_psprintf(client->pool, "%.*s",
                                 object->len, object->data);
    if (is_valid_ip(raw_endpoint_str)) {
        req->host = apr_psprintf(client->pool, "%.*s",
                                 raw_endpoint.len, raw_endpoint.data);
    } else {
        req->host = apr_psprintf(client->pool, "%.*s.%.*s",
                                 bucket->len, bucket->data,
                                 raw_endpoint.len, raw_endpoint.data);
    }
    req->uri = apr_psprintf(client->pool, "%.*s",
                            object->len, object->data);

    return NULL;
}

#if 0

#endif

void tos_write_request_body_from_buffer(tos_list_t *buffer,
                                        tos_http_request_t *req) {
    tos_list_movelist(buffer, &req->body);
    req->body_len = tos_buf_list_len(&req->body);
}

int tos_write_request_body_from_upload_file(tos_pool_t *p,
                                            tos_upload_file_t *upload_file,
                                            tos_http_request_t *req) {
    int res = TOSE_OK;
    tos_file_buf_t *fb = tos_create_file_buf(p);
    res = tos_open_file_for_range_read(p, upload_file->filename.data,
                                       upload_file->file_pos, upload_file->file_last, fb);
    if (res != TOSE_OK) {
        tos_error_log("Open read file fail, filename:%s\n", upload_file->filename.data);
        return res;
    }

    req->body_len = fb->file_last - fb->file_pos;
    req->file_path = upload_file->filename.data;
    req->file_buf = fb;
    req->type = BODY_IN_FILE;
    req->read_body = tos_read_http_body_file;

    return res;
}

void *tos_create_api_result_content(tos_pool_t *p, size_t size) {
    void *result_content = tos_palloc(p, size);
    if (NULL == result_content) {
        return NULL;
    }

    tos_list_init((tos_list_t *) result_content);

    return result_content;
}


tos_upload_file_t *tos_create_upload_file(tos_pool_t *p) {
    return (tos_upload_file_t *) tos_pcalloc(p, sizeof(tos_upload_file_t));
}

void tos_init_request(const tos_client_t *client,
                      http_method_e method,
                      tos_http_request_t **req,
                      tos_table_t *params,
                      tos_table_t *headers,
                      tos_http_response_t **resp) {
    *req = tos_http_request_create(client->pool);
    *resp = tos_http_response_create(client->pool);
    (*req)->method = method;

    (*req)->headers = headers;
    (*req)->query_params = params;
}

tos_error_t *tos_init_object_request(
        const tos_client_t *options,
        const tos_string_t *bucket,
        const tos_string_t *object,
        http_method_e method,
        tos_http_request_t **req,
        tos_table_t *params,
        tos_table_t *headers,
        tos_progress_callback cb,
        uint64_t initcrc,
        tos_http_response_t **resp) {
    tos_init_request(options, method, req, params, headers, resp);
    if (HTTP_GET == method) {
        (*resp)->progress_callback = cb;
    } else if (HTTP_PUT == method || HTTP_POST == method) {
        (*req)->progress_callback = cb;
        (*req)->crc64 = initcrc;
    }
    return tos_get_object_uri(options, bucket, object, *req);
}

#if 0

#endif

tos_error_t *tos_send_request_new(tos_http_controller_t *ctl,
                                  tos_http_request_t *req,
                                  tos_http_response_t *resp) {
    tos_error_t *tos_error = NULL;
    const char *reason = NULL;
    int res = TOSE_OK;

    // 发送请求
    res = tos_http_send_request(ctl, req, resp);
    if (res != TOSE_OK) {
        tos_error = tos_error_create(ctl->pool);
        reason = tos_http_controller_get_reason(ctl);
        tos_error_set_message(tos_error, reason);
        tos_error_set_client_error_code(tos_error, res);
        return tos_error;
    }

    return NULL;
}

void reset_list_pos(tos_list_t *list) {
    tos_buf_t *b;
    tos_list_for_each_entry(tos_buf_t, b, list, node) {
        b->pos = b->start;
    }
}


bool find_in_can_retry_curl_err(int curl_err_code) {
    switch (curl_err_code) {
        case (7):   // CURLE_COULDNT_CONNECT
        case (18):  // CURLE_PARTIAL_FILE
        case (23):  // CURLE_WRITE_ERROR
        case (28):  // CURLE_OPERATION_TIMEDOUT
        case (52):  // CURLE_GOT_NOTHING
        case (55):  // CURLE_SEND_ERROR
        case (56):  // CURLE_RECV_ERROR
        case (65):  // CURLE_SEND_FAIL_REWIND
            return true;
        default:
            return false;
    }
    return false;
}

bool is_no_idempotent_operation(const char *op) {
    if (strcmp(op, "CreateBucket") == 0) return true;
    if (strcmp(op, "DeleteBucket") == 0) return true;
    if (strcmp(op, "CreateMultipartUpload") == 0) return true;
    if (strcmp(op, "CompleteMultipartUpload") == 0) return true;
    if (strcmp(op, "AbortMultipartUpload") == 0) return true;
    if (strcmp(op, "AppendObject") == 0) return true;

    return false;
}

bool is_put_idempotent_operation(const char *op) {
    if (strcmp(op, "PutObjectACL") == 0) return true;
    if (strcmp(op, "PutObject") == 0) return true;
    if (strcmp(op, "UploadPart") == 0) return true;
    if (strcmp(op, "PutObjectFromFile") == 0) return true;
    if (strcmp(op, "UploadPartFromFile") == 0) return true;

    return false;
}

bool is_post_idempotent_operation(const char *op) {
    if (strcmp(op, "SetObjectMeta") == 0) return true;

    return false;
}

bool is_delete_idempotent_operation(const char *op) {
    if (strcmp(op, "DeleteObject") == 0) return true;

    return false;
}


bool stream_upload_operation(const char *op) {
    if (strcmp(op, "AppendObject") == 0) return true;
    if (strcmp(op, "PutObject") == 0) return true;
    if (strcmp(op, "UploadPart") == 0) return true;

    return false;
}

bool is_auto_recognize_content_type_operation(const char *op) {
    if (strcmp(op, "CreateMultipartUpload") == 0) return true;
    if (strcmp(op, "AppendObject") == 0) return true;
    if (strcmp(op, "AppendObjectFromBuffer") == 0) return true;
    if (strcmp(op, "PutObject") == 0) return true;
    if (strcmp(op, "PutObjectFromFile") == 0) return true;
    if (strcmp(op, "PutObjectFromBuffer") == 0) return true;
    if (strcmp(op, "SetObjectMeta") == 0) return true;

    return false;
}

bool check_should_retry_curl_error(const char *request_operation, int curl_error_code, const tos_http_request_t *req) {
    if (find_in_can_retry_curl_err(curl_error_code)) {
        if (req->method == HTTP_GET || req->method == HTTP_HEAD) {
            return true;
        }

        if (is_put_idempotent_operation(request_operation)) return true;
        if (is_delete_idempotent_operation(request_operation)) return true;
        if (is_post_idempotent_operation(request_operation)) return true;
    }

    return false;
}

bool
check_should_retry_resp(const char *request_operation, const tos_http_request_t *req, const tos_http_response_t *resp) {
    if (resp->status == 429 || resp->status == 408 || resp->status >= 500) {
        if (req->method == HTTP_GET || req->method == HTTP_HEAD) {
            return true;
        }

        if (is_put_idempotent_operation(request_operation)) return true;
        if (is_delete_idempotent_operation(request_operation)) return true;
        if (is_post_idempotent_operation(request_operation)) return true;

        if (resp->status != 408) {
            if (is_no_idempotent_operation(request_operation)) return true;
        }
    }

    return false;
}

tos_error_t *tos_process_request(const tos_client_t *client,
                                 tos_http_request_t *req,
                                 tos_http_response_t *resp,
                                 tos_upload_file_t *upload_file,
                                 const char *request_action,
                                 int retry) {
    int res = TOSE_OK;
    tos_error_t *tos_error;
    int64_t retry_sleep_scale = 100000; // 100 ms
    int64_t retry_sleep_time = 0;
    int max_req_time = retry > 0 ? retry + 1 : 1;
    tos_string_t resp_retry_after_str;
    int64_t resp_retry_after_second = 0;

    for (int count = 0; count < max_req_time; ++count) {
        if (count != 0) {
            retry_sleep_time = retry_sleep_time > 10000000 ? 10000000 : retry_sleep_time; // max sleep time 10s
            if (resp_retry_after_second > 0 && resp_retry_after_second * 1000000 < retry_sleep_time) {
                apr_sleep(resp_retry_after_second * 1000000);
            } else {
                apr_sleep(retry_sleep_time);
            }
        }

        req->clear_body = 0;
        // req->crc64 = 0;
        if (strcmp(request_action, "UploadPartFromFile") == 0 || strcmp(request_action, "PutObjectFromFile") == 0) {
            if (upload_file == NULL) {
                return tos_client_error_create(client->pool, TOSE_INTERNAL_ERROR,
                                               "UploadPartFromFile or PutObjectFromFile upload_file is null");
            }

            res = tos_write_request_body_from_upload_file(client->pool, upload_file, req);
            if (res != TOSE_OK) {
                tos_error = tos_client_error_create(client->pool, TOSE_INVALID_ARGUMENT, "open read file fail");
                return tos_error;
            }
        }

        if (!tos_list_empty(&req->body) || req->body_len >= 0) {
            reset_list_pos(&req->body);
        }

        if (!tos_list_empty(&resp->body) || resp->body_len >= 0) {
            tos_buf_t *b;
            tos_buf_t *n;
            tos_list_for_each_entry_safe(tos_buf_t, b, n, &resp->body, node) {
                tos_list_del(&b->node);
            }
        }

        res = tos_sign_request_v4(req, client->config);
        if (res != TOSE_OK) {
            tos_error = tos_client_error_create(client->pool, res, "tos_sign_request_v4 failed");
            return tos_error;
        }

        if (count > 0) {
            tos_table_add(req->headers, HEADER_SDK_RETRY_COUNT,
                          apr_psprintf(client->pool, "attempt=%d; max=%d", count, max_req_time - 1));
        }

        tos_error = tos_send_request_new(client->ctl, req, resp);
        resp_retry_after_second = 0;

        if (tos_error == NULL) {
            if (resp->status >= 300 && check_should_retry_resp(request_action, req, resp)) {
                if ((resp->status == 429 || resp->status == 503) && resp->headers != NULL) {
                    tos_str_set(&resp_retry_after_str, apr_table_get(resp->headers, HEADER_RETRY_AFTER));
                    if (resp_retry_after_str.data != NULL) {
                        resp_retry_after_second = tos_strtoll(resp_retry_after_str.data, NULL, 10);
                    }
                }

                retry_sleep_time = retry_sleep_scale * (1 << count);
                continue;
            }
        } else {
            if (check_should_retry_curl_error(request_action, tos_error->client_error_code, req)) {
                retry_sleep_time = retry_sleep_scale * (1 << count);
                continue;
            }
        }

        break;
    }

    return tos_error;
}

tos_table_t *tos_table_create_if_null(const tos_client_t *options,
                                      tos_table_t *table,
                                      int table_size) {
    if (table == NULL) {
        table = tos_table_make(options->pool, table_size);
    }
    return table;
}

int tos_does_file_exist(const tos_string_t *filepath, tos_pool_t *pool) {
    apr_status_t s;
    apr_file_t *thefile;

    s = apr_file_open(&thefile, filepath->data, APR_READ, APR_UREAD | APR_GREAD, pool);
    if (s != APR_SUCCESS) {
        return TOS_FALSE;
    }

    apr_file_close(thefile);
    return TOS_TRUE;
}

int tos_get_file_info(const tos_string_t *filepath, tos_pool_t *pool, apr_finfo_t *finfo) {
    apr_status_t s;
    char buf[256];
    apr_file_t *thefile;

    s = apr_file_open(&thefile, filepath->data, APR_READ, APR_UREAD | APR_GREAD, pool);
    if (s != APR_SUCCESS) {
        return s;
    }

    s = apr_file_info_get(finfo, APR_FINFO_NORM, thefile);
    if (s != APR_SUCCESS) {
        apr_file_close(thefile);
        return s;
    }
    apr_file_close(thefile);

    return TOSE_OK;
}