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

#include "../../include/common/tos_log.h"
#include "../../include/transport/tos_http_io.h"
#include "../../include/common/tos_sys_define.h"
#include "../../include/utils/tos_sys_util.h"
#include <apr_thread_mutex.h>
#include <apr_file_io.h>

tos_pool_t *tos_global_pool = NULL;
apr_file_t *tos_stderr_file = NULL;

tos_http_request_options_t *tos_default_http_request_options = NULL;
tos_http_transport_options_t *tos_default_http_transport_options = NULL;

tos_http_transport_create_pt tos_http_transport_create = tos_curl_http_transport_create;
tos_http_transport_perform_pt tos_http_transport_perform = tos_curl_http_transport_perform;

static apr_thread_mutex_t* requestStackMutexG = NULL;
apr_thread_mutex_t* downloadMutex = NULL;
static CURL *requestStackG[TOS_REQUEST_STACK_SIZE];
static int requestStackCountG;
static char tos_user_agent[256];


static tos_http_transport_options_t *tos_http_transport_options_create(tos_pool_t *p);

CURL *tos_request_get()
{
    CURL *request = NULL;
    
    apr_thread_mutex_lock(requestStackMutexG);
    if (requestStackCountG > 0) {
        request = requestStackG[--requestStackCountG];
    }
    apr_thread_mutex_unlock(requestStackMutexG);

    // If we got one, deinitialize it for re-use
    if (request) {
        curl_easy_reset(request);
    }
    else {
        request = curl_easy_init();
    }

    return request;
}

void request_release(CURL *request)
{
    apr_thread_mutex_lock(requestStackMutexG);

    // If the request stack is full, destroy this one
    // else put this one at the front of the request stack; we do this because
    // we want the most-recently-used curl handle to be re-used on the next
    // request, to maximize our chances of re-using a TCP connection before it
    // times out
    if (requestStackCountG == TOS_REQUEST_STACK_SIZE) {
        apr_thread_mutex_unlock(requestStackMutexG);
        curl_easy_cleanup(request);
    }
    else {
        requestStackG[requestStackCountG++] = request;
        apr_thread_mutex_unlock(requestStackMutexG);
    }
}

void request_release2(tos_curl_http_transport_t* t)
{
    CURL* request = t->curl;
    CURLcode code = t->curl_code;
    apr_thread_mutex_lock(requestStackMutexG);

    // If the request stack is full, destroy this one
    // else put this one at the front of the request stack; we do this because
    // we want the most-recently-used curl handle to be re-used on the next
    // request, to maximize our chances of re-using a TCP connection before it
    // times out
    if (requestStackCountG == TOS_REQUEST_STACK_SIZE || code != CURLE_OK) {
        apr_thread_mutex_unlock(requestStackMutexG);
        curl_easy_cleanup(request);
    }
    else {
        requestStackG[requestStackCountG++] = request;
        apr_thread_mutex_unlock(requestStackMutexG);
    }
}

void tos_set_default_request_options(tos_http_request_options_t *op)
{
    tos_default_http_request_options = op;
}

void tos_set_default_transport_options(tos_http_transport_options_t *op)
{
    tos_default_http_transport_options = op;
}

tos_http_request_options_t *tos_http_request_options_create(tos_pool_t *p)
{
    tos_http_request_options_t *options;
    
    options = (tos_http_request_options_t *)tos_pcalloc(p, sizeof(tos_http_request_options_t));
    options->socket_timeout = TOS_MIN_SOCKET_TIMEOUT;
    options->connect_timeout = TOS_CONNECT_TIMEOUT;
    options->dns_cache_timeout = TOS_DNS_CACHE_TIMOUT;
    options->max_memory_size = TOS_MAX_MEMORY_SIZE;
    options->enable_crc = TOS_TRUE;
    options->proxy_auth = NULL;
    options->proxy_host = NULL;

    return options;
}

tos_http_transport_options_t *tos_http_transport_options_create(tos_pool_t *p)
{
    return (tos_http_transport_options_t *)tos_pcalloc(p, sizeof(tos_http_transport_options_t));
}

tos_http_controller_t *tos_http_controller_create(tos_pool_t *p, int owner)
{
    tos_http_controller_t *ctl;

    if(p == NULL) {
        if (tos_pool_create(&p, NULL) != APR_SUCCESS) {
            tos_fatal_log("tos_pool_create failure.");
            return NULL;
        }
    }

    ctl = (tos_http_controller_t *)tos_pcalloc(p, sizeof(tos_http_controller_ex_t));
    ctl->pool = p;
    ctl->owner = owner;
    ctl->options = tos_default_http_request_options;

    return ctl;
}

tos_http_request_t *tos_http_request_create(tos_pool_t *p)
{
    tos_http_request_t *req;

    req = (tos_http_request_t *)tos_pcalloc(p, sizeof(tos_http_request_t));
    req->method = HTTP_GET;
    req->headers = tos_table_make(p, 5);
    req->query_params = tos_table_make(p, 3);
    tos_list_init(&req->body);
    req->type = BODY_IN_MEMORY;
    req->body_len = 0;
    req->pool = p;
    req->read_body = tos_read_http_body_memory;

    return req;
}

tos_http_response_t *tos_http_response_create(tos_pool_t *p)
{
    tos_http_response_t *resp;

    resp = (tos_http_response_t *)tos_pcalloc(p, sizeof(tos_http_response_t));
    resp->status = -1;
    resp->headers = tos_table_make(p, 10);
    tos_list_init(&resp->body);
    resp->type = BODY_IN_MEMORY;
    resp->body_len = 0;
    resp->pool = p;
    resp->write_body = tos_write_http_body_memory;

    return resp;
}

int tos_read_http_body_memory(tos_http_request_t *req, char *buffer, int len)
{
    int wsize;
    int bytes = 0;
    tos_buf_t *b;
    tos_buf_t *n;
    
    tos_list_for_each_entry_safe(tos_buf_t, b, n, &req->body, node) {
        wsize = tos_buf_size(b);
        if (wsize == 0) {
            // tos_list_del(&b->node);
            continue;
        }
        wsize = tos_min(len - bytes, wsize);
        if (wsize == 0) {
            break;
        }
        memcpy(buffer + bytes, b->pos, wsize);
        b->pos += wsize;
        bytes += wsize;
        if (b->pos == b->last) {
            // tos_list_del(&b->node);
        }
    }
    req->clear_body = 1;

    return bytes;
}

int tos_read_http_body_file(tos_http_request_t *req, char *buffer, int len)
{
    int s;
    char buf[256];
    apr_size_t nbytes = len;
    apr_size_t bytes_left;
    
    if (req->file_buf == NULL || req->file_buf->file == NULL) {
        tos_error_log("request body arg invalid file_buf NULL.");
        return TOSE_INVALID_ARGUMENT;
    }

    if (req->file_buf->file_pos >= req->file_buf->file_last) {
        tos_debug_log("file read finish.");
        return 0;
    }

    bytes_left = (apr_size_t)(req->file_buf->file_last - req->file_buf->file_pos);
    if (nbytes > bytes_left) {
        nbytes = bytes_left;
    }

    if ((s = apr_file_read(req->file_buf->file, buffer, &nbytes)) != APR_SUCCESS) {
        tos_error_log("apr_file_read filure, code:%d %s.", s, apr_strerror(s, buf, sizeof(buf)));
        return TOSE_FILE_READ_ERROR;
    }
    req->file_buf->file_pos += nbytes;
    return nbytes;
}

int tos_write_http_body_memory(tos_http_response_t *resp, const char *buffer, int len)
{
    tos_buf_t *b;

    b = tos_create_buf(resp->pool, len);
    memcpy(b->pos, buffer, len);
    b->last += len;
    tos_list_add_tail(&b->node, &resp->body);
    resp->body_len += len;

    return len;
}

int tos_http_io_initialize(const char *user_agent_info, int flags)
{
    CURLcode ecode;
    int s;
    char buf[256];
    tos_http_request_options_t *req_options;
    tos_http_transport_options_t *trans_options;

    if ((ecode = curl_global_init(CURL_GLOBAL_ALL &
           ~((flags & TOS_INIT_WINSOCK) ? 0: CURL_GLOBAL_WIN32))) != CURLE_OK) 
    {
        tos_error_log("curl_global_init failure, code:%d %s.\n", ecode, curl_easy_strerror(ecode));
        return TOSE_INTERNAL_ERROR;
    }

    if ((s = apr_initialize()) != APR_SUCCESS) {
        tos_error_log("apr_initialize failure.\n");
        return TOSE_INTERNAL_ERROR;
    }

    if (!user_agent_info || !*user_agent_info) {
        user_agent_info = "Unknown";
    }

    if ((s = tos_pool_create(&tos_global_pool, NULL)) != APR_SUCCESS) {
        tos_error_log("tos_pool_create failure, code:%d %s.\n", s, apr_strerror(s, buf, sizeof(buf)));
        return TOSE_INTERNAL_ERROR;
    }

    if ((s = apr_thread_mutex_create(&requestStackMutexG, APR_THREAD_MUTEX_DEFAULT, tos_global_pool)) != APR_SUCCESS) {
        tos_error_log("apr_thread_mutex_create failure, code:%d %s.\n", s, apr_strerror(s, buf, sizeof(buf)));
        return TOSE_INTERNAL_ERROR;
    }
    requestStackCountG = 0;

    if ((s = apr_thread_mutex_create(&downloadMutex, APR_THREAD_MUTEX_DEFAULT, tos_global_pool)) != APR_SUCCESS) {
        tos_error_log("apr_thread_mutex_create failure, code:%d %s.\n", s, apr_strerror(s, buf, sizeof(buf)));
        return TOSE_INTERNAL_ERROR;
    }

    apr_snprintf(tos_user_agent, sizeof(tos_user_agent)-1, "%s", TOS_VER);

    req_options = tos_http_request_options_create(tos_global_pool);
    trans_options = tos_http_transport_options_create(tos_global_pool);
    trans_options->user_agent = tos_user_agent;

    tos_set_default_request_options(req_options);
    tos_set_default_transport_options(trans_options);

    tos_init_sign_header_table();

    return TOSE_OK;
}

void tos_http_io_deinitialize()
{
    apr_thread_mutex_destroy(requestStackMutexG);
    apr_thread_mutex_destroy(downloadMutex);

    while (requestStackCountG--) {
        curl_easy_cleanup(requestStackG[requestStackCountG]);
    }

    if (tos_stderr_file != NULL) {
        apr_file_close(tos_stderr_file);
        tos_stderr_file = NULL;
    }
    if (tos_global_pool != NULL) {
        tos_pool_destroy(tos_global_pool);
        tos_global_pool = NULL;
    }

    tos_deinit_sign_header_table();
    
    apr_terminate();
}

int tos_http_send_request(tos_http_controller_t *ctl, tos_http_request_t *req, tos_http_response_t *resp)
{
    tos_http_transport_t *t;

    if ((t = tos_http_transport_create(ctl->pool)) == NULL)
    {
        return TOSE_CREATE_TRANSPORT_FAILED;
    }
    t->req = req;
    t->resp = resp;
    t->controller = (tos_http_controller_ex_t *)ctl;
    return tos_http_transport_perform(t);
}

