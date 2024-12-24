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
#include "../../include/utils/tos_sys_util.h"
#include "../../include/common/tos_string.h"
#include "../../include/transport/tos_http_io.h"
#include "../../include/transport/tos_transport.h"
#include "../../include/utils/tos_crc64.h"

int tos_curl_code_to_status(CURLcode code);
static void tos_init_curl_headers(tos_curl_http_transport_t *t);
static void tos_transport_cleanup(tos_http_transport_t *t);
static int tos_init_curl_url(tos_curl_http_transport_t *t);
static void tos_curl_transport_headers_done(tos_curl_http_transport_t *t);
static int tos_curl_transport_setup(tos_curl_http_transport_t *t);
static void tos_curl_transport_finish(tos_curl_http_transport_t *t);
static void tos_move_transport_state(tos_curl_http_transport_t *t, tos_transport_state_e s);

static size_t tos_curl_default_header_callback(char *buffer, size_t size, size_t nitems, void *userdata);
static size_t tos_curl_default_write_callback(char *ptr, size_t size, size_t nmemb, void *userdata);
static size_t tos_curl_default_read_callback(char *buffer, size_t size, size_t nitems, void *instream);

static void tos_init_curl_headers(tos_curl_http_transport_t *t)
{
    int pos;
    char *header;
    const tos_array_header_t *tarr;
    const tos_table_entry_t *telts;
    union tos_func_u func;

    if (t->req->method == HTTP_PUT || t->req->method == HTTP_POST) {
        header = apr_psprintf(t->pool, "Content-Length: %" APR_INT64_T_FMT, t->req->body_len);
        t->headers = curl_slist_append(t->headers, header);
    }

    tarr = tos_table_elts(t->req->headers);
    telts = (tos_table_entry_t*)tarr->elts;
    for (pos = 0; pos < tarr->nelts; ++pos) {
        header = apr_psprintf(t->pool, "%s: %s", telts[pos].key, telts[pos].val);
        t->headers = curl_slist_append(t->headers, header);
    }
    
    /* Disable these headers if they're not set explicitly */
    if (NULL == apr_table_get(t->req->headers, TOS_EXPECT)) {
        header = apr_psprintf(t->pool, "%s: %s", TOS_EXPECT, "");
        t->headers = curl_slist_append(t->headers, header);
    }
    if (NULL == apr_table_get(t->req->headers, TOS_TRANSFER_ENCODING)) {
        header = apr_psprintf(t->pool, "%s: %s", TOS_TRANSFER_ENCODING, "");
        t->headers = curl_slist_append(t->headers, header);
    }
    
    func.func1 = (tos_func1_pt)curl_slist_free_all;
    tos_fstack_push(t->cleanup, t->headers, func, 1);
}

static int tos_init_curl_url(tos_curl_http_transport_t *t)
{
    int rs;
    const char *proto;
    tos_string_t querystr;
    char uristr[3*TOS_MAX_URI_LEN+1];

    uristr[0] = '\0';
    tos_str_null(&querystr);
    
    if ((rs = tos_url_encode(uristr, t->req->uri, TOS_MAX_URI_LEN)) != TOSE_OK) {
        t->controller->error_code = rs;
        t->controller->reason = "uri invalid argument.";
        return rs;
    }

    if ((rs = tos_query_params_to_string(t->pool, t->req->query_params, &querystr)) != TOSE_OK) {
        t->controller->error_code = rs;
        t->controller->reason = "query params invalid argument.";
        return rs;
    }

    proto = strlen(t->req->proto) != 0 ? t->req->proto : TOS_HTTP_PREFIX;
    /* use original host to build url */
    if (NULL == t->controller->options->host_ip || 0 >= t->controller->options->host_port) {
        if (querystr.len == 0) {
            t->url = apr_psprintf(t->pool, "%s%s/%s",
                                  proto,
                                  t->req->host,
                                  uristr);
        } else {
            t->url = apr_psprintf(t->pool, "%s%s/%s%.*s",
                                  proto,
                                  t->req->host,
                                  uristr,
                                  querystr.len,
                                  querystr.data);
        }
    }
    /* use specified ip-port to build url */
    else {
        if (querystr.len == 0) {
            t->url = apr_psprintf(t->pool, "%s%s:%d/%s",
                                  proto,
                                  t->controller->options->host_ip,
                                  t->controller->options->host_port,
                                  uristr);
        } else {
            t->url = apr_psprintf(t->pool, "%s%s:%d/%s%.*s",
                                  proto,
                                  t->controller->options->host_ip,
                                  t->controller->options->host_port,
                                  uristr,
                                  querystr.len,
                                  querystr.data);
        }
    }
    
    tos_info_log("url:%s", t->url);

    return TOSE_OK;
}

static void tos_transport_cleanup(tos_http_transport_t *t)
{
    int s;
    char buf[256];

    if (t->req->file_buf != NULL && t->req->file_buf->owner) {
        tos_trace_log("close request body file.");
        if ((s = apr_file_close(t->req->file_buf->file)) != APR_SUCCESS) {
            tos_warn_log("apr_file_close failure, %s.", apr_strerror(s, buf, sizeof(buf)));
        }
        t->req->file_buf = NULL;
    }
    
    if (t->resp->file_buf != NULL && t->resp->file_buf->owner) {
        tos_trace_log("close response body file.");
        if ((s = apr_file_close(t->resp->file_buf->file)) != APR_SUCCESS) {
            tos_warn_log("apr_file_close failure, %s.", apr_strerror(s, buf, sizeof(buf)));
        }
        t->resp->file_buf = NULL;
    }
}

tos_http_transport_t *tos_curl_http_transport_create(tos_pool_t *p)
{
    tos_func_u func;
    tos_curl_http_transport_t *t;

    t = (tos_curl_http_transport_t *)tos_pcalloc(p, sizeof(tos_curl_http_transport_t));

    t->pool = p;
    t->options = tos_default_http_transport_options;
    t->cleanup = tos_fstack_create(p, 5);

    func.func1 = (tos_func1_pt)tos_transport_cleanup;
    tos_fstack_push(t->cleanup, t, func, 1);
    
    t->curl = tos_request_get();
    func.func1 = (tos_func1_pt)request_release2;
    tos_fstack_push(t->cleanup, t, func, 1);

    t->header_callback = tos_curl_default_header_callback;
    t->read_callback = tos_curl_default_read_callback;
    t->write_callback = tos_curl_default_write_callback;

    return (tos_http_transport_t *)t;
}

static void tos_move_transport_state(tos_curl_http_transport_t *t, tos_transport_state_e s)
{
    if (t->state < s) {
        t->state = s;
    }
}

void tos_curl_response_headers_parse(tos_pool_t *p, tos_table_t *headers, char *buffer, int len)
{
    char *pos;
    tos_string_t str;
    tos_string_t key;
    tos_string_t value;
    
    str.data = buffer;
    str.len = len;

    tos_trip_space_and_cntrl(&str);

    pos = tos_strlchr(str.data, str.data + str.len, ':');
    if (pos == NULL) {
        return;
    }
    key.data = str.data;
    key.len = pos - str.data;

    pos += 1;
    value.len = str.data + str.len - pos;
    value.data = pos;
    tos_strip_space(&value);

    apr_table_addn(headers, tos_pstrdup(p, &key), tos_pstrdup(p, &value));
}

size_t tos_curl_default_header_callback(char *buffer, size_t size, size_t nitems, void *userdata)
{
    int len;
    tos_curl_http_transport_t *t;

    t = (tos_curl_http_transport_t *)(userdata);
    len = size * nitems;

    if (t->controller->first_byte_time == 0) {
        t->controller->first_byte_time = apr_time_now();
    }

    tos_curl_response_headers_parse(t->pool, t->resp->headers, buffer, len);

    tos_move_transport_state(t, TRANS_STATE_HEADER);

    return len;
}

static void tos_curl_transport_headers_done(tos_curl_http_transport_t *t)
{
    int32_t http_code;
    CURLcode code;
    const char *value;

    if (t->controller->error_code != TOSE_OK) {
        tos_debug_log("has error %d.", t->controller->error_code);
        return;
    }
    
    if (t->resp->status > 0) {
        tos_trace_log("http response status %d.", t->resp->status);
        return;
    }

    t->resp->status = 0;
    if ((code = curl_easy_getinfo(t->curl, CURLINFO_RESPONSE_CODE, &http_code)) != CURLE_OK) {
        t->controller->reason = apr_pstrdup(t->pool, curl_easy_strerror(code));
        t->controller->error_code = TOSE_INTERNAL_ERROR;
        return;
    } else {
        t->resp->status = http_code;
    }

    value = apr_table_get(t->resp->headers, "Content-Length");
    if (value != NULL) {
        t->resp->content_length = tos_atoi64(value);
    }
}

size_t tos_curl_default_write_callback(char *ptr, size_t size, size_t nmemb, void *userdata)
{
    int len;
    int bytes;
    tos_curl_http_transport_t *t;

    t = (tos_curl_http_transport_t *)(userdata);
    len = size * nmemb;

    if (t->controller->first_byte_time == 0) {
        t->controller->first_byte_time = apr_time_now();
    }
    
    tos_curl_transport_headers_done(t);

    if (t->controller->error_code != TOSE_OK) {
        tos_debug_log("write callback abort");
        return 0;
    }

    // On HTTP error, we expect to parse an HTTP error response    
    if (t->resp->status < 200 || t->resp->status > 299) {
        bytes = tos_write_http_body_memory(t->resp, ptr, len);
        assert(bytes == len);
        tos_move_transport_state(t, TRANS_STATE_BODY_IN);
        return bytes;
    }

    if (t->resp->type == BODY_IN_MEMORY && t->resp->body_len >= (int64_t)t->controller->options->max_memory_size) {
        t->controller->reason = apr_psprintf(t->pool,
             "receive body too big, current body size: %" APR_INT64_T_FMT ", max memory size: %" APR_INT64_T_FMT,
              t->resp->body_len, t->controller->options->max_memory_size);
        t->controller->error_code = TOSE_OUT_MEMORY;
        tos_error_log("error reason:%s, ", t->controller->reason);
        return 0;
    }

    if ((bytes = t->resp->write_body(t->resp, ptr, len)) < 0) {
        tos_debug_log("write body failure, %d.", bytes);
        t->controller->error_code = TOSE_WRITE_BODY_ERROR;
        t->controller->reason = "write body failure.";
        return 0;
    }

    if (bytes >= 0) {
        // progress callback
        if (NULL != t->resp->progress_callback) {
            t->resp->progress_callback(t->resp->body_len, t->resp->content_length);
        }

        // crc
        if (t->controller->options->enable_crc) {
            t->resp->crc64 = tos_crc64(t->resp->crc64, ptr, bytes);
        }
    }
    
    tos_move_transport_state(t, TRANS_STATE_BODY_IN);
    
    return bytes;
}

size_t tos_curl_default_read_callback(char *buffer, size_t size, size_t nitems, void *instream)
{
    int len;
    int bytes;
    tos_curl_http_transport_t *t;
    
    t = (tos_curl_http_transport_t *)(instream);
    len = size * nitems;

    if (t->controller->error_code != TOSE_OK) {
        tos_debug_log("abort read callback.");
        return CURL_READFUNC_ABORT;
    }

    if ((bytes = t->req->read_body(t->req, buffer, len)) < 0) {
        tos_debug_log("read body failure, %d.", bytes);
        t->controller->error_code = TOSE_READ_BODY_ERROR;
        t->controller->reason = "read body failure.";
        return CURL_READFUNC_ABORT;
    }
    
    if (bytes >= 0) {
        // progress callback
        t->req->consumed_bytes += bytes;
        if (NULL != t->req->progress_callback) {
            t->req->progress_callback(t->req->consumed_bytes, t->req->body_len);
        }

        // crc
        if (t->controller->options->enable_crc) {
            t->req->crc64 = tos_crc64(t->req->crc64, buffer, bytes);
        }
    }

    tos_move_transport_state(t, TRANS_STATE_BODY_OUT);

    return bytes;
}

static void tos_curl_transport_finish(tos_curl_http_transport_t *t)
{
    tos_curl_transport_headers_done(t);
    
    if (t->cleanup != NULL) {
        tos_fstack_destory(t->cleanup);
        t->cleanup = NULL;
    }
}
int debug_callback(CURL *handle, curl_infotype type, char *data, size_t size, void *userptr)
{
    if (type == CURLINFO_DATA_OUT)
    {
        printf("Request body: %.*s\n", (int)size, data);
    }
    return 0;
}

int tos_curl_transport_setup(tos_curl_http_transport_t *t)
{
    CURLcode code;

#define curl_easy_setopt_safe(opt, val)                                 \
    if ((code = curl_easy_setopt(t->curl, opt, val)) != CURLE_OK) {    \
            t->controller->reason = apr_pstrdup(t->pool, curl_easy_strerror(code)); \
            t->controller->error_code = code;         \
            tos_error_log("curl_easy_setopt failed, code:%d %s.", code, t->controller->reason); \
            return code;                              \
    }

    curl_easy_setopt_safe(CURLOPT_PRIVATE, t);

    curl_easy_setopt_safe(CURLOPT_HEADERDATA, t);
    curl_easy_setopt_safe(CURLOPT_HEADERFUNCTION, t->header_callback);
    
    curl_easy_setopt_safe(CURLOPT_READDATA, t);
    curl_easy_setopt_safe(CURLOPT_READFUNCTION, t->read_callback);
    
    curl_easy_setopt_safe(CURLOPT_WRITEDATA, t);    
    curl_easy_setopt_safe(CURLOPT_WRITEFUNCTION, t->write_callback);

    curl_easy_setopt_safe(CURLOPT_FILETIME, 1);
    curl_easy_setopt_safe(CURLOPT_NOSIGNAL, 1);
    curl_easy_setopt_safe(CURLOPT_NOPROGRESS, 1);
    curl_easy_setopt_safe(CURLOPT_TCP_NODELAY, 1);
    curl_easy_setopt_safe(CURLOPT_NETRC, CURL_NETRC_IGNORED);

    // transport options
    curl_easy_setopt_safe(CURLOPT_SSL_VERIFYHOST, 0);
    curl_easy_setopt_safe(CURLOPT_SSL_VERIFYPEER, 0);
    curl_easy_setopt_safe(CURLOPT_USERAGENT, t->options->user_agent);

    // request options
    curl_easy_setopt_safe(CURLOPT_TIMEOUT_MS, 0);
    curl_easy_setopt_safe(CURLOPT_DNS_CACHE_TIMEOUT, t->controller->options->dns_cache_timeout);
    curl_easy_setopt_safe(CURLOPT_CONNECTTIMEOUT, t->controller->options->connect_timeout);
    curl_easy_setopt_safe(CURLOPT_LOW_SPEED_TIME, t->controller->options->socket_timeout);

    curl_easy_setopt_safe(CURLOPT_LOW_SPEED_LIMIT, 1L);

    tos_init_curl_headers(t);
    curl_easy_setopt_safe(CURLOPT_HTTPHEADER, t->headers);

    if (t->controller->options->proxy_host != NULL) {
        // proxy
        curl_easy_setopt_safe(CURLOPT_PROXYTYPE, CURLPROXY_HTTP);
        curl_easy_setopt_safe(CURLOPT_PROXY, t->controller->options->proxy_host);
        // authorize
        if (t->controller->options->proxy_auth != NULL) {
            curl_easy_setopt_safe(CURLOPT_PROXYAUTH, CURLAUTH_BASIC);
            curl_easy_setopt_safe(CURLOPT_PROXYUSERPWD, t->controller->options->proxy_auth);
        }
    }

    if (NULL == t->req->signed_url) {
        if (tos_init_curl_url(t) != TOSE_OK) {
            return t->controller->error_code;
        }
    }
    else {
        t->url = t->req->signed_url; 
    }
    curl_easy_setopt_safe(CURLOPT_URL, t->url);

    switch (t->req->method) {
        case HTTP_HEAD:
            curl_easy_setopt_safe(CURLOPT_NOBODY, 1);
            break;
        case HTTP_PUT:
            curl_easy_setopt_safe(CURLOPT_UPLOAD, 1);
            break;
        case HTTP_POST:
            curl_easy_setopt_safe(CURLOPT_POST, 1);
            break;
        case HTTP_DELETE:
            curl_easy_setopt_safe(CURLOPT_CUSTOMREQUEST, "DELETE");
            break;
        default: // HTTP_GET
            break;
    }
    
#undef curl_easy_setopt_safe
    
    t->state = TRANS_STATE_INIT;
    
    return TOSE_OK;
}

int tos_curl_http_transport_perform(tos_http_transport_t *t_)
{
    CURLcode code;
    tos_curl_http_transport_t *t = (tos_curl_http_transport_t *)(t_);
    code = tos_curl_transport_setup(t);
    if (code != TOSE_OK) {
        return code;
    }

    t->controller->start_time = apr_time_now();
    code = curl_easy_perform(t->curl);
    t->controller->finish_time = apr_time_now();
    tos_move_transport_state(t, TRANS_STATE_DONE);
    
    t->curl_code = code;
    if ((code != TOSE_OK) && (t->controller->error_code == TOSE_OK)) {
        t->controller->error_code = code;
        t->controller->reason = apr_pstrdup(t->pool, curl_easy_strerror(code));
        tos_error_log("transport failure curl code:%d error:%s", code, t->controller->reason);
    }

    tos_curl_transport_finish(t);

    return t->controller->error_code;
}
