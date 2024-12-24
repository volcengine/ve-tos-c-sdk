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

#ifndef LIBTOS_HTTP_IO_H
#define LIBTOS_HTTP_IO_H

#include "tos_transport.h"
#include "../common/tos_define.h"


TOS_CPP_START

tos_http_controller_t *tos_http_controller_create(tos_pool_t *p, int owner);

/* http io error message*/
static APR_INLINE const char *tos_http_controller_get_reason(tos_http_controller_t *ctl)
{
    tos_http_controller_ex_t *ctle = (tos_http_controller_ex_t *)ctl;
    return ctle->reason;
}

CURL *tos_request_get();
void request_release(CURL *request);
void request_release2(tos_curl_http_transport_t* t);

int tos_http_io_initialize(const char *user_agent_info, int flag);
void tos_http_io_deinitialize();

int tos_http_send_request(tos_http_controller_t *ctl, tos_http_request_t *req, tos_http_response_t *resp);

void tos_set_default_request_options(tos_http_request_options_t *op);
void tos_set_default_transport_options(tos_http_transport_options_t *op);

tos_http_request_options_t *tos_http_request_options_create(tos_pool_t *p);

tos_http_request_t *tos_http_request_create(tos_pool_t *p);
tos_http_response_t *tos_http_response_create(tos_pool_t *p);

int tos_read_http_body_memory(tos_http_request_t *req, char *buffer, int len);
int tos_write_http_body_memory(tos_http_response_t *resp, const char *buffer, int len);

int tos_read_http_body_file(tos_http_request_t *req, char *buffer, int len);
int tos_write_http_body_file(tos_http_response_t *resp, const char *buffer, int len);
int tos_write_http_body_file_part(tos_http_response_t *resp, const char *buffer, int len);


typedef tos_http_transport_t *(*tos_http_transport_create_pt)(tos_pool_t *p);
typedef int (*tos_http_transport_perform_pt)(tos_http_transport_t *t);

extern tos_pool_t *tos_global_pool;
extern apr_file_t *tos_stderr_file;

extern tos_http_request_options_t *tos_default_http_request_options;
extern tos_http_transport_options_t *tos_default_http_transport_options;

extern tos_http_transport_create_pt tos_http_transport_create;
extern tos_http_transport_perform_pt tos_http_transport_perform;

TOS_CPP_END

#endif

