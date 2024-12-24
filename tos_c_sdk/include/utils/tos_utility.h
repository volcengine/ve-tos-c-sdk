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

#ifndef LIBTOS_UTILITY_H
#define LIBTOS_UTILITY_H

#include "../common/tos_string.h"
#include "../transport/tos_transport.h"
#include "../common/tos_define.h"
#include "../tos_error.h"
TOS_CPP_START

/**
 * @brief  check hostname is ip.
 **/
int is_valid_ip(const char *str);

/**
 * @brief  create tos config including host, port, access_key_id, access_key_secret, is_tos_domain
 **/
tos_config_t *tos_config_create(tos_pool_t *p);

/**
 * @brief evaluate config to curl
 **/
void tos_config_resolve(tos_pool_t *pool, tos_config_t *config, tos_http_controller_t *ctl);

/**
 * @brief  create tos request options
 * @return tos request options
 **/
tos_client_t *tos_client_create(tos_pool_t *p);

/**
 * @brief  init tos request
 **/
void tos_init_request(const tos_client_t *client, http_method_e method,
                      tos_http_request_t **req, tos_table_t *params, tos_table_t *headers, tos_http_response_t **resp);


/**
 * @brief  init tos object request
 **/
tos_error_t *tos_init_object_request(const tos_client_t *options, const tos_string_t *bucket,
                                     const tos_string_t *object, http_method_e method, tos_http_request_t **req,
                                     tos_table_t *params, tos_table_t *headers, tos_progress_callback cb, uint64_t initcrc,
                                     tos_http_response_t **resp);

/**
 * @brief  tos send request
 **/
tos_error_t *tos_send_request_new(tos_http_controller_t *ctl, tos_http_request_t *req,
                                  tos_http_response_t *resp);


tos_error_t* tos_process_request(const tos_client_t* client,
                                 tos_http_request_t* req,
                                 tos_http_response_t* resp,
                                 tos_upload_file_t* upload_file,
                                 const char* request_action,
                                 int retry);


tos_error_t* tos_get_object_uri(const tos_client_t *client,
                                const tos_string_t *bucket,
                                const tos_string_t *object,
                                tos_http_request_t *req);


/**
 * @brief  write body content into tos request body from buffer
 **/
void tos_write_request_body_from_buffer(tos_list_t *buffer, tos_http_request_t *req);

/**
 * @brief   write body content into tos request body from multipart upload file
 **/
int tos_write_request_body_from_upload_file(tos_pool_t *p, tos_upload_file_t *upload_file, tos_http_request_t *req);


/**
 * @brief  create tos api result content
 * @return tos api result content
 **/
void *tos_create_api_result_content(tos_pool_t *p, size_t size);


/**
 * @brief  create upload file struct for range multipart upload
 * @return upload file struct for range multipart upload
 **/
tos_upload_file_t *tos_create_upload_file(tos_pool_t *p);

tos_table_t *tos_table_create_if_null(const tos_client_t *options,
                                      tos_table_t *table, int table_size);

int starts_with(const char* str, const char* prefix);

int tos_string_starts_with(const tos_string_t *str, const char *prefix);

int tos_does_file_exist(const tos_string_t *filepath, tos_pool_t *pool);

int tos_get_file_info(const tos_string_t *filepath, tos_pool_t *pool, apr_finfo_t *finfo);

TOS_CPP_END

#endif
