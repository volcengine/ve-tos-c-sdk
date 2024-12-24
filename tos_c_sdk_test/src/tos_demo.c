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

#include "transport/tos_http_io.h"
#include "utils/tos_utility.h"
#include "tos_error.h"
#include "model/object/create_multipart_upload.h"
#include "model/object/upload_part.h"
#include "model/object/list_parts.h"
#include "model/object/complete_multipart_upload.h"
#include "model/object/abort_multipart_upload.h"
#include "common/tos_define.h"
#include "tos_client_impl.h"
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

// endpoint 是 TOS 访问域名信息，详情请参见文档
static char TEST_ENDPOINT[] = "";
// 开发者拥有的项目身份ID/密钥，可在 Console 页面获取
static char *TEST_ACCESS_KEY_ID;                //your secret_id
static char *TEST_ACCESS_KEY_SECRET;            //your secret_key
static char *TEST_STS_TOKEN;            //your sts_token
// bucket 是桶名
static char TEST_BUCKET_NAME[] = "";
// 地域信息
static char TEST_REGION[] = "";    //region in endpoint
static char TEST_MULTIPART_OBJECT[] = "";
static char TEST_FILE_PATH[] = "";


void init_test_config_ak_sk(tos_config_t *config) {
    tos_str_set(&config->endpoint, TEST_ENDPOINT);
    tos_str_set(&config->region, TEST_REGION);
    tos_str_set(&config->access_key_id, TEST_ACCESS_KEY_ID);
    tos_str_set(&config->access_key_secret, TEST_ACCESS_KEY_SECRET);
}

void init_test_config_sts_token(tos_config_t *config) {
    tos_str_set(&config->endpoint, TEST_ENDPOINT);
    tos_str_set(&config->region, TEST_REGION);
    tos_str_set(&config->access_key_id, TEST_ACCESS_KEY_ID);
    tos_str_set(&config->access_key_secret, TEST_ACCESS_KEY_SECRET);
    tos_str_set(&config->sts_token, TEST_STS_TOKEN);
}

void init_test_tos_client(tos_client_t *client) {
    client->config = tos_config_create(client->pool);

    init_test_config_ak_sk(client->config);
    // init_test_config_sts_token(client->config);

    client->ctl = tos_http_controller_create(client->pool, 0);

    // client->ctl->options->connect_timeout = 5; // connect timeout 5s, if not set default is 10s
    // client->ctl->options->socket_timeout = 60; // socket timeout 60s, if not set default is 120s
}

int test_create_and_abort_multipart_upload() {
    // basic input
    tos_pool_t *p = NULL;
    tos_string_t bucket;
    tos_string_t object;
    tos_client_t *client = NULL;
    tos_error_t *error = NULL;

    // create multipart upload input
    create_multipart_upload_input_t *create_multipart_upload_input = NULL;
    create_multipart_upload_output_t *create_multipart_upload_output = NULL;

    // abort abort multipart upload input
    abort_multipart_upload_input_t *abort_multipart_upload_input = NULL;
    abort_multipart_upload_output_t *abort_multipart_upload_output = NULL;

    tos_pool_create(&p, NULL);
    client = tos_client_create(p);
    init_test_tos_client(client);

    tos_str_set(&bucket, TEST_BUCKET_NAME);
    tos_str_set(&object, TEST_MULTIPART_OBJECT);

    if (create_multipart_upload_input_new(client->pool, &create_multipart_upload_input) != TOSE_OK)
    {
        tos_pool_destroy(p);
        return -1;
    }
    tos_str_set(&create_multipart_upload_input->bucket, bucket.data);
    tos_str_set(&create_multipart_upload_input->key, object.data);
    tos_str_set(&create_multipart_upload_input->cache_control, "xxx");


    // create multipart upload
    error = create_multipart_upload(client, create_multipart_upload_input, &create_multipart_upload_output);
    if (error == NULL) {
        printf("Init multipart upload succeeded, upload_id:%.*s\n",
               create_multipart_upload_output->upload_id.len,
               create_multipart_upload_output->upload_id.data);
    } else {
        printf("Init multipart upload failed, request_id:%.*s, status_code:%d, message:%.*s, ec:%.*s\n",
               error->request_id.len, error->request_id.data,
               error->status_code,
               error->message.len, error->message.data,
               error->ec.len, error->ec.data);
        tos_pool_destroy(p);
        return -1;
    }

    // abort multipart upload
    if (abort_multipart_upload_input_new(client->pool, &abort_multipart_upload_input) != TOSE_OK)
    {
        tos_pool_destroy(p);
        return -1;
    }
    tos_str_set(&abort_multipart_upload_input->bucket, TEST_BUCKET_NAME);
    tos_str_set(&abort_multipart_upload_input->key, TEST_MULTIPART_OBJECT);
    tos_str_set(&abort_multipart_upload_input->upload_id, create_multipart_upload_output->upload_id.data);

    error = abort_multipart_upload(client, abort_multipart_upload_input, &abort_multipart_upload_output);
    if (error == NULL) {
        printf("Abort multipart upload succeeded, upload_id:%.*s\n",
               create_multipart_upload_output->upload_id.len,
               create_multipart_upload_output->upload_id.data);
    } else {
        printf("Abort multipart upload failed, request_id:%.*s, status_code:%d, message:%.*s, ec:%.*s\n",
               error->request_id.len, error->request_id.data,
               error->status_code,
               error->message.len, error->message.data,
               error->ec.len, error->ec.data);
        tos_pool_destroy(p);
        return -1;
    }

    tos_pool_destroy(p);
    return 0;
}

int test_multipart_upload_from_file() {
    // basic input
    tos_pool_t *p = NULL;
    tos_string_t bucket;
    tos_string_t object;
    tos_client_t *client = NULL;
    tos_error_t *error = NULL;

    // create multipart upload input
    create_multipart_upload_input_t *create_multipart_upload_input = NULL;
    create_multipart_upload_output_t *create_multipart_upload_output = NULL;

    // multipart upload from file input
    upload_part_from_file_input_t *upload_part_from_file_input = NULL;
    upload_part_from_file_output_t *upload_part_from_file_output = NULL;
    tos_file_buf_t *fb = NULL;
    int64_t file_length = 0;
    int64_t pos = 0;
    int part_num = 1;

    // list parts
    list_parts_input_t *list_part_input = NULL;
    list_parts_output_t *list_part_output = NULL;
    upload_part_t *part_content = NULL;

    // complete multipart upload input
    complete_multipart_upload_input_t  *complete_multipart_upload_input = NULL;
    complete_multipart_upload_output_t  *complete_multipart_upload_output = NULL;
    upload_part_t *complete_part_content = NULL;

    tos_pool_create(&p, NULL);
    client = tos_client_create(p);
    init_test_tos_client(client);

    tos_str_set(&bucket, TEST_BUCKET_NAME);
    tos_str_set(&object, TEST_MULTIPART_OBJECT);

    // create multipart upload
    if (create_multipart_upload_input_new(client->pool, &create_multipart_upload_input) != TOSE_OK)
    {
        tos_pool_destroy(p);
        return -1;
    }
    tos_str_set(&create_multipart_upload_input->bucket, bucket.data);
    tos_str_set(&create_multipart_upload_input->key, object.data);

    error = create_multipart_upload(client, create_multipart_upload_input, &create_multipart_upload_output);
    if (error == NULL) {
        printf("Init multipart upload succeeded, upload_id:%.*s\n",
               create_multipart_upload_output->upload_id.len,
               create_multipart_upload_output->upload_id.data);
    } else {
        printf("Init multipart upload failed, request_id:%.*s, status_code:%d, message:%.*s, ec:%.*s\n",
               error->request_id.len, error->request_id.data,
               error->status_code,
               error->message.len, error->message.data,
               error->ec.len, error->ec.data);

        tos_pool_destroy(p);
        return -1;
    }

    // upload part from file
    if((fb = tos_create_file_buf(p)) == NULL)
    {
        tos_pool_destroy(p);
        return -1;
    }
    if (tos_open_file_for_all_read(p, TEST_FILE_PATH, fb) != TOSE_OK)
    {
        tos_pool_destroy(p);
        return -1;
    }

    file_length = fb->file_last;
    apr_file_close(fb->file);

    if (upload_part_from_file_input_new(client->pool, &upload_part_from_file_input) != TOSE_OK)
    {
        tos_pool_destroy(p);
        return -1;
    }
    tos_str_set(&upload_part_from_file_input->upload_id, create_multipart_upload_output->upload_id.data);
    tos_str_set(&upload_part_from_file_input->bucket, TEST_BUCKET_NAME);
    tos_str_set(&upload_part_from_file_input->key, TEST_MULTIPART_OBJECT);
    tos_str_set(&upload_part_from_file_input->file_path, TEST_FILE_PATH);

    while (pos < file_length) {
        upload_part_from_file_input->part_number = part_num++;
        upload_part_from_file_input->offset = pos;
        upload_part_from_file_input->part_size = pos + 10 * 1024 * 1024 > file_length ? file_length - pos : 10 * 1024 * 1024;
        pos += upload_part_from_file_input->part_size;
        error = upload_part_from_file(client, upload_part_from_file_input, &upload_part_from_file_output);
        if (error == NULL) {
            printf("Multipart upload part from file succeeded\n");
        } else {
            printf("Multipart upload part from file failed, request_id:%.*s, status_code:%d, message:%.*s, ec:%.*s\n",
                   error->request_id.len, error->request_id.data,
                   error->status_code,
                   error->message.len, error->message.data,
                   error->ec.len, error->ec.data);

            tos_pool_destroy(p);
            return -1;
        }
    }

    // list part
    if (list_parts_input_new(client->pool,&list_part_input) != TOSE_OK)
    {
        tos_pool_destroy(p);
        return -1;
    }
    list_part_input->max_parts = 1000;
    tos_str_set(&list_part_input->bucket,bucket.data);
    tos_str_set(&list_part_input->key,object.data);
    tos_str_set(&list_part_input->upload_id,create_multipart_upload_output->upload_id.data);

    error = list_parts(client,list_part_input,&list_part_output);
    if (error == NULL) {
        printf("List multipart succeeded\n");
        tos_list_for_each_entry(upload_part_t, part_content, &list_part_output->parts, node) {
            printf("part_number = %d, size = %ld, last_modified = %s, etag = %s\n",
                   part_content->part_number,
                   part_content->size,
                   part_content->last_modified.data,
                   part_content->etag.data);
        }
    } else {
        printf("List multipart failed, request_id:%.*s, status_code:%d, message:%.*s, ec:%.*s\n",
               error->request_id.len, error->request_id.data,
               error->status_code,
               error->message.len, error->message.data,
               error->ec.len, error->ec.data);
        tos_pool_destroy(p);
        return -1;
    }

    // complete multipart upload input
    if (complete_multipart_upload_input_new(client->pool,&complete_multipart_upload_input) != TOSE_OK)
    {
        tos_pool_destroy(p);
        return -1;
    }
    tos_list_for_each_entry(upload_part_t, part_content, &list_part_output->parts, node) {
        complete_part_content = create_list_parts_content(p);
        complete_part_content->part_number = part_content->part_number;
        tos_str_set(&complete_part_content->etag, part_content->etag.data);
        tos_list_add_tail(&complete_part_content->node, &complete_multipart_upload_input->parts);
    }
    tos_str_set(&complete_multipart_upload_input->bucket,bucket.data);
    tos_str_set(&complete_multipart_upload_input->key,object.data);
    tos_str_set(&complete_multipart_upload_input->upload_id,create_multipart_upload_output->upload_id.data);

    error = complete_multipart_upload(client,complete_multipart_upload_input,&complete_multipart_upload_output);
    if (error == NULL) {
        printf("Complete multipart upload from file succeeded, key:%.*s\n",
               complete_multipart_upload_output->key.len, complete_multipart_upload_output->key.data);
    } else {
        printf("Complete multipart upload from file failed, request_id:%.*s, status_code:%d, message:%.*s, ec:%.*s\n",
               error->request_id.len, error->request_id.data,
               error->status_code,
               error->message.len, error->message.data,
               error->ec.len, error->ec.data);

        tos_pool_destroy(p);
        return -1;
    }

    tos_pool_destroy(p);
    return 0;
}

int test_multipart_upload_from_buffer() {
    // basic input
    tos_pool_t *p = NULL;
    tos_string_t bucket;
    tos_string_t object;
    tos_client_t *client = NULL;
    tos_error_t *error = NULL;

    // create multipart upload input
    create_multipart_upload_input_t *create_multipart_upload_input = NULL;
    create_multipart_upload_output_t *create_multipart_upload_output = NULL;

    // multipart upload from buffer input
    upload_part_from_buffer_input_t *upload_part_from_buffer_input = NULL;
    upload_part_from_buffer_output_t *upload_part_from_buffer_output = NULL;

    // list parts
    list_parts_input_t *list_part_input = NULL;
    list_parts_output_t *list_part_output = NULL;
    upload_part_t *part_content = NULL;

    // complete multipart upload input
    complete_multipart_upload_input_t  *complete_multipart_upload_input = NULL;
    complete_multipart_upload_output_t  *complete_multipart_upload_output = NULL;
    upload_part_t *complete_part_content = NULL;

    tos_pool_create(&p, NULL);
    client = tos_client_create(p);
    init_test_tos_client(client);

    tos_str_set(&bucket, TEST_BUCKET_NAME);
    tos_str_set(&object, TEST_MULTIPART_OBJECT);

    // create multipart upload
    if (create_multipart_upload_input_new(client->pool, &create_multipart_upload_input) != TOSE_OK)
    {
        tos_pool_destroy(p);
        return -1;
    }
    tos_str_set(&create_multipart_upload_input->bucket, bucket.data);
    tos_str_set(&create_multipart_upload_input->key, object.data);

    error = create_multipart_upload(client, create_multipart_upload_input, &create_multipart_upload_output);
    if (error == NULL) {
        printf("Init multipart upload succeeded, upload_id:%.*s\n",
               create_multipart_upload_output->upload_id.len,
               create_multipart_upload_output->upload_id.data);
    } else {
        printf("Init multipart upload failed, request_id:%.*s, status_code:%d, message:%.*s, ec:%.*s\n",
               error->request_id.len, error->request_id.data,
               error->status_code,
               error->message.len, error->message.data,
               error->ec.len, error->ec.data);

        tos_pool_destroy(p);
        return -1;
    }

    for (int i = 1; i <= 3;++i)
    {
        // 分配内存
        char *str = (char *)tos_pcalloc(client->pool, 10*1024*1024);
        if (str == NULL) {
            printf(stderr, "Memory allocation failed\n");
            return -1;
        }
        // 填充字符串，例：用字符 'A' 填充
        memset(str, 'A', 10*1024*1024 - 1);
        str[10*1024*1024 - 1] = '\0'; // 确保字符串以 '\0' 结尾
        // buffer 数据
        tos_list_t buffer;
        tos_buf_t* content = NULL;
        tos_list_init(&buffer);
        content = tos_buf_pack(client->pool, str, strlen(str));
        tos_list_add_tail(&content->node, &buffer);

        // upload part from buffer
        if (upload_part_from_buffer_input_new(client->pool, &upload_part_from_buffer_input) != TOSE_OK)
        {
            tos_pool_destroy(p);
            return -1;
        }
        upload_part_from_buffer_input->content = &buffer;
        tos_str_set(&upload_part_from_buffer_input->upload_id,create_multipart_upload_output->upload_id.data);
        tos_str_set(&upload_part_from_buffer_input->bucket,bucket.data);
        tos_str_set(&upload_part_from_buffer_input->key,object.data);
        upload_part_from_buffer_input->part_number = i;

        error = upload_part_from_buffer(client,upload_part_from_buffer_input,&upload_part_from_buffer_output);
        if (error == NULL) {
            printf("Multipart upload part from buffer succeeded\n");
        } else {
            printf("Multipart upload part from buffer failed, request_id:%.*s, status_code:%d, message:%.*s, ec:%.*s\n",
                   error->request_id.len, error->request_id.data,
                   error->status_code,
                   error->message.len, error->message.data,
                   error->ec.len, error->ec.data);
            tos_pool_destroy(p);
            return -1;
        }
    }

    // list part
    if (list_parts_input_new(client->pool,&list_part_input) != TOSE_OK)
    {
        tos_pool_destroy(p);
        return -1;
    }
    list_part_input->max_parts = 1000;
    tos_str_set(&list_part_input->bucket,bucket.data);
    tos_str_set(&list_part_input->key,object.data);
    tos_str_set(&list_part_input->upload_id,create_multipart_upload_output->upload_id.data);

    error = list_parts(client,list_part_input,&list_part_output);
    if (error == NULL) {
        printf("List multipart succeeded\n");
        tos_list_for_each_entry(upload_part_t, part_content, &list_part_output->parts, node) {
            printf("part_number = %d, size = %ld, last_modified = %s, etag = %s\n",
                   part_content->part_number,
                   part_content->size,
                   part_content->last_modified.data,
                   part_content->etag.data);
        }
    } else {
        printf("List multipart failed, request_id:%.*s, status_code:%d, message:%.*s, ec:%.*s\n",
               error->request_id.len, error->request_id.data,
               error->status_code,
               error->message.len, error->message.data,
               error->ec.len, error->ec.data);
        tos_pool_destroy(p);
        return -1;
    }

    // complete multipart upload input
    if (complete_multipart_upload_input_new(client->pool,&complete_multipart_upload_input) != TOSE_OK)
    {
        tos_pool_destroy(p);
        return -1;
    }
    tos_list_for_each_entry(upload_part_t, part_content, &list_part_output->parts, node) {
        complete_part_content = create_list_parts_content(p);
        complete_part_content->part_number = part_content->part_number;
        tos_str_set(&complete_part_content->etag, part_content->etag.data);
        tos_list_add_tail(&complete_part_content->node, &complete_multipart_upload_input->parts);
    }
    tos_str_set(&complete_multipart_upload_input->bucket,bucket.data);
    tos_str_set(&complete_multipart_upload_input->key,object.data);
    tos_str_set(&complete_multipart_upload_input->upload_id,create_multipart_upload_output->upload_id.data);

    error = complete_multipart_upload(client,complete_multipart_upload_input,&complete_multipart_upload_output);
    if (error == NULL) {
        printf("Complete multipart upload from file succeeded, key:%.*s\n",
               complete_multipart_upload_output->key.len, complete_multipart_upload_output->key.data);
    } else {
        printf("Complete multipart upload from file failed, request_id:%.*s, status_code:%d, message:%.*s, ec:%.*s\n",
               error->request_id.len, error->request_id.data,
               error->status_code,
               error->message.len, error->message.data,
               error->ec.len, error->ec.data);

        tos_pool_destroy(p);
        return -1;
    }

    tos_pool_destroy(p);
    return 0;
}

typedef struct {
    char* upload_id;
    int part_num;
} thread_args_t;

void* upload_part_from_buffer_parallel_core(void *arg)
{
    // basic input
    tos_pool_t *p = NULL;
    tos_string_t bucket;
    tos_string_t object;
    tos_client_t *client = NULL;
    tos_error_t *error = NULL;

    thread_args_t *args = (thread_args_t *)arg;

    tos_str_set(&bucket, TEST_BUCKET_NAME);
    tos_str_set(&object, TEST_MULTIPART_OBJECT);

    // multipart upload from buffer input
    upload_part_from_buffer_input_t *upload_part_from_buffer_input = NULL;
    upload_part_from_buffer_output_t *upload_part_from_buffer_output = NULL;

    tos_pool_create(&p, NULL);
    client = tos_client_create(p);
    init_test_tos_client(client);

    tos_str_set(&bucket, TEST_BUCKET_NAME);
    tos_str_set(&object, TEST_MULTIPART_OBJECT);

    // 分配内存
    char *str = (char *)tos_pcalloc(client->pool, 10*1024*1024);
    if (str == NULL) {
        printf(stderr, "Memory allocation failed\n");
        tos_pool_destroy(p);
        pthread_exit((void *)1);
    }
    // 填充字符串，例：用字符 'A' 填充
    memset(str, 'A', 10*1024*1024 - 1);
    str[10*1024*1024 - 1] = '\0'; // 确保字符串以 '\0' 结尾
    // buffer 数据
    tos_list_t buffer;
    tos_buf_t* content = NULL;
    tos_list_init(&buffer);
    content = tos_buf_pack(client->pool, str, strlen(str));
    tos_list_add_tail(&content->node, &buffer);

    // upload part from buffer
    if (upload_part_from_buffer_input_new(client->pool, &upload_part_from_buffer_input) != TOSE_OK)
    {
        tos_pool_destroy(p);
        pthread_exit((void *)1);
    }

    upload_part_from_buffer_input->content = &buffer;
    tos_str_set(&upload_part_from_buffer_input->upload_id,args->upload_id);
    tos_str_set(&upload_part_from_buffer_input->bucket,bucket.data);
    tos_str_set(&upload_part_from_buffer_input->key,object.data);
    upload_part_from_buffer_input->part_number = args->part_num;

    error = upload_part_from_buffer(client,upload_part_from_buffer_input,&upload_part_from_buffer_output);
    if (error == NULL) {
        printf("Multipart upload part from buffer succeeded\n");
    } else {
        printf("Multipart upload part from buffer failed, request_id:%.*s, status_code:%d, message:%.*s, ec:%.*s\n",
               error->request_id.len, error->request_id.data,
               error->status_code,
               error->message.len, error->message.data,
               error->ec.len, error->ec.data);
        tos_pool_destroy(p);
        pthread_exit((void *)1);
    }

    tos_pool_destroy(p);
    pthread_exit(NULL);
}

int test_multipart_upload_from_buffer_parallel() {
    // basic input
    tos_pool_t *p = NULL;
    tos_string_t bucket;
    tos_string_t object;
    tos_client_t *client = NULL;
    tos_error_t *error = NULL;

    // create multipart upload input
    create_multipart_upload_input_t *create_multipart_upload_input = NULL;
    create_multipart_upload_output_t *create_multipart_upload_output = NULL;

    // list parts
    list_parts_input_t *list_part_input = NULL;
    list_parts_output_t *list_part_output = NULL;
    upload_part_t *part_content = NULL;

    // complete multipart upload input
    complete_multipart_upload_input_t  *complete_multipart_upload_input = NULL;
    complete_multipart_upload_output_t  *complete_multipart_upload_output = NULL;
    upload_part_t *complete_part_content = NULL;

    tos_pool_create(&p, NULL);
    client = tos_client_create(p);
    init_test_tos_client(client);

    tos_str_set(&bucket, TEST_BUCKET_NAME);
    tos_str_set(&object, TEST_MULTIPART_OBJECT);

    // create multipart upload
    if (create_multipart_upload_input_new(client->pool, &create_multipart_upload_input) != TOSE_OK)
    {
        tos_pool_destroy(p);
        return -1;
    }
    tos_str_set(&create_multipart_upload_input->bucket, bucket.data);
    tos_str_set(&create_multipart_upload_input->key, object.data);

    error = create_multipart_upload(client, create_multipart_upload_input, &create_multipart_upload_output);
    if (error == NULL) {
        printf("Init multipart upload succeeded, upload_id:%.*s\n",
               create_multipart_upload_output->upload_id.len,
               create_multipart_upload_output->upload_id.data);
    } else {
        printf("Init multipart upload failed, request_id:%.*s, status_code:%d, message:%.*s, ec:%.*s\n",
               error->request_id.len, error->request_id.data,
               error->status_code,
               error->message.len, error->message.data,
               error->ec.len, error->ec.data);

        tos_pool_destroy(p);
        return -1;
    }

    // start 10 threads
    pthread_t threads[10];
    thread_args_t thread_args[10];

    for (int i = 0; i < 10; i++) {
        thread_args[i].part_num = i+1;
        thread_args[i].upload_id = create_multipart_upload_output->upload_id.data;
        if (pthread_create(&threads[i], NULL, upload_part_from_buffer_parallel_core, &thread_args[i]) != 0) {
            fprintf(stderr, "Error creating thread %d\n", i);
            exit(1);
        }
    }

    // wait threads
    for (int i = 0; i < 10; i++) {
        void *status;
        if (pthread_join(threads[i], &status) != 0) {
            fprintf(stderr, "Error joining thread %d\n", i);
            exit(1);
        }

        if (status != NULL) {
            if (status == (void *)1) {
                printf("Thread %d exited with error: Division by zero.\n", i);
            } else {
                printf("Thread %d exited successfully.\n", i);
            }
        }
    }

    // list part
    if (list_parts_input_new(client->pool,&list_part_input) != TOSE_OK)
    {
        tos_pool_destroy(p);
        return -1;
    }
    list_part_input->max_parts = 1000;
    tos_str_set(&list_part_input->bucket,bucket.data);
    tos_str_set(&list_part_input->key,object.data);
    tos_str_set(&list_part_input->upload_id,create_multipart_upload_output->upload_id.data);

    error = list_parts(client,list_part_input,&list_part_output);
    if (error == NULL) {
        printf("List multipart succeeded\n");
        tos_list_for_each_entry(upload_part_t, part_content, &list_part_output->parts, node) {
            printf("part_number = %d, size = %ld, last_modified = %s, etag = %s\n",
                   part_content->part_number,
                   part_content->size,
                   part_content->last_modified.data,
                   part_content->etag.data);
        }
    } else {
        printf("List multipart failed, request_id:%.*s, status_code:%d, message:%.*s, ec:%.*s\n",
               error->request_id.len, error->request_id.data,
               error->status_code,
               error->message.len, error->message.data,
               error->ec.len, error->ec.data);
        tos_pool_destroy(p);
        return -1;
    }

    // complete multipart upload input
    if (complete_multipart_upload_input_new(client->pool,&complete_multipart_upload_input) != TOSE_OK)
    {
        tos_pool_destroy(p);
        return -1;
    }
    tos_list_for_each_entry(upload_part_t, part_content, &list_part_output->parts, node) {
        complete_part_content = create_list_parts_content(p);
        complete_part_content->part_number = part_content->part_number;
        tos_str_set(&complete_part_content->etag, part_content->etag.data);
        tos_list_add_tail(&complete_part_content->node, &complete_multipart_upload_input->parts);
    }
    tos_str_set(&complete_multipart_upload_input->bucket,bucket.data);
    tos_str_set(&complete_multipart_upload_input->key,object.data);
    tos_str_set(&complete_multipart_upload_input->upload_id,create_multipart_upload_output->upload_id.data);

    error = complete_multipart_upload(client,complete_multipart_upload_input,&complete_multipart_upload_output);
    if (error == NULL) {
        printf("Complete multipart upload from file succeeded, key:%.*s\n",
               complete_multipart_upload_output->key.len, complete_multipart_upload_output->key.data);
    } else {
        printf("Complete multipart upload from file failed, request_id:%.*s, status_code:%d, message:%.*s, ec:%.*s\n",
               error->request_id.len, error->request_id.data,
               error->status_code,
               error->message.len, error->message.data,
               error->ec.len, error->ec.data);

        tos_pool_destroy(p);
        return -1;
    }

    tos_pool_destroy(p);
    return 0;
}

int main(int argc, char *argv[]) {
    int res = 0;

    // 通过环境变量获取
    TEST_ACCESS_KEY_ID = getenv("TOS_SECRET_ID");
    TEST_ACCESS_KEY_SECRET = getenv("TOS_SECRET_KEY");
    TEST_STS_TOKEN = getenv("TOS_STS_TOKEN");

    if (tos_http_io_initialize(NULL, 0) != TOSE_OK) {
        exit(1);
    }

    res = test_create_and_abort_multipart_upload();
    if (res) printf("run **** < test_create_and_abort_multipart_upload > **** failed/n");

    res = test_multipart_upload_from_file();
    if (res) printf("run **** < test_multipart_upload_from_file > **** failed/n");

    res = test_multipart_upload_from_buffer();
    if (res) printf("run **** < test_multipart_upload_from_buffer > **** failed/n");


    res = test_multipart_upload_from_buffer_parallel();
    if (res) printf("run **** < test_multipart_test_multipart_upload_from_buffer_parallel > **** failed/n");


    // tos_http_io_deinitialize last
    tos_http_io_deinitialize();

    return 0;
}
