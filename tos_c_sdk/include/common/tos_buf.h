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

#ifndef LIBTOS_BUF_H
#define LIBTOS_BUF_H

#include "tos_sys_define.h"
#include "tos_list.h"

TOS_CPP_START

typedef struct {
    tos_list_t node;
    uint8_t *pos;
    uint8_t *last;
    uint8_t *start;
    uint8_t *end;
} tos_buf_t;

typedef struct {
    tos_list_t node;
    int64_t file_pos;
    int64_t file_last;
    apr_file_t *file;
    uint32_t owner:1;
} tos_file_buf_t;

tos_buf_t *tos_create_buf(tos_pool_t *p, int size);
#define tos_buf_size(b) (b->last - b->pos)

tos_file_buf_t *tos_create_file_buf(tos_pool_t *p);

tos_buf_t *tos_buf_pack(tos_pool_t *p, const void *data, int size);

void set_tos_buf_list_to_specific_len(tos_list_t *buf_list, int64_t len);

int64_t tos_buf_list_len(tos_list_t *list);

char *tos_buf_list_content(tos_pool_t *p, tos_list_t *list);

void tos_buf_append_string(tos_pool_t *p, tos_buf_t *b, const char *str, int len);

/**
 * @param fb file_pos, file_last equal file_size.
 * @return TOSE_OK success, other failure.
 */ 
int tos_open_file_for_read(tos_pool_t *p, const char *path, tos_file_buf_t *fb);

int tos_open_file_for_all_read(tos_pool_t *p, const char *path, tos_file_buf_t *fb);

int tos_open_file_for_range_read(tos_pool_t *p, const char *path, 
                                 int64_t file_pos, int64_t file_last, 
                                 tos_file_buf_t *fb);

/**
 * create the file if not there, truncate if file exists. 
 * @param fb not check file_pos, file_last.
 * @return TOSE_OK success, other failure.
 */
int tos_open_file_for_write(tos_pool_t *p, const char *path, tos_file_buf_t *fb);
int tos_open_file_for_write_notrunc(tos_pool_t *p, const char *path, tos_file_buf_t *fb);

int tos_open_file_for_range_write(tos_pool_t *p, const char *path, int64_t file_pos, int64_t file_last, tos_file_buf_t *fb);


TOS_CPP_END

#endif

