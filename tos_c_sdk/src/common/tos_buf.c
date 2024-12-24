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

#include "../../include/common/tos_buf.h"
#include "../../include/common/tos_log.h"
#include <apr_file_io.h>
#include <stdbool.h>

tos_buf_t *tos_create_buf(tos_pool_t *p, int size)
{
    tos_buf_t* b;

    b = tos_palloc(p, sizeof(tos_buf_t) + size);
    if (b == NULL) {
        return NULL;
    }

    b->pos = (uint8_t *)b + sizeof(tos_buf_t);
    b->start = b->pos;
    b->last = b->start;
    b->end = b->last + size;
    tos_list_init(&b->node);

    return b;
}

tos_buf_t *tos_buf_pack(tos_pool_t *p, const void *data, int size)
{
    tos_buf_t* b;

    b = tos_palloc(p, sizeof(tos_buf_t));
    if (b == NULL) {
        return NULL;
    }

    b->pos = (uint8_t *)data;
    b->start = b->pos;
    b->last = b->start + size;
    b->end = b->last;
    tos_list_init(&b->node);

    return b;
}

void set_tos_buf_list_to_specific_len(tos_list_t *buf_list, int64_t specific_buf_list_len)
{
    tos_buf_t *b;
    int64_t len = 0;
    int64_t cur_buf_len = 0;
    int64_t buf_list_real_len = 0;
    bool reset_flag = false;

    buf_list_real_len = tos_buf_list_len(buf_list);
    if (buf_list_real_len <= 0) return;
    if (buf_list_real_len < specific_buf_list_len) return;

    tos_list_for_each_entry(tos_buf_t, b, buf_list, node) {
        cur_buf_len = tos_buf_size(b);
        if (len + cur_buf_len >= specific_buf_list_len && !reset_flag)
        {
            b->last = (uint8_t *)b->start + (specific_buf_list_len - len);
            reset_flag = true;
        }
        else if (reset_flag)
        {
            // this buffer data will not transfer
            // because of content-length
            b->last = b->start;
        }
        len += cur_buf_len;
    }
}

int64_t tos_buf_list_len(tos_list_t *list)
{
    tos_buf_t *b;
    int64_t len = 0;

    tos_list_for_each_entry(tos_buf_t, b, list, node) {
        len += tos_buf_size(b);
    }

    return len;
}

char *tos_buf_list_content(tos_pool_t *p, tos_list_t *list)
{
    int64_t body_len;
    char *buf;
    int64_t pos = 0;
    int64_t size = 0;
    tos_buf_t *content;

    body_len = tos_buf_list_len(list);
    buf = tos_pcalloc(p, (size_t)(body_len + 1));
    buf[body_len] = '\0';
    tos_list_for_each_entry(tos_buf_t, content, list, node) {
        size = tos_buf_size(content);
        memcpy(buf + pos, content->pos, (size_t)(size));
        pos += size;
    }
    return buf;
}

tos_file_buf_t *tos_create_file_buf(tos_pool_t *p)
{
    return (tos_file_buf_t*)tos_pcalloc(p, sizeof(tos_file_buf_t));
}

int tos_open_file_for_read(tos_pool_t *p, const char *path, tos_file_buf_t *fb)
{
    int s;
    char buf[256];
    apr_finfo_t finfo;

    if ((s = apr_file_open(&fb->file, path, APR_READ, APR_UREAD | APR_GREAD, p)) != APR_SUCCESS) {
        tos_error_log("apr_file_open failure, code:%d %s.", s, apr_strerror(s, buf, sizeof(buf)));
        assert(fb->file == NULL);
        return TOSE_OPEN_FILE_ERROR;
    }

    if ((s = apr_file_info_get(&finfo, APR_FINFO_NORM, fb->file)) != APR_SUCCESS) {
        apr_file_close(fb->file);
        tos_error_log("apr_file_open failure, code:%d %s.", s, apr_strerror(s, buf, sizeof(buf)));
        return TOSE_FILE_INFO_ERROR;
    }
    fb->file_pos = 0;
    fb->file_last = finfo.size;
    fb->owner = 1;

    return TOSE_OK;
}

int tos_open_file_for_all_read(tos_pool_t *p, const char *path, tos_file_buf_t *fb)
{
    return tos_open_file_for_read(p, path, fb);
}

int tos_open_file_for_range_read(tos_pool_t *p, const char *path, 
    int64_t file_pos, int64_t file_last, tos_file_buf_t *fb)
{
    int s;

    s = tos_open_file_for_read(p, path, fb);
    if (s == TOSE_OK) {
        if (file_pos > fb->file_pos) {
            if (file_pos > fb->file_last) {
                tos_warn_log("read range beyond file size, read start:%" APR_INT64_T_FMT ", file size:%" APR_INT64_T_FMT "\n", 
                    file_pos, fb->file_last);
                file_pos = fb->file_last;
            }
            fb->file_pos = file_pos;
        }
        if (file_last < fb->file_last) {
            fb->file_last = file_last;
        }
        apr_file_seek(fb->file, APR_SET, (apr_off_t *)&fb->file_pos);
    }

    return s;
}

int tos_open_file_for_write(tos_pool_t *p, const char *path, tos_file_buf_t *fb)
{
    int s;
    char buf[256];

    if ((s = apr_file_open(&fb->file, path, APR_CREATE | APR_WRITE | APR_TRUNCATE,
                APR_UREAD | APR_UWRITE | APR_GREAD, p)) != APR_SUCCESS) {
        tos_error_log("apr_file_open failure, code:%d %s.", s, apr_strerror(s, buf, sizeof(buf)));
        assert(fb->file == NULL);
        return TOSE_OPEN_FILE_ERROR;
    }
    fb->owner = 1;

    return TOSE_OK;
}

int tos_open_file_for_write_notrunc(tos_pool_t *p, const char *path, tos_file_buf_t *fb)
{
    int s;
    char buf[256];

    if ((s = apr_file_open(&fb->file, path, APR_CREATE | APR_WRITE,
                APR_UREAD | APR_UWRITE | APR_GREAD, p)) != APR_SUCCESS) {
        tos_error_log("apr_file_open failure, code:%d %s.", s, apr_strerror(s, buf, sizeof(buf)));
        assert(fb->file == NULL);
        return TOSE_OPEN_FILE_ERROR;
    }
    fb->owner = 1;

    return TOSE_OK;
}

int tos_open_file_for_range_write(tos_pool_t *p, const char *path, int64_t file_pos, int64_t file_last, tos_file_buf_t *fb)
{
    int s;
    char buf[256];

    if ((s = apr_file_open(&fb->file, path, APR_CREATE | APR_WRITE,
                APR_UREAD | APR_UWRITE | APR_GREAD, p)) != APR_SUCCESS) {
        tos_error_log("apr_file_open failure, code:%d %s.", s, apr_strerror(s, buf, sizeof(buf)));
        assert(fb->file == NULL);
        return TOSE_OPEN_FILE_ERROR;
    }
    fb->owner = 1;
    fb->file_pos = file_pos;
    fb->file_last = file_last;
    apr_file_seek(fb->file, APR_SET, (apr_off_t *)&fb->file_pos);

    return TOSE_OK;
}


void tos_buf_append_string(tos_pool_t *p, tos_buf_t *b, const char *str, int len)
{
    int size;
    int nsize;
    int remain;
    char *buf;

    if (len <= 0) return;

    remain = b->end - b->last;

    if (remain > len + 128) {
        memcpy(b->last, str, len);
        b->last += len;
    } else {
        size = tos_buf_size(b);
        nsize = (size + len) * 2;
        buf = tos_palloc(p, nsize);
        memcpy(buf, b->pos, size);
        memcpy(buf+size, str, len);
        b->start = (uint8_t *)buf;
        b->end = (uint8_t *)buf + nsize;
        b->pos = (uint8_t *)buf;
        b->last = (uint8_t *)buf + size + len;
    }
}
