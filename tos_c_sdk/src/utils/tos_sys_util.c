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

#include "../../include/utils/tos_sys_util.h"
#include "../../include/common/tos_log.h"
#include "../../include/common/tos_define.h"
#include <ctype.h>

static const char *g_s_wday[] = {
    "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"
};

static const char *g_s_mon[] = {
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
};
static const char g_s_ios8601_format[] = "%.4d%.2d%.2dT%.2d%.2d%.2dZ";

static const char g_s_gmt_format[] = "%s, %.2d %s %.4d %.2d:%.2d:%.2d GMT";

static tos_table_t *g_sign_header_table = NULL;
static tos_pool_t *g_table_pool = NULL;


int tos_parse_json_body(tos_list_t *bc, cJSON **json)
{
    tos_buf_t *b;
    size_t len;

    *json = NULL;
    len = (size_t)tos_buf_list_len(bc);

    {
        int nsize = 0;
        char *buffer = (char*)malloc(sizeof(char)*(len+1));
        memset(buffer, 0, len + 1);
        tos_list_for_each_entry(tos_buf_t, b, bc, node) {
            memcpy(buffer + nsize, (char *)b->pos, tos_buf_size(b));
            nsize += tos_buf_size(b);
        }
        *json = cJSON_Parse(buffer);
        free(buffer);
        if (NULL == *json) {
            return TOSE_INTERNAL_ERROR;
        }
    }

    return TOSE_OK;
}

int tos_convert_to_gmt_time(char* date, const char* format, apr_time_exp_t *tm)
{
    int size = apr_snprintf(date, TOS_MAX_GMT_TIME_LEN, format, 
        g_s_wday[tm->tm_wday], tm->tm_mday, g_s_mon[tm->tm_mon], 1900 + tm->tm_year, tm->tm_hour, tm->tm_min, tm->tm_sec);
    if (size >= 0 && size < TOS_MAX_GMT_TIME_LEN) {
        return TOSE_OK;
    } else {
        return TOSE_INTERNAL_ERROR;
    }
}
int tos_get_iso8601_str_time(char datestr[TOS_MAX_GMT_TIME_LEN])
{
    int s;
    apr_time_t now;
    char buf[128];
    apr_time_exp_t result;

    now = apr_time_now();
    if ((s = apr_time_exp_gmt(&result, now)) != APR_SUCCESS) {
        tos_error_log("apr_time_exp_gmt fialure, code:%d %s.", s, apr_strerror(s, buf, sizeof(buf)));
        return TOSE_INTERNAL_ERROR;
    }

    if ((s = tos_convert_to_iso8601_time(datestr, g_s_ios8601_format, &result))
        != TOSE_OK) {
        tos_error_log("tos_convert_to_iso8601_time failure, code:%d.", s);
        }

    return s;
}

int tos_get_gmt_time_date(const char *gmt, char datestr[TOS_MAX_SHORT_TIME_LEN])
{
    char week[4];
    char month[4];
    apr_time_exp_t t;
    int i;
    if (!gmt) {
        return 0;
    }
    memset(week,0,4);
    memset(month,0,4);

    sscanf(gmt,"%3s, %2d %3s %4d %2d:%2d:%2d GMT",
        week, &t.tm_mday, month, &t.tm_year,
        &t.tm_hour, &t.tm_min, &t.tm_sec);

    for (i = 0; i < 12; i++) {
        if (apr_strnatcmp(g_s_mon[i], (char const *)month) == 0) {
            t.tm_mon = i + 1;
            break;
        }
    }
    apr_snprintf(datestr, TOS_MAX_SHORT_TIME_LEN, "%.4d%.2d%.2d",
       t.tm_year, t.tm_mon, t.tm_mday);

    return 0;
}

int tos_convert_to_iso8601_time(char* date, const char* format, apr_time_exp_t* tm)
{
    int size = apr_snprintf(date, TOS_MAX_GMT_TIME_LEN, format,
       1900 + tm->tm_year, 1 + tm->tm_mon, tm->tm_mday, tm->tm_hour, tm->tm_min, tm->tm_sec);
    if (size >= 0 && size < TOS_MAX_GMT_TIME_LEN) {
        return TOSE_OK;
    }
    else {
        return TOSE_INTERNAL_ERROR;
    }
}

int tos_get_gmt_str_time(char datestr[TOS_MAX_GMT_TIME_LEN])
{
    int s;
    apr_time_t now;
    char buf[128];
    apr_time_exp_t result;

    now = apr_time_now();
    if ((s = apr_time_exp_gmt(&result, now)) != APR_SUCCESS) {
        tos_error_log("apr_time_exp_gmt fialure, code:%d %s.", s, apr_strerror(s, buf, sizeof(buf)));
        return TOSE_INTERNAL_ERROR;
    }
    
    if ((s = tos_convert_to_gmt_time(datestr, g_s_gmt_format, &result))
        != TOSE_OK) {
        tos_error_log("tos_convert_to_GMT failure, code:%d.", s);
    }

    return s;
}



int tos_chinese_url_encode(char *dest, const char *src, int maxSrcSize)
{
    static const char *hex = "0123456789ABCDEF";

    int len = 0;

    while (*src) {
        if (++len > maxSrcSize) {
            *dest = 0;
            return TOSE_INVALID_ARGUMENT;
        }

        unsigned char c1 =  (*src);
        if (c1 >= 0xE4 && c1 <= 0xE9 && len+2 <= maxSrcSize) {  // 如果在这个范围内，有可能是中文字符的开始
            unsigned char c2 = (unsigned char) *(src + 1);
            unsigned char c3 = (unsigned char) *(src + 2);
            if (c2 >= 0x80 && c2 <= 0xBF && c3 >= 0x80 && c3 <= 0xBF) {
                *dest++ = '%';
                *dest++ = hex[c1 >> 4];
                *dest++ = hex[c1 & 15];

                *dest++ = '%';
                *dest++ = hex[c2 >> 4];
                *dest++ = hex[c2 & 15];

                *dest++ = '%';
                *dest++ = hex[c3 >> 4];
                *dest++ = hex[c3 & 15];

                src+=2;
            }
        }
        else
        {
            *dest++ = (*src);
        }

        src++;
    }

    *dest = 0;

    return TOSE_OK;
}

int tos_url_encode(char *dest, const char *src, int maxSrcSize)
{
    static const char *hex = "0123456789ABCDEF";

    int len = 0;
    unsigned char c;

    while (*src) {
        if (++len > maxSrcSize) {
            *dest = 0;
            return TOSE_INVALID_ARGUMENT;
        }
        c = *src;
        if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~'|| c=='/') {
            *dest++ = c;
        } else if (*src == ' ') {
            *dest++ = '%';
            *dest++ = '2';
            *dest++ = '0';
        } else {
            *dest++ = '%';
            *dest++ = hex[c >> 4];
            *dest++ = hex[c & 15];
        }
        src++;
    }

    *dest = 0;

    return TOSE_OK;
}

static int table_dict_cmp(const void * a, const void * b)
{
   return strcasecmp(((tos_table_entry_t*)a)->key, ((tos_table_entry_t*)b)->key);
}

void tos_table_sort_by_dict(tos_table_t *table)
{
    const tos_array_header_t *tarr;
    const tos_table_entry_t *telts;

    if (apr_is_empty_table(table)) {
        return;
    }

    tarr = tos_table_elts(table);
    telts = (tos_table_entry_t*)tarr->elts;

    qsort((void *)telts, tarr->nelts, tarr->elt_size, table_dict_cmp);
}

void tos_init_sign_header_table()
{
    int idx = 0;

    if (g_sign_header_table != NULL && !apr_is_empty_table(g_sign_header_table)) {
        return;
    }

    tos_pool_create(&g_table_pool, NULL);
    g_sign_header_table = tos_table_make(g_table_pool, SIGN_HEADER_NUM);
    for (; idx < SIGN_HEADER_NUM; idx++) {
        apr_table_add(g_sign_header_table, SIGN_HEADER[idx], "");
    }
}

void tos_deinit_sign_header_table()
{
    if (g_sign_header_table != NULL) {
        apr_table_clear(g_sign_header_table);
        g_sign_header_table = NULL;
    }

    if (g_table_pool != NULL) {
        tos_pool_destroy(g_table_pool);
        g_table_pool = NULL;
    }
}

static void tos_strlow(char *str)
{
    while (*str) {
        *str = tolower(*str);
        str++;
    }
}

int tos_query_params_to_string(tos_pool_t *p, tos_table_t *query_params, tos_string_t *querystr)
{
    int rs;
    int pos;
    int len;
    char sep = '?';
    char ebuf[TOS_MAX_QUERY_ARG_LEN*3+1];
    char abuf[TOS_MAX_QUERY_ARG_LEN*6+128];
    int max_len;
    const tos_array_header_t *tarr;
    const tos_table_entry_t *telts;
    tos_buf_t *querybuf;

    if (apr_is_empty_table(query_params)) {
        return TOSE_OK;
    }

    max_len = sizeof(abuf)-1;
    querybuf = tos_create_buf(p, 256);
    tos_str_null(querystr);

    tarr = tos_table_elts(query_params);
    telts = (tos_table_entry_t*)tarr->elts;
    
    for (pos = 0; pos < tarr->nelts; ++pos) {
        if ((rs = tos_url_encode(ebuf, telts[pos].key, TOS_MAX_QUERY_ARG_LEN)) != TOSE_OK) {
            tos_error_log("query params args too big, key:%s.", telts[pos].key);
            return TOSE_INVALID_ARGUMENT;
        }
        len = apr_snprintf(abuf, max_len, "%c%s", sep, ebuf);
        if (telts[pos].val != NULL && *telts[pos].val != '\0') {
            if ((rs = tos_url_encode(ebuf, telts[pos].val, TOS_MAX_QUERY_ARG_LEN)) != TOSE_OK) {
                tos_error_log("query params args too big, value:%s.", telts[pos].val);
                return TOSE_INVALID_ARGUMENT;
            }
            len += apr_snprintf(abuf+len, max_len-len, "=%s", ebuf);
            if (len >= TOS_MAX_QUERY_ARG_LEN) {
                tos_error_log("query params args too big, %s.", abuf);
                return TOSE_INVALID_ARGUMENT;
            }
        }
        tos_buf_append_string(p, querybuf, abuf, len);
        sep = '&';
    }

    // result
    querystr->data = (char *)querybuf->pos;
    querystr->len = tos_buf_size(querybuf);
    
    return TOSE_OK;
}

static int is_sign_header(const char *header)
{
    return (apr_table_get(g_sign_header_table, header) != NULL) || 
            (strstr(header, X_TOS_HEADER) == header);
}

static int is_empty_header_value(char *value)
{
    return value != NULL && *value == '\0';
}

int tos_table_to_string(tos_pool_t *p, const tos_table_t *table, tos_string_t *querystr, sign_content_type_e sign_type)
{
    int rs;
    int pos;
    int len;
    char *sep = "";
    char ebuf[TOS_MAX_QUERY_ARG_LEN*3+1];
    char abuf[TOS_MAX_QUERY_ARG_LEN*6+128];
    int max_len;
    const tos_array_header_t *tarr;
    const tos_table_entry_t *telts;
    tos_buf_t *querybuf;

    if (apr_is_empty_table(table)) {
        return TOSE_OK;
    }

    max_len = sizeof(abuf)-1;
    querybuf = tos_create_buf(p, TOS_MAX_QUERY_ARG_LEN);
    tos_str_null(querystr);

    tarr = tos_table_elts(table);
    telts = (tos_table_entry_t*)tarr->elts;
    
    for (pos = 0; pos < tarr->nelts; ++pos) {
        if ((rs = tos_url_encode(ebuf, telts[pos].key, TOS_MAX_QUERY_ARG_LEN)) != TOSE_OK) {
            tos_error_log("table params args too big, key:%s.", telts[pos].key);
            return TOSE_INVALID_ARGUMENT;
        }
        tos_strlow(ebuf);

        if (sign_type == sign_content_header) {
            if (!is_sign_header(ebuf) || is_empty_header_value(telts[pos].val)) {
                continue;
            }
        }

        len = apr_snprintf(abuf, max_len, "%s%s", sep, ebuf);
        if (telts[pos].val != NULL) {
            if ((rs = tos_url_encode(ebuf, telts[pos].val, TOS_MAX_QUERY_ARG_LEN)) != TOSE_OK) {
                tos_error_log("table params args too big, value:%s.", telts[pos].val);
                return TOSE_INVALID_ARGUMENT;
            }
            len += apr_snprintf(abuf+len, max_len-len, "=%s", ebuf);
            if (len >= TOS_MAX_QUERY_ARG_LEN) {
                tos_error_log("table params args too big, %s.", abuf);
                return TOSE_INVALID_ARGUMENT;
            }
        }
        tos_buf_append_string(p, querybuf, abuf, len);
        sep = "&";
    }

    // result
    querystr->data = (char *)querybuf->pos;
    querystr->len = tos_buf_size(querybuf);
    
    return TOSE_OK;
}

int tos_table_key_to_string(tos_pool_t *p, const tos_table_t *table, tos_string_t *querystr, sign_content_type_e sign_type)
{
    int rs;
    int pos;
    int len;
    char *sep = "";
    char ebuf[TOS_MAX_QUERY_ARG_LEN*3+1];
    char abuf[TOS_MAX_QUERY_ARG_LEN*6+128];
    int max_len;
    const tos_array_header_t *tarr;
    const tos_table_entry_t *telts;
    tos_buf_t *querybuf;

    if (apr_is_empty_table(table)) {
        return TOSE_OK;
    }

    max_len = sizeof(abuf)-1;
    querybuf = tos_create_buf(p, 256);
    tos_str_null(querystr);

    tarr = tos_table_elts(table);
    telts = (tos_table_entry_t*)tarr->elts;
    
    for (pos = 0; pos < tarr->nelts; ++pos) {
        if ((rs = tos_url_encode(ebuf, telts[pos].key, TOS_MAX_QUERY_ARG_LEN)) != TOSE_OK) {
            tos_error_log("table params args too big, key:%s.", telts[pos].key);
            return TOSE_INVALID_ARGUMENT;
        }
        tos_strlow(ebuf);

        if (sign_type == sign_content_header) {
            if (!is_sign_header(ebuf) || is_empty_header_value(telts[pos].val)) {
                continue;
            }
        }

        len = apr_snprintf(abuf, max_len, "%s%s", sep, ebuf);
        tos_buf_append_string(p, querybuf, abuf, len);
        sep = ";";
    }

    // result
    querystr->data = (char *)querybuf->pos;
    querystr->len = tos_buf_size(querybuf);
    
    return TOSE_OK;
}

#if 0
void tos_gnome_sort(const char **headers, int size)
{
    const char *tmp;
    int i = 0, last_highest = 0;

    while (i < size) {
        if ((i == 0) || apr_strnatcasecmp(headers[i-1], headers[i]) < 0) {
            i = ++last_highest;
        } else {
            tmp = headers[i];
            headers[i] = headers[i - 1];
            headers[--i] = tmp;
        }
    }
}
#endif
const char* tos_http_method_to_string(http_method_e method)
{
    switch (method) {
        case HTTP_GET:
            return "GET";
        case HTTP_HEAD:
            return "HEAD";
        case HTTP_PUT:
            return "PUT";
        case HTTP_POST:
            return "POST";
        case HTTP_DELETE:
            return "DELETE";
        default:
            return "UNKNOWN";
    }
}


const char* tos_http_method_to_string_lower(http_method_e method)
{
    switch (method) {
        case HTTP_GET:
            return "get";
        case HTTP_HEAD:
            return "head";
        case HTTP_PUT:
            return "put";
        case HTTP_POST:
            return "post";
        case HTTP_DELETE:
            return "delete";
        default:
            return "unknown";
    }
}

/** **************************************************************************
 * util.c
 *
 * Copyright 2008 Bryan Ischo <bryan@ischo.com>
 *
 * This file is part of libs3.
 *
 * libs3 is free software: you can redistribute it and/or modify it under the
 * terms of the GNU General Public License as published by the Free Software
 * Foundation, version 3 of the License.
 *
 * In addition, as a special exception, the copyright holders give
 * permission to link the code of this library and its programs with the
 * OpenSSL library, and distribute linked combinations including the two.
 *
 * libs3 is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License version 3
 * along with libs3, in a file named COPYING.  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 ************************************************************************** **/
int tos_base64_encode(const unsigned char *in, int inLen, char *out)
{
    static const char *ENC = 
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    char *original_out = out;

    while (inLen) {
        // first 6 bits of char 1
        *out++ = ENC[*in >> 2];
        if (!--inLen) {
            // last 2 bits of char 1, 4 bits of 0
            *out++ = ENC[(*in & 0x3) << 4];
            *out++ = '=';
            *out++ = '=';
            break;
        }
        // last 2 bits of char 1, first 4 bits of char 2
        *out++ = ENC[((*in & 0x3) << 4) | (*(in + 1) >> 4)];
        in++;
        if (!--inLen) {
            // last 4 bits of char 2, 2 bits of 0
            *out++ = ENC[(*in & 0xF) << 2];
            *out++ = '=';
            break;
        }
        // last 4 bits of char 2, first 2 bits of char 3
        *out++ = ENC[((*in & 0xF) << 2) | (*(in + 1) >> 6)];
        in++;
        // last 6 bits of char 3
        *out++ = ENC[*in & 0x3F];
        in++, inLen--;
    }

    return (out - original_out);
}

// HMAC-SHA-1:
//
// K - is key padded with zeros to 512 bits
// m - is message
// OPAD - 0x5c5c5c...
// IPAD - 0x363636...
//
// HMAC(K,m) = SHA1((K ^ OPAD) . SHA1((K ^ IPAD) . m))
void HMAC_SHA1(unsigned char hmac[20], const unsigned char *key, int key_len,
               const unsigned char *message, int message_len)
{
    unsigned char kopad[64], kipad[64];
    int i;
    unsigned char digest[APR_SHA1_DIGESTSIZE];
    apr_sha1_ctx_t context;
    
    if (key_len > 64) {
        key_len = 64;
    }

    for (i = 0; i < key_len; i++) {
        kopad[i] = key[i] ^ 0x5c;
        kipad[i] = key[i] ^ 0x36;
    }

    for ( ; i < 64; i++) {
        kopad[i] = 0 ^ 0x5c;
        kipad[i] = 0 ^ 0x36;
    }

    apr_sha1_init(&context);
    apr_sha1_update(&context, (const char *)kipad, 64);
    apr_sha1_update(&context, (const char *)message, (unsigned int)message_len);
    apr_sha1_final(digest, &context);

    apr_sha1_init(&context);
    apr_sha1_update(&context, (const char *)kopad, 64);
    apr_sha1_update(&context, (const char *)digest, 20);
    apr_sha1_final(hmac, &context);
}

unsigned char* tos_md5(tos_pool_t* pool, const char *in, apr_size_t in_len) {
    unsigned char* out;
    apr_md5_ctx_t context;

    //APR_MD5_DIGESTSIZE: The MD5 digest size, value is 16
    out = tos_palloc(pool, APR_MD5_DIGESTSIZE + 1);
    if (!out) {
        return NULL;
    }

    if (0 != apr_md5_init(&context)) {
        return NULL;
    }

    if (0 != apr_md5_update(&context, in, in_len)) {
        return NULL;
    }

    if (0 != apr_md5_final(out, &context)) {
        return NULL;
    }
    out[APR_MD5_DIGESTSIZE] = '\0';
    return out;
};

int tos_url_decode(const char *in, char *out)
{
    static const char tbl[256] = {
        -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
         0, 1, 2, 3, 4, 5, 6, 7,  8, 9,-1,-1,-1,-1,-1,-1,
        -1,10,11,12,13,14,15,-1, -1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
        -1,10,11,12,13,14,15,-1, -1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1
    };
    char c, v1, v2;

    if(in != NULL) {
        while((c=*in++) != '\0') {
            if(c == '%') {
                if(!(v1=*in++) || (v1=tbl[(unsigned char)v1])<0 || 
                   !(v2=*in++) || (v2=tbl[(unsigned char)v2])<0) {
                    *out = '\0';
                    return -1;
                }
                c = (v1<<4)|v2;
            } else if (c == '+') {
                c = ' ';
            }
            *out++ = c;
        }
    }
    *out = '\0';
    return 0;
}

/*
 * Convert a string to a int64_t integer.
 *
 * Ignores `locale' stuff.  Assumes that the upper and lower case
 * alphabets and digits are each contiguous.
 */
int64_t tos_strtoll(const char *nptr, char **endptr, int base)
{
    const char *s;
    /* LONGLONG */
    int64_t acc, cutoff;
    int c;
    int neg, any, cutlim;

    /* endptr may be NULL */

#ifdef __GNUC__
    /* This outrageous construct just to shut up a GCC warning. */
    (void) &acc; (void) &cutoff;
#endif

    /*
     * Skip white space and pick up leading +/- sign if any.
     * If base is 0, allow 0x for hex and 0 for octal, else
     * assume decimal; if base is already 16, allow 0x.
     */
    s = nptr;
    do {
        c = (unsigned char) *s++;
    } while (isspace(c));
    if (c == '-') {
        neg = 1;
        c = *s++;
    } else {
        neg = 0;
        if (c == '+')
            c = *s++;
    }
    if ((base == 0 || base == 16) &&
        c == '0' && (*s == 'x' || *s == 'X')) {
        c = s[1];
        s += 2;
        base = 16;
    }
    if (base == 0)
        base = c == '0' ? 8 : 10;

    /*
     * Compute the cutoff value between legal numbers and illegal
     * numbers.  That is the largest legal value, divided by the
     * base.  An input number that is greater than this value, if
     * followed by a legal input character, is too big.  One that
     * is equal to this value may be valid or not; the limit
     * between valid and invalid numbers is then based on the last
     * digit.  For instance, if the range for int64_ts is
     * [-9223372036854775808..9223372036854775807] and the input base
     * is 10, cutoff will be set to 922337203685477580 and cutlim to
     * either 7 (neg==0) or 8 (neg==1), meaning that if we have
     * accumulated a value > 922337203685477580, or equal but the
     * next digit is > 7 (or 8), the number is too big, and we will
     * return a range error.
     *
     * Set any if any `digits' consumed; make it negative to indicate
     * overflow.
     */
    cutoff = neg ? LLONG_MIN : LLONG_MAX;
    cutlim = (int)(cutoff % base);
    cutoff /= base;
    if (neg) {
        if (cutlim > 0) {
            cutlim -= base;
            cutoff += 1;
        }
        cutlim = -cutlim;
    }
    for (acc = 0, any = 0;; c = (unsigned char) *s++) {
        if (isdigit(c))
            c -= '0';
        else if (isalpha(c))
            c -= isupper(c) ? 'A' - 10 : 'a' - 10;
        else
            break;
        if (c >= base)
            break;
        if (any < 0)
            continue;
        if (neg) {
            if (acc < cutoff || (acc == cutoff && c > cutlim)) {
                any = -1;
                acc = LLONG_MIN;
                errno = ERANGE;
            } else {
                any = 1;
                acc *= base;
                acc -= c;
            }
        } else {
            if (acc > cutoff || (acc == cutoff && c > cutlim)) {
                any = -1;
                acc = LLONG_MAX;
                errno = ERANGE;
            } else {
                any = 1;
                acc *= base;
                acc += c;
            }
        }
    }
    if (endptr != 0)
        /* LINTED interface specification */
        *endptr = (char *)(any ? s - 1 : nptr);
    return (acc);
}

int64_t tos_atoi64(const char *nptr)
{
    return tos_strtoull(nptr, NULL, 10);
}

uint64_t tos_strtoull(const char *nptr, char **endptr, int base)
{
    const char *s;
    uint64_t acc, cutoff;
    int c;
    int neg, any, cutlim;

    /*
     * See strtoq for comments as to the logic used.
     */
    s = nptr;
    do {
        c = (unsigned char) *s++;
    } while (isspace(c));
    if (c == '-') {
        neg = 1;
        c = *s++;
    } else { 
        neg = 0;
        if (c == '+')
            c = *s++;
    }
    if ((base == 0 || base == 16) &&
        c == '0' && (*s == 'x' || *s == 'X')) {
        c = s[1];
        s += 2;
        base = 16;
    }
    if (base == 0)
        base = c == '0' ? 8 : 10;

    cutoff = ULLONG_MAX / (uint64_t)base;
    cutlim = ULLONG_MAX % (uint64_t)base;
    for (acc = 0, any = 0;; c = (unsigned char) *s++) {
        if (isdigit(c))
            c -= '0';
        else if (isalpha(c))
            c -= isupper(c) ? 'A' - 10 : 'a' - 10;
        else
            break;
        if (c >= base)
            break;
        if (any < 0)
            continue;
        if (acc > cutoff || (acc == cutoff && c > cutlim)) {
            any = -1;
            acc = ULLONG_MAX;
            errno = ERANGE;
        } else {
            any = 1;
            acc *= (uint64_t)base;
            acc += c;
        }
    }
    if (neg && any > 0)
#ifdef WIN32
#pragma warning(disable : 4146)
#endif
        acc = -acc;
#ifdef WIN32
#pragma warning(default : 4146)
#endif
    if (endptr != 0)
        *endptr = (char *) (any ? s - 1 : nptr);
    return (acc);
}

uint64_t tos_atoui64(const char *nptr) 
{
    return tos_strtoull(nptr, NULL, 10);
}


void tos_get_hex_from_digest(unsigned char hexdigest[40], unsigned char digest[20])
{
    unsigned char hex_digits[16] = { '0', '1', '2', '3', '4', '5', '6', '7',
                                    '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
    int j = 0;
    int i = 0;
    
    for(; i < 20; i++)
    {
        hexdigest[j++] = hex_digits[(digest[i] >> 4) & 0x0f];
        hexdigest[j++] = hex_digits[digest[i] & 0x0f];
    }
}

void tos_get_hmac_sha1_hexdigest(unsigned char hexdigest[40], const unsigned char *key, int key_len,
                                               const unsigned char *message, int message_len)
{
    unsigned char hmac[20];

    HMAC_SHA1(hmac, key, key_len, message, message_len);

    tos_get_hex_from_digest(hexdigest, hmac);
}

void tos_get_sha1_hexdigest(unsigned char hexdigest[40], const unsigned char *message, int message_len)
{
    unsigned char digest[20];
    apr_sha1_ctx_t context;
    
    apr_sha1_init(&context);
    apr_sha1_update(&context, (const char *)message, (unsigned int)message_len);
    apr_sha1_final(digest, &context);

    tos_get_hex_from_digest(hexdigest, digest);
}

typedef struct sha256_state {
    uint64_t length;
    uint32_t state[8], curlen;
    unsigned char buf[64];
} SHA256_CTX;
/* ===== start - public domain SHA256 implementation ===== */
/* This is based on SHA256 implementation in LibTomCrypt that was released into
 * public domain by Tom St Denis. */
#define WPA_GET_BE32(a) ((((uint32_t)(a)[0]) << 24) |(((uint32_t)(a)[1]) << 16) |(((uint32_t)(a)[2]) <<  8) |((uint32_t)(a)[3]))

#define WPA_PUT_BE64(a, val)                                  \
do {                                                          \
    (a)[0] = (unsigned char)(((uint64_t)(val)) >> 56);  \
    (a)[1] = (unsigned char)(((uint64_t)(val)) >> 48);  \
    (a)[2] = (unsigned char)(((uint64_t)(val)) >> 40);  \
    (a)[3] = (unsigned char)(((uint64_t)(val)) >> 32);  \
    (a)[4] = (unsigned char)(((uint64_t)(val)) >> 24);  \
    (a)[5] = (unsigned char)(((uint64_t)(val)) >> 16);  \
    (a)[6] = (unsigned char)(((uint64_t)(val)) >> 8);   \
    (a)[7] = (unsigned char)(((uint64_t)(val)) & 0xff); \
} while(0)
#define WPA_PUT_BE32(a, val)                                        \
do {                                                                \
    (a)[0] = (unsigned char)((((uint32_t) (val)) >> 24) & 0xff); \
    (a)[1] = (unsigned char)((((uint32_t) (val)) >> 16) & 0xff); \
    (a)[2] = (unsigned char)((((uint32_t) (val)) >> 8) & 0xff);  \
    (a)[3] = (unsigned char)(((uint32_t) (val)) & 0xff);         \
} while(0)

/* sha256.c - Functions to compute SHA256 and SHA224 message digest of files or
   memory blocks according to the NIST specification FIPS-180-2.

   Copyright (C) 2005, 2006 Free Software Foundation, Inc.

   This program is free software; you can redistribute it and/or modify it
   under the terms of the GNU General Public License as published by the
   Free Software Foundation; either version 2, or (at your option) any
   later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software Foundation,
   Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.  */

/* Written by David Madore, considerably copypasting from
   Scott G. Miller's sha1.c
*/

/* the K array */
static const uint32_t K[64] = {
    0x428a2f98UL, 0x71374491UL, 0xb5c0fbcfUL, 0xe9b5dba5UL, 0x3956c25bUL,
    0x59f111f1UL, 0x923f82a4UL, 0xab1c5ed5UL, 0xd807aa98UL, 0x12835b01UL,
    0x243185beUL, 0x550c7dc3UL, 0x72be5d74UL, 0x80deb1feUL, 0x9bdc06a7UL,
    0xc19bf174UL, 0xe49b69c1UL, 0xefbe4786UL, 0x0fc19dc6UL, 0x240ca1ccUL,
    0x2de92c6fUL, 0x4a7484aaUL, 0x5cb0a9dcUL, 0x76f988daUL, 0x983e5152UL,
    0xa831c66dUL, 0xb00327c8UL, 0xbf597fc7UL, 0xc6e00bf3UL, 0xd5a79147UL,
    0x06ca6351UL, 0x14292967UL, 0x27b70a85UL, 0x2e1b2138UL, 0x4d2c6dfcUL,
    0x53380d13UL, 0x650a7354UL, 0x766a0abbUL, 0x81c2c92eUL, 0x92722c85UL,
    0xa2bfe8a1UL, 0xa81a664bUL, 0xc24b8b70UL, 0xc76c51a3UL, 0xd192e819UL,
    0xd6990624UL, 0xf40e3585UL, 0x106aa070UL, 0x19a4c116UL, 0x1e376c08UL,
    0x2748774cUL, 0x34b0bcb5UL, 0x391c0cb3UL, 0x4ed8aa4aUL, 0x5b9cca4fUL,
    0x682e6ff3UL, 0x748f82eeUL, 0x78a5636fUL, 0x84c87814UL, 0x8cc70208UL,
    0x90befffaUL, 0xa4506cebUL, 0xbef9a3f7UL, 0xc67178f2UL
};
#define RORc(x, y) \
      (((((uint32_t)(x) & 0xFFFFFFFFUL) >> (uint32_t)((y) & 31)) | \
          ((uint32_t)(x) << (uint32_t)(32 - ((y) & 31)))) & 0xFFFFFFFFUL)
#define Ch(x,y,z)   (z ^ (x & (y ^ z)))
#define Maj(x,y,z)  (((x | y) & z) | (x & y))
#define S(x, n)     RORc((x), (n))
#define R(x, n)     (((x)&0xFFFFFFFFUL)>>(n))
#define Sigma0(x)   (S(x, 2) ^ S(x, 13) ^ S(x, 22))
#define Sigma1(x)   (S(x, 6) ^ S(x, 11) ^ S(x, 25))
#define Gamma0(x)   (S(x, 7) ^ S(x, 18) ^ R(x, 3))
#define Gamma1(x)   (S(x, 17) ^ S(x, 19) ^ R(x, 10))
#ifndef MIN
#define MIN(x, y)   (((x) < (y)) ? (x) : (y))
#endif
/* compress 512-bits */
static int sha256_compress(struct sha256_state* md, unsigned char* buf)
{
    unsigned long S[8], W[64], t0, t1;
    unsigned long t;
    int i;
    /* copy state into S */
    for (i = 0; i < 8; i++) {
        S[i] = md->state[i];
    }
    /* copy the state into 512-bits into W[0..15] */
    for (i = 0; i < 16; i++)
        W[i] = WPA_GET_BE32(buf + (4 * i));
    /* fill W[16..63] */
    for (i = 16; i < 64; i++) {
        W[i] = Gamma1(W[i - 2]) + W[i - 7] + Gamma0(W[i - 15]) +
            W[i - 16];
    }
    /* Compress */
#define RND(a,b,c,d,e,f,g,h,i)                    \
    t0 = h + Sigma1(e) + Ch(e, f, g) + K[i] + W[i]; \
    t1 = Sigma0(a) + Maj(a, b, c);                  \
    d += t0;                                        \
    h = t0 + t1;
    for (i = 0; i < 64; ++i) {
        RND(S[0], S[1], S[2], S[3], S[4], S[5], S[6], S[7], i);
        t = S[7]; S[7] = S[6]; S[6] = S[5]; S[5] = S[4];
        S[4] = S[3]; S[3] = S[2]; S[2] = S[1]; S[1] = S[0]; S[0] = t;
    }
    /* feedback */
    for (i = 0; i < 8; i++) {
        md->state[i] = md->state[i] + S[i];
    }
    return 0;
}

static void SHA256_Init(struct sha256_state* md)
{
    md->curlen = 0;
    md->length = 0;
    md->state[0] = 0x6A09E667UL;
    md->state[1] = 0xBB67AE85UL;
    md->state[2] = 0x3C6EF372UL;
    md->state[3] = 0xA54FF53AUL;
    md->state[4] = 0x510E527FUL;
    md->state[5] = 0x9B05688CUL;
    md->state[6] = 0x1F83D9ABUL;
    md->state[7] = 0x5BE0CD19UL;
}
/**
   Process a block of memory though the hash
   @param md     The hash state
   @param in     The data to hash
   @param inlen  The length of the data (octets)
   @return CRYPT_OK if successful
*/
static int SHA256_Update(struct sha256_state* md, const unsigned char* in, unsigned long inlen)
{
    unsigned long n;
#define block_size 64
    if (md->curlen > sizeof(md->buf))
        return -1;
    while (inlen > 0) {
        if (md->curlen == 0 && inlen >= block_size) {
            if (sha256_compress(md, (unsigned char*)in) < 0)
                return -1;
            md->length += block_size * 8;
            in += block_size;
            inlen -= block_size;
        }
        else {
            n = MIN(inlen, (block_size - md->curlen));
            memcpy(md->buf + md->curlen, in, n);
            md->curlen += n;
            in += n;
            inlen -= n;
            if (md->curlen == block_size) {
                if (sha256_compress(md, md->buf) < 0)
                    return -1;
                md->length += 8 * block_size;
                md->curlen = 0;
            }
        }
    }
    return 0;
}
/**
   Terminate the hash to get the digest
   @param md  The hash state
   @param out [out] The destination of the hash (32 bytes)
   @return CRYPT_OK if successful
*/
static int SHA256_Final(unsigned char* out, struct sha256_state* md)
{
    int i;
    if (md->curlen >= sizeof(md->buf))
        return -1;
    /* increase the length of the message */
    md->length += md->curlen * 8;
    /* append the '1' bit */
    md->buf[md->curlen++] = (unsigned char)0x80;
    /* if the length is currently above 56 bytes we append zeros
     * then compress.  Then we can fall back to padding zeros and length
     * encoding like normal.
     */
    if (md->curlen > 56) {
        while (md->curlen < 64) {
            md->buf[md->curlen++] = (unsigned char)0;
        }
        sha256_compress(md, md->buf);
        md->curlen = 0;
    }
    /* pad up to 56 bytes of zeroes */
    while (md->curlen < 56) {
        md->buf[md->curlen++] = (unsigned char)0;
    }
    /* store length */
    WPA_PUT_BE64(md->buf + 56, md->length);
    sha256_compress(md, md->buf);
    /* copy output */
    for (i = 0; i < 8; i++)
        WPA_PUT_BE32(out + (4 * i), md->state[i]);
    return 0;
}


void tos_HMAC_SHA256(char hmac[32], const char* key, int key_len, const char* message, int message_len)
{
    unsigned char kopad[64], kipad[64];
    int i;
    unsigned char digest[32];
    SHA256_CTX context;

    if (key_len > 64) {
        key_len = 64;
    }

    for (i = 0; i < key_len; i++) {
        kopad[i] = key[i] ^ 0x5c;
        kipad[i] = key[i] ^ 0x36;
    }

    for (; i < 64; i++) {
        kopad[i] = 0 ^ 0x5c;
        kipad[i] = 0 ^ 0x36;
    }

    SHA256_Init(&context);
    SHA256_Update(&context, kipad, 64);
    SHA256_Update(&context, (unsigned char*)message, (unsigned int)message_len);
    SHA256_Final(digest, &context);

    SHA256_Init(&context);
    SHA256_Update(&context, kopad, 64);
    SHA256_Update(&context, digest, 32);
    SHA256_Final((unsigned char* )hmac, &context);
}

void tos_SHA256(char hash[32], const char* message, int message_len)
{
    SHA256_CTX context;
    memset(hash, 0, 32);
    SHA256_Init(&context);
    SHA256_Update(&context, (const unsigned char*)message, message_len);
    SHA256_Final((unsigned char*)hash, &context);
}

int tos_encode_hex(char* dest, const void* src, int srclen, int* len)
{
    static const char hex_table[] = "0123456789abcdef";
    const unsigned char* in = src;
    int size;

    if (!src) {
        return TOSE_INVALID_ARGUMENT;
    }

    if (dest) {
        for (size = 0; size < srclen; size++) {
            *dest++ = hex_table[in[size] >> 4];
            *dest++ = hex_table[in[size] & 0xf];
        }
        *dest = '\0';
    }

    if (len) {
        *len = srclen * 2 + 1;
    }

    return TOSE_OK;
}
