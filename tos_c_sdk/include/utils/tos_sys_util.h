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

#ifndef LIBTOS_SYS_UTIL_H
#define LIBTOS_SYS_UTIL_H

#include "../common/tos_buf.h"
#include "../common/tos_string.h"
#include "../common/tos_sys_define.h"
#include "tos_fstack.h"

#include <mxml.h>
#include <apr_md5.h>
#include <apr_sha1.h>
#include <cjson/cJSON.h>

TOS_CPP_START


typedef enum {
    sign_content_header,
    sign_content_query_params
} sign_content_type_e;

int tos_parse_json_body(tos_list_t *bc, cJSON **json);

void tos_gnome_sort(const char **headers, int size);

int tos_convert_to_gmt_time(char* date, const char* format, apr_time_exp_t *tm);
int tos_get_iso8601_str_time(char datestr[TOS_MAX_GMT_TIME_LEN]);
int tos_convert_to_iso8601_time(char* date, const char* format, apr_time_exp_t* tm);
int tos_get_gmt_time_date(const char *gmt, char datestr[TOS_MAX_SHORT_TIME_LEN]);

/**
 * URL-encodes chinese char of a string from [src] into [dest]. [dest] must have at least
 * 9x the number of characters that [source] has. At most [maxSrcSize] bytes
 * from [src] are encoded; if more are present in [src], 0 is returned from
 * urlEncode, else nonzero is returned.
 */
int tos_chinese_url_encode(char *dest, const char *src, int maxSrcSize);

/**
 * URL-encodes a string from [src] into [dest]. [dest] must have at least
 * 3x the number of characters that [source] has. At most [maxSrcSize] bytes
 * from [src] are encoded; if more are present in [src], 0 is returned from
 * urlEncode, else nonzero is returned.
 */
int tos_url_encode(char *dest, const char *src, int maxSrcSize);

const char* tos_http_method_to_string(http_method_e method);

/**
 * encode query string, check query args < TOS_MAX_QUERY_ARG_LEN
 * result string "?a&b=x"
 */
int tos_query_params_to_string(tos_pool_t *p, tos_table_t *query_params, tos_string_t *querystr);

/**
 * base64 encode bytes. The output buffer must have at least
 * ((4 * (inLen + 1)) / 3) bytes in it.  Returns the number of bytes written
 * to [out].
 */
int tos_base64_encode(const unsigned char *in, int inLen, char *out);

/**
 * Compute HMAC-SHA-1 with key [key] and message [message], storing result
 * in [hmac]
 */
void HMAC_SHA1(unsigned char hmac[20], const unsigned char *key, int key_len,
               const unsigned char *message, int message_len);

unsigned char* tos_md5(tos_pool_t* pool, const char* in, apr_size_t in_len);

/*
 * Convert a string to a long long integer.
 *
 * Ignores `locale' stuff.  Assumes that the upper and lower case
 * alphabets and digits are each contiguous.
 */
int64_t tos_strtoll(const char *nptr, char **endptr, int base);

/*
 * @brief Convert a string to int64_t.
**/
int64_t tos_atoi64(const char *nptr);

/*
 * @brief Convert a string to an unsigned long long integer.
 *
 * Ignores `locale' stuff.  Assumes that the upper and lower case
 * alphabets and digits are each contiguous.
**/
uint64_t tos_strtoull(const char *nptr, char **endptr, int base);

/*
 * @brief Convert a string to uint64_t.
**/
uint64_t tos_atoui64(const char *nptr);

void tos_get_hex_from_digest(unsigned char hexdigest[40], unsigned char digest[20]);

void tos_get_hmac_sha1_hexdigest(unsigned char hexdigest[40], const unsigned char *key, int key_len,
                                               const unsigned char *message, int message_len);

void tos_get_sha1_hexdigest(unsigned char hexdigest[40], const unsigned char *message, int message_len);

void tos_HMAC_SHA256(char hmac[32], const char* key, int key_len, const char* message, int message_len);

void tos_SHA256(char hash[32], const char* message, int message_len);

/**
 * Convert binary data to a hex encoding.
 */
int tos_encode_hex(char* dest, const void* src, int srclen, int* len);


/*
 * @brief init/deinit sign header table.
**/
void tos_init_sign_header_table();
void tos_deinit_sign_header_table();


TOS_CPP_END

#endif
