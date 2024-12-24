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

#ifndef LIBTOS_STRING_H
#define LIBTOS_STRING_H

#include <stdbool.h>
#include "tos_sys_define.h"


TOS_CPP_START

typedef struct {
    int len;
    char *data;
} tos_string_t;

#define tos_string(str)     { sizeof(str) - 1, (char *) str }
#define tos_null_string     { 0, NULL }

#define tos_str_set(str, text)  do { \
        if( str!=NULL && text != NULL){                        \
            (str)->len = strlen(text);   \
            (str)->data = (char *) text;                             \
        }                             \
    } while(0)

#define tos_str_null(str)   (str)->len = 0; (str)->data = NULL

#define tos_tolower(c)      (char) ((c >= 'A' && c <= 'Z') ? (c | 0x20) : c)
#define tos_toupper(c)      (char) ((c >= 'a' && c <= 'z') ? (c & ~0x20) : c)

#define tos_string_valid(str) ((str).data != NULL && (str).len > 0)

static APR_INLINE void tos_string_tolower(tos_string_t *str)
{
    int i = 0;
    while (i < str->len) {
        str->data[i] = tos_tolower(str->data[i]);
        ++i;
    }
}

static APR_INLINE char *tos_strlchr(char *p, char *last, char c)
{
    while (p < last) {
        if (*p == c) {
            return p;
        }
        p++;
    }
    return NULL;
}

static APR_INLINE int tos_is_quote(char c)
{
    return c == '\"';
}

static APR_INLINE int tos_is_space(char c)
{
    return ((c == ' ') || (c == '\t'));
}

static APR_INLINE int tos_is_space_or_cntrl(char c)
{
    return c <= ' ';
}

static APR_INLINE bool tos_string_equal(const char* s1, const char* s2)
{
    return strcmp(s1,s2) == 0;
}

static APR_INLINE int tos_is_null_string(const tos_string_t *str)
{
    if (str == NULL || str->data == NULL || str->len == 0) {
        return TOS_TRUE;
    }
    return TOS_FALSE;
}

void tos_strip_space(tos_string_t *str);
void tos_trip_space_and_cntrl(tos_string_t *str);
void tos_unquote_str(tos_string_t *str);

char *tos_pstrdup(tos_pool_t *p, const tos_string_t *s);

int tos_ends_with(const tos_string_t *str, const tos_string_t *suffix);

TOS_CPP_END

#endif
