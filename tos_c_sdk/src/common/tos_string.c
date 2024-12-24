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

#include "../../include/common/tos_string.h"

typedef int (*tos_is_char_pt)(char c);

static void tos_strip_str_func(tos_string_t *str, tos_is_char_pt func);

char *tos_pstrdup(tos_pool_t *p, const tos_string_t *s)
{
    return apr_pstrndup(p, s->data, s->len);
}

static void tos_strip_str_func(tos_string_t *str, tos_is_char_pt func)
{
    char *data = str->data;
    int len = str->len;
    int offset = 0;

    if (len == 0) return;
    
    while (len > 0 && func(data[len - 1])) {
        --len;
    }
    
    for (; offset < len && func(data[offset]); ++offset) {
        // empty;
    }

    str->data = data + offset;
    str->len = len - offset;
}

void tos_unquote_str(tos_string_t *str)
{
    tos_strip_str_func(str, tos_is_quote);
}

void tos_strip_space(tos_string_t *str)
{
    tos_strip_str_func(str, tos_is_space);
}

void tos_trip_space_and_cntrl(tos_string_t *str)
{
    tos_strip_str_func(str, tos_is_space_or_cntrl);
}

int tos_ends_with(const tos_string_t *str, const tos_string_t *suffix)
{
    if (!str || !suffix) {
        return 0;
    }

    return (str->len >= suffix->len) && strncmp(str->data + str->len - suffix->len, suffix->data, suffix->len) == 0;
}
