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

#ifndef LIBTOS_FSTACK_H
#define LIBTOS_FSTACK_H

#include "../common/tos_sys_define.h"


TOS_CPP_START

typedef void (*tos_func1_pt)(void*);
typedef void (*tos_func2_pt)();
typedef int (*tos_func3_pt)(void*);
typedef int (*tos_func4_pt)();

typedef union tos_func_u {
    tos_func1_pt func1;
    tos_func2_pt func2;
    tos_func3_pt func3;
    tos_func4_pt func4;
} tos_func_u;

typedef struct tos_fstack_item_t {
    void *data;
    tos_func_u func;
    int order;
} tos_fstack_item_t;

tos_array_header_t *tos_fstack_create(tos_pool_t *p, int size);

tos_fstack_item_t *tos_fstack_pop(tos_array_header_t *fstack);

void tos_fstack_destory(tos_array_header_t *fstack);

void tos_fstack_push(tos_array_header_t *fstack, void *data, tos_func_u func, int order);

TOS_CPP_END

#endif
