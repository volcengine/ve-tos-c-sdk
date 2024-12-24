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

#include "../../include/utils/tos_fstack.h"

tos_array_header_t *tos_fstack_create(tos_pool_t *p, int size)
{
    return apr_array_make(p, size, sizeof(tos_fstack_item_t));
}

void tos_fstack_push(tos_array_header_t *fstack, void *data, tos_func_u func, int order)
{
    tos_fstack_item_t *item;

    item = (tos_fstack_item_t*)apr_array_push(fstack);
    item->data = data;
    item->func = func;
    item->order = order;
}

tos_fstack_item_t *tos_fstack_pop(tos_array_header_t *fstack)
{
    tos_fstack_item_t *item;    
    
    item = (tos_fstack_item_t*)apr_array_pop(fstack);
    if (item == NULL) {
        return NULL;
    }

    switch (item->order) {
        case 1:
            item->func.func1(item->data);
            break;
        case 2:
            item->func.func2();
            break;
        case 3:
            item->func.func3(item->data);
            break;
        case 4:
            item->func.func4();
            break;
        default:
            break;
    }
    
    return item;
}

void tos_fstack_destory(tos_array_header_t *fstack)
{
    while (tos_fstack_pop(fstack) != NULL);
}
