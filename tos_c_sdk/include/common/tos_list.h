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

#ifndef LIBTOS_LIST_H
#define LIBTOS_LIST_H

#include <apr_general.h>

// from kernel list
typedef struct tos_list_s tos_list_t;

struct tos_list_s {
    tos_list_t *next, *prev;
};

#define tos_list_head_init(name) {&(name), &(name)}

#define tos_list_init(ptr) do {                  \
        (ptr)->next = (ptr);                    \
        (ptr)->prev = (ptr);                    \
    } while (0)

static APR_INLINE void __tos_list_add(tos_list_t *list, tos_list_t *prev, tos_list_t *next)
{
    next->prev = list;
    list->next = next;
    list->prev = prev;
    prev->next = list;
}

// list head to add it before
static APR_INLINE void tos_list_add_tail(tos_list_t *list, tos_list_t *head)
{
    __tos_list_add(list, head->prev, head);
}

static APR_INLINE void __tos_list_del(tos_list_t *prev, tos_list_t *next)
{
    next->prev = prev;
    prev->next = next;
}

// deletes entry from list
static APR_INLINE void tos_list_del(tos_list_t *entry)
{
    __tos_list_del(entry->prev, entry->next);
    tos_list_init(entry);
}

// tests whether a list is empty
static APR_INLINE int tos_list_empty(const tos_list_t *head)
{
    return (head->next == head);
}

// move list to new_list
static APR_INLINE void tos_list_movelist(tos_list_t *list, tos_list_t *new_list)
{
    if (!tos_list_empty(list)) {
        new_list->prev = list->prev;
        new_list->next = list->next;
        new_list->prev->next = new_list;
        new_list->next->prev = new_list;
        tos_list_init(list);
    } else {
        tos_list_init(new_list);
    }
}

// get last
#define tos_list_get_last(list, type, member)                           \
    tos_list_empty(list) ? NULL : tos_list_entry((list)->prev, type, member)

// get first
#define tos_list_get_first(list, type, member)                          \
    tos_list_empty(list) ? NULL : tos_list_entry((list)->next, type, member)

#define tos_list_entry(ptr, type, member) \
    (type *)( (char *)ptr - APR_OFFSETOF(type, member) )

// traversing
#define tos_list_for_each_entry(postp, pos, head, member)                      \
    for (pos = tos_list_entry((head)->next, postp, member);      \
         &pos->member != (head);                                        \
         pos = tos_list_entry(pos->member.next, postp, member))

#define tos_list_for_each_entry_reverse(postp, pos, head, member)              \
    for (pos = tos_list_entry((head)->prev, postp, member);      \
         &pos->member != (head);                                        \
         pos = tos_list_entry(pos->member.prev, postp, member))

#define tos_list_for_each_entry_safe(postp, pos, n, head, member)              \
    for (pos = tos_list_entry((head)->next, postp, member),      \
                 n = tos_list_entry(pos->member.next, postp, member); \
         &pos->member != (head);                                        \
         pos = n, n = tos_list_entry(n->member.next, postp, member))

#define tos_list_for_each_entry_safe_reverse(postp, pos, n, head, member)      \
    for (pos = tos_list_entry((head)->prev, postp, member),      \
                 n = tos_list_entry(pos->member.prev, postp, member); \
         &pos->member != (head);                                        \
         pos = n, n = tos_list_entry(n->member.prev, postp, member))

#endif
