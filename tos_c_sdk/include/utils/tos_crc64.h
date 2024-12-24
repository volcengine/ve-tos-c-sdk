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

#ifndef LIBTOS_CRC_H
#define LIBTOS_CRC_H

#include "../common/tos_sys_define.h"


TOS_CPP_START

uint64_t tos_crc64(uint64_t crc, void *buf, size_t len);
uint64_t tos_crc64_combine(uint64_t crc1, uint64_t crc2, uintmax_t len2);
uint64_t tos_crc64_big(uint64_t crc, void *buf, size_t len);

TOS_CPP_END

#endif
