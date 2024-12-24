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

#ifndef LIB_TOS_AUTH_H
#define LIB_TOS_AUTH_H

#include "utils/tos_sys_util.h"
#include "common/tos_string.h"
#include "transport/tos_http_io.h"
#include "common/tos_define.h"
#include "common/tos_sys_define.h"

TOS_CPP_START

/**
  * @brief  sign tos request
**/
int tos_sign_request_v4(tos_http_request_t *req, const tos_config_t *config);

TOS_CPP_END

#endif
