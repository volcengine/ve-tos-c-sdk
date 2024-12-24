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

#ifndef TOS_CLIENT_IMPL_H
#define TOS_CLIENT_IMPL_H


#include "common/tos_define.h"
#include "tos_error.h"
#include "model/object/create_multipart_upload.h"
#include "model/object/upload_part.h"
#include "model/object/list_parts.h"
#include "model/object/complete_multipart_upload.h"
#include "model/object/abort_multipart_upload.h"

TOS_CPP_START


tos_error_t *create_multipart_upload(const tos_client_t* client, const create_multipart_upload_input_t *input, create_multipart_upload_output_t** output);

tos_error_t *upload_part_from_file(const tos_client_t* client, const upload_part_from_file_input_t* input, upload_part_from_file_output_t** output);

tos_error_t *upload_part_from_buffer(const tos_client_t* client, const upload_part_from_buffer_input_t* input, upload_part_from_buffer_output_t** output);

tos_error_t *list_parts(const tos_client_t* client, const list_parts_input_t *input, list_parts_output_t ** output);

tos_error_t *complete_multipart_upload(const tos_client_t* client, const complete_multipart_upload_input_t *input, complete_multipart_upload_output_t ** output);

tos_error_t *abort_multipart_upload(const tos_client_t* client, const abort_multipart_upload_input_t *input, abort_multipart_upload_output_t ** output);

TOS_CPP_END

#endif //TOS_CLIENT_IMPL_H

