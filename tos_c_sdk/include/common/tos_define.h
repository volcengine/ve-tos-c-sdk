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

#ifndef LIBTOS_DEFINE_H
#define LIBTOS_DEFINE_H

#include "tos_string.h"
#include "tos_list.h"
#include "../transport/tos_transport.h"

#ifdef __cplusplus
#define TOS_CPP_START extern "C" {
#define TOS_CPP_END }
#else
#define TOS_CPP_START
#define TOS_CPP_END
#endif


// request header key
extern const char HEADER_CONTENT_LENGTH[];
extern const char HEADER_CACHE_CONTROL[];
extern const char HEADER_CONTENT_TYPE[];
extern const char HEADER_CONTENT_LANGUAGE[];
extern const char HEADER_CONTENT_ENCODING[];
extern const char HEADER_CONTENT_DISPOSITION[];
extern const char HEADER_CONTENT_MD5[];
extern const char HEADER_EXPIRES[];

extern const char HEADER_ACL[];
extern const char HEADER_GRANT_FULL_CONTROL[];
extern const char HEADER_GRANT_READ[];
extern const char HEADER_GRANT_READ_ACP[];
extern const char HEADER_GRANT_WRITE[];
extern const char HEADER_GRANT_WRITE_ACP[];

extern const char HEADER_SSEC_ALGORITHM[];
extern const char HEADER_SSEC_KEY[];
extern const char HEADER_SSEC_KEY_MD5[];
extern const char HEADER_SERVER_SIDE_ENCRYPTION[];
extern const char HEADER_SERVER_SIDE_ENCRYPTION_KMS_KEY_ID[];
extern const char HEADER_ETAG[];
extern const char HEADER_HASH_CRC64_ECMA[];
extern const char ALGORITHM_AES_256[];


extern const char HEADER_META_PREFIX[];

extern const char HEADER_STORAGE_CLASS[];
extern const char HEADER_WEBSITE_REDIRECT_LOCATION[];
extern const char HEADER_TAGGING[];
extern const char HEADER_REQUEST_ID[];
extern const char HEADER_ID_2[];
extern const char HEADER_VERSION_ID[];
extern const char HEADER_SECURITY_TOKEN[];
extern const char HEADER_EC[];

extern const char HEADER_SDK_RETRY_COUNT[];
extern const char HEADER_RETRY_AFTER[];

// request query key
extern const char QUERY_UPLOADS[];
extern const char QUERY_ENCODING_TYPE[];
extern const char QUERY_UPLOAD_ID[];
extern const char QUERY_PART_NUMBER[];
extern const char QUERY_MAX_PARTS[];

extern const char TOS_V4_CONTENT_SHA256[];
extern const char TOS_EMPTY_SHA256[];
extern const char TOS_CANNONICALIZED_HEADER_PREFIX[];
extern const char TOS_CANNONICALIZED_HEADER_DATE[];
extern const char TOS_CONTENT_TYPE[];
extern const char TOS_AUTHORIZATION[];
extern const char TOS_EXPECT[];
extern const char TOS_TRANSFER_ENCODING[];
extern const char TOS_HOST[];
extern const char TOS_MAX_PARTS[];
extern const char TOS_PART_NUMBER_MARKER[];
extern const char TOS_STS_SECURITY_TOKEN[];
extern const int TOS_PER_RET_NUM;
extern const char *SIGN_HEADER[];
extern const int SIGN_HEADER_NUM;
extern const char X_TOS_HEADER[];

typedef struct tos_lib_curl_initializer_s tos_lib_curl_initializer_t;

/**
 * tos_acl is an ACL that can be specified when an object is created or
 * updated.  Each canned ACL has a predefined value when expanded to a full
 * set of TOS ACL Grants.
 * Private canned ACL gives the owner FULL_CONTROL and no other permissions
 *     are issued
 * Public Read canned ACL gives the owner FULL_CONTROL and all users Read
 *     permission 
 * Public Read Write canned ACL gives the owner FULL_CONTROL and all users
 *     Read and Write permission
 **/
typedef enum {
    ACL_UNKNOWN = 0,
    ACL_PRIVATE ,
    ACL_PUBLIC_READ ,
    ACL_PUBLIC_READ_WRITE ,
    ACL_AUTHENTICATED_READ ,
    ACL_BUCKET_OWNER_READ ,
    ACL_BUCKET_OWNER_FULL_CONTROL ,
    ACL_BUCKET_OWNER_ENTRUSTED
} acl_type;

typedef enum {
    STORAGE_CLASS_UNKNOWN = 0,
    STORAGE_CLASS_STANDARD,
    STORAGE_CLASS_IA,
    STORAGE_CLASS_ARCHIVE_FR,
    STORAGE_CLASS_INTELLIGENT_TIERING,
    STORAGE_CLASS_COLD_ARCHIVE,
    STORAGE_CLASS_ARCHIVE,
    STORAGE_CLASS_DEEP_COLD_ARCHIVE,
} storage_class_type;


const char* storage_class_to_string(storage_class_type storage_class);
storage_class_type string_to_storage_class(const char* storage_class_str);

const char* acl_type_to_string(acl_type acl);
acl_type string_to_acl_type(const char* acl_type_str);

typedef struct {
    tos_string_t endpoint;
    tos_string_t access_key_id;
    tos_string_t access_key_secret;
    tos_string_t sts_token;
    tos_string_t region;

    int max_retry_time; // 默认3次
} tos_config_t;

typedef struct {
    tos_config_t *config;
    tos_http_controller_t *ctl; /*< tos http controller, more see tos_transport.h */
    tos_pool_t *pool;
} tos_client_t;

typedef struct {
    tos_string_t filename;  /**< file range read filename */
    int64_t file_pos;   /**< file range read start position */
    int64_t file_last;  /**< file range read last position */
} tos_upload_file_t;

#endif
