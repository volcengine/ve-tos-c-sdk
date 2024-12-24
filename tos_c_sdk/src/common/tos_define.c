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

#include "../../include/common/tos_define.h"

// basic headers
const char HEADER_CONTENT_LENGTH[] = "Content-Length";
const char HEADER_CACHE_CONTROL[] = "Cache-Control";
const char HEADER_CONTENT_TYPE[] = "Content-Type";
const char HEADER_CONTENT_LANGUAGE[] = "Content-Language";
const char HEADER_CONTENT_ENCODING[] = "Content-Encoding";
const char HEADER_CONTENT_DISPOSITION[] = "Content-Disposition";
const char HEADER_CONTENT_MD5[] = "Content-MD5";
const char HEADER_EXPIRES[] = "Expires";

const char HEADER_PREFIX[] = "x-tos-";

// acl headers
const char HEADER_ACL[] = "x-tos-acl";
const char HEADER_GRANT_FULL_CONTROL[] = "x-tos-grant-full-control";
const char HEADER_GRANT_READ[] = "x-tos-grant-read";
const char HEADER_GRANT_READ_ACP[] = "x-tos-grant-read-acp";
const char HEADER_GRANT_WRITE[] = "x-tos-grant-write";
const char HEADER_GRANT_WRITE_ACP[] = "x-tos-grant-write-acp";

// sse headers
const char HEADER_SSEC_ALGORITHM[] = "x-tos-server-side-encryption-customer-algorithm";
const char HEADER_SSEC_KEY[] = "x-tos-server-side-encryption-customer-key";
const char HEADER_SSEC_KEY_MD5[] = "x-tos-server-side-encryption-customer-key-MD5";
const char HEADER_SERVER_SIDE_ENCRYPTION[] = "x-tos-server-server-side-encryption";
const char HEADER_SERVER_SIDE_ENCRYPTION_KMS_KEY_ID[] = "x-tos-server-side-encryption-kms-key-id";
const char HEADER_ETAG[] = "ETag";
const char HEADER_HASH_CRC64_ECMA[] = "x-tos-hash-crc64ecma";
const char ALGORITHM_AES_256[] = "AES256";

// meta
const char HEADER_META_PREFIX[] = "x-tos-meta-";

// misc
const char HEADER_STORAGE_CLASS[] = "x-tos-storage-class";
const char HEADER_WEBSITE_REDIRECT_LOCATION[] = "x-tos-website-redirect-location";

const char HEADER_TAGGING[] = "x-tos-tagging";
const char HEADER_REQUEST_ID[] = "x-tos-request-id";
const char HEADER_ID_2[] = "x-tos-id-2";
const char HEADER_VERSION_ID[] = "x-tos-version-id";
const char HEADER_SECURITY_TOKEN[] = "x-tos-security-token";
const char HEADER_EC[] = "x-tos-ec";

const char HEADER_SDK_RETRY_COUNT[] = "x-sdk-retry-count";
const char HEADER_RETRY_AFTER[] = "Retry-After";

const char QUERY_UPLOADS[] = "uploads";
const char QUERY_ENCODING_TYPE[] = "encoding-type";
const char QUERY_UPLOAD_ID[] = "uploadId";
const char QUERY_PART_NUMBER[] = "partNumber";
const char QUERY_MAX_PARTS[] = "max-parts";

const char TOS_ETAG[] = "ETag";
const char TOS_CANNONICALIZED_HEADER_VERSION_ID[] = "x-tos-version-id";
const char TOS_V4_CONTENT_SHA256[] = "x-tos-content-sha256";
const char TOS_EMPTY_SHA256[] = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const char TOS_UNSIGNED_PAYLOAD[] = "UNSIGNED-PAYLOAD";
const char TOS_SIGN_PREFIX[] = "TOS4-HMAC-SHA256";
const char TOS_CANNONICALIZED_HEADER_PREFIX[] = "x-tos-";
const char TOS_CANNONICALIZED_HEADER_DATE[] = "x-tos-date";
const char TOS_CANNONICALIZED_HEADER_ACL[] = "x-tos-acl";
const char TOS_CANNONICALIZED_HEADER_COPY_SOURCE[] = "x-tos-copy-source";
const char TOS_GRANT_READ[] = "x-tos-grant-read";
const char TOS_GRANT_WRITE[] = "x-tos-grant-write";
const char TOS_GRANT_FULL_CONTROL[] = "x-tos-grant-full-control";
const char TOS_CONTENT_MD5[] = "Content-MD5";
const char TOS_CONTENT_TYPE[] = "Content-Type";

const char TOS_DATE[] = "Date";
const char TOS_AUTHORIZATION[] = "Authorization";
const char TOS_ACCESSKEYID[] = "TOSAccessKeyId";
const char TOS_EXPECT[] = "Expect";
const char TOS_TRANSFER_ENCODING[] = "Transfer-Encoding";
const char TOS_HOST[] = "Host";
const char TOS_RANGE[] = "Range";
const char TOS_EXPIRES[] = "Expires";
const char TOS_SIGNATURE[] = "Signature";
const char TOS_ACL[] = "acl";
const char TOS_ENCODING_TYPE[] = "encoding-type";
const char TOS_PREFIX[] = "prefix";
const char TOS_DELIMITER[] = "delimiter";
const char TOS_MARKER[] = "marker";
const char TOS_MAX_KEYS[] = "max-keys";
const char TOS_RESTORE[] = "restore";
const char TOS_UPLOAD_ID[] = "uploadId";
const char TOS_MAX_PARTS[] = "max-parts";
const char TOS_PART_NUMBER_MARKER[] = "part-number-marker";
const char TOS_KEY_MARKER[] = "key-marker";
const char TOS_UPLOAD_ID_MARKER[] = "upload-id-marker";
const char TOS_MAX_UPLOADS[] = "max-uploads";
const char TOS_PARTNUMBER[] = "partNumber";
const char TOS_APPEND[] = "append";
const char TOS_POSITION[] = "position";
const char TOS_MULTIPART_CONTENT_TYPE[] = "application/x-www-form-urlencoded";
const char TOS_COPY_SOURCE[] = "x-tos-copy-source";
const char TOS_COPY_SOURCE_RANGE[] = "x-tos-copy-source-range";
const char TOS_SECURITY_TOKEN[] = "security-token";
const char TOS_STS_SECURITY_TOKEN[] = "x-tos-security-token";
const char TOS_REPLACE_OBJECT_META[] = "x-tos-replace-object-meta";
const char TOS_OBJECT_TYPE[] = "x-tos-object-type";
const char TOS_NEXT_APPEND_POSITION[] = "x-tos-next-append-position";
const char TOS_HASH_CRC64_ECMA[] = "x-tos-hash-crc64ecma";
const char TOS_CONTENT_SHA1[] = "x-tos-content-sha1";
const char TOS_CALLBACK[] = "x-tos-callback";
const char TOS_CALLBACK_VAR[] = "x-tos-callback-var";
const char TOS_PROCESS[] = "x-tos-process";
const char TOS_LIFECYCLE[] = "lifecycle";
const char TOS_CORS[] = "cors";
const char TOS_REPLICATION[] = "replication";
const char TOS_VERSIONING[] = "versioning";
const char TOS_WEBSITE[] = "website";
const char TOS_DOMAIN[] = "domain";
const char TOS_DELETE[] = "delete";
const char TOS_LOGGING[] = "logging";
const char TOS_INVENTORY[] = "inventory";
const char TOS_TAGGING[] = "tagging";
const char TOS_REFERER[] = "referer";
const char TOS_YES[] = "yes";
const char TOS_OBJECT_TYPE_NORMAL[] = "normal";
const char TOS_OBJECT_TYPE_APPENDABLE[] = "appendable";
const char TOS_LIVE_CHANNEL[] = "live";
const char TOS_LIVE_CHANNEL_STATUS[] = "status";
const char TOS_COMP[] = "comp";
const char TOS_LIVE_CHANNEL_STAT[] = "stat";
const char TOS_LIVE_CHANNEL_HISTORY[] = "history";
const char TOS_LIVE_CHANNEL_VOD[] = "vod";
const char TOS_LIVE_CHANNEL_START_TIME[] = "startTime";
const char TOS_LIVE_CHANNEL_END_TIME[] = "endTime";
const char TOS_PLAY_LIST_NAME[] = "playlistName";
const char LIVE_CHANNEL_STATUS_DISABLED[] = "disabled";
const char LIVE_CHANNEL_STATUS_ENABLED[] = "enabled";
const char LIVE_CHANNEL_STATUS_IDLE[] = "idle";
const char LIVE_CHANNEL_STATUS_LIVE[] = "live";
const char LIVE_CHANNEL_DEFAULT_TYPE[] = "HLS";
const char LIVE_CHANNEL_DEFAULT_PLAYLIST[] = "playlist.m3u8";
const int LIVE_CHANNEL_DEFAULT_FRAG_DURATION = 5;
const int LIVE_CHANNEL_DEFAULT_FRAG_COUNT = 3;
const int TOS_MAX_PART_NUM = 10000;
const int TOS_PER_RET_NUM = 1000;
const int MAX_SUFFIX_LEN = 1024;
const char TOS_INTELLIGENTTIERING[] = "intelligenttiering";
const char TOS_VERSION_ID[] = "versionId";

const char* SIGN_HEADER[] = {
    "cache-control",
    "content-disposition",
    "content-encoding",
    "content-length",
    "content-md5",
    "content-type",
    "expect",
    "expires",
    "host",
    "if-match",
    "if-modified-since",
    "if-none-match",
    "if-unmodified-since",
    "origin",
    "range",
    "response-cache-control",
    "response-content-disposition",
    "response-content-encoding",
    "response-content-language",
    "response-content-type",
    "response-expires",
    "transfer-encoding",
    "versionid",
    "pic-operations"
};
const int SIGN_HEADER_NUM = sizeof(SIGN_HEADER) / sizeof(SIGN_HEADER[0]);
const char X_TOS_HEADER[] = "x-tos-";

const char* storage_class_to_string(storage_class_type storage_class)
{
    switch (storage_class)
    {
    case STORAGE_CLASS_STANDARD: return "STANDARD";
    case STORAGE_CLASS_IA: return "IA";
    case STORAGE_CLASS_ARCHIVE_FR: return "ARCHIVE_FR";
    case STORAGE_CLASS_INTELLIGENT_TIERING: return "INTELLIGENT_TIERING";
    case STORAGE_CLASS_COLD_ARCHIVE: return "COLD_ARCHIVE";
    case STORAGE_CLASS_ARCHIVE: return "ARCHIVE";
    case STORAGE_CLASS_DEEP_COLD_ARCHIVE: return "DEEP_COLD_ARCHIVE";
    default: return NULL;
    }
}

storage_class_type string_to_storage_class(const char* storage_class_str)
{
    if (strcmp(storage_class_str, "STANDARD") == 0) return STORAGE_CLASS_STANDARD;
    if (strcmp(storage_class_str, "IA") == 0) return STORAGE_CLASS_IA;
    if (strcmp(storage_class_str, "ARCHIVE_FR") == 0) return STORAGE_CLASS_ARCHIVE_FR;
    if (strcmp(storage_class_str, "INTELLIGENT_TIERING") == 0) return STORAGE_CLASS_INTELLIGENT_TIERING;
    if (strcmp(storage_class_str, "COLD_ARCHIVE") == 0) return STORAGE_CLASS_COLD_ARCHIVE;
    if (strcmp(storage_class_str, "ARCHIVE") == 0) return STORAGE_CLASS_ARCHIVE;
    if (strcmp(storage_class_str, "DEEP_COLD_ARCHIVE") == 0) return STORAGE_CLASS_DEEP_COLD_ARCHIVE;

    return STORAGE_CLASS_UNKNOWN;
}

const char* acl_type_to_string(acl_type acl)
{
    switch (acl)
    {
    case ACL_PRIVATE: return "private";
    case ACL_PUBLIC_READ: return "public-read";
    case ACL_PUBLIC_READ_WRITE: return "public-read-write";
    case ACL_AUTHENTICATED_READ: return "authenticated-read";
    case ACL_BUCKET_OWNER_READ: return "bucket-owner-read";
    case ACL_BUCKET_OWNER_FULL_CONTROL: return "bucket-owner-full-control";
    case ACL_BUCKET_OWNER_ENTRUSTED: return "bucket-owner-entrusted";
    default: return NULL;
    }
}

acl_type string_to_acl_type(const char* acl_type_str)
{
    if (strcmp(acl_type_str, "private") == 0) return ACL_PRIVATE;
    if (strcmp(acl_type_str, "public-read") == 0) return ACL_PUBLIC_READ;
    if (strcmp(acl_type_str, "public-read-write") == 0) return ACL_PUBLIC_READ_WRITE;
    if (strcmp(acl_type_str, "authenticated-read") == 0) return ACL_AUTHENTICATED_READ;
    if (strcmp(acl_type_str, "bucket-owner-read") == 0) return ACL_BUCKET_OWNER_READ;
    if (strcmp(acl_type_str, "bucket-owner-full-control") == 0) return ACL_BUCKET_OWNER_FULL_CONTROL;
    if (strcmp(acl_type_str, "bucket-owner-entrusted") == 0) return ACL_BUCKET_OWNER_ENTRUSTED;

    return ACL_UNKNOWN;
}
