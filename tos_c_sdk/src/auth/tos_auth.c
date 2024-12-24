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

#include "../../include/auth/tos_auth.h"
#include "../../include/common/tos_log.h"


#define TOS_SHA256_HASH_LEN 32


static int tos_build_string_to_sign_v4(tos_pool_t* p, const tos_string_t* datetime, const tos_string_t* date,
                                       const tos_string_t* region, const tos_string_t* canonical_request,
                                       tos_string_t* out)
{
    char hash[TOS_SHA256_HASH_LEN];
    char hex[TOS_SHA256_HASH_LEN * 2 + 1];
    tos_buf_t* signbuf;

    signbuf = tos_create_buf(p, 256);
    if (signbuf == NULL)
    {
        return TOSE_OUT_MEMORY;
    }

    // TOS4-HMAC-SHA256 + \n +
    // datetime + \n +
    // data/region/product/request + \n +
    // hexEncode(sha256(canonical_request));

    // Algorithm
    tos_buf_append_string(p, signbuf, "TOS4-HMAC-SHA256", 16);
    tos_buf_append_string(p, signbuf, "\n", 1);
    // RequestDate
    tos_buf_append_string(p, signbuf, datetime->data, datetime->len);
    tos_buf_append_string(p, signbuf, "\n", 1);
    //CredentialScope
    tos_buf_append_string(p, signbuf, date->data, date->len);
    tos_buf_append_string(p, signbuf, "/", 1);
    tos_buf_append_string(p, signbuf, region->data, region->len);
    tos_buf_append_string(p, signbuf, "/", 1);
    tos_buf_append_string(p, signbuf, "tos", 3);
    tos_buf_append_string(p, signbuf, "/", 1);
    tos_buf_append_string(p, signbuf, "request", 7);
    tos_buf_append_string(p, signbuf, "\n", 1);

    tos_SHA256(hash, canonical_request->data, canonical_request->len);
    tos_encode_hex(hex, hash, TOS_SHA256_HASH_LEN, NULL);
    tos_buf_append_string(p, signbuf, hex, TOS_SHA256_HASH_LEN * 2);

    // result
    out->data = (char*)signbuf->pos;
    out->len = tos_buf_size(signbuf);

    return TOSE_OK;
}

static int is_tos_signed_header_v4(const char* str)
{
    if (strncasecmp(str, TOS_CANNONICALIZED_HEADER_PREFIX, strlen(TOS_CANNONICALIZED_HEADER_PREFIX)) == 0 ||
        strncasecmp(str, TOS_HOST, strlen(TOS_HOST)) == 0 ||
        strncasecmp(str, TOS_CONTENT_TYPE, strlen(TOS_CONTENT_TYPE)) == 0)
    {
        return 1;
    }
    return 0;
}

static int cmp_table_key_v4(const void* v1, const void* v2)
{
    const apr_table_entry_t* s1 = (const apr_table_entry_t*)v1;
    const apr_table_entry_t* s2 = (const apr_table_entry_t*)v2;
    return strcmp(s1->key, s2->key);
}

static int tos_build_canonical_request_v4(tos_pool_t* p, tos_http_request_t* req, tos_string_t* out,
                                          tos_string_t* sign_headers)
{
    int pos;
    const char* value;
    tos_buf_t* signbuf;
    tos_buf_t* headersbuf;
    const tos_array_header_t* arr;
    const tos_table_entry_t* elts;
    tos_table_t* canon_querys;
    tos_table_t* canon_headers;

    signbuf = tos_create_buf(p, 1024);
    if (NULL == signbuf)
    {
        tos_error_log("failed to call tos_create_buf.");
        return TOSE_OUT_MEMORY;
    }

    headersbuf = tos_create_buf(p, 1024);
    if (NULL == headersbuf)
    {
        tos_error_log("failed to call tos_create_buf.");
        return TOSE_OUT_MEMORY;
    }

    //http method + "\n"
    value = tos_http_method_to_string(req->method);
    tos_buf_append_string(p, signbuf, value, strlen(value));
    tos_buf_append_string(p, signbuf, "\n", 1);

    //Canonical URI + "\n"
    tos_buf_append_string(p, signbuf, "/", 1);
    if (req->resource != NULL)
    {
        char canon_buf[TOS_MAX_URI_LEN];
        canon_buf[0] = '\0';
        tos_url_encode(canon_buf, req->resource, TOS_MAX_URI_LEN);
        tos_buf_append_string(p, signbuf, canon_buf, strlen(canon_buf));
    }
    tos_buf_append_string(p, signbuf, "\n", 1);

    //Canonical Query String + "\n"
    arr = tos_table_elts(req->query_params);
    elts = (tos_table_entry_t*)arr->elts;
    canon_querys = tos_table_make(p, 0);
    for (pos = 0; pos < arr->nelts; ++pos)
    {
        char enc_key[TOS_MAX_QUERY_ARG_LEN];
        char enc_value[TOS_MAX_URI_LEN];
        tos_url_encode(enc_key, elts[pos].key, TOS_MAX_QUERY_ARG_LEN);
        tos_url_encode(enc_value, elts[pos].val, TOS_MAX_QUERY_ARG_LEN);
        apr_table_set(canon_querys, enc_key, enc_value);
    }
    arr = tos_table_elts(canon_querys);
    qsort(arr->elts, arr->nelts, arr->elt_size, cmp_table_key_v4);

    elts = (tos_table_entry_t*)arr->elts;
    for (pos = 0; pos < arr->nelts; ++pos)
    {
        if (pos != 0)
        {
            tos_buf_append_string(p, signbuf, "&", 1);
        }
        value = elts[pos].key;
        tos_buf_append_string(p, signbuf, value, strlen(value));

        value = elts[pos].val;
        tos_buf_append_string(p, signbuf, "=", 1);
        if (value != NULL && *value != '\0')
        {
            tos_buf_append_string(p, signbuf, value, strlen(value));
        }
    }
    tos_buf_append_string(p, signbuf, "\n", 1);

    //Canonical Headers + "\n"
    arr = tos_table_elts(req->headers);
    elts = (tos_table_entry_t*)arr->elts;
    canon_headers = tos_table_make(p, 0);
    for (pos = 0; pos < arr->nelts; ++pos)
    {
        if (is_tos_signed_header_v4(elts[pos].key))
        {
            tos_string_t key;
            tos_str_set(&key, apr_pstrdup(p, elts[pos].key));
            tos_string_tolower(&key);
            tos_strip_space(&key);
            apr_table_addn(canon_headers, key.data, elts[pos].val);
        }
    }
    arr = tos_table_elts(canon_headers);
    qsort(arr->elts, arr->nelts, arr->elt_size, cmp_table_key_v4);

    elts = (tos_table_entry_t*)arr->elts;
    for (pos = 0; pos < arr->nelts; ++pos)
    {
        tos_string_t tmp_str;
        tos_str_set(&tmp_str, elts[pos].val);
        tos_strip_space(&tmp_str);
        tos_buf_append_string(p, signbuf, elts[pos].key, strlen(elts[pos].key));
        tos_buf_append_string(p, signbuf, ":", 1);
        tos_buf_append_string(p, signbuf, tmp_str.data, tmp_str.len);
        tos_buf_append_string(p, signbuf, "\n", 1);
        // append headers
        if (pos != 0)
        {
            tos_buf_append_string(p, headersbuf, ";", 1);
        }
        tos_buf_append_string(p, headersbuf, elts[pos].key, strlen(elts[pos].key));
    }
    tos_buf_append_string(p, signbuf, "\n", 1);

    //SignHeaders
    tos_buf_append_string(p, signbuf, (char*)headersbuf->pos,tos_buf_size(headersbuf));
    //Additional Headers + "\n"
    tos_buf_append_string(p, signbuf, "\n", 1);

    //Hashed PayLoad
    value = apr_table_get(req->headers, TOS_V4_CONTENT_SHA256);
    if (value == NULL)
    {
        tos_buf_append_string(p, signbuf, TOS_EMPTY_SHA256, strlen(TOS_EMPTY_SHA256));
    }
    else
    {
        tos_buf_append_string(p, signbuf, value, strlen(value));
    }

    // result
    out->data = (char*)signbuf->pos;
    out->len = tos_buf_size(signbuf);

    sign_headers->data = (char*)headersbuf->pos;
    sign_headers->len = tos_buf_size(headersbuf);

    return TOSE_OK;
}

static int tos_build_signing_key_v4(tos_pool_t* p, const tos_string_t* access_key_secret, const tos_string_t* date,
                                    const tos_string_t* region, char signing_key[32])
{
    char signing_date[TOS_SHA256_HASH_LEN];
    char signing_region[TOS_SHA256_HASH_LEN];
    char signing_product[TOS_SHA256_HASH_LEN];
    tos_HMAC_SHA256(signing_date, access_key_secret->data, access_key_secret->len, date->data, date->len);
    tos_HMAC_SHA256(signing_region, signing_date, TOS_SHA256_HASH_LEN, region->data, region->len);
    tos_HMAC_SHA256(signing_product, signing_region, TOS_SHA256_HASH_LEN, "tos", 3);
    tos_HMAC_SHA256(signing_key, signing_product, TOS_SHA256_HASH_LEN, "request", 7);

    return TOSE_OK;
}

static int tos_build_signature_v4(tos_pool_t* p, const char signing_key[32], const tos_string_t* string_to_sign,
                                  tos_string_t* out)
{
    char signature[TOS_SHA256_HASH_LEN];
    tos_buf_t* signbuf;

    if ((signbuf = tos_create_buf(p, TOS_SHA256_HASH_LEN * 2 + 1)) == NULL)
    {
        return TOSE_OUT_MEMORY;
    }
    tos_HMAC_SHA256(signature, signing_key, TOS_SHA256_HASH_LEN, string_to_sign->data, string_to_sign->len);
    tos_encode_hex((char*)signbuf->pos, signature, TOS_SHA256_HASH_LEN, NULL);

    out->data = (char*)signbuf->pos;
    out->len = TOS_SHA256_HASH_LEN * 2;

    return TOSE_OK;
}


int tos_sign_request_v4(tos_http_request_t* req, const tos_config_t* config)
{
    tos_string_t datetime;
    tos_string_t date;
    tos_string_t canonical_request;
    tos_string_t string_to_sign;
    tos_string_t signature;
    tos_string_t sign_headers;
    char signing_key[TOS_SHA256_HASH_LEN];
    const char* value;
    int res = TOSE_OK;
    tos_string_t gmt_suffix;
    char shortdate[TOS_MAX_SHORT_TIME_LEN];
    char datestr[TOS_MAX_GMT_TIME_LEN];

    if (req->host && !apr_table_get(req->headers, TOS_HOST))
    {
        apr_table_set(req->headers, TOS_HOST, req->host);
    }

    if (!apr_table_get(req->headers, TOS_CANNONICALIZED_HEADER_DATE))
    {
        if ((res = tos_get_iso8601_str_time(datestr)) != TOSE_OK )
        {
            return res;
        }
        apr_table_set(req->headers, TOS_CANNONICALIZED_HEADER_DATE, datestr);
    }

    // sts token
    if (tos_string_valid(config->sts_token))
    {
        apr_table_set(req->headers, HEADER_SECURITY_TOKEN, config->sts_token.data);
    }

    //datetime & date
    value = apr_table_get(req->headers, TOS_CANNONICALIZED_HEADER_DATE);
    datetime.data = (char*)value;
    datetime.len = strlen(value);

    tos_str_set(&gmt_suffix, "GMT");
    if (tos_ends_with(&datetime, &gmt_suffix))
    {
        tos_get_gmt_time_date(datetime.data, shortdate);
        date.data = shortdate;
        date.len = 8;
    }
    else
    {
        date.data = datetime.data;
        date.len = tos_min(8, datetime.len);
    }

    // gen canonical request
    if ((res = tos_build_canonical_request_v4(req->pool, req, &canonical_request, &sign_headers)) != TOSE_OK)
    {
        return res;
    }

    //gen string to sign
    if (( res = tos_build_string_to_sign_v4(req->pool, &datetime, &date, &config->region, &canonical_request, &string_to_sign)) != TOSE_OK)
    {
        return res;
    }

    //gen signing key
    tos_build_signing_key_v4(req->pool, &config->access_key_secret, &date, &config->region, signing_key);

    //gen signature
    if((res = tos_build_signature_v4(req->pool, signing_key, &string_to_sign, &signature)) != TOSE_OK)
    {
        return  res;
    }

    //sign header
    value = apr_psprintf(
        req->pool, "TOS4-HMAC-SHA256 Credential=%.*s/%.*s/%.*s/tos/request,SignedHeaders=%.*s,Signature=%.*s",
        config->access_key_id.len, config->access_key_id.data,
        date.len, date.data,
        config->region.len, config->region.data,
        sign_headers.len, sign_headers.data,
        signature.len, signature.data);
    apr_table_addn(req->headers, TOS_AUTHORIZATION, value);
    return res;
}
