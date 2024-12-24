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

#ifndef LIBTOS_LOG_H
#define LIBTOS_LOG_H

#include "tos_sys_define.h"


TOS_CPP_START

typedef void (*tos_log_print_pt)(const char *message, int len);

typedef void (*tos_log_format_pt)(int level,
                                  const char *file,
                                  int line,
                                  const char *function,
                                  const char *fmt, ...)
        __attribute__ ((__format__ (__printf__, 5, 6)));

void tos_log_set_print(tos_log_print_pt p);
void tos_log_set_format(tos_log_format_pt p);

typedef enum {
    TOS_LOG_OFF = 1,
    TOS_LOG_FATAL,
    TOS_LOG_ERROR,
    TOS_LOG_WARN,
    TOS_LOG_INFO,
    TOS_LOG_DEBUG,
    TOS_LOG_TRACE,
    TOS_LOG_ALL
} tos_log_level_e;

#ifdef WIN32
#define tos_fatal_log(format, ...) if(tos_log_level>=TOS_LOG_FATAL) \
        tos_log_format(TOS_LOG_FATAL, __FILE__, __LINE__, __FUNCTION__, format, ##__VA_ARGS__)
#define tos_error_log(format, ...) if(tos_log_level>=TOS_LOG_ERROR) \
        tos_log_format(TOS_LOG_ERROR, __FILE__, __LINE__, __FUNCTION__, format, ##__VA_ARGS__)
#define tos_warn_log(format, ...) if(tos_log_level>=TOS_LOG_WARN)   \
        tos_log_format(TOS_LOG_WARN, __FILE__, __LINE__, __FUNCTION__, format, ##__VA_ARGS__)
#define tos_info_log(format, ...) if(tos_log_level>=TOS_LOG_INFO)   \
        tos_log_format(TOS_LOG_INFO, __FILE__, __LINE__, __FUNCTION__, format, ##__VA_ARGS__)
#define tos_debug_log(format, ...) if(tos_log_level>=TOS_LOG_DEBUG) \
        tos_log_format(TOS_LOG_DEBUG, __FILE__, __LINE__, __FUNCTION__, format, ##__VA_ARGS__)
#define tos_trace_log(format, ...) if(tos_log_level>=TOS_LOG_TRACE) \
        tos_log_format(TOS_LOG_TRACE, __FILE__, __LINE__, __FUNCTION__, format, ##__VA_ARGS__)
#else
#define tos_fatal_log(format, args...) if(tos_log_level>=TOS_LOG_FATAL) \
        tos_log_format(TOS_LOG_FATAL, __FILE__, __LINE__, __FUNCTION__, format, ## args)
#define tos_error_log(format, args...) if(tos_log_level>=TOS_LOG_ERROR) \
        tos_log_format(TOS_LOG_ERROR, __FILE__, __LINE__, __FUNCTION__, format, ## args)
#define tos_warn_log(format, args...) if(tos_log_level>=TOS_LOG_WARN)   \
        tos_log_format(TOS_LOG_WARN, __FILE__, __LINE__, __FUNCTION__, format, ## args)
#define tos_info_log(format, args...) if(tos_log_level>=TOS_LOG_INFO)   \
        tos_log_format(TOS_LOG_INFO, __FILE__, __LINE__, __FUNCTION__, format, ## args)
#define tos_debug_log(format, args...) if(tos_log_level>=TOS_LOG_DEBUG) \
        tos_log_format(TOS_LOG_DEBUG, __FILE__, __LINE__, __FUNCTION__, format, ## args)
#define tos_trace_log(format, args...) if(tos_log_level>=TOS_LOG_TRACE) \
        tos_log_format(TOS_LOG_TRACE, __FILE__, __LINE__, __FUNCTION__, format, ## args)
#endif

void tos_log_set_level(tos_log_level_e level);

void tos_log_set_output(apr_file_t *output);

void tos_log_print_default(const char *message, int len);

void tos_log_format_default(int level,
                            const char *file,
                            int line,
                            const char *function,
                            const char *fmt, ...)
        __attribute__ ((__format__ (__printf__, 5, 6)));

extern tos_log_level_e tos_log_level;
extern tos_log_format_pt tos_log_format;
extern tos_log_format_pt tos_log_format;

TOS_CPP_END

#endif
