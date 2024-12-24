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

#include "../../include/common/tos_log.h"
#include "apr_portable.h"

tos_log_print_pt  tos_log_print = tos_log_print_default;
tos_log_format_pt tos_log_format = tos_log_format_default;
tos_log_level_e   tos_log_level = TOS_LOG_WARN;

extern apr_file_t *tos_stderr_file;


void tos_log_set_print(tos_log_print_pt p)
{
    tos_log_print = p;
}

void tos_log_set_format(tos_log_format_pt p)
{
    tos_log_format = p;
}

void tos_log_set_level(tos_log_level_e level)
{   
    tos_log_level = level;
}

void tos_log_set_output(apr_file_t *output)
{
    tos_stderr_file = output;
}

void tos_log_print_default(const char *message, int len)
{
    if (tos_stderr_file == NULL) {
        fprintf(stderr, "%s", message);
    } else {
        apr_size_t bnytes = len;
        apr_file_write(tos_stderr_file, message, &bnytes);
    }
}

void tos_log_format_default(int level,
                            const char *file,
                            int line,
                            const char *function,
                            const char *fmt, ...)
{
    int len;
    apr_time_t t;
    int s;
    apr_time_exp_t tm;
    va_list args;
    char buffer[4096];

    t = apr_time_now();
    if ((s = apr_time_exp_lt(&tm, t)) != APR_SUCCESS) {
        return;
    }
    
    len = apr_snprintf(buffer, 4090, "[%04d-%02d-%02d %02d:%02d:%02d.%03d] %" APR_INT64_T_FMT " %s:%d ",
                   tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                   tm.tm_hour, tm.tm_min, tm.tm_sec, tm.tm_usec/1000,
                   (int64_t)apr_os_thread_current(), file, line);
    
    va_start(args, fmt);
    len += vsnprintf(buffer + len, 4090 - len, fmt, args);
    va_end(args);

    while (buffer[len -1] == '\n') len--;
    buffer[len++] = '\n';
    buffer[len] = '\0';

    tos_log_print(buffer, len);
}

