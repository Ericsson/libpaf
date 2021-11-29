/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#ifndef LOG_H
#define LOG_H

#include <inttypes.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

#include <paf_props.h>

#define PAF_ENV_DEBUG "PAF_DEBUG"

enum log_type { log_type_debug, log_type_error };

bool log_is_enabled(enum log_type type);

void __log_event(enum log_type type, const char *file, int line,
                 const char *function, const char *log_ref,
                 const char *format, ...);

void log_aprint_props(char *buf, size_t capacity,
                      const struct paf_props *props);

const void *log_fd_event_str(int event);

#define log_event(log_type, log_ref, fmt, ...)				\
    do {                                                                \
	const char *_log_ref = log_ref;					\
        if (log_is_enabled(log_type))					\
            __log_event(log_type, __FILE__, __LINE__, __func__,		\
			(_log_ref) != NULL ? (_log_ref) : "",		\
                        fmt, ##__VA_ARGS__);                            \
    } while (0)

#define log_debug(log_ref, fmt, ...)                             \
    log_event(log_type_debug, log_ref, fmt, ##__VA_ARGS__)

#define log_error(log_ref, fmt, ...)				\
    log_event(log_type_error, log_ref, fmt, ##__VA_ARGS__)

#define log_obj_event(log_type, obj, fmt, ...)			\
    log_event(log_type, (obj)->log_ref, fmt, ##__VA_ARGS__)

#define log_obj_debug(obj, fmt, ...)				\
    log_obj_event(log_type_debug, obj, fmt, ##__VA_ARGS__)

#define log_obj_error(obj, fmt, ...)				\
    log_obj_event(log_type_error, obj, fmt, ##__VA_ARGS__)

#define log_match_unknown_service(log_ref, sub_id, service_id)		\
    log_debug(log_ref, "Received notification for unknown service id 0x%" \
              PRIx64" in subscription 0x%"PRIx64".", service_id, sub_id)

#endif
