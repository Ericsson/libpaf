/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#include <assert.h>
#include <libgen.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>

#include <paf_props.h>

#include "util.h"

#include "log.h"

#ifdef PAF_LTTNG
#define TRACEPOINT_DEFINE
#include "paf_lttng.h"
#endif

static bool console_log = false;

#define BUFSZ (1024)

bool log_is_enabled(enum log_type type)
{
    if (console_log)
        return true;
#ifdef PAF_LTTNG
    switch (type) {
    case log_type_debug:
        return tracepoint_enabled(com_ericsson_paf, paf_debug);
    case log_type_error:
        return tracepoint_enabled(com_ericsson_paf, paf_error);
    }
#endif
    return false;
}

static void format_line(char *buf, size_t capacity,
                        const char *file, int line, const char *function)
{
    char bname[strlen(file)+1];
    strcpy(bname, file);
    log_aprintf(buf, capacity, "%s [%s:%d]: ", function, basename(bname),
                line);
}

static void log_console(const char *file, int line, const char *function,
			const char *prefix, const char *format, va_list ap)
{
    if (console_log) {
	UT_SAVE_ERRNO;
	char buf[BUFSZ];
        buf[0] = '\0';
        log_aprintf(buf, sizeof(buf), "<%s> ", prefix);
        format_line(buf, sizeof(buf), file, line, function);
        log_vaprintf(buf, sizeof(buf), format, ap);
        fprintf(stderr, "%s\n", buf);
	fflush(stderr);
	UT_RESTORE_ERRNO_DC;
    }
}


#ifdef PAF_LTTNG
#define LOG_LTTNG(type, file, line, function, prefix, format, ap)	\
    do {								\
        /* LTTng in combination with really old kernels cause           \
           LTTng to misbehave and change errno to ENOSYS (which         \
           in turn is because the membarrier() syscall doesn't          \
           exist). */                                                   \
	UT_SAVE_ERRNO;                                                  \
        char msg[BUFSZ];						\
        msg[0] = '\0';                                                  \
        format_line(msg, sizeof(msg), file, line, function);            \
        vsnprintf(msg+strlen(msg), sizeof(msg)-strlen(msg), format, ap); \
                                                                        \
        tracepoint(com_ericsson_paf, paf_ ## type, prefix, msg);        \
        UT_RESTORE_ERRNO_DC;                                            \
    } while (0)
#endif

void __log_event(enum log_type type, const char *file, int line,
                 const char *function, const char *prefix,
                 const char *format, ...)
{
    va_list ap;
    va_start(ap, format);
    log_console(file, line, function, prefix, format, ap);
    va_end(ap);

#ifdef PAF_LTTNG
    va_start(ap, format);
    switch (type) {
    case log_type_debug:
	LOG_LTTNG(debug, file, line, function, prefix, format, ap);
	break;
    case log_type_error:
	LOG_LTTNG(error, file, line, function, prefix, format, ap);
	break;
    }
    va_end(ap);
#endif
}

void log_vaprintf(char *buf, size_t capacity, const char *format, va_list ap)
{
    size_t len = strlen(buf);

    assert (len < capacity);

    size_t left = capacity - len - 1;

    if (left == 0)
        return;

    int rc = vsnprintf(buf+len, left, format, ap);
    if (rc > left)
        rc = left;

    buf[len+left] = '\0';
}

void log_aprintf(char *buf, size_t capacity, const char *format, ...)
{
    va_list ap;
    va_start(ap, format);
    log_vaprintf(buf, capacity, format, ap);
    va_end(ap);
}

struct state {
    char *buf;
    size_t buf_capacity;
    size_t prop_printed;
    size_t prop_num_values;
};

static void log_aprint_prop(const char *prop_name,
                            const struct paf_value *prop_value, void *user)
{
    struct state *state = user;

    log_aprintf(state->buf, state->buf_capacity, "\"%s\": ", prop_name);
    if (paf_value_is_str(prop_value))
        log_aprintf(state->buf, state->buf_capacity, "\"%s\"",
                    paf_value_str(prop_value));
    else {
        assert(paf_value_is_int64(prop_value));
        log_aprintf(state->buf, state->buf_capacity, " %"PRId64,
                    paf_value_int64(prop_value));
    }

    state->prop_printed++;

    if (state->prop_printed != state->prop_num_values)
        log_aprintf(state->buf, state->buf_capacity, ", ");
}

void log_aprint_props(char *buf, size_t capacity,
                      const struct paf_props *props)
{
    log_aprintf(buf, capacity, "{");

    struct state state = {
        .buf = buf,
        .buf_capacity = capacity,
        .prop_printed = 0,
        .prop_num_values = paf_props_num_values(props)
    };

    paf_props_foreach(props, log_aprint_prop, &state);

    log_aprintf(buf, capacity, "}");
}

const void *log_fd_event_str(int event)
{
    switch (event) {
    case EPOLLIN|EPOLLOUT:
        return "readable and writable";
    case EPOLLIN:
        return "readable";
    case EPOLLOUT:
        return "writable";
    default:
        return "invalid";
    }
}

static void init(void) __attribute__((constructor));

static void init(void)
{
    char *debug = getenv(PAF_ENV_DEBUG);
    if (debug && (strcmp(debug, "1") == 0 || strcmp(debug, "true") == 0))
        console_log = true;
}

