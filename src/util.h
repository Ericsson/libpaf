/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#ifndef UTIL_H
#define UTIL_H

#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

void *ut_malloc(size_t size);
void *ut_realloc(void *ptr, size_t size);
void *ut_calloc(size_t size);
void ut_free(void *ptr);

void *ut_dup(const void *buf, size_t len);
char *ut_strdup(const char *str);

char *ut_asprintf(const char *fmt, ...)
    __attribute__ ((format (printf, 1, 2)));

bool ut_timespec_lte(const struct timespec *a, const struct timespec *b);
double ut_timespec_to_f(const struct timespec *ts);
void ut_f_to_timespec(double t, struct timespec *ts);

double ut_ftime(void);

int64_t ut_rand_id(void);
double ut_frand(void);
double ut_frandomize(double d);

ssize_t ut_read_file(int fd, void* buf, size_t capacity);

bool ut_str_begins_with(const char *s, char c);
bool ut_str_ary_has(char * const *ary, size_t ary_len, const char *needle);

#define UT_SAVE_ERRNO				\
    int _oerrno = errno

#define UT_SAVE_ERRNO_AGAIN                     \
    _oerrno = errno

#define UT_RESTORE_ERRNO(saved_name)	\
    int saved_name = errno;		\
    errno = _oerrno

#define UT_RESTORE_ERRNO_DC			\
    errno = _oerrno

#define UT_PROTECT_ERRNO(stmt)			\
    do {					\
	int _errno = errno;			\
	stmt;					\
	errno = _errno;				\
    } while (0)

#define UT_STATIC_ASSERT(name, expr)                                    \
    __attribute__((constructor)) static void name(void) {               \
        if (!(expr)) {                                                  \
            fprintf(stderr, "Static assertion \"" #expr "\" failed.\n"); \
            abort();                                                    \
        }                                                               \
    }

#endif
