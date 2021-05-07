/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#include <assert.h>
#include <ctype.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "log_ut.h"

#include "util.h"

static void alloc_failure(void)
{
    log_ut_alloc_failure();
    abort();
}    

static void assure_alloc_success(const void* ptr)
{
    /* Attempting to handle out-of-memory conditions is generally a
       bad idea (on the process-level). It's a much more robust
       practice to crash. */
    if (ptr == NULL)
	alloc_failure();
}

void *ut_malloc(size_t size)
{
    void *ptr = malloc(size);
    assure_alloc_success(ptr);
    return ptr;
}

void *ut_realloc(void *ptr, size_t size)
{
    void *new_ptr = realloc(ptr, size);
    assure_alloc_success(new_ptr);
    return new_ptr;
}

void *ut_calloc(size_t size)
{
    void *ptr = ut_malloc(size);
    memset(ptr, 0, size);
    return ptr;
}

void ut_free(void *ptr)
{
    free(ptr);
}

void *ut_dup(const void *buf, size_t len)
{
    void *copy = ut_malloc(len);
    memcpy(copy, buf, len);
    return copy;
}

char *ut_strdup(const char *str)
{
    char *copy = strdup(str);
    assure_alloc_success(copy);
    return copy;
}

char *ut_asprintf(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    char *str;

    int rc = vasprintf(&str, fmt, ap);
    if (rc < 0)
	alloc_failure();

    va_end(ap);

    return str;
}

bool ut_timespec_lte(const struct timespec *a, const struct timespec *b)
{
    if (a->tv_sec < b->tv_sec)
	return true;
    if (a->tv_sec > b->tv_sec)
	return false;
    else
	return a->tv_nsec <= b->tv_nsec;
}

double ut_timespec_to_f(const struct timespec *ts)
{
    return (double)ts->tv_sec + (double)ts->tv_nsec / 1e9;
}

void ut_f_to_timespec(double t, struct timespec *ts)
{
    ts->tv_sec = t;
    ts->tv_nsec = (t - ts->tv_sec) * 1e9;
}

double ut_ftime(clockid_t clk_id)
{
    struct timespec now;
    clock_gettime(clk_id, &now);
    return ut_timespec_to_f(&now);
}

static void entropy(void *buffer, size_t len)
{
    int rc = getentropy(buffer, len);

    if (rc < 0)
	abort();
}

int64_t ut_rand_id(void)
{
    int64_t num;

    entropy(&num, sizeof(num));

    return num >= 0 ? num : -num;
}

double ut_frand(void)
{
    uint64_t num;

    entropy(&num, sizeof(num));

    return (double)num / (double)UINT64_MAX;
}

double ut_frandomize(double d)
{
    double k = ut_frand() + 0.5;

    return k * d;
}

ssize_t ut_read_file(int fd, void* buf, size_t capacity) {
    ssize_t offset = 0;
    do {
        int bytes_read = read(fd, buf+offset, capacity-offset);
        if (bytes_read < 0)
            return -1;
        else if (bytes_read == 0)
            return offset;
        offset += bytes_read;
    } while (offset < capacity);

    return -1;
}

bool ut_str_begins_with(const char *s, char c)
{
    for (;;) {
	char s_c = *s;
	s++;
	if (s_c == '\0')
	    return false;
	if (isspace(s_c))
	    continue;
	if (s_c == c)
	    return true;
    }
}

bool ut_str_ary_has(char * const *ary, size_t ary_len, const char *needle)
{
    size_t i;
    for (i = 0; i < ary_len; i++)
	if (strcmp(ary[i], needle) == 0)
	    return true;
    return false;
}

