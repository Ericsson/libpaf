/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#include <assert.h>
#include <ctype.h>
#include <fcntl.h>
#include <limits.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h> /* gettid */
#include <sys/types.h>
#include <unistd.h>

#include "log_ut.h"

#include "util.h"

static void alloc_failure(void)
{
    log_ut_alloc_failure();
    abort();
}    

static void assure_alloc_success(void* ptr)
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

char *ut_strdup_non_null(const char *str)
{
    return str != NULL ? ut_strdup(str) : NULL;
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

void ut_aprintf(char *buf, size_t capacity, const char *format, ...)
{
    va_list ap;
    va_start(ap, format);
    ut_vaprintf(buf, capacity, format, ap);
    va_end(ap);
}

void ut_vaprintf(char *buf, size_t capacity, const char *format, va_list ap)
{
    size_t len = strlen(buf);

    assert (len < capacity);

    ssize_t left = capacity - len - 1;

    if (left == 0)
        return;

    vsnprintf(buf + len, left, format, ap);
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
    return ut_jitter(d, 0.5);
}

double ut_jitter(double base, double max_jitter)
{
    double k = 1.0 + ((ut_frand() - 0.5) * 2) * max_jitter;

    return k * base;
}

pid_t ut_gettid(void)
{
    return (pid_t)syscall(SYS_gettid);
}

ssize_t ut_read_file(int fd, void* buf, size_t capacity) {
    size_t offset = 0;
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

UT_STATIC_ASSERT(long_long_is_int64, sizeof(long long) == sizeof(int64_t));

int ut_parse_int64(const char *int64_s, int base, int64_t *int64)
{
    char *end;
    int64_t value = strtoll(int64_s, &end, base);

    if (end[0] == '\0') {
	*int64 = value;
	return 0;
    } else
	return -1;
}

int ut_parse_uint63(const char *uint63_s, int base, int64_t *uint63)
{
    int64_t result;

    if (ut_parse_int64(uint63_s, base, &result) < 0)
	return -1;

    if (result < 0)
	return -1;

    *uint63 = result;

    return 0;
}

#define NETNS_NAME_DIR "/run/netns"

static int get_ns_fd(const char *ns) {
    char path[strlen(NETNS_NAME_DIR)+strlen(ns)+2];
    snprintf(path, sizeof(path), "%s/%s", NETNS_NAME_DIR, ns);
    return open(path, O_RDONLY, 0);
}

int ut_net_ns_enter(const char *ns_name)
{
    char old_ns[PATH_MAX];
    /* we can't use "/proc/self/ns/net" here, because it points
       towards the *process* (i.e. main thread's ns), which might not
       be the current thread's ns */
    snprintf(old_ns, sizeof(old_ns), "/proc/%d/ns/net", ut_gettid());

    int old_ns_fd = open(old_ns, O_RDONLY, 0);
    if (old_ns_fd < 0)
	goto err;

    int new_ns_fd = get_ns_fd(ns_name);

    if (new_ns_fd < 0)
	goto err_close_old;

    if (setns(new_ns_fd, CLONE_NEWNET) < 0)
	goto err_close_all;

    close(new_ns_fd);

    return old_ns_fd;

 err_close_all:
    close(new_ns_fd);
 err_close_old:
    close(old_ns_fd);
 err:
    return -1;
}

int ut_net_ns_return(int old_ns_fd)
{
    if (setns(old_ns_fd, CLONE_NEWNET) < 0)
	return -1;

    close(old_ns_fd);

    return 0;
}
