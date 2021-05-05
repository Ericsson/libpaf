/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#include "testutil.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sched.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>

#include "util.h"

void tu_msleep(int ms)
{
    while (ms > 1000) {
	sleep(1);
	ms -= 1000;
    }
    usleep(ms*1000);
}

static void die(const char *msg)
{
    perror(msg);
    exit(EXIT_FAILURE);
}

int tu_execute_es(const char *cmd) {
    int rc = system(cmd);
    if (rc < 0)
	die("system");
    return -WEXITSTATUS(rc);
}

void tu_execute(const char *cmd) {
    if (tu_execute_es(cmd) != 0)
	die(cmd);
}

void tu_executef(const char *fmt, ...)
{
    va_list argp;
    va_start(argp, fmt);

    char cmd[1024];
    vsnprintf(cmd, sizeof(cmd), fmt, argp);
    va_end(argp);

    tu_execute(cmd);
}

int tu_executef_es(const char *fmt, ...)
{
    va_list argp;
    va_start(argp, fmt);

    char cmd[1024];
    vsnprintf(cmd, sizeof(cmd), fmt, argp);
    va_end(argp);

    return tu_execute_es(cmd);
}

int tu_waitstatus(pid_t p)
{
    int status;
    if (waitpid(p, &status, 0) < 0)
	return -1;
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
	errno = 0;
	return -1;
    }
    return 0;
}

static uint32_t rand32(void)
{
    uint32_t r;

    tu_randblk(&r, sizeof(r));

    return r;
}

int tu_randint(int min, int max)
{
    if (min == max)
	return min;

    int diff = max - min;

    return min + (rand32() % diff);
}

bool tu_randbool(void)
{
    return tu_randint(0, 1);
}

void tu_randblk(void *buf, int len)
{
    while (len > 0) {
	/* getentropy() puts a limit of 256 bytes at a time */
	size_t batch = len < 256 ? len : 256;

	if (getentropy(buf, batch) < 0)
	    abort();

	buf += batch;
	len -= batch;
    }
}
