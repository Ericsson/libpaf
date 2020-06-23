/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#include "testutil.h"

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <sys/wait.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sched.h>
#include <limits.h>
#include <sys/utsname.h>
#include <errno.h>

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

int tu_randint(int min, int max)
{
    if (min == max)
	return min;

    int diff = max-min;

    return min+(random() % diff);
}

void tu_randomize(uint8_t *buf, int len)
{
    int i;
    for (i=0; i<len; i++)
	buf[i] = (uint8_t)tu_randint(0, 255);
}
