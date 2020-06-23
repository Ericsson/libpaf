/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#ifndef TESTUTIL_H
#define TESTUTIL_H

#include <inttypes.h>
#include <sys/types.h>

void tu_msleep(int ms);

int tu_execute_es(const char *cmd);
void tu_execute(const char *cmd);
void tu_executef(const char *fmt, ...);
int tu_executef_es(const char *fmt, ...);

int tu_waitstatus(pid_t p);

int tu_randint(int min, int max);
void tu_randomize(uint8_t *buf, int len);

#endif
