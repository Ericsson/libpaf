/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Ericsson AB
 */

#ifndef CMDLINE_H
#define CMDLINE_H

#include <stddef.h>

struct cmdline *cmdline_parse(const char *line);
void cmdline_destroy(struct cmdline *cmdline);

const char *cmdline_get_name(struct cmdline *cmdline);

size_t cmdline_get_num_args(struct cmdline *cmdline);

const char *const *cmdline_get_args(struct cmdline *cmdline);

#endif

