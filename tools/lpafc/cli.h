/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Ericsson AB
 */

#ifndef CLI_H
#define CLI_H

#include <stddef.h>
#include <stdbool.h>

void cli_init(const char *prompt);
void cli_deinit(void);

void cli_exit(int return_code);
bool cli_has_exited(int *return_code);

typedef void (*cli_run_cb)(const char *cmd, const char *const *args,
			   size_t num, void *cb_data);

void cli_register(const char *name, size_t min_num_args, size_t max_num_args,
		  const char *help, cli_run_cb run_cb, void *run_cb_data);

void cli_read_input(void);

#endif
