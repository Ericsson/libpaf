/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Ericsson AB
 */

#ifndef SESSION_H
#define SESSION_H

int session_init(int64_t client_id, const char *addr);

int session_run(void);

void session_deinit(void);

#endif
