/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#ifndef MSG_H
#define MSG_H

#include <sys/queue.h>
#include <sys/types.h>

struct msg
{
    char *data;
    TAILQ_ENTRY(msg) entry;
};

TAILQ_HEAD(msg_queue, msg);

struct msg *msg_create_buf(const char *buf, size_t len);
struct msg *msg_create_prealloc(char *data);
void msg_free(struct msg *msg);

#endif
