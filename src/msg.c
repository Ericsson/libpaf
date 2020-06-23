/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#include <stdlib.h>
#include <string.h>

#include "util.h"

#include "msg.h"

struct msg *msg_create_buf(const char *buf, size_t len)
{
    struct msg *msg = ut_malloc(sizeof(struct msg));

    msg->data = ut_malloc(len + 1);

    memcpy(msg->data, buf, len);
    msg->data[len] = '\0';

    return msg;
}

struct msg *msg_create_prealloc(char *data)
{
    struct msg *msg = ut_malloc(sizeof(struct msg));
    msg->data = data;
    return msg;
}

void msg_free(struct msg *msg)
{
    if (msg != NULL) {
        ut_free(msg->data);
        ut_free(msg);
    }
}
