/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#ifndef EPOLL_REG_H
#define EPOLL_REG_H

#include <sys/epoll.h>

#define EPOLL_REG_MAX_FDS (8)

struct epoll_reg
{
    int epoll_fd;
    int fds[EPOLL_REG_MAX_FDS];
    int events[EPOLL_REG_MAX_FDS];
    int num_fds;
    const char *log_ref;
};

void epoll_reg_init(struct epoll_reg *reg, int epoll_fd,
                    const char *log_ctx);

void epoll_reg_add(struct epoll_reg *reg, int fd, int event);

void epoll_reg_reset(struct epoll_reg *reg);

#endif
