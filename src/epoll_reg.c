/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#include <stdlib.h>
#include <stdbool.h>
#include <assert.h>

#include "log_epoll.h"
#include "util.h"

#include "epoll_reg.h"

void epoll_reg_init(struct epoll_reg *reg, int epoll_fd,
                    const char *log_ref)
{
    reg->epoll_fd = epoll_fd;
    reg->num_fds = 0;
    reg->log_ref = log_ref;
}

void epoll_reg_add(struct epoll_reg *reg, int fd, int event)
{
    log_epoll_add(reg, reg->epoll_fd, fd, event);

    struct epoll_event nevent = {
        .events = event
    };

    int rc = epoll_ctl(reg->epoll_fd, EPOLL_CTL_ADD, fd, &nevent);
    assert(rc == 0);

    reg->fds[reg->num_fds] = fd;
    reg->events[reg->num_fds] = event;
    reg->num_fds++;

    assert(reg->num_fds < EPOLL_REG_MAX_FDS);
}

void epoll_reg_reset(struct epoll_reg *reg)
{
    int i;
    for (i = 0; i < reg->num_fds; i++) {
        log_epoll_del(reg, reg->epoll_fd, reg->fds[i]);
        UT_SAVE_ERRNO;
        int rc = epoll_ctl(reg->epoll_fd, EPOLL_CTL_DEL, reg->fds[i], NULL);
        UT_RESTORE_ERRNO(epoll_errno);
        assert(rc == 0 || (epoll_errno == EBADF ||
			   epoll_errno == ENOENT ||
			   epoll_errno == EPERM));
    }
    reg->num_fds = 0;
}
