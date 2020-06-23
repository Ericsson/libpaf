/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#ifndef LOG_EPOLL_H
#define LOG_EPOLL_H

#include "log.h"

#define log_epoll_debug(_reg, fmt, ...)		\
    log_obj_debug(_reg, fmt, ##__VA_ARGS__)

#define log_epoll_add(_reg, epoll_fd, fd, event)			\
    log_epoll_debug(_reg, "Adding fd %d with event type %s to "		\
		    "epoll fd %d.", fd, log_fd_event_str(event), epoll_fd)

#define log_epoll_del(_reg, epoll_fd, fd)				\
    log_epoll_debug(_reg, "Deleted fd %d from epoll fd %d.",		\
		    fd, epoll_fd)

#endif
