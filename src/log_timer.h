/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#ifndef LOG_TIMER_H
#define LOG_TIMER_H

#include "log.h"

#define log_timer_debug(timer, fmt, ...)	\
    log_obj_debug(timer, fmt, ##__VA_ARGS__)

#define log_timer_arm(timer, timer_fd, timeout)				\
    log_timer_debug(timer, "Arming timer fd %d with a %.0f ms timeout.", \
		    timer_fd, timeout*1000)

#define log_timer_disarm(timer, timer_fd)			\
    log_timer_debug(timer, "Timer with fd %d disarmed.", timer_fd)


#endif
