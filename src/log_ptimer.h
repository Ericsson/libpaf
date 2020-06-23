/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#ifndef LOG_PTIMER_H
#define LOG_PTIMER_H

#include "log.h"

#include <string.h>

#define log_ptimer_debug(ptimer, fmt, ...)	\
    log_obj_debug(ptimer, fmt, ##__VA_ARGS__)

#define log_ptimer_error(ptimer, fmt, ...)	\
    log_obj_error(ptimer, fmt, ##__VA_ARGS__)

#define log_ptimer_created(ptimer)		\
    log_ptimer_debug(ptimer, "Timer created.")

#define log_ptimer_destroyed(ptimer)			\
    log_ptimer_debug(ptimer, "Timer destroyed.")

#define log_ptimer_timer_fd_creation_failed(log_ref, create_errno)	\
    log_debug(log_ref, "Failed to create timer fd; %d (%s).",		\
	      create_errno, strerror(create_errno))

#define log_ptimer_install(ptimer, tmo_type, tmo_id, rel_tmo)		\
    log_ptimer_debug(ptimer, "Installed %s timeout id %"PRId64		\
		     " with a %.0f ms timeout.", tmo_type, tmo_id,	\
		     rel_tmo)

#define log_ptimer_install_abs(ptimer, tmo_id, abs_tmo) \
    log_ptimer_install(ptimer, "absolute", tmo_id,	\
		       (abs_tmo - ut_ftime()))

#define log_ptimer_install_rel(ptimer, tmo_id, rel_tmo) \
    log_ptimer_install(ptimer, "relative", tmo_id, rel_tmo)

#define log_ptimer_cancel(ptimer, tmo_id)				\
    log_ptimer_debug(ptimer, "Canceled timeout id %"PRId64".", tmo_id)

#define log_ptimer_ack(ptimer, tmo_id)					\
    log_ptimer_debug(ptimer, "Acknowledged timeout id %"PRId64".", tmo_id)

#define log_ptimer_arm(ptimer, timeout)					\
    log_ptimer_debug(ptimer, "Arming timer fd with a %.0f ms timeout.", \
		     timeout*1000)

#define log_ptimer_disarm(ptimer)			\
    log_ptimer_debug(ptimer, "Timer fd disarmed.")

#define log_ptimer_settime_failed(ptimer, settime_errno)	     \
    log_ptimer_error(ptimer, "System call settime failed; %d (%s).", \
		     settime_errno, strerror(settime_errno))
#endif
