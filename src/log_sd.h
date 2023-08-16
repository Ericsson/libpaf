/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#ifndef LOG_SD_H
#define LOG_SD_H

#include "log.h"

#define log_sd_debug(sd, fmt, ...)		\
    log_obj_debug(sd, fmt, ##__VA_ARGS__)

#define log_sd_error(sd, fmt, ...)		\
    log_obj_error(sd, fmt, ##__VA_ARGS__)

#define log_sd_timeout(sd, timeout)		\
    do {					\
        if (timeout != DBL_MAX)						\
	    log_sd_debug(sd, "Next orphan timeout in %.1f s.", timeout); \
	else								\
	    log_sd_debug(sd, "No orphan timeout.");			\
    } while (0)

#endif
