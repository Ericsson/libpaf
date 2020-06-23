/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#ifndef CONF_H
#define CONF_H

#include <stdint.h>

#define RESCAN_ENV "PAF_RESCAN"
#define DEFAULT_RESCAN (5) /* s */

#define RECONNECT_MIN_ENV "PAF_RECONNECT_MIN"
#define DEFAULT_RECONNECT_MIN (0.01) /* s */

#define RECONNECT_MAX_ENV "PAF_RECONNECT_MAX"
#define DEFAULT_RECONNECT_MAX (5) /* s */

#define TTL_ENV "PAF_TTL"
#define DEFAULT_TTL (30) /* s */

double conf_get_rescan_period(void);
double conf_get_reconnect_min(void);
double conf_get_reconnect_max(void);
int64_t conf_get_ttl(void);

#endif
