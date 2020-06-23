/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#include <math.h>
#include <stdlib.h>

#include "conf.h"

static double get_double_env(const char *env_name, double default_value)
{
    const char *env = getenv(env_name);

    if (env != NULL) {
        char *end;
        double value = strtod(env, &end);
        if (end != NULL && *end == '\0')
            return value;
    }

    return default_value;
}

double conf_get_rescan_period(void)
{
    return get_double_env(RESCAN_ENV, DEFAULT_RESCAN);
}

double conf_get_reconnect_min(void)
{
    return get_double_env(RECONNECT_MIN_ENV, DEFAULT_RECONNECT_MIN);
}

double conf_get_reconnect_max(void)
{
    return get_double_env(RECONNECT_MAX_ENV, DEFAULT_RECONNECT_MAX);
}


int64_t conf_get_ttl(void)
{
    double d_ttl = get_double_env(TTL_ENV, DEFAULT_TTL);
    int64_t i_ttl = d_ttl;
    if (i_ttl == 0 && d_ttl > 0)
	return 1;
    else
	return d_ttl;
}
