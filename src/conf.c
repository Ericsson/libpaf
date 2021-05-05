/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#include <math.h>
#include <stdlib.h>
#include <string.h>

#include "conf.h"

static const char *get_env_str(const char *env_name,
			       const char *default_value)
{
    const char *value = getenv(env_name);

    return value != NULL ? value : default_value;
}

static bool get_env_bool(const char *env_name, bool default_value)
{
    char *str_value = getenv(env_name);

    if (str_value == NULL)
	return default_value;

    if (strcmp(str_value, "1") == 0 ||
	strcmp(str_value, "true") == 0)
	return true;

    if (strcmp(str_value, "0") == 0 ||
	strcmp(str_value, "false") == 0)
	return false;

    return default_value;
}

const char *conf_get_domains_dir(void)
{
    return get_env_str(DOMAINS_DIR_ENV, DEFAULT_DOMAINS_DIR);
}

bool conf_get_debug_enabled(void)
{
    return get_env_bool(DEBUG_ENABLED_ENV, DEFAULT_DEBUG_ENABLED);
}

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
