/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020-2021 Ericsson AB
 */

#ifndef DOMAIN_FILE_H
#define DOMAIN_FILE_H

#include <sys/types.h>
#include <time.h>

#include "server_conf.h"

struct domain_conf
{
    struct server_conf **servers;
    size_t num_servers;
};

struct domain_conf* domain_conf_read(const char *domain,
				     struct timespec *mtime,
				     const char *log_ref);
void domain_conf_destroy(struct domain_conf *conf);

bool domain_conf_has_server(struct domain_conf *conf,
			    const struct server_conf *server);

#endif
