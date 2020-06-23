/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#ifndef DOMAIN_FILE_H
#define DOMAIN_FILE_H

#include <sys/types.h>
#include <time.h>

ssize_t domain_file_get_addrs(const char *domain, struct timespec *mtime,
			      char ***addrs);
void domain_file_free_addrs(char **addrs, ssize_t count);

#endif
