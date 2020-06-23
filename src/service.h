/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#ifndef SERVICE_H
#define SERVICE_H

#include <inttypes.h>
#include <stdbool.h>

#include "list.h"
#include "paf_props.h"

struct service
{
    int64_t service_id;
    int64_t generation;
    struct paf_props *props;
    int64_t ttl;

    LIST_ENTRY(service) entry;
};

LIST_HEAD(service_list, service);

struct service *service_create(int64_t service_id, int64_t generation,
                               const struct paf_props *props, int64_t ttl);

bool service_modify(struct service *service, const struct paf_props *new_props,
		    const int64_t *ttl);

void service_destroy(struct service *service);

#endif

