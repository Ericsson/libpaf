/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#include <assert.h>

#include "util.h"

#include "service.h"

struct service *service_create(int64_t service_id, int64_t generation,
                               const struct paf_props *props, int64_t ttl)

{
    struct service *service = ut_malloc(sizeof(struct service));

    *service = (struct service) {
        .service_id = service_id,
	.generation = generation,
        .props = paf_props_clone(props),
        .ttl = ttl
    };

    return service;
}

bool service_modify(struct service *service, const struct paf_props *new_props,
		    const int64_t *new_ttl)
{
    bool changed = false;

    if (new_props != NULL && !paf_props_equal(new_props, service->props)) {
	paf_props_destroy(service->props);
	service->props = paf_props_clone(new_props);
	changed = true;
    }

    if (new_ttl != NULL && *new_ttl != service->ttl) {
	service->ttl = *new_ttl;
	changed = true;
    }

    if (changed)
	service->generation++;

    return changed;
}

void service_destroy(struct service *service)
{
    if (service != NULL) {
        paf_props_destroy(service->props);
        ut_free(service);
    }
}

