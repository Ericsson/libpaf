/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#include "utest.h"

#include "util.h"

#include "service.h"

TESTSUITE(service, NULL, NULL)

TESTCASE(service, modify) {


    int64_t service_id = 4711;
    int64_t generation = 42;
    struct paf_props *props = paf_props_create();
    paf_props_add_int64(props, "foo", 99);
    int64_t ttl = 10;

    struct service *service = service_create(service_id, generation, props,
					     ttl);

    CHK(!service_modify(service, props, &ttl));
    CHK(!service_modify(service, NULL, &ttl));
    CHK(!service_modify(service, props, NULL));

    ttl++;
    CHK(service_modify(service, NULL, &ttl));

    paf_props_add_int64(props, "bar", 99);
    CHK(service_modify(service, props, NULL));

    ttl++;
    paf_props_add_int64(props, "foobar", -99);
    CHK(service_modify(service, props, &ttl));

    paf_props_destroy(props);
    service_destroy(service);

    return UTEST_SUCCESS;
}
