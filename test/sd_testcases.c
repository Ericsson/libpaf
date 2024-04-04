/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#include <stdlib.h>
#include <sys/param.h>

#include "utest.h"

#include "util.h"

#include "sd.h"

#define DUMMY_LOG_REF "dummy"

struct sdcb
{
    enum sd_obj_type obj_type;
    int64_t obj_id;
    enum sd_change_type change_type;
};

#define MAX_CBS (1024)

struct sdcb_list
{
    struct sdcb cbs[MAX_CBS];
    size_t len;
};

static bool sdcb_equal(struct sdcb *cb, enum sd_obj_type obj_type,
		       int64_t obj_id, enum sd_change_type change_type)
{
    return cb->obj_type == obj_type && cb->obj_id == obj_id &&
	cb->change_type == change_type;
}

static bool sdcb_list_has(struct sdcb_list *list, enum sd_obj_type obj_type,
			  int64_t obj_id, enum sd_change_type change_type)
{
    size_t i;
    for (i = 0; i < list->len; i++)
	if (sdcb_equal(&list->cbs[i], obj_type, obj_id, change_type))
	    return true;
    return false;
}

static void add_cb(struct sdcb_list *list, enum sd_obj_type obj_type,
		   int64_t obj_id, enum sd_change_type change_type)
{
    struct sdcb *cb = &list->cbs[list->len];
    *cb = (struct sdcb) {
	.obj_type = obj_type,
	.obj_id = obj_id,
	.change_type = change_type
    };
    list->len++;
}

static void cb_recorder(enum sd_obj_type obj_type, int64_t obj_id,
			enum sd_change_type change_type, void *user)
{
    struct sdcb_list *list = user;
    if (!user)
	abort();
    add_cb(list, obj_type, obj_id, change_type);
}

TESTSUITE(sd, NULL, NULL)

TESTCASE(sd, add_modify_remove_service)
{
    struct sd *sd = sd_create(DUMMY_LOG_REF);

    struct sdcb_list list = { 0 };

    CHK(sd_add_listener(sd, cb_recorder, &list) != NULL);

    struct paf_props *props = paf_props_create();
    paf_props_add_int64(props, "foo", 4711);
    int64_t ttl = 99;

    int64_t service_id = sd_add_service(sd, props, ttl);

    CHKINTEQ(list.len, 1);
    CHK(sdcb_equal(&list.cbs[0], sd_obj_type_service, service_id,
		   sd_change_type_added));

    struct service *service = sd_get_service(sd, service_id);
    CHKINTEQ(service->service_id, service_id);

    CHK(paf_props_equal(service->props, props));
    CHKINTEQ(service->ttl, ttl);

    /* no change */
    sd_modify_service(sd, service_id, props, &ttl);
    CHKINTEQ(list.len, 1);

    /* props modification */
    paf_props_add_int64(props, "asdf", 1234);
    sd_modify_service(sd, service_id, props, &ttl);
    CHKINTEQ(list.len, 2);
    CHK(sdcb_equal(&list.cbs[1], sd_obj_type_service, service_id,
		   sd_change_type_modified));

    service = sd_get_service(sd, service_id);
    CHK(paf_props_equal(service->props, props));
    CHKINTEQ(service->ttl, ttl);

    /* ttl modification */
    ttl++;
    sd_modify_service(sd, service_id, props, &ttl);
    CHKINTEQ(list.len, 3);
    CHK(sdcb_equal(&list.cbs[2], sd_obj_type_service, service_id,
		   sd_change_type_modified));

    service = sd_get_service(sd, service_id);
    CHK(paf_props_equal(service->props, props));
    CHKINTEQ(service->ttl, ttl);

    sd_remove_service(sd, service_id);
    CHKINTEQ(list.len, 4);
    CHK(sdcb_equal(&list.cbs[3], sd_obj_type_service, service_id,
		   sd_change_type_removed));

    service = sd_get_service(sd, service_id);
    CHK(service == NULL);

    paf_props_destroy(props);
    sd_destroy(sd);

    return UTEST_SUCCESS;
}

#define NUM_SERVICES (100)

TESTCASE(sd, bulk_remove_services)
{
    struct sd *sd = sd_create(DUMMY_LOG_REF);

    struct sdcb_list list = { 0 };
    CHK(sd_add_listener(sd, cb_recorder, &list) != NULL);

    int64_t service_ids[NUM_SERVICES];
    struct paf_props *props[NUM_SERVICES];
    int64_t ttl[NUM_SERVICES];

    int i;
    for (i = 0; i < NUM_SERVICES; i++) {
	props[i] = paf_props_create();
	paf_props_add_int64(props[i], "value", i);
	ttl[i] = i;
	service_ids[i] = sd_add_service(sd, props[i], ttl[i]);
    }

    CHKINTEQ(list.len, NUM_SERVICES);

    for (i = 0; i < NUM_SERVICES; i++) {
	CHK(sdcb_list_has(&list, sd_obj_type_service, service_ids[i],
			  sd_change_type_added));
	struct service *service = sd_get_service(sd, service_ids[i]);
	CHK(paf_props_equal(service->props, props[i]));
	CHKINTEQ(service->ttl, ttl[i]);

	paf_props_destroy(props[i]);
    }

    sd_remove_all_services(sd);

    CHKINTEQ(list.len, 2*NUM_SERVICES);

    for (i = 0; i < NUM_SERVICES; i++)
	CHK(sdcb_list_has(&list, sd_obj_type_service, service_ids[i],
			  sd_change_type_removed));

    sd_destroy(sd);

    return UTEST_SUCCESS;
}

static void nop_match_cb(enum paf_match_type match_type, int64_t service_id,
			 const struct paf_props *props, void *user)
{
}

TESTCASE(sd, orphan_all_from_source)
{
    int64_t source_id0 = 123;
    int64_t source_id1 = 1234;

    int64_t service_id0 = 100;
    int64_t service_generation = 1;
    struct paf_props *props = paf_props_create();
    paf_props_add_int64(props, "foo", 4711);
    int64_t ttl = 1;

    struct sd *sd = sd_create(DUMMY_LOG_REF);

    int64_t sub_id = sd_add_sub(sd, NULL, nop_match_cb, NULL);

    sd_report_match(sd, source_id0, sub_id, paf_match_type_appeared,
		    service_id0, &service_generation, props, &ttl, NULL);
    sd_report_match(sd, source_id1, sub_id, paf_match_type_appeared,
		    service_id0, &service_generation, props, &ttl, NULL);

    double now = ut_ftime(CLOCK_REALTIME);
    sd_orphan_all_from_source(sd, source_id0, now);
    CHK(!sd_has_timeout(sd));

    sd_orphan_all_from_source(sd, source_id1, now);
    CHK(sd_has_timeout(sd));

    /* marking an orphan orphan again should keep the old orphan time */
    sd_orphan_all_from_source(sd, source_id1, now+ttl+99);

    sd_process(sd, now+ttl+1);
    CHK(!sd_has_timeout(sd));

    paf_props_destroy(props);

    sd_destroy(sd);

    return UTEST_SUCCESS;
}

TESTCASE(sd, add_remove_sub)
{
    struct sd *sd = sd_create(DUMMY_LOG_REF);

    struct sdcb_list list = { 0 };

    CHK(sd_add_listener(sd, cb_recorder, &list) != NULL);

    const char *filter = "(name=foo)";
    int64_t sub_id = sd_add_sub(sd, filter, nop_match_cb, NULL);

    CHKINTEQ(list.len, 1);
    CHK(sdcb_equal(&list.cbs[0], sd_obj_type_sub, sub_id,
		   sd_change_type_added));

    struct sub *sub = sd_get_sub(sd, sub_id);
    CHKINTEQ(sub->sub_id, sub_id);
    CHKSTREQ(sub->filter_str, filter);

    sd_remove_sub(sd, sub_id);
    CHKINTEQ(list.len, 2);
    CHK(sdcb_equal(&list.cbs[1], sd_obj_type_sub, sub_id,
		   sd_change_type_removed));

    sub = sd_get_sub(sd, sub_id);
    CHK(sub == NULL);

    sd_destroy(sd);

    return UTEST_SUCCESS;
}

TESTCASE(sd, add_null_filter_sub) {
    struct sd *sd = sd_create(DUMMY_LOG_REF);

    int64_t sub_id = sd_add_sub(sd, NULL, nop_match_cb, NULL);

    struct sub *sub = sd_get_sub(sd, sub_id);
    CHK(sub->filter_str == NULL);

    sd_destroy(sd);

    return UTEST_SUCCESS;
}

TESTCASE(sd, add_remove_listener) {
    struct sd *sd = sd_create(DUMMY_LOG_REF);

    struct sdcb_list list0 = { 0 };
    struct sd_listener *listener0 =
	sd_add_listener(sd, cb_recorder, &list0);

    struct sdcb_list list1 = { 0 };
    struct sd_listener *listener1 =
	sd_add_listener(sd, cb_recorder, &list1);

    struct sdcb_list list2 = { 0 };
    struct sd_listener *listener2 =
	sd_add_listener(sd, cb_recorder, &list2);

    sd_add_sub(sd, "(name=foo)", nop_match_cb, NULL);
    CHKINTEQ(list0.len, 1);
    CHKINTEQ(list1.len, 1);
    CHKINTEQ(list2.len, 1);

    sd_remove_listener(sd, listener1);

    sd_add_sub(sd, "(name=foo)", nop_match_cb, NULL);
    CHKINTEQ(list0.len, 2);
    CHKINTEQ(list1.len, 1);
    CHKINTEQ(list2.len, 2);

    sd_remove_listener(sd, listener2);

    sd_add_sub(sd, "(name=foo)", nop_match_cb, NULL);
    CHKINTEQ(list0.len, 3);
    CHKINTEQ(list1.len, 1);
    CHKINTEQ(list2.len, 2);

    sd_remove_listener(sd, listener0);

    sd_add_sub(sd, "(name=foo)", nop_match_cb, NULL);
    CHKINTEQ(list0.len, 3);
    CHKINTEQ(list1.len, 1);
    CHKINTEQ(list2.len, 2);

    sd_destroy(sd);

    return UTEST_SUCCESS;
}

TESTCASE(sd, process_purges_orphans) {
    struct sd *sd = sd_create(DUMMY_LOG_REF);

    int64_t sub_id0 = sd_add_sub(sd, NULL, nop_match_cb, NULL);
    int64_t sub_id1 = sd_add_sub(sd, NULL, nop_match_cb, NULL);

    int64_t service_id0 = 3242;
    int64_t service_id1 = 2342332;

    int64_t ttl0 = 60;
    double orphan_since0 = 10;
    double timeout0 = orphan_since0 + ttl0;

    int64_t ttl1 = 20;
    double orphan_since1 = 20;
    double timeout1 = orphan_since1 + ttl1;

    double max_timeout = MAX(timeout0, timeout1);
    double min_timeout = MIN(timeout0, timeout1);

    struct paf_props *props = paf_props_create();
    int64_t source_id = 42;

    CHK(!sd_has_timeout(sd));

    int64_t generation = 0;

    sd_report_match(sd, source_id, sub_id0, paf_match_type_appeared,
		    service_id0, &generation, props, &ttl0, &orphan_since0);
    sd_report_match(sd, source_id, sub_id1, paf_match_type_appeared,
		    service_id1, &generation, props, &ttl1, &orphan_since1);

    CHK(sd_has_timeout(sd));
    CHKDBLAPPROXEQ(sd_next_timeout(sd), min_timeout);

    sd_process(sd, min_timeout - 0.1);
    CHK(sd_has_timeout(sd));

    sd_process(sd, max_timeout + 0.1);
    CHK(!sd_has_timeout(sd));

    paf_props_destroy(props);
    sd_destroy(sd);

    return UTEST_SUCCESS;
}
