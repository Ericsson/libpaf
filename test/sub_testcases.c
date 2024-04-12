/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#include <float.h>

#include "utest.h"

#include "sub.h"
#include "testutil.h"
#include "util.h"

TESTSUITE(sub, NULL, NULL)

#define DUMMY_LOG_REF "dummy"

struct umatch
{
    enum paf_match_type match_type;
    int64_t service_id;
    struct paf_props *props;
};

#define MAX_MATCHES (1024)

struct umatch_list
{
    struct umatch *matches[MAX_MATCHES];
    size_t len;
};

static bool umatch_equal(struct umatch *match, enum paf_match_type match_type,
                        int64_t service_id, const struct paf_props *props)
{
    if (match->match_type != match_type)
        return false;
    if (match->service_id != service_id)
        return false;
    if (match->props == NULL || props == NULL)
        return match->props == NULL && props == NULL;
    return paf_props_equal(match->props, props);
}

static bool umatch_has_service_id(struct umatch_list *list, size_t offset,
				  int64_t service_id)
{
    size_t i;
    for (i = offset; i < list->len; i++)
	if (list->matches[i]->service_id == service_id)
	    return true;
    return false;
}

static bool umatch_service_ids_equal(struct umatch_list *list, size_t offset,
				     int64_t *service_ids, size_t len)
{
    if ((list->len - offset) != len)
	return false;

    size_t i;
    for (i = 0; i < len; i++)
	if (!umatch_has_service_id(list, offset, service_ids[i]))
	    return false;
    return true;
}

static void add_match(struct umatch_list *list, enum paf_match_type match_type,
                      int64_t service_id, const struct paf_props *props)
{
    struct umatch *match = ut_malloc(sizeof(struct umatch));
    *match = (struct umatch) {
        .match_type = match_type,
        .service_id = service_id,
        .props = props != NULL ? paf_props_clone(props) : NULL
    };
    list->matches[list->len] = match;
    list->len++;
}

static void clear_matches(struct umatch_list *list)
{
    size_t i;
    for (i = 0; i < list->len; i++) {
        struct umatch *m = list->matches[i];
        if (m->props != NULL)
            paf_props_destroy(m->props);
        ut_free(m);
    }
    list->len = 0;
}

static void match_recorder(enum paf_match_type match_type, int64_t service_id,
                           const struct paf_props *props, void *user)
{
    struct umatch_list *list = user;
    add_match(list, match_type, service_id, props);
}

static void match_counter(enum paf_match_type match_type, int64_t service_id,
                          const struct paf_props *props, void *user)
{
    int *count = user;

    (*count)++;
}

TESTCASE(sub, single_source_matches)
{
    const int64_t sub_id = 99;

    double now = 99e9;

    struct umatch_list match_list = { .len = 0 };
    struct sub *sub = sub_create(sub_id, NULL, DUMMY_LOG_REF, match_recorder,
				 &match_list);

    int64_t source_id = 1;
    const int64_t service_id = 17;
    int64_t generation = 234;
    int64_t ttl = 60;

    struct paf_props *props = paf_props_create();
    paf_props_add_str(props, "name", "foo");

    sub_report_match(sub, source_id, paf_match_type_appeared, service_id,
		     &generation, props, &ttl, NULL, now);

    CHKINTEQ(match_list.len, 1);
    CHK(umatch_equal(match_list.matches[0], paf_match_type_appeared,
                    service_id, props));

    paf_props_add_str(props, "name", "foo2");
    generation++;
    sub_report_match(sub, source_id, paf_match_type_modified, service_id,
		     &generation, props, &ttl, NULL, now);

    CHKINTEQ(match_list.len, 2);
    CHK(umatch_equal(match_list.matches[1], paf_match_type_modified,
		     service_id, props));

    paf_props_add_int64(props, "adsf", 99);
    generation++;
    sub_report_match(sub, source_id, paf_match_type_modified, service_id,
		     &generation, props, &ttl, NULL, now);

    CHKINTEQ(match_list.len, 3);
    CHK(umatch_equal(match_list.matches[2], paf_match_type_modified,
		     service_id, props));

    /* same generation -> no change */
    sub_report_match(sub, source_id, paf_match_type_modified, service_id,
		     &generation, props, &ttl, NULL, now);
    CHKINTEQ(match_list.len, 3);

    /* older generation -> no change */
    generation--;
    sub_report_match(sub, source_id, paf_match_type_modified, service_id,
		     &generation, props, & ttl, NULL, now);
    CHKINTEQ(match_list.len, 3);


    clear_matches(&match_list);
    sub_destroy(sub);
    paf_props_destroy(props);

    return UTEST_SUCCESS;
}

TESTCASE(sub, disappeared)
{
    const int64_t sub_id = 99;

    struct umatch_list match_list = { .len = 0 };
    struct sub *sub = sub_create(sub_id, NULL, DUMMY_LOG_REF, match_recorder,
				 &match_list);
    double now = 1231231;

    int64_t source_id0 = 0;
    int64_t source_id1 = 1;
    const int64_t service_id = 17;
    int64_t generation = 234;
    int64_t ttl_value = 60;
    int64_t *ttl = &ttl_value;
    double *orphan_since = NULL;

    struct paf_props *props = paf_props_create();
    paf_props_add_str(props, "name", "foo");

    sub_report_match(sub, source_id0, paf_match_type_appeared, service_id,
		     &generation, props, ttl, orphan_since, now);
    CHKINTEQ(match_list.len, 1);
    CHK(umatch_equal(match_list.matches[0], paf_match_type_appeared,
                    service_id, props));

    sub_report_match(sub, source_id1, paf_match_type_appeared, service_id,
		     &generation, props, ttl, orphan_since, now);
    CHKINTEQ(match_list.len, 1);

    sub_report_match(sub, source_id1, paf_match_type_disappeared, service_id,
		     NULL, NULL, NULL, NULL, now);
    CHKINTEQ(match_list.len, 1);

    sub_report_match(sub, source_id0, paf_match_type_disappeared, service_id,
		     NULL, NULL, NULL, NULL, now);
    CHKINTEQ(match_list.len, 2);
    CHK(umatch_equal(match_list.matches[1], paf_match_type_disappeared,
		     service_id, NULL));

    clear_matches(&match_list);
    sub_destroy(sub);
    paf_props_destroy(props);

    return UTEST_SUCCESS;
}

TESTCASE(sub, old_modify)
{
    const int64_t sub_id = 99;

    int count = 0;
    struct sub *sub = sub_create(sub_id, NULL, DUMMY_LOG_REF, match_counter,
				 &count);

    int64_t source_id = 234324;
    const int64_t service_id = 17;
    int64_t generation = 100;
    int64_t ttl = 60;
    double now = 123123123;

    struct paf_props *props = paf_props_create();

    sub_report_match(sub, source_id, paf_match_type_appeared, service_id,
		     &generation, props, &ttl, NULL, now);
    CHKINTEQ(count, 1);

    generation--;
    paf_props_add_str(props, "name", "foo");
    sub_report_match(sub, source_id, paf_match_type_appeared, service_id,
		     &generation, props, &ttl, NULL, now);
    CHKINTEQ(count, 1);

    sub_destroy(sub);
    paf_props_destroy(props);

    return UTEST_SUCCESS;
}

TESTCASE(sub, modify_disappeared)
{
    const int64_t sub_id = 99;

    int count = 0;
    struct sub *sub = sub_create(sub_id, NULL, DUMMY_LOG_REF, match_counter,
				 &count);

    int64_t source_id0 = 0;
    int64_t generation0 = 100;
    int64_t source_id1 = 1;
    int64_t generation1 = 100;
    const int64_t service_id = 17;
    int64_t ttl = 60;
    double now = 10e9;

    struct paf_props *first_props = paf_props_create();
    struct paf_props *second_props = paf_props_create();
    paf_props_add_str(second_props, "name", "foo");

    CHKNOERR(sub_report_match(sub, source_id0, paf_match_type_appeared,
			      service_id, &generation0, first_props, &ttl,
			      NULL, now));
    CHKINTEQ(count, 1);

    generation0++;
    CHKNOERR(sub_report_match(sub, source_id0, paf_match_type_modified,
			      service_id, &generation0, second_props, &ttl,
			      NULL, now));
    CHKINTEQ(count, 2);

    CHKNOERR(sub_report_match(sub, source_id1, paf_match_type_appeared,
			      service_id, &generation1, first_props, &ttl,
			      NULL, now));
    CHKINTEQ(count, 2);

    CHKNOERR(sub_report_match(sub, source_id0, paf_match_type_disappeared,
			      service_id, NULL, NULL, NULL, NULL, now + 1));
    CHKINTEQ(count, 3);

    generation1++;
    CHKNOERR(sub_report_match(sub, source_id1, paf_match_type_modified,
			      service_id, &generation1, second_props,
			      &ttl, NULL, now + 1));
    CHKINTEQ(count, 3);

    CHKNOERR(sub_report_match(sub, source_id1, paf_match_type_disappeared,
			      service_id, NULL, NULL, NULL, NULL, now + 1));
    CHKINTEQ(count, 3);

    sub_destroy(sub);
    paf_props_destroy(first_props);
    paf_props_destroy(second_props);

    return UTEST_SUCCESS;
}

TESTCASE(sub, ttl_change_unnoticed)
{
    const int64_t sub_id = 99;

    int count = 0;
    struct sub *sub = sub_create(sub_id, NULL, DUMMY_LOG_REF, match_counter,
				 &count);

    int64_t source_id = 234324;
    const int64_t service_id = 17;
    int64_t generation = 100;
    int64_t ttl = 60;
    double now = 999999;

    struct paf_props *props = paf_props_create();

    sub_report_match(sub, source_id, paf_match_type_appeared, service_id,
		     &generation, props, &ttl, NULL, now);
    CHKINTEQ(count, 1);

    ttl++;
    generation += 10;
    sub_report_match(sub, source_id, paf_match_type_appeared, service_id,
		     &generation, props, &ttl, NULL, now);
    CHKINTEQ(count, 1);

    sub_destroy(sub);
    paf_props_destroy(props);

    return UTEST_SUCCESS;
}

TESTCASE(sub, errornous_match_reporting)
{
    const int64_t sub_id = 99;

    struct umatch_list match_list = { .len = 0 };
    struct sub *sub = sub_create(sub_id, NULL, DUMMY_LOG_REF, match_recorder,
				 &match_list);
    int64_t source_id0 = 123;
    int64_t source_id1 = 456;
    const int64_t service_id = 17;
    int64_t generation = 0;
    int64_t ttl = 60;
    double now = 99e99;

    struct paf_props *props = paf_props_create();

    /* modified before appeared */
    CHKINTEQ(sub_report_match(sub, source_id0, paf_match_type_modified,
			      service_id, &generation, props, &ttl, NULL,
			      now), -1);
    CHKINTEQ(match_list.len, 0);

    /* disappear before appeared */
    CHKINTEQ(sub_report_match(sub, source_id1, paf_match_type_disappeared,
			      service_id, NULL, NULL, NULL, NULL, now), -1);
    CHKINTEQ(match_list.len, 0);

    /* after failed calls, a proper report should be accepted */
    CHKNOERR(sub_report_match(sub, source_id0, paf_match_type_appeared,
			      service_id, &generation, props, &ttl, NULL, now));
    CHKINTEQ(match_list.len, 1);

    generation++;
    /* appeared twice */
    CHKERR(sub_report_match(sub, source_id0, paf_match_type_appeared,
			    service_id, &generation, props, &ttl, NULL, now));
    CHKINTEQ(match_list.len, 1);

    clear_matches(&match_list);
    sub_destroy(sub);
    paf_props_destroy(props);

    return UTEST_SUCCESS;
}

int run_afk_rejoin(bool connected)
{
    const int64_t sub_id = 99;

    struct umatch_list match_list = { .len = 0 };
    struct sub *sub = sub_create(sub_id, NULL, DUMMY_LOG_REF, match_recorder,
				 &match_list);
    int64_t source_id = 123;
    const int64_t service_id = 17;
    int64_t generation = 0;
    int64_t ttl = 60;
    double now = 100;

    struct paf_props *props = paf_props_create();

    CHKNOERR(sub_report_match(sub, source_id, paf_match_type_appeared,
			      service_id, &generation, props, &ttl, NULL, now));
    CHKINTEQ(match_list.len, 1);

    now += 10;

    if (connected)
	CHKNOERR(sub_report_match(sub, source_id, paf_match_type_modified,
				  service_id, &generation, props, &ttl,
				  &now, now));
    else
	sub_report_source_disconnected(sub, source_id, now);

    CHKINTEQ(match_list.len, 1);

    now += (ttl + 1);

    if (connected)
	CHKNOERR(sub_report_match(sub, source_id, paf_match_type_disappeared,
				  service_id, NULL, NULL, NULL, NULL, now));

    sub_process_timeout(sub, now);

    CHKINTEQ(match_list.len, 2);

    now++;
    CHKNOERR(sub_report_match(sub, source_id, paf_match_type_appeared,
			      service_id, &generation, props, &ttl, NULL,
			      now));
    CHKINTEQ(match_list.len, 3);

    /* stale match source processing */
    now += 1000;
    sub_process_timeout(sub, now);

    CHKINTEQ(match_list.len, 3);

    clear_matches(&match_list);
    sub_destroy(sub);
    paf_props_destroy(props);

    return UTEST_SUCCESS;
}

TESTCASE(sub, server_afk)
{
    return run_afk_rejoin(false);
}

TESTCASE(sub, provider_client_afk)
{
    return run_afk_rejoin(true);
}

TESTCASE(sub, ignore_old_match_reports)
{
    const int64_t sub_id = 99;

    struct umatch_list match_list = { .len = 0 };
    struct sub *sub = sub_create(sub_id, NULL, DUMMY_LOG_REF, match_recorder,
				 &match_list);
    int64_t source_id0 = 10;
    int64_t source_id1 = 11;
    int64_t source_id2 = 12;
    const int64_t service_id = 17;
    int64_t generation = 20;
    int64_t ttl = 60;
    double now = 1;

    struct paf_props *props = paf_props_create();

    CHKNOERR(sub_report_match(sub, source_id0, paf_match_type_appeared,
			      service_id, &generation, props, &ttl, NULL,
			      now));
    CHKNOERR(sub_report_match(sub, source_id0, paf_match_type_disappeared,
			      service_id, NULL, NULL, NULL, NULL, now));
    CHKINTEQ(match_list.len, 2);

    generation--;
    CHKNOERR(sub_report_match(sub, source_id1, paf_match_type_appeared,
			      service_id, &generation, props, &ttl, NULL, now));

    generation++;
    CHKNOERR(sub_report_match(sub, source_id2, paf_match_type_appeared,
			      service_id, &generation, props, &ttl, NULL, now));

    CHKINTEQ(match_list.len, 2);

    clear_matches(&match_list);
    sub_destroy(sub);
    paf_props_destroy(props);

    return UTEST_SUCCESS;
}

TESTCASE(sub, unconnected_orphan)
{
    const int64_t sub_id = 99;

    struct umatch_list match_list = { .len = 0 };
    struct sub *sub = sub_create(sub_id, NULL, DUMMY_LOG_REF, match_recorder,
				 &match_list);
    int64_t source_id0 = 0;
    int64_t source_id1 = 1;
    const int64_t service_id = 17;
    int64_t generation = 0;
    int64_t ttl = 60;
    double now = 99e99;

    struct paf_props *props = paf_props_create();

    CHKNOERR(sub_report_match(sub, source_id0, paf_match_type_appeared,
			      service_id, &generation, props, &ttl, NULL, now));
    CHKINTEQ(match_list.len, 1);

    CHK(!sub_has_timeout(sub));

    double orphan_since = now;
    CHKNOERR(sub_report_match(sub, source_id0, paf_match_type_modified,
			      service_id, &generation, props, &ttl,
			      &orphan_since, now));
    CHKINTEQ(match_list.len, 1);
    CHK(!sub_has_timeout(sub));

    sub_report_source_disconnected(sub, source_id0, now);

    CHK(sub_has_timeout(sub));

    now++;

    CHKNOERR(sub_report_match(sub, source_id1, paf_match_type_appeared,
			      service_id, &generation, props, &ttl,
			      NULL, now));

    CHK(!sub_has_timeout(sub));

    CHKNOERR(sub_report_match(sub, source_id1, paf_match_type_modified,
			      service_id, &generation, props, &ttl,
			      &orphan_since, now));

    CHK(!sub_has_timeout(sub));

    sub_report_source_disconnected(sub, source_id1, now);

    CHK(sub_has_timeout(sub));

    CHKINTEQ(match_list.len, 1);

    clear_matches(&match_list);
    sub_destroy(sub);
    paf_props_destroy(props);

    return UTEST_SUCCESS;
}

TESTCASE(sub, purge_unconnected_orphans)
{
    const int64_t sub_id = 99;

    struct umatch_list match_list = { .len = 0 };
    struct sub *sub = sub_create(sub_id, NULL, DUMMY_LOG_REF, match_recorder,
				 &match_list);

    int64_t source_id0 = 10;
    int64_t source_id1 = 20;

    double now = 50;

    int64_t service_id_old = 1;
    int64_t ttl_old = 30;
    double orphan_since_old = now - 20;
    double timeout_old = orphan_since_old + ttl_old;

    int64_t service_id_recent = 2;
    int64_t ttl_recent = 25;
    double orphan_since_recent = now - 5;
    double timeout_recent = orphan_since_recent + ttl_recent;

    int64_t service_id_connected = 3;
    int64_t ttl_connected = 30;
    double orphan_since_connected = now - 15;

    int64_t generation = 10000;

    struct paf_props *props = paf_props_create();

    CHK(!sub_has_timeout(sub));

    CHKNOERR(sub_report_match(sub, source_id0, paf_match_type_appeared,
			      service_id_old, &generation, props,
			      &ttl_old, &orphan_since_old, now));

    CHKNOERR(sub_report_match(sub, source_id0, paf_match_type_appeared,
			      service_id_recent, &generation, props,
			      &ttl_recent, NULL, now));
    generation++;
    CHKNOERR(sub_report_match(sub, source_id0, paf_match_type_modified,
			      service_id_recent, &generation, props,
			      &ttl_recent, &orphan_since_recent, now));

    CHKNOERR(sub_report_match(sub, source_id0, paf_match_type_appeared,
			      service_id_connected, &generation, props,
			      &ttl_connected, &orphan_since_connected, now));
    CHKNOERR(sub_report_match(sub, source_id1, paf_match_type_appeared,
			      service_id_connected, &generation, props,
			      &ttl_connected, &orphan_since_connected, now));

    CHKINTEQ(match_list.len, 3);

    CHK(!sub_has_timeout(sub));

    sub_report_source_disconnected(sub, source_id0, now);

    CHK(sub_has_timeout(sub));

    sub_process_timeout(sub, now);

    CHKINTEQ(match_list.len, 3);

    CHK(sub_has_timeout(sub));
    CHKDBLAPPROXEQ(sub_get_timeout(sub), timeout_old);

    sub_process_timeout(sub, timeout_old + 1);
    CHKINTEQ(match_list.len, 4);

    CHKDBLAPPROXEQ(sub_get_timeout(sub), timeout_recent);

    sub_process_timeout(sub, timeout_recent + 1);
    CHKINTEQ(match_list.len, 5);

    CHK(sub_has_timeout(sub));

    /* stale timeouts */
    double timeout = sub_get_timeout(sub);
    sub_process_timeout(sub, timeout);

    CHKINTEQ(match_list.len, 5);

    clear_matches(&match_list);
    sub_destroy(sub);
    paf_props_destroy(props);

    return UTEST_SUCCESS;
}

#define MANY (1000)

TESTCASE(sub, purge_many)
{
    const int64_t sub_id = 99;

    int count = 0;
    struct sub *sub = sub_create(sub_id, NULL, DUMMY_LOG_REF, match_counter,
				 &count);
    int64_t source_id = 1;
    const int64_t base_service_id = 17;
    int64_t generation = 234;
    int64_t ttl = 60;
    double orphan_since = time(NULL);
    double orphan_timeout = orphan_since + ttl;

    struct paf_props *props = paf_props_create();
    paf_props_add_int64(props, "lucky number", 10);

    int i;
    for (i = 0; i < MANY; i++) {
	int64_t service_id = base_service_id + i;
	double *orphan_since_ptr = tu_randbool() ? &orphan_since : NULL;
	CHKNOERR(sub_report_match(sub, source_id, paf_match_type_appeared,
				  service_id, &generation, props, &ttl,
				  orphan_since_ptr, orphan_since));
	CHKINTEQ(count, i+1);
    }

    count = 0;

    sub_report_source_disconnected(sub, source_id, orphan_since);

    sub_process_timeout(sub, orphan_timeout - 1);
    CHKINTEQ(count, 0);

    sub_process_timeout(sub, orphan_timeout + 0.1);
    CHKINTEQ(count, MANY);

    /* Local and remote server orphan cleanup is a race, so you may
       get stray disappear notifications. */
    CHKNOERR(sub_report_match(sub, source_id, paf_match_type_disappeared,
			      base_service_id, NULL, NULL, NULL, NULL,
			      orphan_since + 1));
    CHKINTEQ(count, MANY);

    /* process stale */
    sub_process_timeout(sub, orphan_timeout + 1000);

    CHKINTEQ(count, MANY);

    sub_destroy(sub);
    paf_props_destroy(props);

    return UTEST_SUCCESS;
}

TESTCASE(sub, orphan_from_source)
{
    const int64_t sub_id = 999;

    struct umatch_list match_list = { .len = 0 };
    struct sub *sub = sub_create(sub_id, NULL, DUMMY_LOG_REF, match_recorder,
				 &match_list);

    double now = 2342334.4;
    int64_t source_id_leaving = 99;
    int64_t source_id_staying = 100;

    int64_t num_service_ids = 100;
    int64_t service_ids_leaving[num_service_ids];
    int i;
    for (i = 0; i < num_service_ids; i++)
	service_ids_leaving[i] = ut_rand_id();

    int64_t generation = 234;
    int64_t ttl = 60;

    struct paf_props *props = paf_props_create();
    paf_props_add_str(props, "name", "foo");

    for (i = 0; i < num_service_ids; i++) {
	sub_report_match(sub, source_id_leaving, paf_match_type_appeared,
			 service_ids_leaving[i], &generation, props, &ttl,
			 NULL, now);
	sub_report_match(sub, source_id_staying, paf_match_type_appeared,
			 ut_rand_id(), &generation, props, &ttl,
			 NULL, now);
    }

    CHKINTEQ(match_list.len, num_service_ids * 2);
    sub_process_timeout(sub, DBL_MAX);
    CHKINTEQ(match_list.len, num_service_ids * 2);

    double orphan_since = 234234.4;
    double orphan_timeout = orphan_since + ttl;

    sub_report_source_disconnected(sub, source_id_leaving, orphan_since);

    CHKINTEQ(match_list.len, num_service_ids * 2);
    sub_process_timeout(sub, orphan_timeout - 0.1);
    CHKINTEQ(match_list.len, num_service_ids * 2);

    sub_process_timeout(sub, orphan_timeout + 0.1);
    CHKINTEQ(match_list.len, num_service_ids * 3);
    CHK(match_list.matches[num_service_ids * 2]->match_type ==
	paf_match_type_disappeared);
    CHK(match_list.matches[num_service_ids * 3 - 1]->match_type ==
	paf_match_type_disappeared);

    CHK(umatch_service_ids_equal(&match_list, num_service_ids * 2,
				 service_ids_leaving, num_service_ids));

    clear_matches(&match_list);
    sub_destroy(sub);
    paf_props_destroy(props);

    return UTEST_SUCCESS;
}

TESTCASE(sub, stale_timeout)
{
    return UTEST_SUCCESS;
}
