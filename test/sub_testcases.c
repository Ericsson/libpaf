/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#include <float.h>

#include "utest.h"

#include "util.h"
#include "sub.h"

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
		     &generation, props, &ttl, NULL);

    CHKINTEQ(match_list.len, 1);
    CHK(umatch_equal(match_list.matches[0], paf_match_type_appeared,
                    service_id, props));

    paf_props_add_str(props, "name", "foo2");
    generation++;
    sub_report_match(sub, source_id, paf_match_type_modified, service_id,
		     &generation, props, &ttl, NULL);

    CHKINTEQ(match_list.len, 2);
    CHK(umatch_equal(match_list.matches[1], paf_match_type_modified,
                    service_id, props));

    paf_props_add_int64(props, "adsf", 99);
    generation++;
    sub_report_match(sub, source_id, paf_match_type_modified, service_id,
		     &generation, props, &ttl, NULL);

    CHKINTEQ(match_list.len, 3);
    CHK(umatch_equal(match_list.matches[2], paf_match_type_modified,
		     service_id, props));

    /* same generation -> no change */
    sub_report_match(sub, source_id, paf_match_type_modified, service_id,
		     &generation, props, &ttl, NULL);
    CHKINTEQ(match_list.len, 3);

    /* older generation -> no change */
    generation--;
    sub_report_match(sub, source_id, paf_match_type_modified, service_id,
		     &generation, props, & ttl, NULL);
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

    int64_t source_id_0 = 0;
    int64_t source_id_1 = 1;
    const int64_t service_id = 17;
    int64_t generation = 234;
    int64_t ttl_value = 60;
    int64_t *ttl = &ttl_value;
    double *orphan_since = NULL;

    struct paf_props *props = paf_props_create();
    paf_props_add_str(props, "name", "foo");

    sub_report_match(sub, source_id_0, paf_match_type_appeared, service_id,
		     &generation, props, ttl, orphan_since);
    CHKINTEQ(match_list.len, 1);
    CHK(umatch_equal(match_list.matches[0], paf_match_type_appeared,
                    service_id, props));

    sub_report_match(sub, source_id_1, paf_match_type_appeared, service_id,
		     &generation, props, ttl, orphan_since);
    CHKINTEQ(match_list.len, 1);

    sub_report_match(sub, source_id_1, paf_match_type_disappeared, service_id,
		     NULL, NULL, NULL, NULL);
    CHKINTEQ(match_list.len, 1);

    sub_report_match(sub, source_id_0, paf_match_type_disappeared, service_id,
		     NULL, NULL, NULL, NULL);
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

    struct paf_props *props = paf_props_create();

    sub_report_match(sub, source_id, paf_match_type_appeared, service_id,
		     &generation, props, &ttl, NULL);
    CHKINTEQ(count, 1);

    generation--;
    paf_props_add_str(props, "name", "foo");
    sub_report_match(sub, source_id, paf_match_type_appeared, service_id,
		     &generation, props, &ttl, NULL);
    CHKINTEQ(count, 1);

    sub_destroy(sub);
    paf_props_destroy(props);

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

    struct paf_props *props = paf_props_create();

    sub_report_match(sub, source_id, paf_match_type_appeared, service_id,
		     &generation, props, &ttl, NULL);
    CHKINTEQ(count, 1);

    ttl++;
    generation += 10;
    sub_report_match(sub, source_id, paf_match_type_appeared, service_id,
		     &generation, props, &ttl, NULL);
    CHKINTEQ(count, 1);

    sub_destroy(sub);
    paf_props_destroy(props);

    return UTEST_SUCCESS;
}

TESTCASE(sub, orphan)
{
    const int64_t sub_id = 99;

    struct umatch_list match_list = { .len = 0 };
    struct sub *sub = sub_create(sub_id, NULL, DUMMY_LOG_REF, match_recorder,
				 &match_list);
    int64_t source_id_0 = 0;
    int64_t source_id_1 = 1;
    const int64_t service_id = 17;
    int64_t generation = 0;
    int64_t ttl = 60;

    struct paf_props *props = paf_props_create();

    sub_report_match(sub, source_id_0, paf_match_type_appeared, service_id,
		     &generation, props, &ttl, NULL);
    CHKINTEQ(match_list.len, 1);

    CHK(!sub_has_orphan(sub));

    double orphan_since = 99e99;
    sub_report_match(sub, source_id_0, paf_match_type_modified, service_id,
		     &generation, props, &ttl, &orphan_since);
    CHKINTEQ(match_list.len, 1);
    CHK(sub_has_orphan(sub));

    sub_report_match(sub, source_id_0, paf_match_type_modified, service_id,
		     &generation, props, &ttl, NULL);
    CHKINTEQ(match_list.len, 1);
    CHK(!sub_has_orphan(sub));

    sub_report_match(sub, source_id_1, paf_match_type_modified, service_id,
		     &generation, props, &ttl, NULL);
    CHKINTEQ(match_list.len, 1);
    CHK(!sub_has_orphan(sub));

    sub_report_match(sub, source_id_0, paf_match_type_modified, service_id,
		     &generation, props, &ttl, &orphan_since);
    CHKINTEQ(match_list.len, 1);
    CHK(!sub_has_orphan(sub));

    sub_report_match(sub, source_id_1, paf_match_type_modified, service_id,
		     &generation, props, &ttl, &orphan_since);
    CHKINTEQ(match_list.len, 1);
    CHK(sub_has_orphan(sub));

    clear_matches(&match_list);
    sub_destroy(sub);
    paf_props_destroy(props);

    return UTEST_SUCCESS;
}

TESTCASE(sub, purge_orphans)
{
    const int64_t sub_id = 99;

    struct umatch_list match_list = { .len = 0 };
    struct sub *sub = sub_create(sub_id, NULL, DUMMY_LOG_REF, match_recorder,
				 &match_list);
    int64_t source_id = 0;

    const int64_t service_id_parented = 424242;
    int64_t ttl_parented = 60;

    const int64_t service_id_old = 99;
    int64_t ttl_old = 30;
    double orphan_since_old = 30;
    double timeout_old = orphan_since_old + ttl_old;

    const int64_t service_id_recent = 42;
    int64_t ttl_recent = 25;
    double orphan_since_recent = 40;
    double timeout_recent = orphan_since_recent + ttl_recent;

    int64_t generation = 10000;

    struct paf_props *props = paf_props_create();

    sub_report_match(sub, source_id, paf_match_type_appeared,
		     service_id_parented, &generation, props, &ttl_parented,
		     NULL);
    CHKINTEQ(match_list.len, 1);
    sub_purge_orphans(sub, DBL_MAX);
    CHKINTEQ(match_list.len, 1);

    sub_report_match(sub, source_id, paf_match_type_appeared,
		     service_id_old, &generation, props,
		     &ttl_old, &orphan_since_old);
    CHKINTEQ(match_list.len, 2);
    sub_purge_orphans(sub, timeout_old-1);
    CHKINTEQ(match_list.len, 2);

    sub_report_match(sub, source_id, paf_match_type_appeared,
		     service_id_recent, &generation, props, &ttl_recent,
		     &orphan_since_recent);
    CHKINTEQ(match_list.len, 3);
    sub_purge_orphans(sub, timeout_old-1);
    CHKINTEQ(match_list.len, 3);

    CHKDBLAPPROXEQ(sub_next_orphan_timeout(sub), timeout_old);

    sub_purge_orphans(sub, timeout_old+1);
    CHKINTEQ(match_list.len, 4);
    CHK(umatch_equal(match_list.matches[3], paf_match_type_disappeared,
		     service_id_old, NULL));

    CHKDBLAPPROXEQ(sub_next_orphan_timeout(sub), timeout_recent);

    sub_purge_orphans(sub, timeout_recent+1);
    CHKINTEQ(match_list.len, 5);
    CHK(umatch_equal(match_list.matches[4], paf_match_type_disappeared,
		     service_id_recent, NULL));

    CHK(!sub_has_orphan(sub));

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
	sub_report_match(sub, source_id, paf_match_type_appeared, service_id,
			 &generation, props, &ttl, &orphan_since);
	CHKINTEQ(count, i+1);
    }

    count = 0;

    sub_purge_orphans(sub, orphan_timeout - 1);
    CHKINTEQ(count, 0);

    sub_purge_orphans(sub, orphan_timeout + 0.1);
    CHKINTEQ(count, MANY);

    /* Local and remote server orphan cleanup is a race, so you may
       get stray disappear notifications. */
    sub_report_match(sub, source_id, paf_match_type_disappeared,
		     base_service_id, NULL, NULL, NULL, NULL);
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
			 NULL);
	sub_report_match(sub, source_id_staying, paf_match_type_appeared,
			 ut_rand_id(), &generation, props, &ttl,
			 NULL);
    }

    CHKINTEQ(match_list.len, num_service_ids * 2);
    sub_purge_orphans(sub, DBL_MAX);
    CHKINTEQ(match_list.len, num_service_ids * 2);

    double orphan_since = 234234.4;
    double orphan_timeout = orphan_since + ttl;

    sub_orphan_all_from_source(sub, source_id_leaving, orphan_since);

    CHKINTEQ(match_list.len, num_service_ids * 2);
    sub_purge_orphans(sub, orphan_timeout - 0.1);
    CHKINTEQ(match_list.len, num_service_ids * 2);

    sub_purge_orphans(sub, orphan_timeout + 0.1);
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
