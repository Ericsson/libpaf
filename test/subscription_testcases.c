/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#include "utest.h"

#include "util.h"

#include "subscription.h"

TESTSUITE(subscription, NULL, NULL)

#define DUMMY_LOG_REF "testclient"

struct match
{
    enum paf_match_type match_type;
    int64_t service_id;
    struct paf_props *props;
};

#define MAX_MATCHES (1024)

struct match_list
{
    struct match *matches[MAX_MATCHES];
    size_t len;
};

static bool match_equal(struct match *match, enum paf_match_type match_type,
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

static void add_match(struct match_list *list, enum paf_match_type match_type,
                      int64_t service_id, const struct paf_props *props)
{
    struct match *match = ut_malloc(sizeof(struct match));
    *match = (struct match) {
        .match_type = match_type,
        .service_id = service_id,
        .props = props != NULL ? paf_props_clone(props) : NULL
    };
    list->matches[list->len] = match;
    list->len++;
}

static void clear_matches(struct match_list *list)
{
    size_t i;
    for (i = 0; i < list->len; i++) {
        struct match *m = list->matches[i];
        if (m->props != NULL)
            paf_props_destroy(m->props);
        ut_free(m);
    }
    list->len = 0;
}

static void match_recorder(enum paf_match_type match_type, int64_t service_id,
                           const struct paf_props *props, void *user)
{
    struct match_list *list = user;
    add_match(list, match_type, service_id, props);
}

static void match_counter(enum paf_match_type match_type, int64_t service_id,
                          const struct paf_props *props, void *user)
{
    int *count = user;

    (*count)++;
}

TESTCASE(subscription, matches)
{
    const int64_t sub_id = 99;

    struct match_list match_list = { .len = 0 };
    struct subscription *subscription =
        subscription_create(sub_id, NULL, DUMMY_LOG_REF, match_recorder,
                            &match_list);

    const int64_t service_id = 17;
    int64_t ttl = 60;
    double orphan_since = -1;
    struct paf_props *props = paf_props_create();

    paf_props_add_str(props, "name", "foo");
    subscription_notify_match(subscription, paf_match_type_appeared,
                              service_id, props, ttl, orphan_since);

    CHKINTEQ(match_list.len, 1);
    CHK(match_equal(match_list.matches[0], paf_match_type_appeared,
                    service_id, props));

    paf_props_add_str(props, "name", "foo2");
    subscription_notify_match(subscription, paf_match_type_modified,
                              service_id, props, ttl, orphan_since);

    CHKINTEQ(match_list.len, 2);
    CHK(match_equal(match_list.matches[1], paf_match_type_modified,
                    service_id, props));

    paf_props_add_int64(props, "adsf", 99);
    subscription_notify_match(subscription, paf_match_type_modified,
                              service_id, props, ttl, orphan_since);

    CHKINTEQ(match_list.len, 3);
    CHK(match_equal(match_list.matches[2], paf_match_type_modified, service_id, 
                    props));

    clear_matches(&match_list);
    subscription_destroy(subscription);
    paf_props_destroy(props);

    return UTEST_SUCCESS;
}

#define MANY_MATCHES (10000)

TESTCASE(subscription, many_matches)
{
    const int64_t sub_id = 42;

    int count = 0;
    struct subscription *subscription =
        subscription_create(sub_id, NULL, DUMMY_LOG_REF, match_counter,
                            &count);

    int64_t service_ids[MANY_MATCHES];
    size_t i;

    for (i = 0; i < MANY_MATCHES; i++)
        service_ids[i] = random();

    for (i = 0; i < MANY_MATCHES; i++) {
        const int64_t ttl = i * 60;
        const double orphan_since = -1;

        struct paf_props *props = paf_props_create();
        paf_props_add_int64(props, "value", i);

        subscription_notify_match(subscription, paf_match_type_appeared,
                                  service_ids[i], props, ttl, orphan_since);
        paf_props_destroy(props);
    }

    for (i = 0; i < MANY_MATCHES; i++) {
        const int64_t ttl = i * 60;
        const double orphan_since = -1;

        struct paf_props *props = paf_props_create();
        paf_props_add_int64(props, "value", i);

        subscription_notify_match(subscription, paf_match_type_disappeared,
                                  service_ids[i], props, ttl, orphan_since);
        paf_props_destroy(props);
    }

    CHKINTEQ(count, 2*MANY_MATCHES);

    subscription_destroy(subscription);

    return UTEST_SUCCESS;
}

TESTCASE(subscription, meta_data_changes)
{
    const int64_t sub_id = 4711;

    struct match_list match_list = { .len = 0 };
    struct subscription *subscription =
        subscription_create(sub_id, NULL, DUMMY_LOG_REF, match_recorder,
                            &match_list);

    const int64_t service_id = 42;
    int64_t ttl = 10000;
    double orphan_since = -1;
    struct paf_props *props = paf_props_create();

    subscription_notify_match(subscription, paf_match_type_appeared,
                              service_id, props, ttl, orphan_since);

    CHKINTEQ(match_list.len, 1);

    subscription_notify_match(subscription, paf_match_type_appeared,
                              service_id, props, ttl, orphan_since);

    /* no change shouldn't yield any application response */
    CHKINTEQ(match_list.len, 1);

    ttl++;
    subscription_notify_match(subscription, paf_match_type_appeared,
                              service_id, props, ttl, orphan_since);

    /* TTL changes are not relevant for the application */
    CHKINTEQ(match_list.len, 1);

    orphan_since = 1;
    subscription_notify_match(subscription, paf_match_type_appeared,
                              service_id, props, ttl, orphan_since);

    /* A service becoming orphan is not relevant for the application */
    CHKINTEQ(match_list.len, 1);

    clear_matches(&match_list);
    subscription_destroy(subscription);
    paf_props_destroy(props);

    return UTEST_SUCCESS;
}

TESTCASE(subscription, next_orphan_timeout_and_service_reoccurence)
{
    const int64_t sub_id = 4711;

    struct match_list match_list = { .len = 0 };
    struct subscription *subscription =
        subscription_create(sub_id, NULL, DUMMY_LOG_REF, match_recorder,
                            &match_list);

    struct paf_props *props = paf_props_create();

    subscription_notify_match(subscription, paf_match_type_appeared, 0,
                              props, 5, 5);

    subscription_notify_match(subscription, paf_match_type_appeared, 1,
                              props, 1, -1);

    subscription_notify_match(subscription, paf_match_type_appeared, 2,
                              props, 1, 6);

    subscription_notify_match(subscription, paf_match_type_appeared, 3,
                              props, 6, 6);

    CHKINTEQ(subscription_next_orphan_timeout(subscription), 7);

    subscription_notify_match(subscription, paf_match_type_disappeared, 2,
                              props, 1, 6);

    CHKINTEQ(subscription_next_orphan_timeout(subscription), 10);

    subscription_notify_match(subscription, paf_match_type_modified, 0,
                              props, 1, -1);

    CHKINTEQ(subscription_next_orphan_timeout(subscription), 12);

    CHKINTEQ(match_list.len, 5);

    clear_matches(&match_list);
    subscription_destroy(subscription);
    paf_props_destroy(props);

    return UTEST_SUCCESS;
}

TESTCASE(subscription, make_all_orphans)
{
    const int64_t sub_id = 4711;

    struct match_list match_list = { .len = 0 };
    struct subscription *subscription =
        subscription_create(sub_id, NULL, DUMMY_LOG_REF, match_recorder,
                            &match_list);

    struct paf_props *props = paf_props_create();

    subscription_notify_match(subscription, paf_match_type_appeared, 0,
                              props, 5, 5);

    subscription_notify_match(subscription, paf_match_type_appeared, 1,
                              props, 1, -1);

    subscription_make_all_orphans(subscription, 10);

    CHKINTEQ(subscription_next_orphan_timeout(subscription), 10);

    subscription_notify_match(subscription, paf_match_type_appeared, 0,
                              props, 5, -1);

    CHKINTEQ(subscription_next_orphan_timeout(subscription), 11);

    clear_matches(&match_list);
    subscription_destroy(subscription);
    paf_props_destroy(props);

    return UTEST_SUCCESS;
}

TESTCASE(subscription, purge_orphans_simple)
{
    const int64_t sub_id = 4711;

    struct match_list match_list = { .len = 0 };
    struct subscription *subscription =
        subscription_create(sub_id, NULL, DUMMY_LOG_REF, match_recorder,
                            &match_list);

    const int64_t service_id = 234234;
    struct paf_props *props = paf_props_create();
    paf_props_add_str(props, "name", "foo");

    subscription_notify_match(subscription, paf_match_type_appeared,
                              service_id, props, 5, 5);

    subscription_purge_orphans(subscription, 5);
    subscription_purge_orphans(subscription, 7);

    CHKINTEQ(match_list.len, 1);
    
    subscription_purge_orphans(subscription, 10);

    CHKINTEQ(match_list.len, 2);
    CHK(match_equal(match_list.matches[1], paf_match_type_disappeared,
                    service_id, NULL));

    clear_matches(&match_list);
    subscription_destroy(subscription);
    paf_props_destroy(props);

    return UTEST_SUCCESS;
}

TESTCASE(subscription, purge_orphans_many)
{
    const int64_t sub_id = 4711;

    struct match_list match_list = { .len = 0 };
    struct subscription *subscription =
        subscription_create(sub_id, NULL, DUMMY_LOG_REF, match_recorder,
                            &match_list);

    struct paf_props *props = paf_props_create();
    paf_props_add_str(props, "name", "foo");
    paf_props_add_int64(props, "name", 4711);

    subscription_notify_match(subscription, paf_match_type_appeared, 0,
                              props, 5, -1);
    subscription_notify_match(subscription, paf_match_type_appeared, 1,
                              props, 5, -1);
    subscription_notify_match(subscription, paf_match_type_appeared, 2,
                              props, 5, -1);
    subscription_notify_match(subscription, paf_match_type_appeared, 3,
                              props, 5, 1);

    subscription_notify_match(subscription, paf_match_type_modified, 0,
                              props, 10, 1);
    CHKINTEQ(match_list.len, 4);
    clear_matches(&match_list);

    subscription_purge_orphans(subscription, 0);
    CHKINTEQ(match_list.len, 0);

    subscription_purge_orphans(subscription, 7);
    CHKINTEQ(match_list.len, 1);
    CHKINTEQ(match_list.matches[0]->service_id, 3);

    subscription_purge_orphans(subscription, 8);
    CHKINTEQ(match_list.len, 1);

    subscription_notify_match(subscription, paf_match_type_modified, 1,
                              props, 5, 2);

    subscription_purge_orphans(subscription, 8);
    CHKINTEQ(match_list.len, 2);
    CHKINTEQ(match_list.matches[1]->service_id, 1);

    subscription_notify_match(subscription, paf_match_type_modified, 0,
                              props, 5, 3);
    subscription_notify_match(subscription, paf_match_type_modified, 2,
                              props, 10, 3);

    subscription_purge_orphans(subscription, 8);
    CHKINTEQ(match_list.len, 3);
    CHKINTEQ(match_list.matches[2]->service_id, 0);

    subscription_purge_orphans(subscription, 13);
    CHKINTEQ(match_list.len, 4);
    CHKINTEQ(match_list.matches[3]->service_id, 2);

    size_t i;
    for (i = 0; i < match_list.len; i++)
        CHK(match_list.matches[i]->match_type == paf_match_type_disappeared);

    clear_matches(&match_list);
    subscription_destroy(subscription);
    paf_props_destroy(props);

    return UTEST_SUCCESS;
}
