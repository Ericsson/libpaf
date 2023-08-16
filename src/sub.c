/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#include <assert.h>
#include <float.h>
#include <string.h>
#include <stdio.h>

#include "log_sub.h"
#include "util.h"

#include "sub.h"

struct sub *sub_create(int64_t sub_id, const char *filter_str,
		       const char *log_ref, paf_match_cb match_cb,
		       void *user)
{
    struct sub *sub = ut_malloc(sizeof(struct sub));

    char *sub_log_ref = ut_asprintf("%s: subscription: 0x%"PRIx64, log_ref,
				    sub_id);

    *sub = (struct sub) {
        .sub_id = sub_id,
        .filter_str = filter_str != NULL ? ut_strdup(filter_str) : NULL,
        .log_ref = sub_log_ref,
        .match_cb = match_cb,
        .user = user
    };

    LIST_INIT(&sub->matches);

    return sub;
}

static void app_match(enum paf_match_type match_type, int64_t service_id,
		      const struct paf_props *props, void *user)
{
    struct sub *sub = user;

    log_sub_app_match(sub, service_id, props, match_type_str(match_type));

    sub->match_cb(match_type, service_id, props, sub->user);
}

static void check_disappearence(struct sub *sub __attribute__((unused)),
				struct match *match)
{
    if (match_has_disappeared(match)) {
	LIST_REMOVE(match, entry);
	match_destroy(match);
    }
}

int sub_report_match(struct sub *sub, int64_t source_id,
		     enum paf_match_type match_type,
		     int64_t service_id, const int64_t *generation,
		     const struct paf_props *props,
		     const int64_t *ttl, const double *orphan_since)
{
    log_sub_server_match(sub, service_id, generation, props, ttl,
			 orphan_since, match_type_str(match_type));

    struct match *match =
	LIST_FIND(&sub->matches, service_id, service_id, entry);

    if (match == NULL) {
	/* Local and remote server orphan cleanup is a race, so you may
	   get stray disappear notifications. */
	if (match_type == paf_match_type_disappeared) {
	    log_sub_stray_disappeared(sub, service_id);
	    return 0;
	} else if (match_type == paf_match_type_modified) {
	    log_sub_invalid_modified(sub, service_id);
	    return -1;
	}

	match = match_create();
	LIST_INSERT_HEAD(&sub->matches, match, entry);
    }

    match_report(match, source_id, match_type, service_id, generation,
		 props, ttl, orphan_since, app_match, sub);
    check_disappearence(sub, match);

    return 0;
}

void sub_orphan_all_from_source(struct sub *sub, int64_t source_id,
				double since)
{
    assert(since >= 0);

    struct match *match;
    LIST_FOREACH(match, &sub->matches, entry)
	match_report_orphan(match, source_id, since);
}

bool sub_has_orphan(struct sub *sub)
{
    struct match *match;
    LIST_FOREACH(match, &sub->matches, entry) {
	if (match_is_orphan(match))
	    return true;
    }
    return false;
}

double sub_next_orphan_timeout(struct sub *sub)
{
    double next_timeout = DBL_MAX;

    struct match *match;
    LIST_FOREACH(match, &sub->matches, entry) {
        if (match_is_orphan(match)) {
	    double orphan_timeout = match_orphan_timeout(match);
	    if (orphan_timeout < next_timeout)
		next_timeout = orphan_timeout;
	}
    }

    return next_timeout;
}

void sub_purge_orphans(struct sub *sub, double now)
{
    struct match *match = LIST_FIRST(&sub->matches);
    while (match != NULL) {
	struct match *next = LIST_NEXT(match, entry);
	match_purge_orphan(match, now, sub->match_cb, sub->user);
	check_disappearence(sub, match);
	match = next;
    }
}

void sub_destroy(struct sub *sub)
{
    if (sub != NULL) {
        ut_free(sub->filter_str);

	struct match *match;
	while ((match = LIST_FIRST(&sub->matches)) != NULL) {
	    LIST_REMOVE(match, entry);
	    match_destroy(match);
	}

	ut_free(sub->log_ref);
        ut_free(sub);
    }
}
