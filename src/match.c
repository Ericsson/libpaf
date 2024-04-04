/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#include <assert.h>

#include "util.h"

#include "match.h"

static struct source *source_create(int64_t source_id,
				    const double *orphan_since)
{
    struct source *source = ut_malloc(sizeof(struct source));

    *source = (struct source) {
	.source_id = source_id,
	.orphan_since = orphan_since == NULL ? -1 : *orphan_since
    };

    return source;
}

static void source_service_orphan_update(struct source *source,
					 const double *orphan_since)
{
    if (orphan_since != NULL) {
	assert(*orphan_since >= 0);

	if (source->orphan_since == -1 || *orphan_since < source->orphan_since)
	    source->orphan_since = *orphan_since;
    } else
	source->orphan_since = -1;
}

static bool source_considers_service_orphan(struct source *source)
{
    return source->orphan_since >= 0;
}

static void source_destroy(struct source *source)
{
    ut_free(source);
}

struct match *match_create(void)
{
    struct match *match = ut_malloc(sizeof(struct match));

    *match = (struct match) {
	.service_id = -1
    };

    LIST_INIT(&match->sources);

    return match;
}

static void destroy_sources(struct match *match)
{
    struct source *source;
    while ((source = LIST_FIRST(&match->sources)) != NULL) {
	LIST_REMOVE(source, entry);
	source_destroy(source);
    }
}

static void service_appeared(struct match *match, int64_t service_id,
			     int64_t generation,
			     const struct paf_props *props, int64_t ttl,
			     paf_match_cb match_cb, void *user)
{
    match->service_id = service_id;
    match->service_generation = generation;
    match->service_props = paf_props_clone(props);
    match->service_ttl = ttl;

    match_cb(paf_match_type_appeared, match->service_id, match->service_props,
	     user);
}

static void service_modified(struct match *match, int64_t generation,
			     const struct paf_props *props, int64_t ttl,
			     paf_match_cb match_cb, void *user)
{
    match->service_generation = generation;
    match->service_ttl = ttl;

    if (!paf_props_equal(props, match->service_props)) {
	paf_props_destroy(match->service_props);
	match->service_props = paf_props_clone(props);
	match_cb(paf_match_type_modified, match->service_id,
		 match->service_props, user);
    }
}

static void service_disappeared(struct match *match, paf_match_cb match_cb,
				void *user)
{
    match_cb(paf_match_type_disappeared, match->service_id, NULL, user);
}

static void report_appeared_modified(struct match *match, int64_t source_id,
				     int64_t service_id, int64_t generation,
				     const struct paf_props *props,
				     int64_t ttl, const double *orphan_since,
				     paf_match_cb match_cb, void *user)
{
    /* information about old matches is irrelevant */
    if (generation < match->service_generation)
	return;

    bool initial_source = LIST_EMPTY(&match->sources);

    if (!initial_source && generation > match->service_generation)
	destroy_sources(match);

    struct source *source =
	LIST_FIND(&match->sources, source_id, source_id, entry);

    if (source == NULL) {
	struct source *source = source_create(source_id, orphan_since);
	LIST_INSERT_HEAD(&match->sources, source, entry);
    } else
	source_service_orphan_update(source, orphan_since);

    if (initial_source) {
	assert(match->service_id < 0);
	service_appeared(match, service_id, generation, props, ttl,
			 match_cb, user);
    } else if (generation > match->service_generation) {
	assert(service_id == match->service_id);
	service_modified(match, generation, props, ttl, match_cb, user);
    }

}

static void report_disappeared(struct match *match, int64_t source_id,
			       paf_match_cb match_cb, void *user)
{
    struct source *source =
	LIST_FIND(&match->sources, source_id, source_id, entry);

    LIST_REMOVE(source, entry);
    source_destroy(source);

    if (LIST_EMPTY(&match->sources))
	service_disappeared(match, match_cb, user);
}

void match_report(struct match *match, int64_t source_id,
		  enum paf_match_type match_type, int64_t service_id,
		  const int64_t *generation, const struct paf_props *props,
		  const int64_t *ttl, const double *orphan_since,
		  paf_match_cb match_cb, void *user)
{
    switch (match_type) {
    case paf_match_type_appeared:
    case paf_match_type_modified:
	assert(generation != NULL && ttl != NULL);
	report_appeared_modified(match, source_id, service_id, *generation,
				 props, *ttl, orphan_since, match_cb,
				 user);
	break;
    case paf_match_type_disappeared:
	assert(generation == NULL && props == NULL && ttl == NULL &&
	       orphan_since == NULL);
	report_disappeared(match, source_id, match_cb, user);
        break;
    default:
        assert(0);
    }

}

void match_report_orphan(struct match *match, int64_t source_id,
			 double since)
{
    struct source *source;
    LIST_FOREACH(source, &match->sources, entry)
        if (source->source_id == source_id) {
	    source_service_orphan_update(source, &since);
	    break;
	}
}

bool match_is_orphan(const struct match *match)
{
    struct source *source;
    LIST_FOREACH(source, &match->sources, entry)
        if (!source_considers_service_orphan(source))
	    return false;
    return true;
}

static double service_last_seen(const struct match *match)
{
    double last_seen = 0;

    struct source *source;
    LIST_FOREACH(source, &match->sources, entry) {
	assert(source_considers_service_orphan(source));
	if (source->orphan_since > last_seen)
	    last_seen = source->orphan_since;
    }

    return last_seen;
}

double match_orphan_timeout(const struct match *match)
{
    double last_seen = service_last_seen(match);

    assert(last_seen >= 0);

    return last_seen + match->service_ttl;
}

void match_purge_orphan(struct match *match, double now,
			paf_match_cb match_cb, void *user)
{
    if (match_is_orphan(match)) {
	double timeout = match_orphan_timeout(match);
	if (timeout <= now) {
	    service_disappeared(match, match_cb, user);
	    destroy_sources(match);
	}
    }
}

void match_make_orphan(struct match *match, int64_t source_id, double since)
{
    struct source *source =
	LIST_FIND(&match->sources, source_id, source_id, entry);

    if (source != NULL)
	source->orphan_since = since;
}

bool match_has_disappeared(const struct match *match)
{
    return LIST_EMPTY(&match->sources);
}

void match_destroy(struct match *match)
{
    if (match != NULL) {
	destroy_sources(match);
	paf_props_destroy(match->service_props);
	ut_free(match);
    }
}

#define SLABEL(prefix, name)                    \
    case prefix ## _ ## name:                   \
    return "" #name ""

const char *match_type_str(enum paf_match_type type)
{
    switch (type) {
        SLABEL(paf_match_type, appeared);
        SLABEL(paf_match_type, modified);
        SLABEL(paf_match_type, disappeared);
    default:
        return "undefined";
    }
}
