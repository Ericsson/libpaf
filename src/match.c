/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#include <assert.h>

#include "log_match.h"
#include "util.h"

#include "match.h"

static struct source *source_create(int64_t source_id, int64_t generation,
				    const double *orphan_since)
{
    struct source *source = ut_malloc(sizeof(struct source));

    *source = (struct source) {
	.source_id = source_id,
	.generation = generation,
	.connected = true,
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

static bool source_is_orphan(struct source *source)
{
    return source->orphan_since >= 0;
}

static void source_destroy(struct source *source)
{
    ut_free(source);
}

struct match *match_create(int64_t service_id, const char *log_ref)
{
    struct match *match = ut_malloc(sizeof(struct match));

    char *match_log_ref = ut_asprintf("%s: service: 0x%"PRIx64, log_ref,
				      service_id);

    *match = (struct match) {
	.service_id = service_id,
	.service_generation = -1,
	.state = match_state_initial,
        .log_ref = match_log_ref,
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
    assert(match_is_stale(match) || match->state == match_state_initial);

    match->service_id = service_id;
    match->service_generation = generation;
    match->service_props = paf_props_clone(props);
    match->service_ttl = ttl;

    match->state = match_state_announced;
    match->stale_since = -1;

    match_cb(paf_match_type_appeared, match->service_id, match->service_props,
	     user);
}

static void service_modified(struct match *match, int64_t generation,
			     const struct paf_props *props, int64_t ttl,
			     paf_match_cb match_cb, void *user)
{
    assert(match->state == match_state_announced);

    match->service_generation = generation;
    match->service_ttl = ttl;

    if (!paf_props_equal(props, match->service_props)) {
	paf_props_destroy(match->service_props);
	match->service_props = paf_props_clone(props);
	match_cb(paf_match_type_modified, match->service_id,
		 match->service_props, user);
    }
}

static void service_disappeared(struct match *match, double now,
				paf_match_cb match_cb, void *user)
{
    assert(match->state == match_state_announced);
    assert(now >= 0);

    if (match_is_orphan(match))
	match->state = match_state_orphaned_out;
    else
	match->state = match_state_unpublished;

    match->stale_since = now;

    match_cb(paf_match_type_disappeared, match->service_id, NULL, user);
}

static struct source *get_source(struct match *match, int64_t source_id)
{
    return LIST_FIND(&match->sources, source_id, source_id, entry);
}

static int report_appeared(struct match *match, int64_t source_id,
			   int64_t service_id, int64_t generation,
			   const struct paf_props *props, int64_t ttl,
			   const double *orphan_since, paf_match_cb match_cb,
			   void *user)
{
    struct source *source = get_source(match, source_id);

    if (source == NULL) {
	source = source_create(source_id, generation, orphan_since);
	LIST_INSERT_HEAD(&match->sources, source, entry);
    } else if (source->connected) {
	log_match_source_appeared_without_disappeared(match, source_id);
	return -1;
    } else {
	if (generation < source->generation) {
	    log_match_source_out_of_order(match, source_id, generation,
					  source->generation);
	    return -1;
	}

	if (match->state == match_state_unpublished)
	    log_match_source_appeared_after_unpublished(match, source_id,
							service_id);
	else if (match->state == match_state_orphaned_out)
	    log_match_source_appeared_after_orphaned_out(match, source_id,
							 service_id);
	    
	source->generation = generation;
	source->connected = true;
	source_service_orphan_update(source, orphan_since);
    }

    bool initial = match->state == match_state_initial;
    bool update = source->generation > match->service_generation;
    bool rejoin = source->generation == match->service_generation &&
	match->state == match_state_orphaned_out;

    if (initial || update || rejoin) {
	if (match->state != match_state_announced)
	    service_appeared(match, service_id, generation, props, ttl,
			     match_cb, user);
	else
	    service_modified(match, generation, props, ttl, match_cb, user);
    }

    return 0;
}

static int report_modified(struct match *match, int64_t source_id,
			   int64_t service_id, int64_t generation,
			   const struct paf_props *props, int64_t ttl,
			   const double *orphan_since, paf_match_cb match_cb,
			   void *user)
{
    struct source *source = get_source(match, source_id);

    if (source == NULL) {
	log_match_source_modified_before_appeared(match, source_id);
	return -1;
    } else if (!source->connected) {
	log_match_source_modified_after_disappeared(match, source_id);
	return -1;
    }

    if (generation < source->generation) {
	log_match_source_out_of_order(match, source_id, generation,
				      source->generation);
	return -1;
    }

    source->generation = generation;
    source_service_orphan_update(source, orphan_since);

    /* XXX: change to the same logic as 'appeared' */
    if (generation > match->service_generation) {
	/* The match may not have been announced in the original
	   'appeared' (from this source) if the generation number
	   equal to or older than than a generation that was reported
	   as 'disappeared'. */
	if (match_is_stale(match))
	    service_appeared(match, service_id, generation, props, ttl,
			     match_cb, user);
	else
	    service_modified(match, generation, props, ttl, match_cb, user);
    }

    return 0;
}

static bool has_connected_current_source(const struct match *match)
{
    struct source *source;
    LIST_FOREACH(source, &match->sources, entry)
	if (source->connected && source->generation == match->service_generation)
	    return true;
    return false;
}

static int report_disappeared(struct match *match, int64_t source_id,
			      double now, paf_match_cb match_cb, void *user)
{
    struct source *source = get_source(match, source_id);

    if (source == NULL) {
	log_match_source_disappeared_before_appeared(match, source_id);
	return -1;
    }

    source->connected = false;

    if (!has_connected_current_source(match) &&
	match->state == match_state_announced)
	service_disappeared(match, now, match_cb, user);

    return 0;
}

int match_report(struct match *match, int64_t source_id,
		 enum paf_match_type match_type, int64_t service_id,
		 const int64_t *generation, const struct paf_props *props,
		 const int64_t *ttl, const double *orphan_since,
		 double now, paf_match_cb match_cb, void *user)
{
    int rc;

    switch (match_type) {
    case paf_match_type_appeared:
	assert(generation != NULL && ttl != NULL);
	rc = report_appeared(match, source_id, service_id, *generation,
			     props, *ttl, orphan_since, match_cb, user);
	break;
    case paf_match_type_modified:
	assert(generation != NULL && ttl != NULL);
	rc = report_modified(match, source_id, service_id, *generation, props,
			     *ttl, orphan_since, match_cb, user);
	break;
    case paf_match_type_disappeared:
	assert(generation == NULL && props == NULL && ttl == NULL &&
	       orphan_since == NULL);
	rc = report_disappeared(match, source_id, now, match_cb, user);
        break;
    default:
        assert(0);
	rc = -1;
	break;
    }

    return rc;
}

void match_report_source_disconnected(struct match *match, int64_t source_id,
				      double since)
{
    struct source *source;
    LIST_FOREACH(source, &match->sources, entry)
        if (source->source_id == source_id) {
	    if (!source_is_orphan(source))
		source_service_orphan_update(source, &since);
	    source->connected = false;
	    break;
	}
}

bool match_is_orphan(const struct match *match)
{
    if (match->state != match_state_announced)
	return false;

    struct source *source;
    LIST_FOREACH(source, &match->sources, entry)
        if (source->generation == match->service_generation &&
	    !source_is_orphan(source))
	    return false;

    return true;
}

bool match_is_unconnected_orphan(const struct match *match)
{
    if (match->state != match_state_announced)
	return false;

    struct source *source;
    LIST_FOREACH(source, &match->sources, entry)
        if (source->generation == match->service_generation &&
	    (!source_is_orphan(source) || source->connected))
	    return false;

    return true;
}

static double service_last_seen(const struct match *match)
{
    double last_seen = 0;

    struct source *source;
    LIST_FOREACH(source, &match->sources, entry) {
	assert(source_is_orphan(source));
	if (source->orphan_since > last_seen)
	    last_seen = source->orphan_since;
    }

    return last_seen;
}

double match_unconnected_orphan_timeout(const struct match *match)
{
    assert(match_is_unconnected_orphan(match));

    double last_seen = service_last_seen(match);

    assert(last_seen >= 0);

    return last_seen + match->service_ttl;
}

void match_purge_unconnected_orphan(struct match *match, double now,
				    paf_match_cb match_cb, void *user)
{
    if (match_is_unconnected_orphan(match)) {
	double timeout = match_unconnected_orphan_timeout(match);

	if (timeout <= now) {
	    log_match_unconnected_orphan_timed_out(match);
	    service_disappeared(match, now, match_cb, user);
	}
    }
}

bool match_is_stale(const struct match *match)
{
    switch (match->state) {
    case match_state_orphaned_out:
    case match_state_unpublished:
	assert(match->stale_since >= 0);
	return true;
    default:
	return false;
    }
}

double match_stale_timeout(const struct match *match)
{
    assert(match_is_stale(match));

    return match->stale_since + MATCH_STALE_TIMEOUT;
}

void match_destroy(struct match *match)
{
    if (match != NULL) {
	destroy_sources(match);
	paf_props_destroy(match->service_props);
	ut_free(match->log_ref);
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
