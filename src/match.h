/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#ifndef MATCH_H
#define MATCH_H

#include <stdint.h>

#include "list.h"
#include "paf_match.h"

#define MATCH_STALE_TIMEOUT 30.0

struct source
{
    int64_t source_id;
    int64_t generation;
    double orphan_since;
    /* A service is 'connected' starting with the 'appeared' and until
       'disappeared', from the point of view of this source. Since
       sources may be slightly out-of-sync, there may be an connected
       source even though the matched service has been reported as
       'disappeared' to the application, since the connected source has
       only reported on older generation of that service. */
    bool connected;
    LIST_ENTRY(source) entry;
};

LIST_HEAD(source_list, source);

enum match_state {
    match_state_initial,
    match_state_announced,
    match_state_orphaned_out,
    match_state_unpublished
};

struct match
{
    int64_t service_id;
    int64_t service_generation;
    struct paf_props *service_props;
    int64_t service_ttl;

    enum match_state state;

    struct source_list sources;

    double stale_since;

    char *log_ref;

    LIST_ENTRY(match) entry;
};

LIST_HEAD(match_list, match);

struct match *match_create(int64_t service_id, const char *log_ref);

int match_report(struct match *match, int64_t source_id,
		 enum paf_match_type match_type, int64_t service_id,
		 const int64_t *generation, const struct paf_props *props,
		 const int64_t *ttl, const double *orphan_since,
		 double now, paf_match_cb match_cb, void *user);
void match_report_source_disconnected(struct match *match, int64_t source_id,
				      double since);
bool match_is_orphan(const struct match *match);
bool match_is_unconnected_orphan(const struct match *match);
double match_unconnected_orphan_timeout(const struct match *match);
void match_purge_unconnected_orphan(struct match *match, double now,
				    paf_match_cb match_cb, void *user);

bool match_is_stale(const struct match *match);
double match_stale_timeout(const struct match *match);

bool match_is_unpublished(const struct match *match);

void match_destroy(struct match *match);

const char *match_type_str(enum paf_match_type type);

#endif
