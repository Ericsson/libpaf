/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#ifndef MATCH_H
#define MATCH_H

#include <stdint.h>

#include "list.h"
#include "paf_match.h"

struct source
{
    int64_t source_id;
    double orphan_since;
    LIST_ENTRY(source) entry;
};

LIST_HEAD(source_list, source);

struct match
{
    int64_t service_id;
    int64_t service_generation;
    struct paf_props *service_props;
    int64_t service_ttl;

    struct source_list sources;

    LIST_ENTRY(match) entry;
};

LIST_HEAD(match_list, match);

struct match *match_create(void);

void match_report(struct match *match, int64_t source_id,
		  enum paf_match_type match_type, int64_t service_id,
		  const int64_t *generation, const struct paf_props *props,
		  const int64_t *ttl, const double *orphan_since,
		  paf_match_cb match_cb, void *user);
void match_report_orphan(struct match *match, int64_t source_id,
			 double since);
bool match_is_orphan(const struct match *match);
double match_orphan_timeout(const struct match *match);
void match_purge_orphan(struct match *match, double now,
			paf_match_cb match_cb, void *user);
bool match_has_disappeared(const struct match *match);
void match_destroy(struct match *match);

const char *match_type_str(enum paf_match_type type);

#endif
