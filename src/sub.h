/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#ifndef SUB_H
#define SUB_H

#include <inttypes.h>
#include <stdbool.h>
#include <sys/types.h>

#include "list.h"
#include "match.h"
#include "paf_match.h"

struct sub
{
    int64_t sub_id;

    char *filter_str;

    paf_match_cb match_cb;
    void *user;

    struct match_list matches;

    char *log_ref;

    LIST_ENTRY(sub) entry;
};

LIST_HEAD(sub_list, sub);

struct sub *sub_create(int64_t sub_id, const char *filter_str,
		       const char *log_ref, paf_match_cb match_cb,
		       void *user);

void sub_report_match(struct sub *sub, int64_t source_id,
		      enum paf_match_type match_type,
		      int64_t service_id, const int64_t *generation,
		      const struct paf_props *props, const int64_t *ttl,
		      const double *orphan_since);

void sub_orphan_all_from_source(struct sub *sub, int64_t source_id,
				double since);

bool sub_has_orphan(struct sub *sub);
double sub_next_orphan_timeout(struct sub *sub);

void sub_purge_orphans(struct sub *sub, double now);

void sub_destroy(struct sub *sub);

#endif
