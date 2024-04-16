/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 Ericsson AB
 */

#ifndef LOG_MATCH_H
#define LOG_MATCH_H

#include "log.h"

#define log_match_debug(match, fmt, ...)		\
    log_obj_debug(match, fmt, ##__VA_ARGS__)

#define log_match_error(match, fmt, ...)		\
    log_obj_error(match, fmt, ##__VA_ARGS__)

#define log_match_unconnected_orphan_timed_out(match)		\
    log_match_debug(match, "Unconnected orphan match hit library-internal " \
		    "time out.")

#define log_match_source_out_of_order(match, source_id, received_generation, \
				      prev_known_generation)		\
    log_match_debug(match, "Received notification from source id %"PRId64" " \
		    " out of order: got %"PRId64" after %"PRId64".",	\
		    source_id, received_generation, prev_known_generation)

#define log_match_source(match, source_id, error_s)			\
    log_match_debug(match, "Source id %"PRId64" reported service %s.", \
		    error_s, source_id)

#define log_match_source_appeared_after_orphaned_out(match, source_id,	\
						     service_id)	\
    log_match_source(match, "appeared after having been removed due to " \
		     "orphan timeout", source_id)

#define log_match_source_appeared_after_unpublished(match, source_id,	\
						     service_id)	\
    log_match_source(match, "appeared after having been unpublished", \
		     source_id)

#define log_match_source_appeared_without_disappeared(match, source_id)	\
    log_match_source(match, "appeared after same generation already having " \
		     "disappeared", source_id)

#define log_match_source_modified_before_appeared(match, source_id)	\
    log_match_source(match, "modified before appearing", source_id)

#define log_match_source_modified_after_disappeared(match, source_id)	\
    log_match_source(match, "modified after disappearing", source_id)

#define log_match_source_disappeared_before_appeared(match, source_id)	\
    log_match_source(match, "disappeared before appearing", source_id)

#endif
