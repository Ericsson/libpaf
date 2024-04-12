/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#ifndef LOG_SUB_H
#define LOG_SUB_H

#include "log.h"

#define log_sub_debug(sub, fmt, ...)		\
    log_obj_debug(sub, fmt, ##__VA_ARGS__)

#define log_sub_error(sub, fmt, ...)		\
    log_obj_error(sub, fmt, ##__VA_ARGS__)


#define log_sub_server_match(sub, source_id, service_id, generation,	\
			     props, ttl, orphan_since, match_type_str)	\
    do {                                                                \
        char buf[1024];							\
	snprintf(buf, sizeof(buf), "Received server type \"%s\" "	\
		 "match from source id %"PRId64" for service id 0x%"	\
		 PRIx64".", match_type_str, source_id, service_id);	\
	if (generation != NULL)						\
	    ut_aprintf(buf, sizeof(buf), " Generation: %"PRId64".",	\
		       *generation);					\
	if (ttl != NULL)						\
	    ut_aprintf(buf, sizeof(buf), " TTL: %"PRId64".", *ttl);	\
	if (orphan_since != NULL)					\
	    ut_aprintf(buf, sizeof(buf), " Orphan since: %f.",		\
		       *orphan_since);					\
        if (props != NULL) {                                            \
            ut_aprintf(buf, sizeof(buf), " Props: ");			\
            log_aprint_props(buf, sizeof(buf), props);                  \
            ut_aprintf(buf, sizeof(buf), ".");				\
        }                                                               \
	log_sub_debug(sub, "%s", buf);					\
    } while (0)

#define log_sub_app_match(sub, service_id, props, match_type_str)	\
    do {                                                                \
        char buf[1024];							\
	buf[0] = '\0';							\
	ut_aprintf(buf, sizeof(buf), "Announcing type \"%s\" "	\
		   "application-level match for service id 0x%"		\
		   PRIx64".", match_type_str, service_id);		\
        if (props != NULL) {                                            \
            ut_aprintf(buf, sizeof(buf), " Props: ");			\
            log_aprint_props(buf, sizeof(buf), props);                  \
        }                                                               \
	log_sub_debug(sub, "%s", buf);					\
    } while (0)

#endif
