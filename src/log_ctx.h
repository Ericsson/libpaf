/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#ifndef LOG_CTX_H
#define LOG_CTX_H

#include "log.h"

#define log_ctx_debug(ctx, fmt, ...)		\
    log_obj_debug(ctx, fmt, ##__VA_ARGS__)

#define log_ctx_error(ctx, fmt, ...)		\
    log_obj_error(ctx, fmt, ##__VA_ARGS__)

#define log_ctx_start(ctx, epoll_fd)					\
    log_ctx_debug(ctx, "Pathfinder context with epoll instance fd %d "	\
		  "created.", epoll_fd)

#define log_ctx_detached(ctx)			\
    log_ctx_debug(ctx, "Detach complete.")

#define log_ctx_close(log_ref)			\
    log_ctx_debug(ctx, "Closing context.")

#define log_ctx_detaching(ctx)				\
    log_ctx_debug(ctx, "Detaching from domain.")

#define log_ctx_link_setup(ctx, server, link_id)			\
    do {                                                                \
	char buf[1024];							\
	ut_snprintf(buf, sizeof(buf), "Setting up link id %"PRId64" "	\
		    "with domain address %s.", link_id, (server)->addr); \
	if (server->cert_file != NULL)					\
	    ut_aprintf(buf, sizeof(buf), " Certificate file: \"%s\".",	\
		       server->cert_file);				\
	if (server->key_file != NULL)					\
	    ut_aprintf(buf, sizeof(buf), " Key file: \"%s\".",		\
		       server->key_file);				\
	if (server->tc_file != NULL)					\
	    ut_aprintf(buf, sizeof(buf), " Trusted CA file: \"%s\".",	\
		       server->tc_file);				\
	log_ctx_debug(ctx, buf);					\
    } while (0)

#define log_ctx_link_teardown(ctx, server, link_id)			\
    log_ctx_debug(ctx, "Tearing down link id %d with domain address %s.", \
		  link_id, (server)->addr)

#define log_ctx_processing(link, state_str)	\
    log_ctx_debug(link, "Processing context in state %s.", state_str)

#define log_ctx_publish(ctx, service_id, props)				\
    do {                                                                \
        char buf[1024];                                                 \
        buf[0] = '\0';                                                  \
        ut_aprintf(buf, sizeof(buf), "Publishing service id 0x%"PRIx64 \
		   " with props ", service_id);				\
        log_aprint_props(buf, sizeof(buf), props);                      \
        log_ctx_debug(ctx, "%s.", buf);					\
    } while (0)

#define log_ctx_modify(ctx, service_id, old_props, new_props)		\
    do {                                                                \
        char buf[1024];                                                 \
        buf[0] = '\0';                                                  \
        ut_aprintf(buf, sizeof(buf), "Modifying service id 0x%"PRIx64  \
		   " props from ", service_id);				\
        log_aprint_props(buf, sizeof(buf), old_props);                  \
        ut_aprintf(buf, sizeof(buf), " to ");                          \
        log_aprint_props(buf, sizeof(buf), new_props);                  \
        log_ctx_debug(ctx, "%s.", buf);					\
    } while (0)

#define log_ctx_set_ttl(ctx, service_id, old_ttl, new_ttl)		\
    log_ctx_debug(ctx, "Changing TTL for service id 0x%"PRIx64		\
		  " from %"PRId64" to %"PRId64" s.", service_id,	\
		  old_ttl, new_ttl)

#define log_ctx_unpublish(ctx, service_id)				\
    log_ctx_debug(ctx, "Unpublishing service id 0x%"PRIx64".",		\
		  service_id)

#define log_ctx_subscribe(ctx, sub_id, filter_str)			\
    do {								\
        if (filter_str != NULL)						\
	    log_ctx_debug(ctx, "Subscription with id 0x%"PRIx64" and "	\
			  "filter \"%s\" added.", sub_id, filter_str);	\
	else								\
	    log_ctx_debug(ctx, "Subscription with id 0x%"PRIx64" and "	\
			  "NULL (i.e. match-all) filter added.", sub_id); \
    } while (0)

#define log_ctx_unsubscribe(ctx, sub_id)				\
    log_ctx_debug(ctx, "Unsubscribing to subscription id 0x%"PRIx64".", \
		  sub_id)

#define log_ctx_sd_timeout(ctx, clk_id, abs_tmo)	 \
    log_ctx_debug(ctx, "Next orphan timeout in %.1f s.", \
		  abs_tmo - ut_ftime(clk_id))

#endif
