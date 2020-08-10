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

#define log_ctx_domain_file_error(ctx, op_errno)		\
    log_ctx_debug(ctx, "Error accessing domain file: %d (%s).", \
		  op_errno, strerror(op_errno))

#define log_ctx_domain_file_unchanged(ctx)		\
    log_ctx_debug(ctx, "Domain file unchanged.")

#define log_ctx_link_setup(ctx, link_addr, link_id)			\
    log_ctx_debug(ctx, "Setting up link id %d with domain address %s.", \
		  link_id, link_addr)

#define log_ctx_link_teardown(ctx, link_addr, link_id)		\
    log_ctx_debug(ctx, "Tearing down link id %d with domain address %s.", \
		  link_id, link_addr)

#define log_ctx_processing(link, state_str)	\
    log_ctx_debug(link, "Processing context in state %s.", state_str)

#define log_ctx_publish(ctx, service_id, props)				\
    do {                                                                \
        char buf[1024];                                                 \
        buf[0] = '\0';                                                  \
        log_aprintf(buf, sizeof(buf), "Publishing service id 0x%"PRIx64 \
                    " with props ", service_id);                        \
        log_aprint_props(buf, sizeof(buf), props);                      \
        log_ctx_debug(ctx, "%s.", buf);					\
    } while (0)

#define log_ctx_modify(ctx, service_id, old_props, new_props)		\
    do {                                                                \
        char buf[1024];                                                 \
        buf[0] = '\0';                                                  \
        log_aprintf(buf, sizeof(buf), "Modifying service id 0x%"PRIx64  \
                    " props from ", service_id);			\
        log_aprint_props(buf, sizeof(buf), old_props);                  \
        log_aprintf(buf, sizeof(buf), " to ");                          \
        log_aprint_props(buf, sizeof(buf), new_props);                  \
        log_ctx_debug(ctx, "%s.", buf);					\
    } while (0)

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
