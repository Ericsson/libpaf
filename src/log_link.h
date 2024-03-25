/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#ifndef LOG_LINK_H
#define LOG_LINK_H

#include "log.h"

#define log_link_debug(link, fmt, ...)		\
    log_obj_debug(link, fmt, ##__VA_ARGS__)

#define log_link_error(link, fmt, ...)		\
    log_obj_error(link, fmt, ##__VA_ARGS__)

#define log_link_start(link)			\
    log_link_debug(link, "Link created.")

#define log_link_query_timeout(link)			\
    log_link_debug(link, "Server query timed out.")

#define log_link_idle_time_changed(link, max_idle_time)			\
    log_link_debug(link, "Maximum idle time was adjusted to %.0f s.",	\
		   max_idle_time)

#define log_link_restart(link)			\
    log_link_debug(link, "Link restarting.")

#define log_link_track_reply(link, latency)				\
    log_link_debug(link, "Received server track reply in %d ms.",	\
		   (latency) * 1e3)

#define log_link_track_unsolicited_reply(link)				\
    log_link_debug(link, "Received unsolicited server track reply.")

#define log_link_track_replied(link)		\
    log_link_debug(link, "Replied to server track query.")

#define log_link_track_completed(link)		\
    log_link_debug(link, "Track transaction unexpectedly completed.")

#define log_link_detaching(link)		\
    log_link_debug(link, "Detaching link.")

#define log_link_pending_unpublications(link, num)			\
    log_link_debug(link, "%zd in-progress services unpublications before " \
		   "link can be detached.", num)

#define log_link_detached(link)			\
    log_link_debug(link, "Link is detached.")

#define log_link_forced_detachment(link, detach_tmo)			\
    log_link_debug(link, "Server failed to respond within the allowed " \
		   "%.0f ms. Forcing detach.", (detach_tmo) * 1e3)

#define log_link_dead(link)			\
    log_link_debug(link, "Link is dead.")

#define log_link_destroy(link)						\
    log_link_debug(link, "Link destroyed.")

#define log_link_operational(link, protocol_version)			\
    log_link_debug(link, "Operational using protocol "			\
		   "version %"PRId64".", protocol_version)

#define log_link_processing(link, state_str)				\
    log_link_debug(link, "Processing link in state %s.",		\
		   state_str)

#define log_link_state_change(link, from_state, to_state)	\
    log_link_debug(link, "Transition from state %s to %s.", \
		   from_state, to_state)
    
#define log_link_service_count(link, count)				\
    log_link_debug(link, "%zd service relays installed.", count)

#define log_link_sub_count(link, count)					\
    log_link_debug(link, "%zd subscription relays installed.", count)

#define log_link_server_conn_eof(link)				\
    log_link_debug(link, "Server closed down XCM connection.")

#define log_link_server_conn_error(link, conn_errno)			\
    log_link_debug(link, "Fatal error %d (%s) on XCM "			\
		   "connection.", conn_errno, strerror(conn_errno))

#define log_link_request(link, request_str)			\
    log_link_debug(link, "Outgoing request: %s.", request_str)

#define log_link_response(link, response_str)				\
    log_link_debug(link, "Incoming response: %s.", response_str)

#define log_link_relay(link, type, action, obj_id)		 \
    log_link_debug(link, "%s relay for %s with id 0x%"PRIx64".", \
		   action, type, obj_id)

#define log_link_install_service_relay(link, service_id)	\
    log_link_relay(link, "service", "Installing", service_id)

#define log_link_update_service_relay(link, service_id)		\
    log_link_relay(link, "service", "Updating", service_id)

#define log_link_uninstall_service_relay(link, service_id)	\
    log_link_relay(link, "service", "Uninstalling", service_id)

#define log_link_install_sub_relay(link, sub_id)			\
    log_link_relay(link, "subscription", "Installing", sub_id)

#define log_link_uninstall_sub_relay(link, sub_id)			\
    log_link_relay(link, "subscription", "Uninstalling", sub_id)

#define log_link_attempt(link, type, action, obj_id, ta_id)	   \
    log_link_debug(link, "Attemting to %s %s with %s id 0x%"PRIx64	\
		   " to remote server as transaction %"PRId64".", action, \
		   type, type, obj_id, ta_id)

#define log_link_completion(link, type, action, obj_id)	       \
    log_link_debug(link, "Successfully %s %s id 0x%"PRIx64".", \
		   action, type, obj_id)

#define log_link_service_sync(link, service_id, ta_id)			\
    log_link_attempt(link, "service", "sync", service_id, ta_id)

#define log_link_service_synced(link, service_id)		\
    log_link_completion(link, "service", "synced", service_id)

#define log_link_service_unsync(link, service_id, ta_id)	\
    log_link_attempt(link, "service", "unsync", service_id, ta_id)

#define log_link_service_unsynced(link, service_id)		\
    log_link_completion(link, "service", "unsynced", service_id)

#define log_link_sub_sync(link, sub_id, ta_id)		\
    log_link_attempt(link, "subscription", "sync", sub_id, ta_id)

#define log_link_sub_synced(link, sub_id)			\
    log_link_completion(link, "subscription", "synced", sub_id)

#define log_link_sub_match(link, sub_id) \
    log_link_debug(link, "Received match notification in subscription " \
		   "id 0x%"PRIx64".", sub_id)

#define log_link_sub_match_ignored(link) \
    log_link_debug(link, "Unsyncing or detach in process; match ignored.")

#define log_link_sub_unsync(link, sub_id, ta_id)		\
    log_link_attempt(link, "subscription", "unsync", sub_id, ta_id)

#define log_link_sub_unsynced(link, sub_id)			\
    log_link_completion(link, "subscription", "unsynced", sub_id)

#define log_link_sd_changed(link, obj_type, change_type, obj_id) \
    log_link_debug(link, "Object type %s with id %"PRIx64" %s.", \
		   obj_type, obj_id, change_type)

#endif
