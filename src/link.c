/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020-2021 Ericsson AB
 */

#include <assert.h>
#include <float.h>
#include <string.h>
#include <time.h>
#include <xcm_version.h>
#include <xcm_addr.h>

#include "conf.h"
#include "list.h"
#include "log_link.h"
#include "util.h"

#include "link.h"

#define MAX_DETACH_TIME(num_services) (0.5 + 0.001 * (num_services))

#define MAX_SYNCING_UNSYNCING_RELAYS (32)

#define SLABEL(name)				     \
    case link_state_ ## name:                        \
    return #name

static const char *link_state_str(enum link_state state)
{
    switch (state) {
        SLABEL(connecting);
        SLABEL(greeting);
        SLABEL(operational);
        SLABEL(restarting);
        SLABEL(detaching);
        SLABEL(detached);
    default:
        assert(0);
    }
}

static struct relay *relay_create(int64_t obj_id)
{
    struct relay *relay = ut_malloc(sizeof(struct relay));
    *relay = (struct relay) {
	.obj_id = obj_id,
	.state = relay_state_unsynced,
	.sync_ta_id = -1,
	.unsync_ta_id = -1,
	.pending_sync = false,
	.pending_unsync = false
    };
    return relay;
}

static void relay_destroy(struct relay *relay)
{
    ut_free(relay);
}

static void set_state(struct link *link, enum link_state state)
{
    log_link_state_change(link, link_state_str(link->state),
			  link_state_str(state));
    link->state = state;
}

static void clear_tmos(struct link *link)
{
    ptimer_cancel(link->timer, &link->reconnect_tmo);
    ptimer_cancel(link->timer, &link->idle_tmo);
    ptimer_cancel(link->timer, &link->detached_tmo);
}

static void untie_from_sd(struct link *link)
{
    if (link->listener != NULL) {
	sd_remove_listener(link->sd, link->listener);
	link->listener = NULL;
    }
    sd_orphan_all_from_source(link->sd, link->link_id,
			      ut_ftime(CLOCK_REALTIME));
}

static void handle_error(struct link *link);

static bool is_io_capable_state(enum link_state state)
{
    switch (state) {
    case link_state_greeting:
    case link_state_operational:
    case link_state_detaching:
	return true;
    default:
	return false;
    }
}

static void try_finish_detach(struct link *link)
{
    size_t num_service_relays = LIST_COUNT(&link->service_relays, entry);

    bool tmo_expired = ptimer_has_expired(link->timer, link->detached_tmo);

    if (num_service_relays > 0 && !tmo_expired) {
	log_link_pending_unpublications(link, num_service_relays);
	return;
    }

    if (tmo_expired)
	log_link_forced_detachment(link, link->max_detach_time);

    link->state = link_state_detached;
    log_link_detached(link);

    ptimer_reschedule_rel(link->timer, 0, &link->detached_tmo);
}

static bool is_tracking(struct link *link)
{
    return link->track_ta_id >= 0;
}

static bool is_track_querying(struct link *link)
{
    return link->track_query_ts >= 0;
}

#define IDLE_QUERY_THRESHOLD 0.5

static void schedule_idle_query_tmo(struct link *link)
{
    assert(is_tracking(link) && !is_track_querying(link));

    double idle_query_time =
	ut_jitter(link->max_idle_time * IDLE_QUERY_THRESHOLD, 0.1);

    ptimer_reschedule_rel(link->timer, idle_query_time, &link->idle_tmo);
}

static void schedule_idle_reply_tmo(struct link *link)
{
    assert(is_tracking(link) && is_track_querying(link));

    double idle_reply_time =
	link->max_idle_time * (1.0 - IDLE_QUERY_THRESHOLD);

    ptimer_reschedule_rel(link->timer, idle_reply_time, &link->idle_tmo);
}

static void fail_cb(int64_t ta_id UT_UNUSED, int fail_reason_err UT_UNUSED,
		    void *cb_data)
{
    struct link *link = cb_data;
    handle_error(link);
}

static void server_active(struct link *link)
{
    if (link->state == link_state_operational &&
	is_tracking(link)) {

	if (is_track_querying(link))
	    /* We've heard from the server, so we can post-poned query
	       reply timeout. This is useful since the reply may
	       already be in our socket buffer. A large backlog of
	       incoming messages may cause the idle timeout to fire,
	       needlessly tearing down the connection. */
	    schedule_idle_reply_tmo(link);
	else
	    /* We've heard from the server, so we can post-pone the next
	       track query */
	    schedule_idle_query_tmo(link);
    }
}

static void track_notify_cb(int64_t ta_id, bool is_query, void *cb_data)
{
    struct link *link = cb_data;

    if (is_query) {
	log_link_track_replied(link);
	conn_track_inform(link->conn, ta_id, false);
    } else {
	if (!is_track_querying(link)) {
	    log_link_track_unsolicited_reply(link);
	    handle_error(link);
	} else {
	    double latency =
		ut_ftime(CLOCK_MONOTONIC) - link->track_query_ts;

	    log_link_track_reply(link, latency);
	    link->track_query_ts = -1;

	    if (link->state == link_state_operational)
		schedule_idle_query_tmo(link);
	}
    }

    server_active(link);
}

static void track_complete_cb(int64_t ta_id UT_UNUSED, void *cb_data)
{
    struct link *link = cb_data;

    log_link_track_completed(link);

    link->track_ta_id = -1;
    handle_error(link);
}

static void configure_idle_tracking(struct link *link)
{
    if (conn_is_track_supported(link->conn)) {
	link->track_ta_id =
	    conn_track_nb(link->conn, fail_cb, NULL, track_notify_cb,
			  track_complete_cb, link);

	schedule_idle_query_tmo(link);
    }
}

/* XXX: 1. relay -> obj_relay
 *      2. only store active relays
 */
static void install_service_relays(struct link *link);
static void install_sub_relays(struct link *link);
static void sd_changed_cb(enum sd_obj_type obj_type, int64_t obj_id,
			  enum sd_change_type change_type, void *user);

static void hello_complete_cb(int64_t ta_id UT_UNUSED, int64_t proto_version,
			      void *cb_data)
{
    struct link *link = cb_data;

    log_link_operational(link, proto_version);

    set_state(link, link_state_operational);

    link->reconnect_time = 0;

    configure_idle_tracking(link);

    install_service_relays(link);
    install_sub_relays(link);

    link->listener = sd_add_listener(link->sd, sd_changed_cb, link);
}

static void try_sync_service(struct link *link, struct relay *service_relay);
static void try_unsync_service(struct link *link, struct relay *service_relay);

static void publish_complete_cb(int64_t ta_id, void *cb_data)
{
    struct link *link = cb_data;

    struct relay *service_relay =
	LIST_FIND(&link->service_relays, sync_ta_id, ta_id, entry);

    assert(service_relay != NULL);
    assert(service_relay->state == relay_state_syncing);

    log_link_service_synced(link, service_relay->obj_id);

    service_relay->state = relay_state_synced;
    service_relay->sync_ta_id = -1;

    if (service_relay->pending_unsync)
	try_unsync_service(link, service_relay);
    else if (service_relay->pending_sync)
	try_sync_service(link, service_relay);

    server_active(link);
}

static void try_sync_sub(struct link *link, struct relay *sub_relay);
static void try_unsync_sub(struct link *link, struct relay *sub_relay);

static void unpublish_complete_cb(int64_t ta_id, void *cb_data)
{
    struct link *link = cb_data;

    struct relay *service_relay =
	LIST_FIND(&link->service_relays, unsync_ta_id, ta_id, entry);

    log_link_service_unsynced(link, service_relay->obj_id);

    LIST_REMOVE(service_relay, entry);

    relay_destroy(service_relay);

    server_active(link);
}

static void check_sub_relay_removal(struct link *link,
				   struct relay *sub_relay)
{
    /* The order of the subscribe complete and the unsubscribe
       complete is not defined, so both cases need to be handled */
    if (sub_relay->sync_ta_id == -1 && sub_relay->unsync_ta_id == -1) {
	log_link_sub_unsynced(link, sub_relay->obj_id);
	LIST_REMOVE(sub_relay, entry);
	relay_destroy(sub_relay);
    }
}

static void subscribe_accept_cb(int64_t ta_id, void *cb_data)
{
    struct link *link = cb_data;
    struct relay *sub_relay =
	LIST_FIND(&link->sub_relays, sync_ta_id, ta_id, entry);

    log_link_sub_synced(link, sub_relay->obj_id);

    sub_relay->state = relay_state_synced;

    if (sub_relay->pending_unsync)
	try_unsync_sub(link, sub_relay);
    else if (sub_relay->pending_sync)
	try_sync_sub(link, sub_relay);

    server_active(link);
}

static void subscribe_notify_cb(int64_t ta_id, enum paf_match_type match_type,
				int64_t service_id, const int64_t *generation,
				const struct paf_props *props,
				const int64_t *ttl, const double *orphan_since,
				void *cb_data)
{
    struct link *link = cb_data;
    struct relay *sub_relay =
	LIST_FIND(&link->sub_relays, sync_ta_id, ta_id, entry);

    assert(sub_relay->state == relay_state_synced ||
	   sub_relay->state == relay_state_unsyncing);

    log_link_sub_match(link, sub_relay->obj_id);

    if (sub_relay->state == relay_state_unsyncing ||
	sub_relay->pending_unsync || link->state == link_state_detaching) {
	log_link_sub_match_ignored(link);
	return;
    }

    if (sd_report_match(link->sd, link->link_id, sub_relay->obj_id,
			match_type, service_id, generation,
			props, ttl, orphan_since) < 0)
	handle_error(link);

    server_active(link);
}

static void subscribe_complete_cb(int64_t ta_id, void *cb_data)
{
    struct link *link = cb_data;
    struct relay *sub_relay =
	LIST_FIND(&link->sub_relays, sync_ta_id, ta_id, entry);

    sub_relay->sync_ta_id = -1;
    check_sub_relay_removal(link, sub_relay);

    server_active(link);
}

static void unsubscribe_complete_cb(int64_t ta_id, void *cb_data)
{
    struct link *link = cb_data;
    struct relay *sub_relay =
	LIST_FIND(&link->sub_relays, unsync_ta_id, ta_id, entry);

    sub_relay->unsync_ta_id = -1;
    check_sub_relay_removal(link, sub_relay);

    server_active(link);
}

static void sync_service(struct link *link, struct relay *service_relay)
{
    assert(link->state == link_state_operational);
    assert(service_relay->state == relay_state_unsynced ||
           service_relay->state == relay_state_synced);

    service_relay->pending_sync = false;

    struct service *service = sd_get_service(link->sd, service_relay->obj_id);

    service_relay->sync_ta_id =
	conn_publish_nb(link->conn, service->service_id, service->generation,
			service->props, service->ttl, fail_cb,
			publish_complete_cb, link);

    log_link_service_sync(link, service_relay->obj_id,
			  service_relay->sync_ta_id);

    service_relay->state = relay_state_syncing;
}

static void unsync_service(struct link *link, struct relay *service_relay)
{
    assert(link->state == link_state_operational ||
	   link->state == link_state_detaching);
    assert(service_relay->state == relay_state_synced);

    service_relay->pending_unsync = false;

    service_relay->unsync_ta_id =
	conn_unpublish_nb(link->conn, service_relay->obj_id, fail_cb,
			  unpublish_complete_cb, link);

    log_link_service_unsync(link, service_relay->obj_id,
			    service_relay->unsync_ta_id);

    service_relay->state = relay_state_unsyncing;
}

static int count_syncing_unsyncing_objs(struct relay_list *list)
{
    int count = 0;

    struct relay *relay;
    LIST_FOREACH(relay, list, entry)
	switch (relay->state) {
	case relay_state_syncing:
	case relay_state_unsyncing:
	    count++;
	    break;
	default:
	    break;
    }

    return count;
}

static int count_syncing_unsyncing(struct link *link)
{
    return count_syncing_unsyncing_objs(&link->service_relays) +
	count_syncing_unsyncing_objs(&link->sub_relays);
}

static void try_sync_service(struct link *link, struct relay *service_relay)
{
    if (link->state == link_state_operational &&
	(service_relay->state == relay_state_unsynced ||
	 (service_relay->state == relay_state_synced &&
	  service_relay->pending_sync)) &&
	count_syncing_unsyncing(link) < MAX_SYNCING_UNSYNCING_RELAYS)
	sync_service(link, service_relay);
}

static void try_unsync_service(struct link *link, struct relay *service_relay)
{
    if ((link->state == link_state_operational ||
	 link->state == link_state_detaching) &&
	service_relay->state == relay_state_synced &&
	service_relay->pending_unsync &&
	count_syncing_unsyncing(link) < MAX_SYNCING_UNSYNCING_RELAYS)
	unsync_service(link, service_relay);
}

static void sync_sub(struct link *link, struct relay *sub_relay)
{
    assert(link->state == link_state_operational);
    assert(sub_relay->state == relay_state_unsynced);

    sub_relay->pending_sync = false;

    struct sub *sub = sd_get_sub(link->sd, sub_relay->obj_id);

    sub_relay->sync_ta_id =
	conn_subscribe_nb(link->conn, sub->sub_id, sub->filter_str,
			  fail_cb, subscribe_accept_cb, subscribe_notify_cb,
			  subscribe_complete_cb, link);

    log_link_sub_sync(link, sub_relay->obj_id, sub_relay->sync_ta_id);

    sub_relay->state = relay_state_syncing;
}

static void unsync_sub(struct link *link, struct relay *sub_relay)
{
    assert(link->state == link_state_operational ||
	   link->state == link_state_detaching);
    assert(sub_relay->state == relay_state_synced);

    sub_relay->pending_unsync = false;

    sub_relay->unsync_ta_id =
	conn_unsubscribe_nb(link->conn, sub_relay->obj_id, fail_cb,
			    unsubscribe_complete_cb, link);

    log_link_sub_unsync(link, sub_relay->obj_id, sub_relay->unsync_ta_id);

    sub_relay->state = relay_state_unsyncing;
}

static void try_sync_sub(struct link *link, struct relay *sub_relay)
{
    if (link->state == link_state_operational &&
	sub_relay->state == relay_state_unsynced &&
	count_syncing_unsyncing(link) < MAX_SYNCING_UNSYNCING_RELAYS)
	sync_sub(link, sub_relay);
}

static void try_unsync_sub(struct link *link, struct relay *sub_relay)
{
    if ((link->state == link_state_operational ||
	 link->state == link_state_detaching) &&
	sub_relay->state == relay_state_synced &&
	sub_relay->pending_unsync &&
	count_syncing_unsyncing(link) < MAX_SYNCING_UNSYNCING_RELAYS)
	unsync_sub(link, sub_relay);
}

static double lowest_service_ttl(struct link *link)
{
    double candidate = DBL_MAX;
    struct service *service;
    LIST_FOREACH(service, &link->sd->services, entry)
	if (service->ttl < candidate)
	    candidate = service->ttl;

    return candidate;
}

static void adjust_max_idle_time(struct link *link)
{
    double max_idle_time;

    if (LIST_EMPTY(&link->sd->services))
	max_idle_time = conf_get_idle_max();
    else {
	max_idle_time = lowest_service_ttl(link);
	max_idle_time = UT_MAX(max_idle_time, conf_get_idle_min());
    }

    if (max_idle_time != link->max_idle_time) {
	log_link_idle_time_changed(link, max_idle_time);

	if (is_tracking(link) && !is_track_querying(link)) {
	    double left = ptimer_time_left(link->timer, link->idle_tmo);

	    if (left > max_idle_time)
		schedule_idle_query_tmo(link);
	}

	link->max_idle_time = max_idle_time;
    }
}

static void install_service_relay(struct link *link, int64_t service_id)
{
    assert(link->state == link_state_operational);
    assert(!LIST_EXISTS(&link->service_relays, obj_id, service_id,
			entry));

    log_link_install_service_relay(link, service_id);

    struct relay *service_relay = relay_create(service_id);
    LIST_INSERT_HEAD(&link->service_relays, service_relay, entry);

    try_sync_service(link, service_relay);

    adjust_max_idle_time(link);
}

static void clear_service_relays(struct link *link)
{
    struct relay *service_relay;
    while ((service_relay = LIST_FIRST(&link->service_relays)) != NULL) {
        LIST_REMOVE(service_relay, entry);
        relay_destroy(service_relay);
    }
}

static void update_service_relay(struct link *link, int64_t service_id)
{
    struct relay *service_relay =
	LIST_FIND(&link->service_relays, obj_id, service_id, entry);

    log_link_update_service_relay(link, service_id);

    switch (service_relay->state) {
    case relay_state_syncing:
	service_relay->pending_sync = true;
	break;
    case relay_state_synced:
	service_relay->pending_sync = true;
	try_sync_service(link, service_relay);
	break;
    case relay_state_unsynced:
    case relay_state_unsyncing:
    default:
	assert(0);
    }

    adjust_max_idle_time(link);
}

static void install_service_relays(struct link *link)
{
    struct service *service;
    LIST_FOREACH(service, &link->sd->services, entry)
	install_service_relay(link, service->service_id);
}

static void uninstall_service_relay(struct link *link, int64_t service_id)
{
    struct relay *service_relay =
	LIST_FIND(&link->service_relays, obj_id, service_id, entry);

    assert(service_relay != NULL);

    log_link_uninstall_service_relay(link, service_id);

    switch (service_relay->state) {
    case relay_state_unsynced:
	break;
    case relay_state_syncing:
	service_relay->pending_unsync = true;
	break;
    case relay_state_synced:
	service_relay->pending_unsync = true;
	try_unsync_service(link, service_relay);
	break;
    case relay_state_unsyncing:
	break;
    default:
	assert(0);
    }

    adjust_max_idle_time(link);
}

static void uninstall_service_relays(struct link *link)
{
    struct service *service;
    LIST_FOREACH(service, &link->sd->services, entry)
	uninstall_service_relay(link, service->service_id);
}

static void install_sub_relay(struct link *link, int64_t sub_id)
{
    assert(link->state == link_state_operational);
    assert(!LIST_EXISTS(&link->sub_relays, obj_id, sub_id, entry));

    log_link_install_sub_relay(link, sub_id);

    struct relay *sub_relay = relay_create(sub_id);
    LIST_INSERT_HEAD(&link->sub_relays, sub_relay, entry);

    try_sync_sub(link, sub_relay);
}

static void install_sub_relays(struct link *link)
{
    struct sub *sub;
    LIST_FOREACH(sub, &link->sd->subs, entry)
	install_sub_relay(link, sub->sub_id);
}

static void uninstall_sub_relay(struct link *link, int64_t sub_id)
{
    struct relay *sub_relay =
	LIST_FIND(&link->sub_relays, obj_id, sub_id, entry);

    assert(sub_relay != NULL);

    log_link_uninstall_sub_relay(link, sub_id);

    switch (sub_relay->state) {
    case relay_state_unsynced:
	break;
    case relay_state_syncing:
	sub_relay->pending_unsync = true;
	break;
    case relay_state_synced:
	sub_relay->pending_unsync = true;
	try_unsync_sub(link, sub_relay);
	break;
    case relay_state_unsyncing:
	break;
    default:
	assert(0);
    }
}

static void clear_sub_relays(struct link *link)
{
    struct relay *sub_relay;
    while ((sub_relay = LIST_FIRST(&link->sub_relays)) != NULL) {
        LIST_REMOVE(sub_relay, entry);
        relay_destroy(sub_relay);
    }
}

static void clear_track(struct link *link)
{
    link->track_ta_id = -1;
    link->max_idle_time = conf_get_idle_max();
    link->track_query_ts = -1;
}

static void clear(struct link *link)
{
    clear_service_relays(link);
    clear_sub_relays(link);
    clear_tmos(link);
    clear_track(link);
}

static void service_changed(struct link *link, int64_t obj_id,
			    enum sd_change_type change_type)
{
    switch (change_type) {
    case sd_change_type_added:
	install_service_relay(link, obj_id);
	break;
    case sd_change_type_modified:
	update_service_relay(link, obj_id);
	break;
    case sd_change_type_removed:
	uninstall_service_relay(link, obj_id);
	break;
    default:
	assert(0);
    }

    adjust_max_idle_time(link);
}

static void sub_changed(struct link *link, int64_t obj_id,
			enum sd_change_type change_type)
{
    switch (change_type) {
    case sd_change_type_added:
	install_sub_relay(link, obj_id);
	break;
    case sd_change_type_removed:
	uninstall_sub_relay(link, obj_id);
	break;
    case sd_change_type_modified:
    default:
	assert(0);
    }
}

static void sd_changed_cb(enum sd_obj_type obj_type, int64_t obj_id,
			  enum sd_change_type change_type, void *user)
{
    struct link *link = user;

    log_link_sd_changed(link, sd_obj_type_str(obj_type),
			sd_change_type_str(change_type), obj_id);

    switch (obj_type) {
    case sd_obj_type_service:
	service_changed(link, obj_id, change_type);
	break;
    case sd_obj_type_sub:
	sub_changed(link, obj_id, change_type);
	break;
    default:
	assert(0);
    }
}

struct link *link_create(int64_t link_id, int64_t client_id,
			 const struct server_conf *server,
			 struct sd *sd, struct ptimer *timer,
			 int epoll_fd, const char *log_ref)
{
    assert(link_id >= 0 && client_id >= 0);

    char *link_log_ref = ut_asprintf("%s link: %"PRId64, log_ref, link_id);

    struct link *link = ut_malloc(sizeof(struct link));

    *link = (struct link) {
	.link_id = link_id,
	.client_id = client_id,
	.server = server_conf_clone(server),
	.state = link_state_detached,
	.sd = sd,
        .timer = timer,
	.reconnect_tmo = -1,
	.idle_tmo = -1,
	.track_ta_id = -1,
	.max_idle_time = conf_get_idle_max(),
	.track_query_ts = -1,
	.detached_tmo = -1,
	.log_ref = link_log_ref
    };

    LIST_INIT(&link->service_relays);
    LIST_INIT(&link->sub_relays);

    epoll_reg_init(&link->epoll_reg, epoll_fd, link_log_ref);

    log_link_start(link);

    link->state = link_state_connecting;

    link->reconnect_tmo = ptimer_schedule_rel(link->timer, 0);

    return link;
}

static void assure_reconnect_tmo(struct link *link)
{
    /* randomized expontial backoff */
    double reconnect_min = conf_get_reconnect_min();
    double reconnect_max = conf_get_reconnect_max();

    if (link->reconnect_time == 0)
	link->reconnect_time = reconnect_min * (1 + ut_frand());
    else
	link->reconnect_time *= 2;

    if (link->reconnect_time > reconnect_max)
	link->reconnect_time = reconnect_max;
    if (link->reconnect_time < reconnect_min)
	link->reconnect_time = reconnect_min;

    ptimer_reschedule_rel(link->timer, link->reconnect_time,
			  &link->reconnect_tmo);
}

static void handle_error(struct link *link)
{
    if (link->state != link_state_detaching)
	link->state = link_state_restarting;
    else
	link->state = link_state_detached;
}

static void try_connect(struct link *link)
{
    /* don't spam the server even though link_process() is being
       called in rapid succession */
    if (!ptimer_has_expired(link->timer, link->reconnect_tmo))
	return;

    ptimer_ack(link->timer, &link->reconnect_tmo);

    UT_SAVE_ERRNO;

    link->conn = conn_connect(link->server, link->client_id, link->log_ref);

    UT_RESTORE_ERRNO_DC;

    if (link->conn == NULL) {
	assure_reconnect_tmo(link);
	return;
    }

    epoll_reg_add(&link->epoll_reg, conn_get_fd(link->conn), EPOLLIN);

    ptimer_cancel(link->timer, &link->reconnect_tmo);

    set_state(link, link_state_greeting);

    conn_hello_nb(link->conn, fail_cb, hello_complete_cb, link);
}

static void restart(struct link *link)
{
    log_link_restart(link);

    epoll_reg_reset(&link->epoll_reg);

    untie_from_sd(link);

    if (link->conn != NULL) {
	conn_close(link->conn);
	link->conn = NULL;
    }

    clear(link);

    set_state(link, link_state_connecting);

    assure_reconnect_tmo(link);
}

static void check_idle(struct link *link)
{
    if (!is_tracking(link))
	return;

    if (!ptimer_has_expired(link->timer, link->idle_tmo))
	return;

    if (is_track_querying(link)) {
	log_link_query_timeout(link);
	handle_error(link);
    } else {
	conn_track_inform(link->conn, link->track_ta_id, true);
	link->track_query_ts = ut_ftime(CLOCK_MONOTONIC);
	schedule_idle_reply_tmo(link);
    }
}

static void try_sync_services(struct link *link)
{
    struct relay *relay;
    LIST_FOREACH(relay, &link->service_relays, entry)
	try_sync_service(link, relay);
}

static void try_unsync_services(struct link *link)
{
    struct relay *relay;
    LIST_FOREACH(relay, &link->service_relays, entry)
	try_unsync_service(link, relay);
}

static void try_sync_subs(struct link *link)
{
    struct relay *relay;
    LIST_FOREACH(relay, &link->sub_relays, entry)
	try_sync_sub(link, relay);
}

static void try_unsync_subs(struct link *link)
{
    struct relay *relay;
    LIST_FOREACH(relay, &link->sub_relays, entry)
	try_unsync_sub(link, relay);
}

int link_process(struct link *link)
{
    log_link_processing(link, link_state_str(link->state));

    if (link->state == link_state_connecting)
        try_connect(link);

    if (is_io_capable_state(link->state)) {
	size_t service_relay_count =
	    LIST_COUNT(&link->service_relays, entry);
	size_t sub_relay_count =
	    LIST_COUNT(&link->sub_relays, entry);
	log_link_service_count(link, service_relay_count);
	log_link_sub_count(link, sub_relay_count);

	if (conn_process(link->conn) < 0)
	    handle_error(link);
    }

    if (link->state == link_state_operational ||
	link->state == link_state_detaching) {
	size_t in_progress = count_syncing_unsyncing(link);
	log_link_syncing_unsyncing(link, in_progress);

	try_sync_services(link);
	try_sync_subs(link);

	try_unsync_services(link);
	try_unsync_subs(link);
    }

    if (link->state == link_state_operational)
	check_idle(link);

    if (link->state == link_state_detaching)
        try_finish_detach(link);

    if (link->state == link_state_restarting)
	restart(link);

    int rc = 0;

    if (link->state == link_state_detached)
        rc = LINK_ERR_DETACHED;

    return rc;
}

void link_detach(struct link *link)
{
    log_link_detaching(link);

    untie_from_sd(link);

    if (link->state == link_state_operational) {
        uninstall_service_relays(link);
        link->state = link_state_detaching;
	link->max_detach_time =
	    MAX_DETACH_TIME(LIST_COUNT(&link->service_relays, entry));
	link->detached_tmo =
	    ptimer_schedule_rel(link->timer, link->max_detach_time);
    } else {
	link->detached_tmo = ptimer_schedule_rel(link->timer, 0);
	link->state = link_state_detached;
	log_link_detached(link);
    }
}

void link_destroy(struct link *link)
{
    if (link != NULL) {
	epoll_reg_reset(&link->epoll_reg);

	untie_from_sd(link);

        if (link->conn != NULL)
            conn_close(link->conn);

	clear(link);
        log_link_destroy(link);
	ut_free(link->log_ref);
	server_conf_destroy(link->server);
        ut_free(link);
    }
}
