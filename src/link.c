/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#include <assert.h>
#include <string.h>
#include <time.h>

#include "conf.h"
#include "list.h"
#include "log_link.h"
#include "proto_ta.h"
#include "util.h"

#include "link.h"

#define SLABEL(name)				     \
    case link_state_ ## name:                        \
    return #name

static const char *link_state_str(enum link_state state)
{
    switch (state) {
        SLABEL(connecting);
        SLABEL(greeting);
        SLABEL(operational);
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
    ptimer_cancel(link->timer, &link->xcm_tmo);
    ptimer_cancel(link->timer, &link->detached_tmo);
}

static int64_t get_next_ta_id(struct link *link)
{
    return link->next_ta_id++;
}

static void rereg_xcm(struct link *link);

static void queue_request(struct link *link, struct msg *request)
{
    bool needs_rereg = TAILQ_EMPTY(&link->out_queue);

    TAILQ_INSERT_TAIL(&link->out_queue, request, entry);

    if (needs_rereg)
	rereg_xcm(link);
}

static void clear_queue(struct link *link)
{
    struct msg *out_msg;
    while ((out_msg = TAILQ_FIRST(&link->out_queue)) != NULL) {
        TAILQ_REMOVE(&link->out_queue, out_msg, entry);
        msg_free(out_msg);
    }
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

static void restart(struct link *link);

static void try_flush_queue(struct link *link)
{
    if (TAILQ_EMPTY(&link->out_queue))
	return;

    struct msg *out_msg;
    while ((out_msg = TAILQ_FIRST(&link->out_queue)) != NULL) {
        UT_SAVE_ERRNO;
        int rc = xcm_send(link->conn, out_msg->data, strlen(out_msg->data));
        UT_RESTORE_ERRNO(send_errno);

        if (rc < 0) {
            if (send_errno != EAGAIN)
                restart(link);
	    break;
        }

        log_link_request(link, out_msg->data);

        TAILQ_REMOVE(&link->out_queue, out_msg, entry);

        msg_free(out_msg);
    }

    rereg_xcm(link);
}

static void clear_tas(struct link *link)
{
    struct proto_ta *ta;
    while ((ta = LIST_FIRST(&link->transactions)) != NULL) {
        LIST_REMOVE(ta, entry);
        proto_ta_destroy(ta);
    }
}

static int translate_event(int xcm_event)
{
    int epoll_event = 0;
    if (xcm_event & XCM_FD_READABLE)
        epoll_event |= EPOLLIN;
    if (xcm_event & XCM_FD_WRITABLE)
        epoll_event |= EPOLLOUT;
    return epoll_event;
}

#define XCM_MAX_FDS (8)

static void rereg_xcm(struct link *link)
{
    epoll_reg_reset(&link->epoll_reg);

    switch(link->state) {
    case link_state_connecting:
	break;
    case link_state_greeting:
    case link_state_operational:
    case link_state_detaching: {
        int condition = XCM_SO_RECEIVABLE;
        if (!TAILQ_EMPTY(&link->out_queue))
            condition |= XCM_SO_SENDABLE;
        int fds[XCM_MAX_FDS];
        int events[XCM_MAX_FDS];

        UT_SAVE_ERRNO;
        int rc = xcm_want(link->conn, condition, fds, events, XCM_MAX_FDS);
        UT_RESTORE_ERRNO_DC;

        assert(rc >= 0);

        if (rc == 0)
	    ptimer_reinstall_rel(link->timer, 0, &link->xcm_tmo);
	else {
	    ptimer_cancel(link->timer, &link->xcm_tmo);
            int i;
            for (i = 0; i < rc; i++)
                epoll_reg_add(&link->epoll_reg, fds[i],
                              translate_event(events[i]));
        }
        break;
    }
    case link_state_detached:
        break;
    default:
	assert(0);
    }
}

#define MSG_MAX (65535)

static void try_read_incoming(struct link *link)
{
    char* buf = ut_malloc(MSG_MAX);
    for (;;) {
        UT_SAVE_ERRNO;
        int rc = xcm_receive(link->conn, buf, MSG_MAX);
        UT_RESTORE_ERRNO(receive_errno);

        if (rc == 0) {
            log_link_server_conn_eof(link);
            restart(link);
            break;
        } else if (rc < 0) {
            if (receive_errno == EAGAIN)
                break;
            else {
                log_link_server_conn_error(link, receive_errno);
                restart(link);
                break;
            }
        } else {
            struct msg *response = msg_create_buf(buf, rc);

	    log_link_response(link, response->data);

	    int rc = proto_ta_consume_response(&link->transactions, response,
                                               link->log_ref);
            if (rc < 0) {
                restart(link);
                break;
            }
        }
    }
    ut_free(buf);
}

static void try_finish_detach(struct link *link)
{
    size_t num_service_relays = LIST_COUNT(&link->service_relays, entry);

    if (num_service_relays == 0) {
	set_state(link, link_state_detached);
        log_link_detached(link);
    } else
        log_link_pending_unpublications(link, num_service_relays);

}

/* XXX: 1. relay -> obj_relay
 *      2. only store active relays
 */
static void install_service_relays(struct link *link);
static void install_sub_relays(struct link *link);
static void sd_changed_cb(enum sd_obj_type obj_type, int64_t obj_id,
			  enum sd_change_type change_type, void *user);

static void hello_response_cb(int64_t ta_id, enum proto_msg_type msg_type,
                              void **args, void **optargs, void *user)
{
    struct link *link = user;

    switch (msg_type) {
    case proto_msg_type_complete: {
        int64_t *proto_version = args[0];
        log_link_operational(link, *proto_version);
	set_state(link, link_state_operational);
	link->reconnect_time = 0;
	install_service_relays(link);
	install_sub_relays(link);
	link->listener = sd_add_listener(link->sd, sd_changed_cb, link);
        break;
    }
    case proto_msg_type_fail:
        log_link_ta_failure(link, ta_id, optargs[0]);
        restart(link);
        break;
    default:
        assert(0);
    }
}

static void sync_service(struct link *link, struct relay *service_relay);
static void unsync_service(struct link *link, struct relay *service_relay);

static void publish_response_cb(int64_t ta_id, enum proto_msg_type msg_type,
                                void **args, void **optargs, void *user)
{
    struct link *link = user;

    struct relay *service_relay =
	LIST_FIND(&link->service_relays, sync_ta_id, ta_id, entry);

    assert(service_relay != NULL);
    assert(service_relay->state == relay_state_syncing);

    switch (msg_type) {
    case proto_msg_type_complete: {
        log_link_service_synced(link, service_relay->obj_id);
        service_relay->state = relay_state_synced;
	service_relay->sync_ta_id = -1;
        if (service_relay->pending_unsync)
            unsync_service(link, service_relay);
	else if (service_relay->pending_sync)
            sync_service(link, service_relay);
        break;
    }
    case proto_msg_type_fail:
        log_link_ta_failure(link, ta_id, optargs[0]);
        restart(link);
        break;
    default:
        assert(0);
    }
}

static void sync_sub(struct link *link, struct relay *sub_relay);
static void unsync_sub(struct link *link, struct relay *sub_relay);

static void unpublish_response_cb(int64_t ta_id, enum proto_msg_type msg_type,
                                  void **args, void **optargs, void *user)
{
    struct link *link = user;

    switch (msg_type) {
    case proto_msg_type_complete: {
        struct relay *service_relay =
	    LIST_FIND(&link->service_relays, unsync_ta_id, ta_id, entry);
        log_link_service_unsynced(link, service_relay->obj_id);
	LIST_REMOVE(service_relay, entry);
	relay_destroy(service_relay);
        break;
    }
    case proto_msg_type_fail:
        log_link_ta_failure(link, ta_id, optargs[0]);
        restart(link);
        break;
    default:
        assert(0);
    }
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

static void subscribe_response_cb(int64_t ta_id, enum proto_msg_type msg_type,
                                  void **args, void **optargs, void *user)
{
    struct link *link = user;

    struct relay *sub_relay =
	LIST_FIND(&link->sub_relays, sync_ta_id, ta_id, entry);
    assert(sub_relay != NULL);

    switch (msg_type) {
    case proto_msg_type_accept: {
	assert(sub_relay->state == relay_state_syncing);

        log_link_sub_synced(link, sub_relay->obj_id);
        sub_relay->state = relay_state_synced;
        if (sub_relay->pending_unsync)
            unsync_sub(link, sub_relay);
        else if (sub_relay->pending_sync)
            sync_sub(link, sub_relay);
        break;
    }
    case proto_msg_type_notify: {
	assert(sub_relay->state == relay_state_synced ||
	       sub_relay->state == relay_state_unsyncing);

        const enum paf_match_type *server_match_type = args[0];
        const int64_t *service_id = args[1];

        const int64_t *generation = optargs[0];
        const struct paf_props *props = optargs[1];
        const int64_t *ttl = optargs[2];
        const double *orphan_since = optargs[3];

	log_link_sub_match(link, sub_relay->obj_id);

	if (sub_relay->state == relay_state_unsyncing ||
	    sub_relay->pending_unsync) {
	    log_link_sub_match_ignored(link);
	    break;
	}

	/* XXX: consider the implications of server producing
	   inconsistent subscription notifications */
        sd_report_match(link->sd, link->link_id, sub_relay->obj_id,
			*server_match_type, *service_id, generation,
			props, ttl, orphan_since);
        break;
    }
    case proto_msg_type_complete:
	sub_relay->sync_ta_id = -1;
	check_sub_relay_removal(link, sub_relay);
        break;
    case proto_msg_type_fail:
        log_link_ta_failure(link, ta_id, optargs[0]);
        restart(link);
        break;
    default:
        assert(0);
    }
}

static void unsubscribe_response_cb(int64_t ta_id, enum proto_msg_type msg_type,
                                    void **args, void **optargs, void *user)
{
    struct link *link = user;

    struct relay *sub_relay =
	LIST_FIND(&link->sub_relays, unsync_ta_id, ta_id, entry);
    assert(sub_relay != NULL);

    switch (msg_type) {
    case proto_msg_type_complete:
	sub_relay->unsync_ta_id = -1;
	check_sub_relay_removal(link, sub_relay);
        break;
    case proto_msg_type_fail:
        log_link_ta_failure(link, ta_id, optargs[0]);
        restart(link);
        break;
    default:
        assert(0);
    }
}

static void sync_service(struct link *link, struct relay *service_relay)
{
    assert(link->state == link_state_operational);
    assert(service_relay->state == relay_state_unsynced ||
           service_relay->state == relay_state_synced);

    service_relay->pending_sync = false;

    struct service *service = sd_get_service(link->sd, service_relay->obj_id);

    int64_t ta_id = get_next_ta_id(link);
    struct proto_ta *publish_ta =
        proto_ta_publish(ta_id, link->log_ref, publish_response_cb, link);
    LIST_INSERT_HEAD(&link->transactions, publish_ta, entry);
    struct msg *publish_request =
        proto_ta_produce_request(publish_ta, service->service_id,
				 service->generation, service->props,
				 service->ttl);
    queue_request(link, publish_request);
    service_relay->sync_ta_id = ta_id;

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

    int64_t ta_id = get_next_ta_id(link);
    struct proto_ta *unpublish_ta =
        proto_ta_unpublish(ta_id, link->log_ref, unpublish_response_cb,
                           link);
    LIST_INSERT_HEAD(&link->transactions, unpublish_ta, entry);
    struct msg *unpublish_request =
	proto_ta_produce_request(unpublish_ta, service_relay->obj_id);
    queue_request(link, unpublish_request);
    service_relay->unsync_ta_id = ta_id;

    log_link_service_unsync(link, service_relay->obj_id, ta_id);

    service_relay->state = relay_state_unsyncing;
}

static void sync_sub(struct link *link, struct relay *sub_relay)
{
    assert(link->state == link_state_operational);
    assert(sub_relay->state == relay_state_unsynced);

    struct sub *sub = sd_get_sub(link->sd, sub_relay->obj_id);

    sub_relay->sync_ta_id = get_next_ta_id(link);
    struct proto_ta *subscribe_ta =
        proto_ta_subscribe(sub_relay->sync_ta_id, link->log_ref,
			   subscribe_response_cb, link);
    LIST_INSERT_HEAD(&link->transactions, subscribe_ta, entry);
    struct msg *subscribe_request =
        proto_ta_produce_request(subscribe_ta, sub->sub_id, sub->filter_str);
    queue_request(link, subscribe_request);

    log_link_sub_sync(link, sub_relay->obj_id, sub_relay->sync_ta_id);

    sub_relay->state = relay_state_syncing;
}

static void unsync_sub(struct link *link, struct relay *sub_relay)
{
    assert(link->state == link_state_operational ||
	   link->state == link_state_detaching);
    assert(sub_relay->state == relay_state_synced);

    sub_relay->unsync_ta_id = get_next_ta_id(link);
    struct proto_ta *unsubscribe_ta =
        proto_ta_unsubscribe(sub_relay->unsync_ta_id, link->log_ref,
			     unsubscribe_response_cb, link);
    LIST_INSERT_HEAD(&link->transactions, unsubscribe_ta, entry);
    struct msg *unsubscribe_request =
        proto_ta_produce_request(unsubscribe_ta, sub_relay->obj_id);
    queue_request(link, unsubscribe_request);

    log_link_sub_unsync(link, sub_relay->obj_id, sub_relay->unsync_ta_id);

    sub_relay->state = relay_state_unsyncing;
}

static void install_service_relay(struct link *link, int64_t service_id)
{
    assert(link->state == link_state_operational);
    assert(!LIST_EXISTS(&link->service_relays, obj_id, service_id,
			entry));

    log_link_install_service_relay(link, service_id);

    struct relay *service_relay = relay_create(service_id);
    LIST_INSERT_HEAD(&link->service_relays, service_relay, entry);

    sync_service(link, service_relay);
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
    assert(link->state == link_state_operational);

    struct relay *service_relay =
	LIST_FIND(&link->service_relays, obj_id, service_id, entry);

    assert(service_relay != NULL);
    assert(!service_relay->pending_unsync);

    log_link_update_service_relay(link, service_id);

    switch (service_relay->state) {
    case relay_state_synced:
	sync_service(link, service_relay);
	break;
    case relay_state_syncing:
	service_relay->pending_sync = true;
	break;
    case relay_state_unsynced:
    case relay_state_unsyncing:
    default:
	assert(0);
    }
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
    case relay_state_synced:
	if (!service_relay->pending_unsync)
	    unsync_service(link, service_relay);
	break;
    case relay_state_syncing:
	service_relay->pending_unsync = true;
	break;
    case relay_state_unsyncing:
	break;
    case relay_state_unsynced:
    default:
	assert(0);
    }
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

    sync_sub(link, sub_relay);
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
    case relay_state_synced:
	if (!sub_relay->pending_unsync)
	    unsync_sub(link, sub_relay);
	break;
    case relay_state_syncing:
	sub_relay->pending_unsync = true;
	break;
    case relay_state_unsyncing:
	break;
    case relay_state_unsynced:
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

static void clear(struct link *link)
{
    clear_queue(link);
    clear_tas(link);
    clear_service_relays(link);
    clear_sub_relays(link);
    clear_tmos(link);
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
			 const char *domain_addr,
			 struct sd *sd, struct ptimer *timer,
			 int epoll_fd, const char *log_ref)
{
    assert(link_id >= 0 && client_id >= 0);

    char *link_log_ref = ut_asprintf("%s link: %"PRId64, log_ref, link_id);

    struct link *link = ut_malloc(sizeof(struct link));

    *link = (struct link) {
	.link_id = link_id,
	.client_id = client_id,
	.domain_addr = ut_strdup(domain_addr),
	.state = link_state_detached,
	.sd = sd,
        .timer = timer,
	.reconnect_tmo = -1,
	.xcm_tmo = -1,
	.detached_tmo = -1,
	.log_ref = link_log_ref
    };

    LIST_INIT(&link->service_relays);
    LIST_INIT(&link->sub_relays);

    epoll_reg_init(&link->epoll_reg, epoll_fd, link_log_ref);

    TAILQ_INIT(&link->out_queue);
    LIST_INIT(&link->transactions);

    log_link_start(link, domain_addr);

    link->state = link_state_connecting;

    link->reconnect_tmo = ptimer_install_rel(link->timer, 0);

    rereg_xcm(link);

    return link;
}

static void reinstall_reconnect_tmo(struct link *link)
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
    
    ptimer_reinstall_rel(link->timer, link->reconnect_time,
			 &link->reconnect_tmo);
}

static void restart(struct link *link)
{
    log_link_restart(link, domain_addr);

    epoll_reg_reset(&link->epoll_reg);

    untie_from_sd(link);

    if (link->conn != NULL) {
	xcm_close(link->conn);
	link->conn = NULL;
    }

    clear(link);

    set_state(link, link_state_connecting);

    reinstall_reconnect_tmo(link);

    rereg_xcm(link);
}

static void try_connect(struct link *link)
{
    /* don't spam the server even though link_process() is being
       called in rapid succession */
    if (!ptimer_has_expired(link->timer, link->reconnect_tmo))
	return;

    ptimer_ack(link->timer, &link->reconnect_tmo);

    UT_SAVE_ERRNO;
    link->conn = xcm_connect(link->domain_addr, XCM_NONBLOCK);
    UT_RESTORE_ERRNO(connect_errno);

    if (link->conn == NULL) {
        log_link_xcm_connect_failed(link, link->domain_addr, connect_errno);
	reinstall_reconnect_tmo(link);
	return;
    }

    log_link_xcm_connected(link, link->domain_addr, xcm_local_addr(link->conn));

    ptimer_cancel(link->timer, &link->reconnect_tmo);

    set_state(link, link_state_greeting);

    struct proto_ta *hello_ta = proto_ta_hello(get_next_ta_id(link),
                                               link->log_ref,
                                               hello_response_cb, link);
    LIST_INSERT_HEAD(&link->transactions, hello_ta, entry);
    struct msg *hello_request =
        proto_ta_produce_request(hello_ta, link->client_id, PROTO_VERSION,
				 PROTO_VERSION);
    queue_request(link, hello_request);
}

int link_process(struct link *link)
{
    log_link_processing(link, link_state_str(link->state));

    if (link->state == link_state_connecting)
        try_connect(link);

    if (link->state == link_state_greeting ||
	link->state == link_state_operational ||
        link->state == link_state_detaching) {
	size_t ta_count =
	    LIST_COUNT(&link->transactions, entry);
	size_t service_relay_count =
	    LIST_COUNT(&link->service_relays, entry);
	size_t sub_relay_count =
	    LIST_COUNT(&link->sub_relays, entry);
	log_link_ongoing_ta(link, ta_count);
	log_link_service_count(link, service_relay_count);
	log_link_sub_count(link, sub_relay_count);

        try_flush_queue(link);
    }

    if (link->state == link_state_greeting ||
        link->state == link_state_operational ||
        link->state == link_state_detaching)
        try_read_incoming(link);

    if (link->state == link_state_detaching)
        try_finish_detach(link);

    int rc = 0;

    if (link->state == link_state_detached)
        rc = LINK_ERR_DETACHED;

    rereg_xcm(link);

    return rc;
}

void link_detach(struct link *link)
{
    log_link_detaching(link);

    untie_from_sd(link);

    if (link->state == link_state_operational) {
        uninstall_service_relays(link);
        link->state = link_state_detaching;
    } else {
	log_link_detached(link);
        link->state = link_state_detached;
	ptimer_reinstall_rel(link->timer, 0, &link->detached_tmo);
    }

    rereg_xcm(link);
}

void link_destroy(struct link *link)
{
    if (link != NULL) {
	epoll_reg_reset(&link->epoll_reg);

	untie_from_sd(link);

        if (link->conn != NULL)
            xcm_close(link->conn);

	clear(link);
        log_link_destroy(link);
	ut_free(link->log_ref);
	ut_free(link->domain_addr);
        ut_free(link);
    }
}
