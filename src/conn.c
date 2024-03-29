/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Ericsson AB
 */

#include <assert.h>
#include <poll.h>
#include <string.h>
#include <xcm.h>
#include <xcm_attr.h>
#include <xcm_version.h>

#include "list.h"
#include "log_conn.h"
#include "proto_ta.h"
#include "util.h"

#include "conn.h"

typedef void (*any_cb)();

struct call
{
    struct proto_ta *proto_ta;
    any_cb fail_cb;
    any_cb accept_cb;
    any_cb notify_cb;
    any_cb complete_cb;
    void *cb_data;
    LIST_ENTRY(call) entry;
};

LIST_HEAD(call_list, call);

static struct call *call_mr_create(struct proto_ta *proto_ta,
				   any_cb fail_cb, any_cb accept_cb,
				   any_cb notify_cb, any_cb complete_cb,
				   void *cb_data)
{
    struct call *call = ut_malloc(sizeof(struct call));

    *call = (struct call) {
	.proto_ta = proto_ta,
	.fail_cb = fail_cb,
	.accept_cb = accept_cb,
	.notify_cb = notify_cb,
	.complete_cb = complete_cb,
	.cb_data = cb_data
    };

    return call;
}

static struct call *call_sr_create(struct proto_ta *proto_ta,
				   any_cb fail_cb, any_cb complete_cb,
				   void *cb_data)
{
    return call_mr_create(proto_ta, fail_cb, NULL, NULL, complete_cb, cb_data);
}

static void call_destroy(struct call *call)
{
    ut_free(call);
}

struct conn
{
    struct xcm_socket *sock;

    int64_t proto_version_min;
    int64_t proto_version_max;

    int64_t client_id;
    int64_t proto_version;

    int64_t next_ta_id;

    /* XXX: it's strange to have two lists */
    struct call_list calls;
    struct proto_ta_list transactions;

    struct msg_queue out_queue;

    char *log_ref;
};

static bool is_tcp_based(const char *addr)
{
    const char *tls_based_protos[] = { "tcp", "tls", "utls" };

    size_t i;
    for (i = 0; i < UT_ARRAY_LEN(tls_based_protos); i++) {
	const char *proto = tls_based_protos[i];

	if (strncmp(proto, addr, strlen(proto)) == 0)
	    return true;
    }

    return false;
}

static void add_non_null(struct xcm_attr_map *attrs,
			 const char *attr_name,
			 const char *attr_value)
{
    if (attr_value != NULL)
	xcm_attr_map_add_str(attrs, attr_name, attr_value);
}

static void consider_adding_dns_attrs(const char *addr,
				      struct xcm_attr_map *attrs)
{
    bool supports_dns_algorithm_attr =
	xcm_version_api_major() >= 1 || xcm_version_api_minor() >= 24;

    if (supports_dns_algorithm_attr && is_tcp_based(addr))
	xcm_attr_map_add_str(attrs, "dns.algorithm", "happy_eyeballs");
}

static struct xcm_socket *connect_xcm(const struct server_conf *server)
{
    struct xcm_attr_map *attrs = xcm_attr_map_create();

    xcm_attr_map_add_bool(attrs, "xcm.blocking", false);

    consider_adding_dns_attrs(server->addr, attrs);

    add_non_null(attrs, "xcm.local_addr", server->local_addr);

    add_non_null(attrs, "tls.cert_file", server->cert_file);
    add_non_null(attrs, "tls.key_file", server->key_file);
    add_non_null(attrs, "tls.tc_file", server->tc_file);

    if (server->crl_file != NULL)  {
	xcm_attr_map_add_bool(attrs, "tls.check_crl", true);
	xcm_attr_map_add_str(attrs, "tls.crl_file", server->crl_file);
    }

    struct xcm_socket *sock = xcm_connect_a(server->addr, attrs);

    xcm_attr_map_destroy(attrs);

    return sock;
}

static void await(struct xcm_socket *conn, int condition)
{
    int rc = xcm_await(conn, condition);

    /* only reason for xcm_await() failure is EINVAL -> internal error */
    assert(rc >= 0);
}

static int set_proto_range(struct conn* conn, int64_t configured_min,
			   int64_t configured_max)
{
    if (configured_min >= 0) {
	if (configured_min > PROTO_MAX_VERSION) {
	    log_conn_proto_min_version_too_large(conn, configured_min,
						 PROTO_MAX_VERSION);
	    return -1;
	}
	conn->proto_version_min = UT_MAX(PROTO_MIN_VERSION, configured_min);
    } else
	conn->proto_version_min = PROTO_MIN_VERSION;

    if (configured_max >= 0) {
	if (configured_max < PROTO_MIN_VERSION) {
	    log_conn_proto_max_version_too_small(conn, configured_max,
						 PROTO_MIN_VERSION);
	    return -1;
	}
	conn->proto_version_max = UT_MIN(PROTO_MAX_VERSION, configured_max);
    } else
	conn->proto_version_max = PROTO_MAX_VERSION;

    log_conn_proto_version_range(conn, conn->proto_version_min,
				 conn->proto_version_max);

    return 0;
}

struct conn *conn_connect(const struct server_conf *server_conf,
			  int64_t client_id, const char *log_ref)
{
    struct conn *conn = ut_malloc(sizeof(struct conn));

    assert(client_id >= 0);

    *conn = (struct conn) {
	.client_id = client_id,
	.proto_version = -1,
	.log_ref = ut_strdup_non_null(log_ref)
    };

    LIST_INIT(&conn->calls);
    LIST_INIT(&conn->transactions);
    TAILQ_INIT(&conn->out_queue);

    log_conn_connect(conn, server_conf->addr);

    if (set_proto_range(conn, server_conf->proto_version_min,
			server_conf->proto_version_max) < 0)
	goto err_free;

    int old_ns_fd = -1;

    if (server_conf->net_ns != NULL) {
	old_ns_fd = ut_net_ns_enter(server_conf->net_ns);

	if (old_ns_fd < 0) {
	    log_conn_net_ns_enter_failed(conn, server_conf->net_ns, errno);
	    goto err_close;
	}

	log_conn_net_ns_entered(conn, server_conf->net_ns);
    }

    conn->sock = connect_xcm(server_conf);

    if (conn->sock == NULL) {
	log_conn_connect_failed(conn, errno);
	goto err_switch_back;
    }

    await(conn->sock, XCM_SO_RECEIVABLE);

    if (old_ns_fd != -1) {
	int rc = ut_net_ns_return(old_ns_fd);

	if (rc < 0) {
	    log_conn_net_ns_return_failed(conn, server_conf->net_ns, errno);
	    goto err_close;
	}

	log_conn_net_ns_returned(conn, server_conf->net_ns);
    }

    return conn;

err_switch_back:
    if (old_ns_fd >= 0)
	ut_net_ns_return(old_ns_fd);
err_close:
    xcm_close(conn->sock);
err_free:
    ut_free(conn->log_ref);
    ut_free(conn);

    return NULL;
}

void conn_close(struct conn *conn)
{
    if (conn != NULL) {
	log_conn_close(conn);

	xcm_close(conn->sock);

	struct call *call;
	while ((call = LIST_FIRST(&conn->calls)) != NULL) {
	    LIST_REMOVE(call, entry);
	    call_destroy(call);
	}

	struct proto_ta *ta;
	while ((ta = LIST_FIRST(&conn->transactions)) != NULL) {
	    LIST_REMOVE(ta, entry);
	    proto_ta_destroy(ta);
	}

	struct msg *out_msg;
	while ((out_msg = TAILQ_FIRST(&conn->out_queue)) != NULL) {
	    TAILQ_REMOVE(&conn->out_queue, out_msg, entry);
	    msg_free(out_msg);
	}

	ut_free(conn->log_ref);

	ut_free(conn);
    }
}

int64_t conn_get_client_id(const struct conn *conn)
{
    return conn->client_id;
}

int64_t conn_get_proto_version(const struct conn *conn)
{
    return conn->proto_version;
}

const char *conn_get_local_addr(const struct conn *conn)
{
    return xcm_local_addr(conn->sock);
}

static int64_t get_next_ta_id(struct conn *conn)
{
    return conn->next_ta_id++;
}

static void out_queue_append(struct conn *conn, struct msg *msg)
{
    bool was_empty = TAILQ_EMPTY(&conn->out_queue);

    TAILQ_INSERT_TAIL(&conn->out_queue, msg, entry);

    if (was_empty)
	await(conn->sock, XCM_SO_SENDABLE|XCM_SO_RECEIVABLE);
}

static void end_call(struct call *call)
{
    LIST_REMOVE(call, entry);
    call_destroy(call);
}

static struct call *find_call(struct conn *conn, int64_t ta_id)
{
    struct call *call;

    LIST_FOREACH(call, &conn->calls, entry)
	if (call->proto_ta->ta_id == ta_id)
	    return call;

    return NULL;
}

static void consider_ending_call(struct call *call,
				 enum proto_msg_type msg_type)
{
    switch (msg_type) {
    case proto_msg_type_fail:
    case proto_msg_type_complete:
	end_call(call);
    default:
	;
    }
}

static int fail_reason_to_err(const char *fail_reason);

static void std_sr_response(int64_t ta_id, enum proto_msg_type msg_type,
			    void **optargs, struct conn *conn,
			    struct call *call)
{
    switch (msg_type) {
    case proto_msg_type_complete: {
	conn_ta_cb cb = (conn_ta_cb)call->complete_cb;
	cb(call->proto_ta->ta_id, call->cb_data);
        break;
    }
    case proto_msg_type_fail: {
	const char *fail_reason = optargs[0];

        log_conn_ta_failure(conn, ta_id, fail_reason);

	conn_fail_cb cb = (conn_fail_cb)call->fail_cb;

	int err = fail_reason != NULL ? fail_reason_to_err(fail_reason) :
	    CONN_ERR_UNKNOWN;

	cb(call->proto_ta->ta_id, err, call->cb_data);

        break;
    }
    default:
        assert(0);
    }

    consider_ending_call(call, msg_type);
}

static void std_mr_response(int64_t ta_id, enum proto_msg_type msg_type,
			    void **optargs, struct conn *conn,
			    struct call *call)
{
    if (msg_type == proto_msg_type_accept) {
	conn_ta_cb cb = (conn_ta_cb)call->accept_cb;
	if (cb != NULL)
	    cb(call->proto_ta->ta_id, call->cb_data);
    } else
	std_sr_response(ta_id, msg_type, optargs, conn, call);
}

static void disable_tcp_keepalive(struct conn *conn)
{
    UT_SAVE_ERRNO;
    const char *addr = xcm_local_addr(conn->sock);
    if (addr != NULL && is_tcp_based(addr)) {
	if (xcm_attr_set_bool(conn->sock, "tcp.keepalive", false) < 0)
	    log_conn_failed_to_disable_tcp_keepalive(conn, errno);
	else
	    log_conn_disabled_tcp_keepalive(conn, errno);
    }
    UT_RESTORE_ERRNO_DC;
}

static void hello_response_cb(int64_t ta_id, enum proto_msg_type msg_type,
                              void **args, void **optargs,
			      void *cb_data)
{
    struct conn *conn = cb_data;
    struct call *call = find_call(conn, ta_id);

    if (msg_type == proto_msg_type_complete) {
	conn_hello_complete_cb cb = (conn_hello_complete_cb)call->complete_cb;
        const int64_t *proto_version = args[0];

	conn->proto_version = *proto_version;

	if (conn_is_track_supported(conn))
	    disable_tcp_keepalive(conn);

	cb(call->proto_ta->ta_id, *proto_version, call->cb_data);

	end_call(call);
    } else
	std_sr_response(ta_id, msg_type, optargs, conn, call);
}

int64_t conn_hello_nb(struct conn *conn, conn_fail_cb fail_cb,
		      conn_hello_complete_cb complete_cb, void *cb_data)
{
    int64_t ta_id = get_next_ta_id(conn);

    struct proto_ta *hello_ta =
	proto_ta_hello(ta_id, conn->log_ref, hello_response_cb, conn);

    struct call *hello_call =
	call_sr_create(hello_ta, (any_cb)fail_cb, (any_cb)complete_cb,
		       cb_data);

    LIST_INSERT_HEAD(&conn->calls, hello_call, entry);
    LIST_INSERT_HEAD(&conn->transactions, hello_ta, entry);

    struct msg *hello_request =
        proto_ta_produce_request(hello_ta, conn->client_id,
				 conn->proto_version_min,
				 conn->proto_version_max);

    out_queue_append(conn, hello_request);

    return ta_id;
}

static int wait_for_event(struct conn *conn)
{
    int fd = conn_get_fd(conn);

    struct pollfd pollfd = {
	.fd = fd,
	.events = POLLIN
    };

    int rc;

    while ((rc = poll(&pollfd, 1, -1)) < 0 && errno == EINTR)
	;

    return rc;
}

struct result
{
    bool done;
    int rc;
};

struct hello_result
{
    struct result result;
    int64_t proto_version;
};

static void fail_cb(int64_t ta_id UT_UNUSED, int fail_reason, void *cb_data)
{
    struct result *result = cb_data;

    result->done = true;
    result->rc = fail_reason;
}

static void complete_cb(int64_t ta_id UT_UNUSED,
			void *cb_data)
{
    struct result *result = cb_data;

    result->done = true;
    result->rc = 0;
}

static void hello_complete_cb(int64_t ta_id UT_UNUSED, int64_t proto_version,
			      void *cb_data)
{
    struct hello_result *result = cb_data;

    complete_cb(ta_id, cb_data);

    result->proto_version = proto_version;
}

static void wait_until_done(struct conn *conn, struct result *result)
{
    if (result->done)
	return;

    *result = (struct result) {
	.rc = CONN_ERR_UNSPEC
    };

    for (;;) {
	if (conn_process(conn) < 0)
	    break;

	if (result->done)
	    break;

	if (wait_for_event(conn) < 0)
	    break;
    }
}

int conn_hello(struct conn *conn, int64_t *proto_version)
{
    struct hello_result result = {};

    conn_hello_nb(conn, fail_cb, hello_complete_cb, &result);

    wait_until_done(conn, &result.result);

    if (result.result.rc == 0 && proto_version != NULL)
	*proto_version = result.proto_version;

    return result.result.rc;
}

static void track_response_cb(int64_t ta_id, enum proto_msg_type msg_type,
			      void **args, void **optargs, void *cb_data)
{
    struct conn *conn = cb_data;
    struct call *call = find_call(conn, ta_id);

    if (msg_type == proto_msg_type_notify) {
        const bool *is_query = args[0];

	conn_track_notify_cb cb = (conn_track_notify_cb)call->notify_cb;

	cb(call->proto_ta->ta_id, *is_query, call->cb_data);
    } else
	std_mr_response(ta_id, msg_type, optargs, conn, call);
}

int64_t conn_track_nb(struct conn *conn, conn_fail_cb fail_cb,
		      conn_ta_cb accept_cb, conn_track_notify_cb notify_cb,
		      conn_ta_cb complete_cb, void *cb_data)
{
    int64_t ta_id = get_next_ta_id(conn);

    struct proto_ta *track_ta =
	proto_ta_track(ta_id, conn->log_ref, track_response_cb, conn);

    struct call *track_call =
	call_mr_create(track_ta, (any_cb)fail_cb, (any_cb)accept_cb,
		       (any_cb)notify_cb, (any_cb)complete_cb, cb_data);

    LIST_INSERT_HEAD(&conn->calls, track_call, entry);
    LIST_INSERT_HEAD(&conn->transactions, track_ta, entry);

    struct msg *track_request = proto_ta_produce_request(track_ta);

    out_queue_append(conn, track_request);

    return ta_id;
}

void conn_track_inform(struct conn *conn, int64_t ta_id, bool is_query)
{
    struct call *call = find_call(conn, ta_id);

    struct msg *track_inform =
        proto_ta_produce_inform(call->proto_ta, &is_query);

    out_queue_append(conn, track_inform);
}

bool conn_is_track_supported(struct conn *conn)
{
    return conn->proto_version >= 3;
}

static void subscribe_response_cb(int64_t ta_id, enum proto_msg_type msg_type,
				  void **args, void **optargs, void *cb_data)
{
    struct conn *conn = cb_data;
    struct call *call = find_call(conn, ta_id);

    if (msg_type == proto_msg_type_notify) {
        const enum paf_match_type *match_type = args[0];
        const int64_t *service_id = args[1];

        const int64_t *generation = optargs[0];
        const struct paf_props *props = optargs[1];
        const int64_t *ttl = optargs[2];
        const double *orphan_since = optargs[3];

	conn_subscribe_notify_cb cb =
	    (conn_subscribe_notify_cb)call->notify_cb;

	cb(call->proto_ta->ta_id, *match_type, *service_id, generation, props,
	   ttl, orphan_since, call->cb_data);
    } else
	std_mr_response(ta_id, msg_type, optargs, conn, call);
}

int64_t conn_subscribe_nb(struct conn *conn, int64_t sub_id,
			  const char *filter, conn_fail_cb fail_cb,
			  conn_ta_cb accept_cb,
			  conn_subscribe_notify_cb notify_cb,
			  conn_ta_cb complete_cb, void *cb_data)
{
    int64_t ta_id = get_next_ta_id(conn);

    struct proto_ta *subscribe_ta =
	proto_ta_subscribe(ta_id, conn->log_ref, subscribe_response_cb, conn);

    struct call *subscribe_call =
	call_mr_create(subscribe_ta, (any_cb)fail_cb, (any_cb)accept_cb,
		       (any_cb)notify_cb, (any_cb)complete_cb, cb_data);

    LIST_INSERT_HEAD(&conn->calls, subscribe_call, entry);
    LIST_INSERT_HEAD(&conn->transactions, subscribe_ta, entry);

    struct msg *subscribe_request =
        proto_ta_produce_request(subscribe_ta, sub_id, filter);

    out_queue_append(conn, subscribe_request);

    return ta_id;
}

static void unsubscribe_response_cb(int64_t ta_id, enum proto_msg_type msg_type,
				    void **args UT_UNUSED, void **optargs,
				    void *cb_data)
{
    struct conn *conn = cb_data;
    struct call *call = find_call(conn, ta_id);

    std_sr_response(ta_id, msg_type, optargs, conn, call);
}

int64_t conn_unsubscribe_nb(struct conn *conn, int64_t sub_id,
			    conn_fail_cb fail_cb, conn_ta_cb complete_cb,
			    void *cb_data)
{
    int64_t ta_id = get_next_ta_id(conn);

    struct proto_ta *unsubscribe_ta =
	proto_ta_unsubscribe(ta_id, conn->log_ref, unsubscribe_response_cb,
			     conn);

    struct call *unsubscribe_call =
	call_sr_create(unsubscribe_ta, (any_cb)fail_cb, (any_cb)complete_cb,
		       cb_data);

    LIST_INSERT_HEAD(&conn->calls, unsubscribe_call, entry);
    LIST_INSERT_HEAD(&conn->transactions, unsubscribe_ta, entry);

    struct msg *unsubscribe_request =
        proto_ta_produce_request(unsubscribe_ta, sub_id);

    out_queue_append(conn, unsubscribe_request);

    return ta_id;
}

int conn_unsubscribe(struct conn *conn, int64_t sub_id)
{
    struct result result = {};

    conn_unsubscribe_nb(conn, sub_id, fail_cb, complete_cb, &result);

    wait_until_done(conn, &result);

    return result.rc;
}

static void subscriptions_response_cb(int64_t ta_id, enum proto_msg_type msg_type,
				 void **args, void **optargs, void *cb_data)
{
    struct conn *conn = cb_data;
    struct call *call = find_call(conn, ta_id);

    if (msg_type ==  proto_msg_type_notify) {
        const int64_t *sub_id = args[0];
        const int64_t *client_id = args[1];
        const char *filter = optargs[0];

	conn_subscriptions_notify_cb cb =
	    (conn_subscriptions_notify_cb)call->notify_cb;

	cb(call->proto_ta->ta_id, *sub_id, *client_id, filter, call->cb_data);
    } else
	std_mr_response(ta_id, msg_type, optargs, conn, call);
}

int64_t conn_subscriptions_nb(struct conn *conn, conn_fail_cb fail_cb,
			      conn_ta_cb accept_cb,
			      conn_subscriptions_notify_cb notify_cb,
			      conn_ta_cb complete_cb, void *cb_data)
{
    int64_t ta_id = get_next_ta_id(conn);

    struct proto_ta *subscriptions_ta =
	proto_ta_subscriptions(ta_id, conn->log_ref, subscriptions_response_cb,
			       conn);

    struct call *subscriptions_call =
	call_mr_create(subscriptions_ta, (any_cb)fail_cb, (any_cb)accept_cb,
		       (any_cb)notify_cb, (any_cb)complete_cb, cb_data);

    LIST_INSERT_HEAD(&conn->calls, subscriptions_call, entry);
    LIST_INSERT_HEAD(&conn->transactions, subscriptions_ta, entry);

    struct msg *subscriptions_request =
	proto_ta_produce_request(subscriptions_ta);

    out_queue_append(conn, subscriptions_request);

    return ta_id;
}

struct subscriptions_result
{
    struct result result;
    conn_subscriptions_cb user_cb;
    void *user_cb_data;
};

static void subscriptions_notify_forward_cb(int64_t ta_id UT_UNUSED,
					    int64_t sub_id,
					    int64_t client_id,
					    const char *filter,
					    void *cb_data)
{
    struct subscriptions_result *result = cb_data;
    result->user_cb(sub_id, client_id, filter, result->user_cb_data);
}

int conn_subscriptions(struct conn *conn, conn_subscriptions_cb cb,
		       void *cb_data)
{
    struct subscriptions_result result = {
	.user_cb = cb,
	.user_cb_data = cb_data
    };

    conn_subscriptions_nb(conn, fail_cb, NULL, subscriptions_notify_forward_cb,
			  complete_cb, &result);

    wait_until_done(conn, &result.result);

    return result.result.rc;
}

static void services_response_cb(int64_t ta_id, enum proto_msg_type msg_type,
				 void **args, void **optargs, void *cb_data)
{
    struct conn *conn = cb_data;
    struct call *call = find_call(conn, ta_id);

    if (msg_type ==  proto_msg_type_notify) {
        const int64_t *service_id = args[0];
        const int64_t *generation = args[1];
        const struct paf_props *props = args[2];
        const int64_t *ttl = args[3];
	const int64_t *client_id = args[4];
        const double *orphan_since = optargs[0];

	conn_services_notify_cb cb =
	    (conn_services_notify_cb)call->notify_cb;

	cb(call->proto_ta->ta_id, *service_id, *generation, props,
	   *ttl, *client_id, orphan_since, call->cb_data);
    } else
	std_mr_response(ta_id, msg_type, optargs, conn, call);
}

int64_t conn_services_nb(struct conn *conn, const char *filter,
			      conn_fail_cb fail_cb,
			      conn_ta_cb accept_cb,
			      conn_services_notify_cb notify_cb,
			      conn_ta_cb complete_cb, void *cb_data)
{
    int64_t ta_id = get_next_ta_id(conn);

    struct proto_ta *services_ta =
	proto_ta_services(ta_id, conn->log_ref, services_response_cb,
			       conn);

    struct call *services_call =
	call_mr_create(services_ta, (any_cb)fail_cb, (any_cb)accept_cb,
		       (any_cb)notify_cb, (any_cb)complete_cb, cb_data);

    LIST_INSERT_HEAD(&conn->calls, services_call, entry);
    LIST_INSERT_HEAD(&conn->transactions, services_ta, entry);

    struct msg *services_request =
	proto_ta_produce_request(services_ta, filter);

    out_queue_append(conn, services_request);

    return ta_id;
}

struct services_result
{
    struct result result;
    conn_services_cb user_cb;
    void *user_cb_data;
};

static void services_notify_forward_cb(int64_t ta_id UT_UNUSED,
				       int64_t service_id,
				       int64_t generation,
				       const struct paf_props *props,
				       int64_t ttl, int64_t client_id,
				       const double *orphan_since,
				       void *cb_data)
{
    struct services_result *result = cb_data;
    result->user_cb(service_id, generation, props, ttl, client_id,
		    orphan_since, result->user_cb_data);
}

int conn_services(struct conn *conn, const char *filter, conn_services_cb cb,
		  void *cb_data)
{
    struct services_result result = {
	.user_cb = cb,
	.user_cb_data = cb_data
    };

    conn_services_nb(conn, filter, fail_cb, NULL, services_notify_forward_cb,
		    complete_cb, &result);

    wait_until_done(conn, &result.result);

    return result.result.rc;
}

static void publish_response_cb(int64_t ta_id, enum proto_msg_type msg_type,
				    void **args UT_UNUSED, void **optargs,
				    void *cb_data)
{
    struct conn *conn = cb_data;
    struct call *call = find_call(conn, ta_id);

    std_sr_response(ta_id, msg_type, optargs, conn, call);
}

int64_t conn_publish_nb(struct conn *conn, int64_t service_id,
			int64_t generation, const struct paf_props *props,
			int64_t ttl, conn_fail_cb fail_cb,
			conn_ta_cb complete_cb, void *cb_data)
{
    int64_t ta_id = get_next_ta_id(conn);

    struct proto_ta *publish_ta =
	proto_ta_publish(ta_id, conn->log_ref, publish_response_cb,  conn);

    struct call *publish_call =
	call_sr_create(publish_ta, (any_cb)fail_cb, (any_cb)complete_cb,
		       cb_data);

    LIST_INSERT_HEAD(&conn->calls, publish_call, entry);
    LIST_INSERT_HEAD(&conn->transactions, publish_ta, entry);

    struct msg *publish_request =
        proto_ta_produce_request(publish_ta, service_id, generation, props,
				 ttl);

    out_queue_append(conn, publish_request);

    return ta_id;
}

int conn_publish(struct conn *conn, int64_t service_id,	int64_t generation,
		 const struct paf_props *props, int64_t ttl)
{
    struct result result = {};

    conn_publish_nb(conn, service_id, generation, props, ttl, fail_cb,
		    complete_cb, &result);

    wait_until_done(conn, &result);

    return result.rc;
}

static void unpublish_response_cb(int64_t ta_id, enum proto_msg_type msg_type,
				  void **args UT_UNUSED, void **optargs,
				  void *cb_data)
{
    struct conn *conn = cb_data;
    struct call *call = find_call(conn, ta_id);

    std_sr_response(ta_id, msg_type, optargs, conn, call);
}

int64_t conn_unpublish_nb(struct conn *conn, int64_t service_id,
			  conn_fail_cb fail_cb, conn_ta_cb complete_cb,
			  void *cb_data)
{
    int64_t ta_id = get_next_ta_id(conn);

    struct proto_ta *unpublish_ta =
	proto_ta_unpublish(ta_id, conn->log_ref, unpublish_response_cb,
			   conn);

    struct call *unpublish_call =
	call_sr_create(unpublish_ta, (any_cb)fail_cb, (any_cb)complete_cb,
		       cb_data);

    LIST_INSERT_HEAD(&conn->calls, unpublish_call, entry);
    LIST_INSERT_HEAD(&conn->transactions, unpublish_ta, entry);

    struct msg *unpublish_request =
        proto_ta_produce_request(unpublish_ta, service_id);

    out_queue_append(conn, unpublish_request);

    return ta_id;
}

int conn_unpublish(struct conn *conn, int64_t service_id)
{
    struct result result = {};

    conn_unpublish_nb(conn, service_id, fail_cb, complete_cb, &result);

    wait_until_done(conn, &result);

    return result.rc;
}

static void ping_response_cb(int64_t ta_id, enum proto_msg_type msg_type,
                              void **args UT_UNUSED, void **optargs,
			      void *cb_data)
{
    struct conn *conn = cb_data;
    struct call *call = find_call(conn, ta_id);

    std_sr_response(ta_id, msg_type, optargs, conn, call);
}

int64_t conn_ping_nb(struct conn *conn, conn_fail_cb fail_cb,
		     conn_ta_cb complete_cb, void *cb_data)
{
    int64_t ta_id = get_next_ta_id(conn);

    struct proto_ta *ping_ta =
	proto_ta_ping(ta_id, conn->log_ref, ping_response_cb, conn);

    struct call *ping_call =
	call_sr_create(ping_ta, (any_cb)fail_cb, (any_cb)complete_cb, cb_data);

    LIST_INSERT_HEAD(&conn->calls, ping_call, entry);
    LIST_INSERT_HEAD(&conn->transactions, ping_ta, entry);

    struct msg *ping_request =
	proto_ta_produce_request(ping_ta, conn->client_id);

    out_queue_append(conn, ping_request);

    return ta_id;
}

int conn_ping(struct conn *conn)
{
    struct result result = {};

    conn_ping_nb(conn, fail_cb, complete_cb, &result);

    wait_until_done(conn, &result);

    return result.rc;
}

static void clients_response_cb(int64_t ta_id, enum proto_msg_type msg_type,
				void **args, void **optargs, void *cb_data)
{
    struct conn *conn = cb_data;
    struct call *call = find_call(conn, ta_id);

    if (msg_type == proto_msg_type_notify) {
        const int64_t *client_id = args[0];
	const char *client_addr = args[1];
	const int64_t *connect_time = args[2];
	const double *idle = NULL;
	const int64_t *proto_version = NULL;
	const double *latency = NULL;

	if (conn->proto_version >= 3) {
	    idle = args[3];
	    proto_version = args[4];
	    latency = optargs[0];
	}

	conn_clients_notify_cb cb =
	    (conn_clients_notify_cb)call->notify_cb;

	cb(call->proto_ta->ta_id, *client_id, client_addr, *connect_time,
	   idle, proto_version, latency, call->cb_data);
    } else
	std_mr_response(ta_id, msg_type, optargs, conn, call);
}

int64_t conn_clients_nb(struct conn *conn, conn_fail_cb fail_cb,
			conn_ta_cb accept_cb, conn_clients_notify_cb notify_cb,
			conn_ta_cb complete_cb, void *cb_data)
{
    int64_t ta_id = get_next_ta_id(conn);
    struct proto_ta *(*proto_ta_clients)(int64_t, const char *,
					 proto_response_cb, void *);
    if (conn->proto_version < 3)
	proto_ta_clients = proto_ta_clients_v2;
    else
	proto_ta_clients = proto_ta_clients_v3;

    struct proto_ta *clients_ta =
	proto_ta_clients(ta_id, conn->log_ref, clients_response_cb, conn);

    struct call *clients_call =
	call_mr_create(clients_ta, (any_cb)fail_cb, (any_cb)accept_cb,
		       (any_cb)notify_cb, (any_cb)complete_cb, cb_data);

    LIST_INSERT_HEAD(&conn->calls, clients_call, entry);
    LIST_INSERT_HEAD(&conn->transactions, clients_ta, entry);

    struct msg *clients_request = proto_ta_produce_request(clients_ta);

    out_queue_append(conn, clients_request);

    return ta_id;
}

struct clients_result
{
    struct result result;
    conn_clients_cb user_cb;
    void *user_cb_data;
};

static void clients_notify_forward_cb(int64_t ta_id UT_UNUSED,
				      int64_t client_id,
				      const char *client_addr,
				      int64_t connect_time,
				      const double *idle,
				      const int64_t *proto_version,
				      const double *latency,
				      void *cb_data)
{
    struct clients_result *result = cb_data;
    result->user_cb(client_id, client_addr, connect_time, idle, proto_version,
		    latency, result->user_cb_data);
}

int conn_clients(struct conn *conn, conn_clients_cb cb, void *cb_data)
{
    struct clients_result result = {
	.user_cb = cb,
	.user_cb_data = cb_data
    };

    conn_clients_nb(conn, fail_cb, NULL, clients_notify_forward_cb,
		    complete_cb, &result);

    wait_until_done(conn, &result.result);

    return result.result.rc;
}

#define MAX_OUT_MSGS_PER_CALL (64)

static int process_outgoing(struct conn *conn)
{
    if (TAILQ_EMPTY(&conn->out_queue))
	return 0;

    int count;
    for (count = 0; count < MAX_OUT_MSGS_PER_CALL; count++) {
	struct msg *out_msg = TAILQ_FIRST(&conn->out_queue);

	if (out_msg == NULL)
	    break;

        UT_SAVE_ERRNO;
        int rc = xcm_send(conn->sock, out_msg->data, strlen(out_msg->data));
        UT_RESTORE_ERRNO(send_errno);

        if (rc < 0)
            return send_errno == EAGAIN ? 0 : -1;

        log_conn_out_msg(conn, out_msg->data);

        TAILQ_REMOVE(&conn->out_queue, out_msg, entry);

        msg_free(out_msg);
    }

    if (TAILQ_EMPTY(&conn->out_queue))
	await(conn->sock, XCM_SO_RECEIVABLE);

    return 0;
}

#define MSG_MAX (65535)
#define MAX_IN_MSGS_PER_CALL (64)

static int process_incoming(struct conn *conn)
{
    char* buf = ut_malloc(MSG_MAX);
    int rc = 0;

    int count;
    for (count = 0; count < MAX_IN_MSGS_PER_CALL; count++) {
	int xcm_rc = xcm_receive(conn->sock, buf, MSG_MAX);

	if (xcm_rc == 0) {
	    log_conn_eof(conn);
	    rc = -1;
	    break;
	} else if (xcm_rc < 0) {
	    if (errno != EAGAIN) {
		log_conn_receive_error(conn, errno);
		rc = -1;
	    }
	    break;
	}

	struct msg *in_msg = msg_create_buf(buf, xcm_rc);

	log_conn_in_msg(conn, in_msg->data);

	if (proto_ta_consume_response(&conn->transactions, in_msg,
				      conn->log_ref) < 0) {
	    rc = -1;
	    break;
	}
    }

    ut_free(buf);

    return rc;
}

int conn_process(struct conn *conn)
{
    log_conn_processing(conn);

    UT_SAVE_ERRNO;

    if (process_outgoing(conn) < 0)
	goto err;

    if (process_incoming(conn) < 0)
	goto err;

    UT_RESTORE_ERRNO_DC;

    return 0;

err:
    return -1;
}

int conn_get_fd(const struct conn *conn)
{
    return xcm_fd(conn->sock);
}

const char *conn_err_str(int64_t err)
{
    if (err > 0)
	return "Success";

    switch (err) {
    case CONN_ERR_UNSPEC:
	return "Unspecified error";
    case CONN_ERR_NO_HELLO:
	return "Handshake not completed";
    case CONN_ERR_CLIENT_ID_EXISTS:
	return "Client id exists";
    case CONN_ERR_INVALID_FILTER_SYNTAX:
	return "Invalid filter syntax";
    case CONN_ERR_SUBSCRIPTION_ID_EXISTS:
	return "Subscription id exists";
    case CONN_ERR_NON_EXISTENT_SUBSCRIPTION_ID:
	return "Non-existent subscription id";
    case CONN_ERR_NON_EXISTENT_SERVICE_ID:
	return "Non-existent service id";
    case CONN_ERR_UNSUPPORTED_PROTOCOL_VERSION:
	return "Unsupported protocol version";
    case CONN_ERR_PERMISSION_DENIED:
	return "Permission denied";
    case CONN_ERR_OLD_GENERATION:
	return "Old generation";
    case CONN_ERR_SAME_GENERATION_BUT_DIFFERENT:
	return "Same generation but different data";
    case CONN_ERR_INSUFFICIENT_RESOURCES:
	return "Insufficient resources";
    default:
	return "Unknown error";
    }
}

#define GEN_FAIL_CMP(fail_name, fail_reason)				\
    do {								\
	if (strcmp(PROTO_FAIL_REASON_ ## fail_name, fail_reason) == 0)	\
	    return CONN_ERR_ ## fail_name;				\
    } while (0)

static int fail_reason_to_err(const char *fail_reason)
{
    GEN_FAIL_CMP(NO_HELLO, fail_reason);
    GEN_FAIL_CMP(CLIENT_ID_EXISTS, fail_reason);
    GEN_FAIL_CMP(INVALID_FILTER_SYNTAX, fail_reason);
    GEN_FAIL_CMP(SUBSCRIPTION_ID_EXISTS, fail_reason);
    GEN_FAIL_CMP(NON_EXISTENT_SUBSCRIPTION_ID, fail_reason);
    GEN_FAIL_CMP(NON_EXISTENT_SERVICE_ID, fail_reason);
    GEN_FAIL_CMP(UNSUPPORTED_PROTOCOL_VERSION, fail_reason);
    GEN_FAIL_CMP(PERMISSION_DENIED, fail_reason);
    GEN_FAIL_CMP(OLD_GENERATION, fail_reason);
    GEN_FAIL_CMP(SAME_GENERATION_BUT_DIFFERENT, fail_reason);
    GEN_FAIL_CMP(INSUFFICIENT_RESOURCES, fail_reason);

    return CONN_ERR_UNKNOWN;
}
