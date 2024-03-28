/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#include <limits.h>
#include <poll.h>
#include <stdarg.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

#include "testutil.h"
#include "testsetup.h"
#include "utest.h"
#include "util.h"

#include "conn.h"

static int setup(unsigned int setup_flags)
{
    int rc = ts_domain_setup(setup_flags);
    if (rc < 0)
	return rc;
    
    if (setenv("XCM_TLS_CERT", TS_CLIENT_CERT_DIR, 1) < 0)
	return UTEST_FAILED;

    if (tu_executef_es("test -f %s/cert.pem", TS_CLIENT_CERT_DIR) != 0)
	return UTEST_FAILED;

    return UTEST_SUCCESS;
}

static int teardown(unsigned setup_flags)
{
    ts_stop_servers();

    ts_domain_teardown();

    return UTEST_SUCCESS;
}

TESTSUITE(conn, setup, teardown)

static void init_conf(const struct server *server, struct server_conf *conf)
{
    *conf = (struct server_conf) {
	.net_ns = server->net_ns,
	.addr = server->addr,
	.proto_version_min = -1,
	.proto_version_max = -1
    };
}

TESTCASE(conn, connect)
{
    struct server_conf server_conf;
    init_conf(&ts_servers[0], &server_conf);

    int64_t client_id = 4711;

    CHK(conn_connect(&server_conf, client_id, "foo") == NULL);
    CHKERRNOEQ(ECONNREFUSED);

    ts_start_servers();

    struct conn *conn = conn_connect(&server_conf, client_id, "foo");

    CHK(conn != NULL);

    conn_close(conn);

    return UTEST_SUCCESS;
}

struct hello_result
{
    int64_t ta_id;
    int call_result;
    int64_t proto_version;
    int num_calls;
};

static bool is_valid_proto_version(int64_t proto_version)
{
    switch (proto_version) {
    case 2:
    case 3:
	return true;
    default:
	return false;
    }
}

static void hello_complete_cb(int64_t ta_id, int64_t proto_version,
			      void *cb_data)
{
    struct hello_result *result = cb_data;
    *result = (struct hello_result) {
	.ta_id = ta_id,
	.call_result = 0,
	.proto_version = proto_version,
	.num_calls = result->num_calls + 1
    };
}

static void hello_fail_cb(int64_t ta_id, int fail_reason, void *cb_data)
{
    struct hello_result *result = cb_data;

    *result = (struct hello_result) {
	.ta_id = ta_id,
	.call_result = fail_reason,
	.num_calls = result->num_calls + 1
    };
}

TESTCASE(conn, hello_nb)
{
    struct server_conf server_conf;
    init_conf(&ts_servers[0], &server_conf);

    int64_t client_id = INT_MAX;

    ts_start_servers();

    struct conn *conn = conn_connect(&server_conf, client_id, NULL);

    CHK(conn != NULL);

    struct hello_result result = {};

    int64_t hello_ta_id =
	conn_hello_nb(conn, hello_fail_cb, hello_complete_cb, &result);

    CHK(hello_ta_id >= 0);

    while (result.num_calls == 0)
	CHKNOERR(conn_process(conn));

    CHKINTEQ(result.ta_id, hello_ta_id);
    CHKINTEQ(result.call_result, 0);
    CHK(is_valid_proto_version(result.proto_version));
    CHKINTEQ(result.num_calls, 1);

    conn_close(conn);

    return UTEST_SUCCESS;
}

TESTCASE(conn, hello_and_ping)
{
    struct server_conf server_conf;
    init_conf(&ts_servers[0], &server_conf);

    int64_t client_id = INT_MAX;

    ts_start_servers();

    struct conn *conn = conn_connect(&server_conf, client_id, NULL);

    int64_t proto_version = -1;
    CHKNOERR(conn_hello(conn, &proto_version));
    CHK(is_valid_proto_version(proto_version));

    CHKNOERR(conn_ping(conn));

    conn_close(conn);

    return UTEST_SUCCESS;
}

struct subscribe_result
{
    int num_fail_calls;
    int num_accept_calls;
    int num_notify_calls;
    int num_complete_calls;
};

static void subscribe_fail_cb(int64_t ta_id, int fail_reason, void *cb_data)
{
    struct subscribe_result *result = cb_data;

    result->num_fail_calls++;
}

static void subscribe_accept_cb(int64_t ta_id, void *cb_data)
{
    struct subscribe_result *result = cb_data;

    result->num_accept_calls++;
}

static void subscribe_notify_cb(int64_t ta_id, enum paf_match_type match_type,
				int64_t service_id, const int64_t *generation,
				const struct paf_props *props,
				const int64_t *ttl, const double *orphan_since,
				void *cb_data)
{
    struct subscribe_result *result = cb_data;

    result->num_notify_calls++;
}

static void subscribe_complete_cb(int64_t ta_id, void *cb_data)
{
    struct subscribe_result *result = cb_data;

    result->num_complete_calls++;
}

static int process_for(struct conn *conn, double t)
{
    double deadline = ut_ftime(CLOCK_MONOTONIC) + t;

    while (ut_ftime(CLOCK_MONOTONIC) < deadline) {
	int rc = conn_process(conn);
	if (rc < 0)
	    return rc;
	tu_msleep(25);
    }

    return 0;
}

#define PROCESS_WHILE(conn, expr) \
    do {					\
	CHKNOERR(process_for(conn, 0.01));	\
    } while (expr)

TESTCASE(conn, subscribe_unsubscribe)
{
    struct server_conf server_conf;
    init_conf(&ts_servers[0], &server_conf);

    ts_start_servers();

    struct conn *conn = conn_connect(&server_conf, 42, "test");

    CHKNOERR(conn_hello(conn, NULL));

    struct subscribe_result result = {};

    int64_t sub_id = ut_rand_id();

    CHKNOERR(conn_subscribe_nb(conn, sub_id, "(name=foo)", subscribe_fail_cb,
			       subscribe_accept_cb, subscribe_notify_cb,
			       subscribe_complete_cb, &result));

    CHKNOERR(process_for(conn, 0.25));

    CHKINTEQ(result.num_fail_calls, 0);
    CHKINTEQ(result.num_accept_calls, 1);
    CHKINTEQ(result.num_notify_calls, 0);
    CHKINTEQ(result.num_complete_calls, 0);

    int64_t service_id = ut_rand_id();
    struct paf_props *props = paf_props_create();
    paf_props_add_str(props, "name", "foo");

    CHKNOERR(conn_publish(conn, service_id, 0, props, 60));

    paf_props_destroy(props);

    CHKNOERR(process_for(conn, 0.25));

    CHKINTEQ(result.num_fail_calls, 0);
    CHKINTEQ(result.num_accept_calls, 1);
    CHKINTEQ(result.num_notify_calls, 1);
    CHKINTEQ(result.num_complete_calls, 0);

    CHKNOERR(conn_unsubscribe(conn, sub_id));

    CHKNOERR(process_for(conn, 0.25));

    CHKINTEQ(result.num_fail_calls, 0);
    CHKINTEQ(result.num_accept_calls, 1);
    CHKINTEQ(result.num_notify_calls, 1);
    CHKINTEQ(result.num_complete_calls, 1);

    conn_close(conn);

    return UTEST_SUCCESS;
}

static void subscriptions_cb(int64_t sub_id, int64_t client_id,
			     const char *filter, void *cb_data)
{
    int *count = cb_data;

    (*count)++;
}

TESTCASE(conn, subscriptions)
{
    struct server_conf server_conf;
    init_conf(&ts_servers[0], &server_conf);

    ts_start_servers();

    struct conn *conn = conn_connect(&server_conf, 42, NULL);

    CHKNOERR(conn_hello(conn, NULL));

    int sub_count = 0;

    CHKNOERR(conn_subscriptions(conn, subscriptions_cb, &sub_count));
    CHKNOERR(process_for(conn, 0.25));

    CHKINTEQ(sub_count, 0);

    struct subscribe_result result0 = {};
    int64_t sub_id0 = ut_rand_id();
    CHKNOERR(conn_subscribe_nb(conn, sub_id0, "(!(name=asdf))",
			       subscribe_fail_cb, subscribe_accept_cb,
			       subscribe_notify_cb, subscribe_complete_cb,
			       &result0));

    struct subscribe_result result1 = {};
    int64_t sub_id1 = ut_rand_id();
    CHKNOERR(conn_subscribe_nb(conn, sub_id1, NULL, subscribe_fail_cb,
			       subscribe_accept_cb, subscribe_notify_cb,
			       subscribe_complete_cb, &result1));

    do {
	CHKNOERR(process_for(conn, 0.1));
    } while (result0.num_accept_calls != 1 || result1.num_accept_calls != 1);

    CHKNOERR(conn_subscriptions(conn, subscriptions_cb, &sub_count));
    CHKNOERR(process_for(conn, 0.25));

    CHKINTEQ(sub_count, 2);

    conn_close(conn);

    return UTEST_SUCCESS;
}

static void services_cb(int64_t service_id, int64_t generation,
			const struct paf_props *props, int64_t ttl,
			int64_t client_id, const double *orphan_since,
			void *cb_data)
{
    int *count = cb_data;

    (*count)++;
}

TESTCASE(conn, services)
{
    struct server_conf server_conf;
    init_conf(&ts_servers[0], &server_conf);

    ts_start_servers();

    struct conn *conn = conn_connect(&server_conf, 42, NULL);

    CHKNOERR(conn_hello(conn, NULL));

    int service_count = 0;

    CHKNOERR(conn_services(conn, NULL, services_cb, &service_count));

    CHKNOERR(process_for(conn, 0.25));
    CHKINTEQ(service_count, 0);

    int64_t service_id0 = ut_rand_id();
    struct paf_props *props0 = paf_props_create();
    paf_props_add_str(props0, "name", "foo");

    CHKNOERR(conn_publish(conn, service_id0, 0, props0, 60));

    paf_props_destroy(props0);

    int64_t service_id1 = ut_rand_id();
    struct paf_props *props1 = paf_props_create();
    paf_props_add_str(props1, "name", "bar");

    CHKNOERR(conn_publish(conn, service_id1, 0, props1, 60));

    paf_props_destroy(props1);

    CHKNOERR(conn_services(conn, NULL, services_cb, &service_count));
    PROCESS_WHILE(conn, service_count != 2);

    service_count = 0;
    CHKNOERR(conn_services(conn, "(name=foo)", services_cb, &service_count));
    PROCESS_WHILE(conn, service_count != 1);

    CHKNOERR(conn_unpublish(conn, service_id0));

    service_count = 0;
    CHKNOERR(conn_services(conn, "(name=foo)", services_cb, &service_count));

    CHKNOERR(process_for(conn, 0.25));
    CHKINTEQ(service_count, 0);

    conn_close(conn);

    return UTEST_SUCCESS;
}

struct client {
    int64_t client_id;
    char client_addr[128];
    int64_t connect_time;
    double idle;
    int64_t proto_version;
    double latency;
};

#define MAX_CLIENTS 16

struct clients_result
{
    struct client clients[MAX_CLIENTS];
    int num_clients;
};

static void clients_cb(int64_t client_id, const char *client_addr,
		       int64_t connect_time, const double *idle,
		       const int64_t *proto_version, const double *latency,
		       void *cb_data)
{
    struct clients_result *result = cb_data;
    struct client *client = &result->clients[result->num_clients];

    result->num_clients++;

    client->client_id = client_id;
    strcpy(client->client_addr, client_addr);
    client->connect_time = connect_time;
    client->idle = idle != NULL ? *idle : -1;
    client->proto_version = proto_version != NULL ? *proto_version : -1;
    client->latency = latency != NULL ? *latency : -1;
}

TESTCASE(conn, clients)
{
    struct server_conf server_conf;
    init_conf(&ts_servers[0], &server_conf);

    int64_t client_id0 = 0;
    int64_t client_id1 = INT64_MAX;

    ts_start_servers();

    int64_t connect_time = ut_ftime(CLOCK_REALTIME);

    struct conn *conn0 = conn_connect(&server_conf, client_id0, "client 0");
    CHKNOERR(conn_hello(conn0, NULL));

    struct conn *conn1 = conn_connect(&server_conf, client_id1, "client 1");
    CHKNOERR(conn_hello(conn1, NULL));

    struct clients_result result = {};
    CHKNOERR(conn_clients(conn0, clients_cb, &result));

    tu_msleep(1001);

    CHKINTEQ(result.num_clients, 2);

    struct client *client0;
    struct client *client1;

    if (result.clients[0].client_id == client_id0) {
	client0 = &result.clients[0];
	client1 = &result.clients[1];
    } else {
	client0 = &result.clients[1];
	client1 = &result.clients[0];
    }

    CHKINTEQ(client0->client_id, client_id0);
    CHKINTEQ(client1->client_id, client_id1);

    CHKSTREQ(client0->client_addr, conn_get_local_addr(conn0));
    CHKSTREQ(client1->client_addr, conn_get_local_addr(conn1));

    CHK(llabs(client0->connect_time - connect_time) < 2);
    CHK(llabs(client1->connect_time - connect_time) < 2);

    if (conn_get_proto_version(conn0) >= 3) {
	CHKINTEQ(client0->proto_version, conn_get_proto_version(conn0));
	CHK(client0->idle >= 0 && client0->idle < 1);
    }

    if (conn_get_proto_version(conn1) >= 3) {
	CHKINTEQ(client1->proto_version, conn_get_proto_version(conn1));
	CHK(client1->idle >= 0 && client1->idle < 1);
    }

    CHK(client0->latency < 0);
    CHK(client1->latency < 0);

    conn_close(conn0);
    conn_close(conn1);

    return UTEST_SUCCESS;
}

TESTCASE(conn, no_hello)
{
    struct server_conf server_conf;
    init_conf(&ts_servers[0], &server_conf);

    ts_start_servers();

    struct conn *conn = conn_connect(&server_conf, 42, NULL);

    CHKINTEQ(conn_ping(conn), CONN_ERR_NO_HELLO);
    CHKINTEQ(conn_unsubscribe(conn, 99), CONN_ERR_NO_HELLO);

    struct clients_result result = {};
    CHKINTEQ(conn_clients(conn, clients_cb, &result), CONN_ERR_NO_HELLO);

    conn_close(conn);

    return UTEST_SUCCESS;
}

TESTCASE(conn, no_version_overlap)
{
    ts_start_servers();

    struct server_conf server_conf;
    init_conf(&ts_servers[0], &server_conf);

    server_conf.proto_version_min = 100;

    CHK(conn_connect(&server_conf, 42, NULL) == NULL);

    server_conf.proto_version_min = 1;
    server_conf.proto_version_max = 1;

    CHK(conn_connect(&server_conf, 42, NULL) == NULL);

    return UTEST_SUCCESS;
}
