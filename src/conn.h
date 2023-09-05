/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Ericsson AB
 */

#ifndef CONN_H
#define CONN_H

#include <stdint.h>

#include "paf_props.h"
#include "paf_match.h"
#include "server_conf.h"

struct conn;

struct conn *conn_connect(const struct server_conf *server_conf,
			  int64_t client_id, const char *log_ref);

void conn_close(struct conn *conn);

int64_t conn_get_client_id(const struct conn *conn);
const char *conn_get_local_addr(const struct conn *conn);

/* callback signature reused across multiple commands */
typedef void (*conn_ta_cb)(int64_t ta_id, void *cb_data);
typedef void (*conn_fail_cb)(int64_t ta_id, int fail_reason_err,
			     void *cb_data);

/* hello */
typedef void (*conn_hello_complete_cb )(int64_t ta_id, int64_t proto_version,
					void *cb_data);
int64_t conn_hello_nb(struct conn *conn, conn_fail_cb fail_cb,
		      conn_hello_complete_cb complete_cb, void *cb_data);
int conn_hello(struct conn *conn, int64_t *proto_version);

/* subscribe */
typedef void (*conn_subscribe_notify_cb)(int64_t ta_id,
					 enum paf_match_type match_type,
					 int64_t service_id,
					 const int64_t *generation,
					 const struct paf_props *props,
					 const int64_t *ttl,
					 const double *orphan_since,
					 void *cb_data);
int64_t conn_subscribe_nb(struct conn *conn, int64_t sub_id,
			  const char *filter, conn_fail_cb fail_cb,
			  conn_ta_cb accept_cb,
			  conn_subscribe_notify_cb notify_cb,
			  conn_ta_cb complete_cb, void *cb_data);

/* unsubscribe */
int64_t conn_unsubscribe_nb(struct conn *conn, int64_t sub_id,
			    conn_fail_cb fail_cb, conn_ta_cb complete_cb,
			    void *cb_data);
int conn_unsubscribe(struct conn *conn, int64_t sub_id);

/* subscriptions */

typedef void (*conn_subscriptions_notify_cb)(int64_t ta_id, int64_t sub_id,
					     int64_t client_id,
					     const char *filter,
					     void *cb_data);
int64_t conn_subscriptions_nb(struct conn *conn, conn_fail_cb fail_cb,
			      conn_ta_cb accept_cb,
			      conn_subscriptions_notify_cb notify_cb,
			      conn_ta_cb complete_cb, void *cb_data);

typedef void (*conn_subscriptions_cb)( int64_t sub_id, int64_t client_id,
				       const char *filter, void *cb_data);
int conn_subscriptions(struct conn *conn, conn_subscriptions_cb cb,
		       void *cb_data);

/* services */

typedef void (*conn_services_notify_cb)(int64_t ta_id, int64_t service_id,
					int64_t generation,
					const struct paf_props *props,
					int64_t ttl, int64_t client_id,
					const double *orphan_since,
					void *cb_data);
int64_t conn_services_nb(struct conn *conn, const char *filter,
			 conn_fail_cb fail_cb,
			 conn_ta_cb accept_cb,
			 conn_services_notify_cb notify_cb,
			 conn_ta_cb complete_cb, void *cb_data);

typedef void (*conn_services_cb)(int64_t service_id,
				 int64_t generation,
				 const struct paf_props *props,
				 int64_t ttl,
				 int64_t client_id,
				 const double *orphan_since,
				 void *cb_data);
int conn_services(struct conn *conn, const char *filter,
		  conn_services_cb cb, void *cb_data);

/* publish */
int64_t conn_publish_nb(struct conn *conn, int64_t service_id,
			int64_t generation, const struct paf_props *props,
			int64_t ttl, conn_fail_cb fail_cb,
			conn_ta_cb complete_cb, void *cb_data);
int conn_publish(struct conn *conn, int64_t service_id,	int64_t generation,
		 const struct paf_props *props, int64_t ttl);

/* unpublish */
int64_t conn_unpublish_nb(struct conn *conn, int64_t service_id,
			  conn_fail_cb fail_cb, conn_ta_cb complete_cb,
			  void *cb_data);
int conn_unpublish(struct conn *conn, int64_t service_id);

/* ping */
int64_t conn_ping_nb(struct conn *conn, conn_fail_cb fail_cb,
		     conn_ta_cb complete_cb, void *cb_data);
int conn_ping(struct conn *conn);

/* clients */
typedef void (*conn_clients_notify_cb)(int64_t ta_id,
				       int64_t client_id,
				       const char *client_addr,
				       int64_t connect_time, void *cb_data);
int64_t conn_clients_nb(struct conn *conn, conn_fail_cb fail_cb,
			conn_ta_cb accept_cb, conn_clients_notify_cb notify_cb,
			conn_ta_cb complete_cb, void *cb_data);

typedef void (*conn_clients_cb)(int64_t client_id, const char *client_addr,
				int64_t connect_time, void *cb_data);
int conn_clients(struct conn *conn, conn_clients_cb cb, void *cb_data);

int conn_process(struct conn *conn);

int conn_get_fd(const struct conn *conn);

#define CONN_ERR_UNSPEC (-1)
#define CONN_ERR_NO_HELLO (-2)
#define CONN_ERR_CLIENT_ID_EXISTS (-3)
#define CONN_ERR_INVALID_FILTER_SYNTAX (-4)
#define CONN_ERR_SUBSCRIPTION_ID_EXISTS (-5)
#define CONN_ERR_NON_EXISTENT_SUBSCRIPTION_ID (-6)
#define CONN_ERR_NON_EXISTENT_SERVICE_ID (-7)
#define CONN_ERR_UNSUPPORTED_PROTOCOL_VERSION (-8)
#define CONN_ERR_PERMISSION_DENIED (-9)
#define CONN_ERR_OLD_GENERATION (-10)
#define CONN_ERR_SAME_GENERATION_BUT_DIFFERENT (-11)
#define CONN_ERR_INSUFFICIENT_RESOURCES (-12)
#define CONN_ERR_UNKNOWN (-42)

const char *conn_err_str(int64_t err);

#endif
