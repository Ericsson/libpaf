/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#ifndef PROTO_H
#define PROTO_H

#include <stdarg.h>
#include <sys/queue.h>

#include "msg.h"

#define PROTO_VERSION INT64_C(2)

#define PROTO_MSG_TYPE_REQUEST "request"
#define PROTO_MSG_TYPE_ACCEPT "accept"
#define PROTO_MSG_TYPE_NOTIFY "notify"
#define PROTO_MSG_TYPE_COMPLETE "complete"
#define PROTO_MSG_TYPE_FAIL "fail"

#define PROTO_CMD_HELLO "hello"
#define PROTO_CMD_SUBSCRIBE "subscribe"
#define PROTO_CMD_UNSUBSCRIBE "unsubscribe"
#define PROTO_CMD_SUBSCRIPTIONS "subscriptions"
#define PROTO_CMD_SERVICES "services"
#define PROTO_CMD_PUBLISH "publish"
#define PROTO_CMD_UNPUBLISH "unpublish"
#define PROTO_CMD_PING "ping"
#define PROTO_CMD_CLIENTS "clients"

#define PROTO_FIELD_TA_CMD "ta-cmd"
#define PROTO_FIELD_TA_ID "ta-id"
#define PROTO_FIELD_MSG_TYPE "msg-type"

#define PROTO_FIELD_FAIL_REASON "fail-reason"

#define PROTO_FIELD_PROTO_MIN_VERSION "protocol-minimum-version"
#define PROTO_FIELD_PROTO_MAX_VERSION "protocol-maximum-version"
#define PROTO_FIELD_PROTO_VERSION "protocol-version"

#define PROTO_FIELD_SERVICE_ID "service-id"
#define PROTO_FIELD_SERVICE_PROPS "service-props"

#define PROTO_FIELD_GENERATION "generation"
#define PROTO_FIELD_TTL "ttl"
#define PROTO_FIELD_ORPHAN_SINCE "orphan-since"

#define PROTO_FIELD_SUBSCRIPTION_ID "subscription-id"
#define PROTO_FIELD_FILTER "filter"

#define PROTO_FIELD_CLIENT_ID "client-id"
#define PROTO_FIELD_CLIENT_ADDR "client-address"
#define PROTO_FIELD_TIME "time"

#define PROTO_FIELD_MATCH_TYPE "match-type"

#define PROTO_MATCH_TYPE_APPEARED "appeared"
#define PROTO_MATCH_TYPE_MODIFIED "modified"
#define PROTO_MATCH_TYPE_DISAPPEARED "disappeared"

#define PROTO_FAIL_REASON_NO_HELLO "no-hello"
#define PROTO_FAIL_REASON_CLIENT_ID_EXISTS "client-id-exists"
#define PROTO_FAIL_REASON_INVALID_FILTER_SYNTAX "invalid-filter-syntax"
#define PROTO_FAIL_REASON_SUBSCRIPTION_ID_EXISTS "subscription-id-exists"
#define PROTO_FAIL_REASON_NON_EXISTENT_SUBSCRIPTION_ID \
    "non-existent-subscription-id"
#define PROTO_FAIL_REASON_NON_EXISTENT_SERVICE_ID "non-existent-service-id"
#define PROTO_FAIL_REASON_UNSUPPORTED_PROTOCOL_VERSION \
    "unsupported-protocol-version"
#define PROTO_FAIL_REASON_PERMISSION_DENIED "permission-denied"
#define PROTO_FAIL_REASON_OLD_GENERATION "old-generation"
#define PROTO_FAIL_REASON_SAME_GENERATION_BUT_DIFFERENT \
    "same-generation-but-different"
#define PROTO_FAIL_REASON_INSUFFICIENT_RESOURCES "insufficient-resources"

enum proto_msg_type {
    proto_msg_type_request,
    proto_msg_type_accept,
    proto_msg_type_notify,
    proto_msg_type_complete,
    proto_msg_type_fail,
    proto_msg_type_undefined
};

typedef void (*proto_response_cb)(int64_t ta_id, enum proto_msg_type msg_type,
                                  void **args, void **optargs, void *user);

enum proto_field_type {
    proto_field_type_str,
    proto_field_type_int64,
    proto_field_type_number,
    proto_field_type_props,
    proto_field_type_match_type
};

struct proto_field
{
    const char *name;
    enum proto_field_type type;
};

enum proto_ia_type {
    proto_ia_type_single_response,
    proto_ia_type_multi_response
};

#define MAX_FIELDS (16)

struct proto_ta_type
{
    const char *cmd;
    enum proto_ia_type ia_type;
    struct proto_field request_fields[MAX_FIELDS];
    struct proto_field opt_request_fields[MAX_FIELDS];
    struct proto_field notify_fields[MAX_FIELDS];
    struct proto_field opt_notify_fields[MAX_FIELDS];
    struct proto_field complete_fields[MAX_FIELDS];
    struct proto_field opt_fail_fields[MAX_FIELDS];
};

enum proto_ta_state {
    proto_ta_state_idle,
    proto_ta_state_requesting,
    proto_ta_state_accepted,
    proto_ta_state_completed,
    proto_ta_state_failed
};

struct proto_ta
{
    const struct proto_ta_type *type;
    int64_t ta_id;
    enum proto_ta_state state;
    char *log_ref;
    proto_response_cb cb;
    void *user;
    LIST_ENTRY(proto_ta) entry;
};

LIST_HEAD(proto_ta_list, proto_ta);

struct proto_ta *proto_ta_hello(int64_t ta_id, const char *log_ref,
                                proto_response_cb cb, void *user);

struct proto_ta *proto_ta_publish(int64_t ta_id, const char *log_ref,
                                  proto_response_cb cb, void *user);

struct proto_ta *proto_ta_unpublish(int64_t ta_id, const char *log_ref,
                                    proto_response_cb cb, void *user);

struct proto_ta *proto_ta_subscribe(int64_t ta_id, const char *log_ref,
                                    proto_response_cb cb, void *user);

struct proto_ta *proto_ta_unsubscribe(int64_t ta_id, const char *log_ref,
                                      proto_response_cb cb, void *user);

struct proto_ta *proto_ta_subscriptions(int64_t ta_id, const char *log_ref,
					proto_response_cb cb, void *user);

struct proto_ta *proto_ta_services(int64_t ta_id, const char *log_ref,
				   proto_response_cb cb, void *user);

struct proto_ta *proto_ta_ping(int64_t ta_id, const char *log_ref,
			       proto_response_cb cb, void *user);

struct proto_ta *proto_ta_clients(int64_t ta_id, const char *log_ref,
				  proto_response_cb cb, void *user);

struct msg *proto_ta_produce_request(struct proto_ta *ta, ...);

int proto_ta_consume_response(struct proto_ta_list *ta_list,
                              struct msg *response, const char *log_ref);

void proto_ta_destroy(struct proto_ta *ta);

#endif
