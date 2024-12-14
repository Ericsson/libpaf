/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#ifndef LINK_H
#define LINK_H

#include <stdint.h>

#include "conn.h"
#include "epoll_reg.h"
#include "list.h"
#include "msg.h"
#include "proto_ta.h"
#include "ptimer.h"
#include "sd.h"
#include "server_conf.h"

#define LINK_ERR_DETACHED (-2)

enum link_state {
    link_state_connecting,
    link_state_greeting,
    link_state_operational,
    link_state_restarting,
    link_state_detaching,
    link_state_detached
};

enum relay_state {
    relay_state_unsynced,
    relay_state_syncing,
    relay_state_synced,
    relay_state_unsyncing
};

struct relay
{
    int64_t obj_id;
    enum relay_state state;
    int64_t sync_ta_id;
    int64_t unsync_ta_id;
    bool pending_sync;
    bool pending_unsync;

    LIST_ENTRY(relay) entry;
};

LIST_HEAD(relay_list, relay);

struct link
{
    int64_t link_id;
    int64_t client_id;
    struct server_conf *server;
    enum link_state state;

    struct sd *sd;
    struct sd_listener *listener;

    struct relay_list service_relays;
    struct relay_list sub_relays;

    struct epoll_reg epoll_reg;

    struct ptimer *timer;

    int64_t reconnect_tmo;
    double reconnect_time;

    struct conn *conn;

    int64_t greeting_tmo;

    int64_t idle_tmo;
    int64_t track_ta_id;
    bool track_accepted;
    double max_idle_time;
    double track_query_ts;

    int64_t detached_tmo;
    double max_detach_time;

    struct msg_queue out_queue;

    char *log_ref;

    LIST_ENTRY(link) entry;
};

LIST_HEAD(link_list, link);

struct link *link_create(int64_t link_id, int64_t client_id,
			 const struct server_conf *server, struct sd *sd,
			 struct ptimer *timer, int epoll_fd,
			 const char *log_ref);

int link_process(struct link *link);

void link_detach(struct link *link);

void link_destroy(struct link *link);

#endif
