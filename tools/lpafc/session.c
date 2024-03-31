/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Ericsson AB
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <poll.h>

#include "cli.h"
#include "conn.h"
#include "util.h"

#include "session.h"

#define LPAFC_PROMPT "> "

struct session
{
    struct conn *conn;
    int64_t track_ta_id;
    bool track_accepted;
    double track_query_ts;
    bool track_verbose;
    struct cli *cli;
};

/* 'static' scope since the handle_line callback doesn't allow pass
   user data (i.e., a void pointer) */
static struct session session;

static void cmd_ok(void)
{
    printf("OK.\n");
}

static void cmd_failed(int64_t reason)
{
    printf("Protocol transaction failed: %s.\n", conn_err_str(reason));
}

#define QUIT_CMD "quit"
#define QUIT_CMD_HELP				\
    QUIT_CMD "\n"				\
    "    Close the connection and quit.\n"

static void run_quit(const char *cmd, const char *const *args, size_t num,
		     void *cb_data UT_UNUSED)
{
    cli_exit(0);
}

#define ID_CMD "id"
#define ID_CMD_HELP				\
    ID_CMD "\n"				\
    "    Show client identifier.\n"

static void run_id(const char *cmd, const char *const *args, size_t num,
		   void *cb_data UT_UNUSED)
{
    int64_t client_id = conn_get_client_id(session.conn);

    printf("Client Id: %"PRIx64"\n", client_id);
}

#define HELLO_CMD "hello"
#define HELLO_CMD_HELP				\
    HELLO_CMD "\n"				\
    "    Redo protocol handshake.\n"

static void run_hello(const char *cmd, const char *const *args, size_t num,
		     void *cb_data)
{
    int64_t protocol_version;
    int rc = conn_hello(session.conn, &protocol_version);
    if (rc < 0)
	cmd_failed(rc);
    else {
	printf("Negotiated Protocol Version: %"PRId64"\n", protocol_version);
	cmd_ok();
    }
}

#define TRACK_CMD "track"
#define TRACK_CMD_HELP							\
    TRACK_CMD " [query|verbose|quiet]\n"				\
    "    The purpose of a track transaction is to allow the server and the\n" \
    "    client to ensure that the remote peer is still alive.\n"	\
    "\n"								\
    "    'track' without any arguments initiates a track protocol transaction.\n" \
    "\n"								\
    "    'track query' results in a track query being sent to the server.\n" \
    "\n"								\
    "    lpafc will reply to any track queries received from the server within\n" \
    "    the track transaction.\n" \
    "\n"								\
    "    'track verbose' results in server-initiated query to be logged to\n" \
    "    the console.\n"						\
    "\n"								\
    "    'track quiet' results in server-initiated query to no longer be\n" \
    "    logged the console. Quiet mode is the default.\n"		\
    "\n"								\
    "    This command is only available on protocol version 3 connections.\n"

static void track_notify_cb(int64_t ta_id, bool is_query, void *cb_data)
{
    if (is_query) {
	conn_track_inform(session.conn, ta_id, false);
	if (session.track_verbose)
	    printf("Responded to track query notification.\n");
    } else {
	if (session.track_query_ts < 0) {
	    printf("WARNING: Received unsolicited track query reply.");
	} else {
	    double latency =
		ut_ftime(CLOCK_MONOTONIC) - session.track_query_ts;
	    printf("Received reply to track query in %.1f ms.\n",
		   (latency * 1e3));
	    session.track_query_ts = -1;
	}
    }
}

static void track_accept_cb(int64_t ta_id, void *cb_data)
{
    session.track_accepted = true;
}

static void track_complete_cb(int64_t ta_id, void *cb_data)
{
    printf("Track transaction canceled.\n");

    session.track_accepted = false;
    session.track_ta_id = -1;
    session.track_query_ts = -1;
}

static void fail_cb(int64_t ta_id, int fail_reason, void *cb_data)
{
    printf("Operation failed: %s.\n", conn_err_str(fail_reason));
}

static void run_track_init(void)
{
    session.track_ta_id = conn_track_nb(session.conn, fail_cb,
					track_accept_cb, track_notify_cb,
					track_complete_cb, NULL);
    if (session.track_ta_id < 0)
	cmd_failed(session.track_ta_id);
    else
	cmd_ok();
}

static void run_track_query(void)
{
    if (session.track_accepted) {
	if (session.track_query_ts < 0) {
	    session.track_query_ts = ut_ftime(CLOCK_MONOTONIC);

	    conn_track_inform(session.conn, session.track_ta_id, true);
	    cmd_ok();
	} else
	    printf("Track query already in progress.\n");
    } else
	printf("Track request not yet accepted by server.\n");
}

static void run_track_set_verbose(bool on)
{
    session.track_verbose = on;
    cmd_ok();
}

static void run_track(const char *cmd, const char *const *args, size_t num,
		      void *cb_data)
{
    if (!conn_is_track_supported(session.conn)) {
	printf("Not available in negotiated Pathfinder protocol version (%"
	       PRId64").\n", conn_get_proto_version(session.conn));
	return;
    }

    if (num == 0)
	run_track_init();
    else {
	if (strcmp(args[0], "query") == 0)
	    run_track_query();
	else if (strcmp(args[0], "verbose") == 0)
	    run_track_set_verbose(true);
	else if (strcmp(args[0], "quiet") == 0)
	    run_track_set_verbose(false);
	else
	    printf("Unknown track sub-command '%s'.\n", args[0]);
    }
}

#define SUBSCRIBE_CMD "subscribe"
#define SUBSCRIBE_CMD_HELP \
    SUBSCRIBE_CMD " [<filter>]\n" \
    "     Subscribe to changes in services (optionally only those " \
    "matching a filter).\n"

#define SLABEL(prefix, name)                    \
    case prefix ## _ ## name:                   \
    return "" #name ""

static const char *match_type_str(enum paf_match_type type)
{
    switch (type) {
        SLABEL(paf_match_type, appeared);
        SLABEL(paf_match_type, modified);
        SLABEL(paf_match_type, disappeared);
    default:
        return "undefined";
    }
}

struct prop_print_state {
    FILE *f;
    size_t prop_printed;
    size_t prop_num_values;
};

static void print_prop(const char *prop_name,
		       const struct paf_value *prop_value, void *user)
{
    struct prop_print_state *state = user;

    fprintf(state->f, "'%s': ", prop_name);

    if (paf_value_is_int64(prop_value))
	fprintf(state->f, "%"PRId64, paf_value_int64(prop_value));
    else
	fprintf(state->f, "'%s'", paf_value_str(prop_value));

    state->prop_printed++;

    bool last = state->prop_printed == state->prop_num_values;

    if (!last)
	fprintf(state->f, ", ");
}

static void print_props(FILE *f, const struct paf_props *props)
{
    fprintf(f, "{");

    struct prop_print_state state = {
	.f = f,
	.prop_num_values = paf_props_num_values(props)
    };
    paf_props_foreach(props, print_prop, &state);

    fprintf(f, "}");
}

static double orphan_left(double orphan_since, double ttl)
{
    return orphan_since + ttl - ut_ftime(CLOCK_REALTIME);
}

static void sub_notify_cb(int64_t ta_id, enum paf_match_type match_type,
			  int64_t service_id, const int64_t *generation,
			  const struct paf_props *props, const int64_t *ttl,
			  const double *orphan_since, void *cb_data)
{
    const int64_t *sub_id = cb_data;

    printf("Subscription %"PRIx64": Match type: %s; Service Id: %"PRIx64,
	   *sub_id, match_type_str(match_type), service_id);

    if (generation != NULL)
	printf("; Generation: %"PRId64, *generation);
    if (ttl != NULL)
	printf("; TTL: %"PRId64, *ttl);
    if (orphan_since != NULL)
	printf("; Orphan: %.1f s until timeout",
	       orphan_left(*orphan_since, *ttl));
    if (props != NULL) {
	printf("; Properties: ");
	print_props(stdout, props);
    }

    printf("\n");
}

static void sub_complete_cb(int64_t ta_id, void *cb_data)
{
    int64_t *sub_id = cb_data;

    printf("Subscription %"PRIx64" canceled.\n", *sub_id);

    ut_free(sub_id);
}

static void run_subscribe(const char *cmd, const char *const *args, size_t num,
			  void *cb_data)
{
    const char *filter = num == 1 ? args[0] : NULL;

    int64_t *sub_id = ut_malloc(sizeof(int64_t));

    *sub_id = ut_rand_id();

    int64_t rc =
	conn_subscribe_nb(session.conn, *sub_id, filter, fail_cb, NULL,
			  sub_notify_cb, sub_complete_cb, sub_id);

    if (rc < 0) {
	ut_free(sub_id);
	cmd_failed(rc);
    } else {
	printf("Subscription Id %"PRIx64".\n", *sub_id);
	cmd_ok();
    }
}

#define UNSUBSCRIBE_CMD "unsubscribe"
#define UNSUBSCRIBE_CMD_HELP				\
    UNSUBSCRIBE_CMD " <subscription-id>\n"		\
    "    Remove a subscription.\n"

static void run_unsubscribe(const char *cmd, const char *const *args,
			    size_t num, void *cb_data)
{
    const char *sub_id_s = args[0];
    int64_t sub_id;

    if (ut_parse_uint63(sub_id_s, 16, &sub_id) < 0) {
	printf("\"%s\" is not a non-negative number in hexadecimal format.\n",
	       sub_id_s);
	return;
    }

    int rc = conn_unsubscribe(session.conn, sub_id);
    if (rc < 0)
	cmd_failed(rc);
    else
	cmd_ok();
}

#define SUBSCRIPTIONS_CMD "subscriptions"
#define SUBSCRIPTIONS_CMD_HELP						\
    SUBSCRIPTIONS_CMD "\n"						\
    "    List all subscriptions.\n"

static void print_sub(int64_t sub_id, int64_t client_id, const char *filter,
		      void *cb_data)

{
    printf("%-17"PRIx64" %-17"PRIx64"  %s\n", sub_id, client_id,
	   filter == NULL ? "-" : filter);
}

static void run_subscriptions(const char *cmd, const char *const *args,
			      size_t num, void *cb_data)
{
    printf("Subscription Id   Owner Id           Filter Expression\n");

    int rc = conn_subscriptions(session.conn, print_sub, NULL);

    if (rc < 0)
	cmd_failed(rc);
    else
	cmd_ok();
}

#define SERVICES_CMD "services"
#define SERVICES_CMD_HELP						\
    SERVICES_CMD " [<filter-expression>]\n"				\
    "    List all services (optionally matching the filter expression).\n"

static void print_service(int64_t service_id, int64_t generation,
			  const struct paf_props *props, int64_t ttl,
			  int64_t client_id, const double *orphan_since,
			  void *cb_data)

{
    char orphan_s[128];

    if (orphan_since != NULL) {
	double left = orphan_left(*orphan_since, ttl);
	snprintf(orphan_s, sizeof(orphan_s), "%6.1f", left);
    } else
	strcpy(orphan_s, "-");

    printf("%16"PRIx64" %4"PRId64" %4"PRId64" %11s  %-17"PRIx64"  ", service_id,
	   generation, ttl, orphan_s, client_id);

    print_props(stdout, props);

    printf("\n");
}

static void run_services(const char *cmd, const char *const *args,
			 size_t num, void *cb_data)
{
    const char *filter = num == 1 ? args[0] : NULL;

    printf("      Service Id  Gen  TTL  Orphan Tmo  Owner            "
	   "  Properties\n");

    int rc = conn_services(session.conn, filter, print_service, NULL);

    if (rc < 0)
	cmd_failed(rc);
    else
	cmd_ok();
}

#define PUBLISH_CMD "publish"
#define PUBLISH_CMD_HELP						\
    PUBLISH_CMD " [<service-id>] <generation> <ttl> [<prop-name> "	\
    "<prop-value>] ...\n"						\
    "    Publish a new service, or republish a service with updated\n"	\
    "    properties.\n"							\
    "\n"								\
    "    In case <prop-value> is an integer in decimal format, it will\n" \
    "    be added as an integer. Otherwise, the string property value type\n" \
    "    will be used. To force the use of strings, use '|<integer>|'\n" \
    "    (e.g. |4711|).\n"

#define TRY_PARSE_UINT63(str_value, base, int_ptr)			\
    do {								\
	if (ut_parse_uint63(str_value, base, int_ptr) < 0) {		\
	    const char *format = base == 16 ? "hexadecimal" : "decimal"; \
	    printf("\"%s\" is not a non-negative number in %s "		\
		   "format.\n", str_value, format);			\
	    return;							\
	}								\
    } while (0)

static void run_publish(const char *cmd, const char *const *args, size_t num,
			void *cb_data)
{
    const char *service_id_s = NULL;
    int offset = 0;

    if (num % 2 != 0)
	service_id_s = args[offset++];

    const char *generation_s = args[offset++];
    const char *ttl_s = args[offset++];

    int64_t service_id;
    if (service_id_s != NULL)
	TRY_PARSE_UINT63(service_id_s, 16, &service_id);
    else
	service_id = ut_rand_id();

    int64_t generation;
    TRY_PARSE_UINT63(generation_s, 10, &generation);

    int64_t ttl;
    TRY_PARSE_UINT63(ttl_s, 10, &ttl);

    struct paf_props *props = paf_props_create();

    size_t num_props = (num - offset) / 2;
    size_t i;
    for (i = 0; i < num_props; i++) {
	const char *prop_name = args[offset++];
	const char *prop_value = args[offset++];

	int64_t prop_int_value;
	if (ut_parse_int64(prop_value, 10, &prop_int_value) == 0)
	    paf_props_add_int64(props, prop_name, prop_int_value);
	else {
	    char prop_str_value[strlen(prop_value) + 1];
	    size_t len = strlen(prop_value);

	    /* |42| is a way to add integer-looking string as a string */
	    if (prop_value[0] != '|' && prop_value[len - 1] == '|') {
		/* skip quote chars */
		strncpy(prop_str_value, prop_value + 1, len - 2);
		prop_str_value[len - 2] = '\0';
	    } else
		strcpy(prop_str_value, prop_value);
		
	    paf_props_add_str(props, prop_name, prop_str_value);
	}
    }

    int rc = conn_publish(session.conn, service_id, generation, props, ttl);

    paf_props_destroy(props);

    if (rc < 0)
	cmd_failed(rc);
    else
	cmd_ok();
}

#define UNPUBLISH_CMD "unpublish"
#define UNPUBLISH_CMD_HELP				\
    UNPUBLISH_CMD " <service-id>\n"			\
    "    Unpublish a service.\n"

static void run_unpublish(const char *cmd, const char *const *args,
			    size_t num, void *cb_data)
{
    const char *service_id_s = args[0];
    int64_t service_id;

    if (ut_parse_uint63(service_id_s, 16, &service_id) < 0) {
	printf("\"%s\" is not a non-negative number in hexadecimal format.\n",
	       service_id_s);
	return;
    }

    int rc = conn_unpublish(session.conn, service_id);
    if (rc < 0)
	cmd_failed(rc);
    else
	cmd_ok();
}

#define CLIENTS_CMD "clients"
#define CLIENTS_CMD_HELP \
    CLIENTS_CMD "\n" \
    "    List connected clients.\n"

static void print_client(int64_t client_id, const char *client_addr,
			 int64_t connect_time, const double *idle,
			 const int64_t *proto_version, const double *latency,
			 void *cb_data)
{
    int total_secs = ut_ftime(CLOCK_REALTIME) - connect_time;
    int hours = total_secs / 3600;
    int mins = total_secs / 60;
    int secs = total_secs - hours * 3600 - mins * 60;
    char uptime_s[128];

    snprintf(uptime_s, sizeof(uptime_s), "%d:%02d:%02d", hours, mins, secs);

    char idle_s[64] = "-";
    char latency_s[64] = "-";
    char proto_version_s[64] = "-";

    if (idle != NULL)
	snprintf(idle_s, sizeof(idle_s), "%.3f", *idle);
    if (latency != NULL)
	snprintf(latency_s, sizeof(latency_s), "%.1f", (*latency) * 1e3);
    if (proto_version != NULL)
	snprintf(proto_version_s, sizeof(proto_version), "%"PRId64,
		 *proto_version);

    printf("%-16"PRIx64" %-17s %-10s %-10s %-10s    %s\n", client_id,
	   client_addr, uptime_s,idle_s, latency_s, proto_version_s);
}

static void run_clients(const char *cmd, const char *const *args, size_t num,
			void *cb_data)
{
    printf("Client Id        Remote Address    Uptime     Idle [s]   "
	   "Latency [ms]  Version\n");

    int rc = conn_clients(session.conn, print_client, NULL);
    if (rc < 0)
	cmd_failed(rc);
    else
	cmd_ok();
}

#define PING_CMD "ping"
#define PING_CMD_HELP				\
    PING_CMD "\n"				\
    "    Measure network and server latency.\n"

static void run_ping(const char *cmd, const char *const *args, size_t num,
		     void *cb_data)
{
    double start = ut_ftime(CLOCK_MONOTONIC);

    int rc = conn_ping(session.conn);
    if (rc < 0)
	cmd_failed(rc);
    else {
	double latency = ut_ftime(CLOCK_MONOTONIC) - start;

	printf("%.1f ms\n", latency * 1e3);

	cmd_ok();
    }
}

int session_init(int64_t client_id, const char *addr)
{
    struct server_conf server = {
	.addr = ut_strdup(addr),
	.proto_version_min = -1,
	.proto_version_max = -1
    };

    char log_ref[1024];

    if (client_id < 0)
	client_id = ut_rand_id();

    snprintf(log_ref, sizeof(log_ref), "client: %"PRId64, client_id);

    struct conn *conn = conn_connect(&server, client_id, log_ref);

    ut_free(server.addr);

    if (conn == NULL) {
	fprintf(stderr, "Unable to connect to \"%s\": %s.\n", addr,
		strerror(errno));
	goto err;
    }

    if (conn_hello(conn, NULL) < 0) {
	fprintf(stderr, "An error occured while attempt to connect "
		"to \"%s\": %s.\n", addr, strerror(errno));
	goto err_close;
    }

    session = (struct session) {
	.conn = conn,
	.track_ta_id = -1,
	.track_query_ts = -1
    };

    cli_init(LPAFC_PROMPT);

    cli_register(QUIT_CMD, 0, 0, QUIT_CMD_HELP, run_quit, NULL);
    cli_register(ID_CMD, 0, 0, ID_CMD_HELP, run_id, NULL);
    cli_register(HELLO_CMD, 0, 0, HELLO_CMD_HELP, run_hello, NULL);
    cli_register(TRACK_CMD, 0, 1, TRACK_CMD_HELP, run_track, NULL);
    cli_register(SUBSCRIBE_CMD, 0, 1, SUBSCRIBE_CMD_HELP, run_subscribe,
		 NULL);
    cli_register(UNSUBSCRIBE_CMD, 1, 1, UNSUBSCRIBE_CMD_HELP, run_unsubscribe,
		 NULL);
    cli_register(SUBSCRIPTIONS_CMD, 0, 0, SUBSCRIPTIONS_CMD_HELP,
		 run_subscriptions, NULL);
    cli_register(SERVICES_CMD, 0, 1, SERVICES_CMD_HELP, run_services, NULL);
    cli_register(PUBLISH_CMD, 2, 1024, PUBLISH_CMD_HELP, run_publish, NULL);
    cli_register(UNPUBLISH_CMD, 1, 1, UNPUBLISH_CMD_HELP, run_unpublish,
		 NULL);
    cli_register(CLIENTS_CMD, 0, 0, CLIENTS_CMD_HELP, run_clients, NULL);
    cli_register(PING_CMD, 0, 0, PING_CMD_HELP, run_ping, NULL);

    return 0;

err_close:
    conn_close(conn);
err:

    return -1;
}

int session_run(void)
{
    int conn_fd = conn_get_fd(session.conn);
    int stdin_fd = fileno(stdin);

    int rc;

    for (;;) {
	struct pollfd fds[2];

	fds[0] = (struct pollfd) {
	    .fd = stdin_fd,
	    .events = POLLIN
	};

	fds[1] = (struct pollfd) {
	    .fd = conn_fd,
	    .events = POLLIN
	};

	rc = poll(fds, UT_ARRAY_LEN(fds), -1);

	if (rc < 0) {
	    if (errno == EINTR)
		continue;
	    else
		break;
	}

	if (rc < 0)
	    break;

	if (fds[0].revents) {
	    cli_read_input();

	    if (cli_has_exited(&rc))
		break;
	}

	if (fds[1].revents) {
	    rc = conn_process(session.conn);

	    if (rc < 0)
		break;
	}
    }

    return rc;
}

void session_deinit(void)
{
    conn_close(session.conn);
    cli_deinit();
}
