/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <xcm.h>

#include "utest.h"
#include "util.h"
#include "testutil.h"

#include <paf.h>

//#define PAFD_DEBUG

static bool is_in_valgrind(void)
{
    return getenv("IN_VALGRIND") ? true : false;
}

#define REQUIRE_NOT_IN_VALGRIND \
    if (is_in_valgrind())	\
	return UTEST_NOT_RUN

static pid_t run_server(const char *addr)
{
    pid_t p = fork();

    if (p < 0)
        return -1;
    else if (p == 0) {
#ifdef PAFD_DEBUG
        execlp("pafd", "pafd", "-l", "debug", addr, NULL);
#else
        execlp("pafd", "pafd", addr, NULL);
#endif
        exit(EXIT_FAILURE);
    } else
        return p;
}

#define NUM_SERVERS (3)

static char *domains_dir;
static char *domain_name;
static char *domains_filename;
static char *domain_addrs[NUM_SERVERS];

static pid_t server_pids[NUM_SERVERS];

static int assure_server_up(const char *addr);

static int start_server(int idx)
{
    if (server_pids[idx] > 0)
	return UTEST_SUCCESS;

    pid_t server_pid = run_server(domain_addrs[idx]);

    if (server_pid < 0)
        return UTEST_FAIL;
    if (assure_server_up(domain_addrs[idx]) < 0)
        return UTEST_FAIL;

    server_pids[idx] = server_pid;

    return UTEST_SUCCESS;
}

static int start_servers(void)
{
    int i;
    for (i = 0; i < NUM_SERVERS; i++) {
	int rc = start_server(i);
	if (rc < 0)
	    return rc;
    }
    return UTEST_SUCCESS;
}

static void stop_server(int idx)
{
    if (server_pids[idx] > 0) {
        kill(server_pids[idx], SIGTERM);
        tu_waitstatus(server_pids[idx]);
        server_pids[idx] = -1;
    }
}

static void stop_servers(void)
{
    int i;
    for (i = 0; i < NUM_SERVERS; i++)
	stop_server(i);
}

static char *random_tcp_addr(void)
{
    int port = tu_randint(32768, 60999);
    printf("port %d\n", port);
    return ut_asprintf("tcp:127.0.0.1:%d", port);
}

static char *random_ux_addr(void)
{
    return ut_asprintf("ux:%d-%d", getpid(), tu_randint(0, INT_MAX));
}

static char *random_addr(void)
{
    if (tu_randint(0, 1))
	return random_tcp_addr();
    else
	return random_ux_addr();
}

static int domain_setup(void)
{
    domains_dir = ut_asprintf("./test/domains.d-%d", getpid());
    CHKNOERR(tu_executef_es("mkdir -p %s", domains_dir));

    domain_name = ut_asprintf("testdomain-%d", getpid());

    domains_filename = ut_asprintf("%s/%s", domains_dir, domain_name);

    FILE *domains_file = fopen(domains_filename, "w");

    CHK(domains_file != NULL);

    int i;
    for (i = 0; i < NUM_SERVERS; i++) {
	domain_addrs[i] = random_addr();
	fprintf(domains_file, "%s\n", domain_addrs[i]);
    }

    CHKNOERR(fclose(domains_file));

    return UTEST_SUCCESS;
}

#define AVG_RESCAN_PERIOD (2)
#define MAX_RESCAN_PERIOD (AVG_RESCAN_PERIOD * 1.5 + 0.25)

#define PAF_RECONNECT_MAX (0.1)
#define MAX_RECONNECT_PERIOD (PAF_RECONNECT_MAX + 0.2)

#define TTL (1)

static int setenv_double(const char *name, double value)
{
    char value_s[128];
    snprintf(value_s, sizeof(value_s), "%.6f", value);
    if (setenv(name, value_s, 1) < 0)
	return -1;
    return 0;
}

static int setup(void)
{
    int rc = domain_setup();
    if (rc < 0)
	return rc;
    
    if (setenv("PAF_DOMAINS", domains_dir, 1) < 0)
	return UTEST_FAIL;

    if (setenv_double("PAF_RESCAN", AVG_RESCAN_PERIOD) < 0)
	return UTEST_FAIL;

    if (setenv_double("PAF_RECONNECT_MAX", PAF_RECONNECT_MAX) < 0)
	return UTEST_FAIL;

    if (setenv_double("PAF_TTL", TTL) < 0)
	return UTEST_FAIL;

    return UTEST_SUCCESS;
}

static void domain_teardown(void)
{
    tu_executef("rm -f %s", domains_filename);
    tu_executef("rmdir %s", domains_dir);

    ut_free(domains_dir);
    ut_free(domain_name);
    ut_free(domains_filename);
    int i;
    for (i = 0; i < NUM_SERVERS; i++)
	ut_free(domain_addrs[i]);
}

static int teardown(void)
{
    stop_servers();

    domain_teardown();

    return UTEST_SUCCESS;
}

#define MAX_FDS (64)

static int wait_for_all(struct paf_context **contexts, size_t num_contexts,
                        double duration)
{
    double now = ut_ftime(CLOCK_REALTIME);
    double deadline = now + duration;

    for (; now < deadline; now = ut_ftime(CLOCK_REALTIME)) {
        double left = deadline - now;

        struct pollfd pollfds[MAX_FDS];

        size_t i;
        for (i = 0; i < num_contexts; i++) {
            int fd = paf_fd(contexts[i]);
            if (fd < 0)
                return -1;
            pollfds[i] = (struct pollfd) {
                .fd = fd,
                .events = POLLIN
            };
        }

        int rc = poll(pollfds, num_contexts, left * 1000);

        if (rc == 0) /* timeout */
            return 0;
        else if (rc < 0)
            return -1;

        for (i = 0; i < num_contexts; i++) {
	    int rc = paf_process(contexts[i]);
	    if (rc < 0)
		return rc;
	}
    }

    return 0;
}

static int wait_for(struct paf_context *context, double duration)
{
    return wait_for_all(&context, 1, duration);
}

#define TCLIENT "./test/tclient.py"

static void add_prop(const char *prop_name, const struct paf_value *prop_value,
                     void *user)
{
    char *cmd = user;

    snprintf(cmd+strlen(cmd), 1024, " %s ", prop_name);

    if (paf_value_is_str(prop_value))
        snprintf(cmd+strlen(cmd), 1024, "%s", paf_value_str(prop_value));
    else
        snprintf(cmd+strlen(cmd), 1024, "%"PRId64" ",
                 paf_value_int64(prop_value));
}

static int assure_server_up(const char *addr)
{
    return tu_executef_es(TCLIENT " %s assure-up", addr);
}

static int server_assure_service(const char *addr, int64_t service_id,
				 const struct paf_props *props)
{
    char cmd[4*1024];

    snprintf(cmd, sizeof(cmd), TCLIENT " %s assure-service",
             addr);

    if (service_id >= 0) 
        snprintf(cmd+strlen(cmd), sizeof(cmd)-strlen(cmd),
                 " %"PRIx64" ", service_id);
    else
        snprintf(cmd+strlen(cmd), sizeof(cmd)-strlen(cmd),
                 " any ");

    paf_props_foreach(props, add_prop, cmd);

    return tu_execute_es(cmd);
}

static int assure_service(int64_t service_id, const struct paf_props *props)
{
    int i;
    for (i = 0; i < NUM_SERVERS; i++) {
	int rc = server_assure_service(domain_addrs[i], service_id,
				       props);
	if (rc < 0)
	    return rc;
    }
    return UTEST_SUCCESS;
}

static int wait_for_service(struct paf_context *context,
			    double duration, int64_t service_id,
			    const struct paf_props *props)
{
    double deadline = ut_ftime(CLOCK_REALTIME) + duration;
    for (;;) {
	int rc = assure_service(service_id, props);
	if (rc == 0)
	    return UTEST_SUCCESS;
	if (ut_ftime(CLOCK_REALTIME) > deadline)
	    return UTEST_FAIL;
	wait_for(context, 0.1);
    }
}

static int server_assure_service_count(const char *addr, int count)
{
    return tu_executef_es(TCLIENT " %s assure-service-count %d", addr, count);
}

static int assure_service_count(int count)
{
    int i;
    for (i = 0; i < NUM_SERVERS; i++) {
	int rc = server_assure_service_count(domain_addrs[i], count);
	if (rc < 0)
	    return rc;
    }
    return UTEST_SUCCESS;
}

#if 0
static int wait_for_service_count(struct paf_context *context, double duration,
				  const char *addr, int count)
{
    double deadline = ut_ftime() + duration;
    for (;;) {
	int rc = assure_service_count(addr, count);
	if (rc == 0)
	    return UTEST_SUCCESS;
	if (ut_ftime() > deadline)
	    return UTEST_FAIL;
	wait_for(context, 0.1);
    }
}
#endif

static int server_assure_subscription(const char *addr, int64_t sub_id,
				      const char *filter)
{
    return tu_executef_es(TCLIENT " %s assure-subscription %"PRIx64" '%s'",
                          addr, sub_id, filter);
}

static int assure_subscription(int64_t sub_id, const char *filter)
{
    int i;
    for (i = 0; i < NUM_SERVERS; i++) {
	int rc = server_assure_subscription(domain_addrs[i], sub_id, filter);
	if (rc < 0)
	    return rc;
    }
    return UTEST_SUCCESS;
}

TESTSUITE(paf, setup, teardown)

TESTCASE(paf, publish_flaky_servers)
{
    struct paf_context *context = paf_attach(domain_name);

    CHK(context != NULL);

    const int64_t cellid = 17;

    struct paf_props *props = paf_props_create();
    paf_props_add_str(props, "name", "foo");
    paf_props_add_int64(props, "cellid", cellid);

    int64_t service_id = paf_publish(context, props);

    start_servers();

    CHK(service_id >= 0);

    CHKNOERR(wait_for(context, MAX_RECONNECT_PERIOD));

    CHKNOERR(assure_service(service_id, props));

    stop_servers();

    CHKNOERR(wait_for(context, 0.25));

    start_servers();

    CHKNOERR(wait_for(context, MAX_RECONNECT_PERIOD));

    CHKNOERR(assure_service(service_id, props));

    paf_close(context);

    paf_props_destroy(props);

    return UTEST_SUCCESS;
}

#define MANY (1000)

TESTCASE(paf, publish_unpublish_many)
{
    //REQUIRE_NOT_IN_VALGRIND;

    struct paf_context *context = paf_attach(domain_name);

    CHK(context != NULL);

    struct paf_props *base_props = paf_props_create();
    paf_props_add_str(base_props, "name", "foo");

    start_servers();

    int64_t service_ids[MANY];
    int i;
    for (i = 0; i < MANY; i++) {
        struct paf_props *props = paf_props_clone(base_props);
        paf_props_add_int64(props, "num", i);
        service_ids[i] = paf_publish(context, props);
        paf_props_destroy(props);
        CHK(service_ids[i] >= 0);
    }

    do {
        CHKNOERR(wait_for(context, 0.1));
    } while (assure_service_count(MANY) < 0);

    for (i = 0; i < 10; i++) {
        int num = rand() % MANY;
        struct paf_props *props = paf_props_clone(base_props);
        paf_props_add_int64(props, "num", num);
        CHKNOERR(assure_service(service_ids[num], props));
        paf_props_destroy(props);
    }

    for (i = 0; i < MANY; i++)
        paf_unpublish(context, service_ids[i]);

    do {
        CHKNOERR(wait_for(context, 0.1));
    } while (assure_service_count(0) < 0);

    paf_close(context);

    paf_props_destroy(base_props);

    stop_servers();

    return UTEST_SUCCESS;
}

static pid_t check_publish_latency(const char *domain_name,
				   double max_latency)
{
    pid_t p = fork();

    if (p < 0)
        return -1;
    else if (p > 0)
	return p;

    struct paf_context *context = paf_attach(domain_name);

    if (context == NULL)
	exit(EXIT_FAILURE);

    struct paf_props *props = paf_props_create();

    if (paf_publish(context, props) < 0)
	exit(EXIT_FAILURE);

    paf_props_destroy(props);

    if (wait_for(context, max_latency) < 0)
	exit(EXIT_FAILURE);

    if (assure_service_count(1) < 0)
	exit(EXIT_FAILURE);

    paf_close(context);


    exit(EXIT_SUCCESS);
}

TESTCASE_SERIALIZED(paf, connect_publish_latency_retry)
{
    REQUIRE_NOT_IN_VALGRIND;

    pid_t client_pid =
	check_publish_latency(domain_name, MAX_RECONNECT_PERIOD + 0.2);
    
    CHKNOERR(client_pid);

    tu_msleep(100);

    start_servers();

    CHKNOERR(tu_waitstatus(client_pid));

    stop_servers();

    return UTEST_SUCCESS;
}

TESTCASE(paf, connect_publish_latency_no_retry)
{
    REQUIRE_NOT_IN_VALGRIND;

    start_servers();
    tu_msleep(100);

    pid_t client_pid =
	check_publish_latency(domain_name, 0.05);

    CHKNOERR(client_pid);

    CHKNOERR(tu_waitstatus(client_pid));

    stop_servers();

    return UTEST_SUCCESS;
}

enum sync_mode {
    sync_mode_synced,
    sync_mode_unsynced
};

static int test_modify(enum sync_mode mode)
{
    struct paf_context *context = paf_attach(domain_name);

    CHK(context != NULL);

    struct paf_props *orig_props = paf_props_create();
    paf_props_add_str(orig_props, "name", "foo");
    paf_props_add_int64(orig_props, "cellid", 42);

    if (mode == sync_mode_synced)
        start_servers();

    int64_t service_id = paf_publish(context, orig_props);

    CHK(service_id >= 0);

    CHKNOERR(wait_for(context, MAX_RECONNECT_PERIOD));

    struct paf_props *mod_props = paf_props_create();
    paf_props_add_str(mod_props, "name", "foo");
    paf_props_add_int64(mod_props, "cellid", 99);

    CHKNOERR(paf_modify(context, service_id, mod_props));

    if (mode == sync_mode_unsynced)
        start_servers();

    CHKNOERR(wait_for(context, MAX_RECONNECT_PERIOD));

    CHKNOERR(assure_service(service_id, mod_props));

    stop_servers();

    paf_props_destroy(orig_props);
    paf_props_destroy(mod_props);
    paf_close(context);

    return UTEST_SUCCESS;

}

TESTCASE(paf, modify_unsynced)
{
    return test_modify(sync_mode_unsynced);
}

TESTCASE(paf, modify_synced)
{
    return test_modify(sync_mode_synced);
}

static void count_match_cb(enum paf_match_type match_type, int64_t service_id,
                           const struct paf_props *props, void *user)
{
    int *hits = user;
    if (hits != NULL)
        (*hits)++;
}

static pid_t __attribute__ ((noinline))
bg_publisher(const char *domain_name,
	     const struct paf_props *props, double duration)
{
    pid_t pid = fork();

    if (pid < 0)
        return -1;
    else if (pid == 0) {
        struct paf_context *context = paf_attach(domain_name);
        if (!context)
            exit(EXIT_FAILURE);
        paf_publish(context, props);
        if (wait_for(context, duration) < 0)
            exit(EXIT_FAILURE);
        paf_close(context);
        exit(EXIT_SUCCESS);
    } else
        return pid;
}

TESTCASE(paf, subscribe_flaky_server)
{
    struct paf_context *context = paf_attach(domain_name);

    int hits = 0;

    const char *filter_s = "(name=foo)";
    int64_t sub_id = paf_subscribe(context, filter_s, count_match_cb, &hits);

    struct paf_props *props = paf_props_create();
    paf_props_add_str(props, "name", "foo");

    const double publish_duration = MAX_RECONNECT_PERIOD * 4;
    pid_t bg_pid = bg_publisher(domain_name, props, publish_duration);

    CHKNOERR(bg_pid);

    start_servers();

    do {
	CHKNOERR(wait_for(context, 0.1));
    } while (hits != 1 ||
	     assure_service(-1, props) < 0 ||
	     assure_subscription(sub_id, filter_s) < 0);

    stop_servers();

    CHKNOERR(wait_for(context, 0.1));

    start_servers();

    do {
	CHKNOERR(wait_for(context, 0.1));
    } while (assure_service(-1, props) < 0 ||
	     assure_subscription(sub_id, filter_s) < 0);

    /* the library should have filtered the 'appeared' event, since
       this is a previously known service */
    CHK(hits == 1);

    while (hits != 2)
        CHKNOERR(wait_for(context, 0.1));

    paf_close(context);

    paf_props_destroy(props);

    CHKNOERR(tu_waitstatus(bg_pid));

    return UTEST_SUCCESS;
}

TESTCASE(paf, subscription_match)
{
    struct paf_context *context = paf_attach(domain_name);

    const char *filter_s = "(|(name=foo)(name=bar))";
    int hits = 0;
    int64_t sub_id = paf_subscribe(context, filter_s, count_match_cb, &hits);

    CHKNOERR(sub_id);

    start_servers();

    struct paf_props *props = paf_props_create();
    paf_props_add_str(props, "name", "bar");

    int64_t service_id = paf_publish(context, props);

    paf_props_destroy(props);

    CHKNOERR(service_id);

    while (hits == 0)
        CHKNOERR(wait_for(context, 0.1));

    CHKINTEQ(hits, 1);

    paf_close(context);

    stop_servers();

    return UTEST_SUCCESS;
}

TESTCASE(paf, match_with_most_servers_down)
{
    start_servers();

    struct paf_context *sub_context = paf_attach(domain_name);
    struct paf_context *pub_context = paf_attach(domain_name);
    struct paf_context *contexts[] = { pub_context, sub_context };

    struct paf_props *props = paf_props_create();
    paf_props_add_str(props, "name", "foo");
    int64_t service_id = paf_publish(pub_context, props);
    CHKNOERR(service_id);

    CHKNOERR(wait_for_all(contexts, 2, 0.1));

    int i;
    for (i = 0; i < (NUM_SERVERS-1); i++)
	stop_server(i);

    int hits = 0;
    CHKNOERR(paf_subscribe(sub_context, "(|(name=*)(age=42))",
			   count_match_cb, &hits));

    do {
	CHKNOERR(wait_for_all(contexts, 2, 0.1));
    } while (hits != 1);

    paf_props_destroy(props);
    paf_close(sub_context);
    paf_close(pub_context);

    return UTEST_SUCCESS;
}

#define NAME "*name*"
#define VALUE "()<>;"

static void escaped_match_cb(enum paf_match_type match_type,
                             int64_t service_id, const struct paf_props *props,
                             void *user)
{
    int *hits = user;

    if (props != NULL && paf_props_num_values(props) == 1) {
        const struct paf_value *value = paf_props_get_one(props, NAME);
        if (value && paf_value_is_str(value) &&
            strcmp(paf_value_str(value), VALUE) == 0)
            (*hits)++;
    }
}

TESTCASE(paf, subscription_escaped)
{
    struct paf_context *context = paf_attach(domain_name);

    char *fname = paf_filter_escape(NAME);
    char *fvalue = paf_filter_escape(VALUE);
    char filter_s[128];
    snprintf(filter_s, sizeof(filter_s), "(%s=%s)", fname , fvalue);

    free(fname);
    free(fvalue);

    int hits = 0;
    int64_t sub_id = paf_subscribe(context, filter_s, escaped_match_cb, &hits);

    CHKNOERR(sub_id);

    start_servers();

    struct paf_props *props = paf_props_create();
    paf_props_add_str(props, NAME, VALUE);

    int64_t service_id = paf_publish(context, props);

    paf_props_destroy(props);

    CHKNOERR(service_id);

    while (hits == 0)
        CHKNOERR(wait_for(context, 0.1));

    CHKINTEQ(hits, 1);

    paf_close(context);

    stop_servers();

    return UTEST_SUCCESS;
}

enum timeout_mode {
    timeout_mode_server_unavailable,
    timeout_mode_client_disconnect
};

static int test_timeout(enum timeout_mode mode) {
    struct paf_context *sub_context = paf_attach(domain_name);

    int hits = 0;
    int64_t sub_id = paf_subscribe(sub_context, NULL, count_match_cb, &hits);

    CHKNOERR(sub_id);

    start_servers();

    struct paf_context *pub_context = paf_attach(domain_name);

    struct paf_props *props = paf_props_create();

    CHKNOERR(paf_publish(pub_context, props));

    paf_props_destroy(props);

    do {
        struct paf_context *contexts[] = { pub_context, sub_context };
        CHKNOERR(wait_for_all(contexts, 2, 0.1));
    } while (hits != 1);

    double start = ut_ftime(CLOCK_REALTIME);

    if (mode == timeout_mode_server_unavailable)
        stop_servers();
    else
        paf_close(pub_context);

    do {
        if (mode == timeout_mode_server_unavailable)
            CHKNOERR(wait_for(pub_context, 0.01));
        CHKNOERR(wait_for(sub_context, 0.01));
    } while (hits == 1);

    double latency = ut_ftime(CLOCK_REALTIME) - start;

    CHKINTEQ(hits, 2);

    CHK(latency > TTL);
    CHK(latency < (TTL+0.5));

    paf_close(sub_context);

    if (mode == timeout_mode_server_unavailable)
        paf_close(pub_context);
    else
        stop_servers();

    return UTEST_SUCCESS;
}

TESTCASE(paf, match_timeout_after_server_unavailability)
{
    return test_timeout(timeout_mode_server_unavailable);
}

TESTCASE(paf, match_timeout_after_client_disconnect)
{
    return test_timeout(timeout_mode_client_disconnect);
}

TESTCASE(paf, invalid_filter)
{
    start_servers();

    struct paf_context *context = paf_attach(domain_name);

    const char *invalid_filter_s = "(name=foo))";

    CHKINTEQ(paf_subscribe(context, invalid_filter_s, count_match_cb, NULL),
             PAF_ERR_INVALID_FILTER_SYNTAX);

    paf_close(context);

    stop_servers();

    return UTEST_SUCCESS;
}

TESTCASE(paf, unsubscribe_unsynced)
{
    struct paf_context *sub_context = paf_attach(domain_name);

    int hits = 0;
    int64_t sub_id = paf_subscribe(sub_context, NULL, count_match_cb, &hits);

    CHKNOERR(sub_id);

    CHKNOERR(wait_for(sub_context, 0.1));

    paf_unsubscribe(sub_context, sub_id);

    struct paf_context *pub_context = paf_attach(domain_name);

    struct paf_props *props = paf_props_create();

    int64_t service_id = paf_publish(pub_context, props);

    CHK(service_id >= 0);

    CHKINTEQ(hits, 0);

    start_servers();

    struct paf_context *contexts[] = { sub_context, pub_context };
    wait_for_all(contexts, sizeof(contexts)/sizeof(contexts[0]),
                 MAX_RECONNECT_PERIOD);

    CHKINTEQ(hits, 0);

    paf_props_destroy(props);
    paf_close(sub_context);
    paf_close(pub_context);

    return UTEST_SUCCESS;
}

TESTCASE(paf, unsubscribe_synced)
{
    struct paf_context *sub_context = paf_attach(domain_name);

    start_servers();

    int hits = 0;
    int64_t sub_id = paf_subscribe(sub_context, NULL, count_match_cb, &hits);

    CHKNOERR(sub_id);

    CHKNOERR(wait_for(sub_context, 0.25));

    struct paf_context *pub_context = paf_attach(domain_name);

    struct paf_props *props = paf_props_create();

    int64_t service_id = paf_publish(pub_context, props);

    CHK(service_id >= 0);

    struct paf_context *contexts[] = { sub_context, pub_context };
    wait_for_all(contexts, sizeof(contexts)/sizeof(contexts[0]),
                 MAX_RECONNECT_PERIOD);

    CHKINTEQ(hits, 1);

    paf_unsubscribe(sub_context, sub_id);

    wait_for(sub_context, 0.25);

    int64_t service_id_2 = paf_publish(pub_context, props);

    CHK(service_id_2 >= 0);

    wait_for_all(contexts, sizeof(contexts)/sizeof(contexts[0]), 0.25);

    CHKINTEQ(hits, 1);

    paf_props_destroy(props);
    paf_close(sub_context);
    paf_close(pub_context);

    return UTEST_SUCCESS;
}

#define NUM_SUBSCRIPTIONS (100)

TESTCASE(paf, unsubscribe_syncing)
{
    struct paf_context *context = paf_attach(domain_name);

    start_servers();

    int hits = 0;
    size_t i;
    for (i = 0; i < NUM_SUBSCRIPTIONS; i++) {
        int64_t sub_id = paf_subscribe(context, NULL, count_match_cb, &hits);
        CHK(sub_id >= 0);
        paf_unsubscribe(context, sub_id);
    }

    CHKNOERR(wait_for(context, 0.25));

    struct paf_props *props = paf_props_create();

    int64_t service_id = paf_publish(context, props);

    CHK(service_id >= 0);

    wait_for(context, 0.25);

    CHKINTEQ(hits, 0);

    stop_servers();

    paf_props_destroy(props);
    paf_close(context);

    return UTEST_SUCCESS;
}

TESTCASE(paf, no_matches_after_unsubscribe)
{
    struct paf_context *context = paf_attach(domain_name);

    start_servers();

    int hits = 0;
    int64_t sub_id = paf_subscribe(context, NULL, count_match_cb, &hits);

    CHKNOERR(sub_id);

    CHKNOERR(wait_for(context, MAX_RECONNECT_PERIOD));

    struct paf_props *props = paf_props_create();

    int64_t service_id = paf_publish(context, props);

    CHK(service_id >= 0);

    CHKINTEQ(hits, 0);

    paf_unsubscribe(context, sub_id);

    CHKNOERR(wait_for(context, 0.25));

    CHKINTEQ(hits, 0);

    paf_props_destroy(props);
    paf_close(context);

    stop_servers();

    return UTEST_SUCCESS;
}

static int test_detach(bool with_server, bool manual_unpublish,
                       size_t service_count)
{
    struct paf_context *context = paf_attach(domain_name);

    if (with_server)
        start_servers();

    struct paf_props *props = paf_props_create();

    int64_t service_ids[service_count];

    size_t i;
    for (i = 0; i < service_count; i++) {
        service_ids[i] = paf_publish(context, props);
        CHK(service_ids[i] >= 0);
    }

    paf_props_destroy(props);

    if (with_server) {
        do {
            CHKNOERR(wait_for(context, 0.1));
        } while (assure_service_count(service_count) < 0);
    }

    for (i = 0; i < service_count && manual_unpublish; i++)
        paf_unpublish(context, service_ids[i]);

    paf_process(context);

    paf_detach(context);

    wait_for(context, 0.25);

    CHKINTEQ(paf_process(context), PAF_ERR_DETACHED);

    paf_close(context);

    if (with_server) {
        CHKNOERR(assure_service_count(0));
        stop_servers();
    }

    return UTEST_SUCCESS;
}

#define DETACH_NUM_SERVICES (16)
TESTCASE(paf, detach_attempts_unpublish_pending)
{
    return test_detach(true, true, DETACH_NUM_SERVICES);
}

TESTCASE(paf, detach_auto_unpublish_no_server)
{
    return test_detach(false, false, DETACH_NUM_SERVICES);
}

TESTCASE(paf, detach_auto_unpublish_server)
{
    return test_detach(true, false, DETACH_NUM_SERVICES);
}

TESTCASE(paf, detach_no_services)
{
    return test_detach(true, true, 0);
}

TESTCASE(paf, detach_no_server)
{
    return test_detach(false, true, DETACH_NUM_SERVICES);
}

#if 0
TESTCASE(paf, detach_unresponsive_server)
{
    start_servers();

    struct paf_context *context = paf_attach(domain_name);

    CHK(context != NULL);

    struct paf_props *props = paf_props_create();
    CHKNOERR(paf_publish(context, props));

    CHKNOERR(wait_for_service_count(context, 1, domain_addr, 1));

    CHKNOERR(kill(server_pid, SIGSTOP));

    paf_detach(context);

    CHKINTEQ(wait_for(context, 1), PAF_ERR_DETACHED);

    paf_props_destroy(props);
    paf_close(context);

    CHKNOERR(kill(server_pid, SIGCONT));

    return UTEST_SUCCESS;
}
#endif

TESTCASE(paf, create_domains_file)
{
    start_servers();
    char *tmp_domains_filename = ut_asprintf("%s.tmp", domains_filename);
    CHKNOERR(rename(domains_filename, tmp_domains_filename));

    struct paf_context *context = paf_attach(domain_name);

    struct paf_props *props = paf_props_create();
    paf_props_add_str(props, "name", "abc");
    int64_t service_id = paf_publish(context, props);
    CHKNOERR(service_id);
    CHKNOERR(wait_for(context, 0.25));

    CHKNOERR(rename(tmp_domains_filename, domains_filename));

    CHKNOERR(wait_for_service(context, MAX_RESCAN_PERIOD,
			      service_id, props));

    paf_detach(context);

    CHKINTEQ(wait_for(context, 1), PAF_ERR_DETACHED);

    ut_free(tmp_domains_filename);
    paf_props_destroy(props);
    paf_close(context);

    return UTEST_SUCCESS;
}

TESTCASE(paf, change_domains_file)
{
    if (NUM_SERVERS == 1)
	return UTEST_NOT_RUN;

    start_servers();

    CHKNOERR(tu_executef_es("echo '%s' > %s", domain_addrs[0],
			    domains_filename));

    struct paf_context *context = paf_attach(domain_name);

    struct paf_props *props = paf_props_create();
    paf_props_add_str(props, "name", "abc");
    int64_t service_id = paf_publish(context, props);
    CHKNOERR(service_id);

    CHKNOERR(wait_for(context, 0.25));

    CHKNOERR(server_assure_service(domain_addrs[0], service_id, props));
    CHK(server_assure_service(domain_addrs[1], service_id, props) < 0);

    CHKNOERR(tu_executef_es("echo '%s' > %s", domain_addrs[1],
			    domains_filename));

    CHKNOERR(wait_for(context, MAX_RESCAN_PERIOD));

    CHKNOERR(server_assure_service(domain_addrs[1], service_id, props));
    CHK(server_assure_service(domain_addrs[0], service_id, props) < 0);

    paf_detach(context);

    paf_props_destroy(props);
    paf_close(context);

    return UTEST_SUCCESS;
}

pid_t fake_server(double duration, double reconnect_min,
		  double reconnect_max, const char *addr)
{
    pid_t p = fork();

    if (p < 0)
        return -1;
    else if (p > 0)
	return p;

    struct xcm_socket *server_socket = xcm_server(addr);

    if (server_socket == NULL)
	exit(EXIT_FAILURE);


    double deadline = ut_ftime(CLOCK_REALTIME) + duration;
    int i;
    for (i = 0; ut_ftime(CLOCK_REALTIME) < deadline; i++) {
	double period_start = ut_ftime(CLOCK_REALTIME);
	struct xcm_socket *client = xcm_accept(server_socket);
	xcm_close(client);

	if (i == 0)
	    continue;

	double period = ut_ftime(CLOCK_REALTIME) - period_start;

	if (period < reconnect_min)
	    exit(EXIT_FAILURE);
	if (period > (reconnect_max + 0.25))
	    exit(EXIT_FAILURE);
    }
    exit(EXIT_SUCCESS);
}

TESTCASE(paf, reconnect)
{
    REQUIRE_NOT_IN_VALGRIND;

    double reconnect_min = 0.1;
    double reconnect_max = 1.0;
    double duration = reconnect_max * 2;

    if (setenv_double("PAF_RECONNECT_MAX", reconnect_max) < 0)
	return UTEST_FAIL;
    if (setenv_double("PAF_RECONNECT_MIN", reconnect_min) < 0)
	return UTEST_FAIL;

    pid_t pid = fake_server(duration, reconnect_min, reconnect_max,
			    domain_addrs[0]);

    tu_msleep(100);
    
    struct paf_context *context = paf_attach(domain_name);

    double deadline =
	ut_ftime(CLOCK_REALTIME) + duration + reconnect_max + 0.25;
    while (ut_ftime(CLOCK_REALTIME) < deadline)
	CHKNOERR(wait_for(context, 0.1));

    CHKNOERR(tu_waitstatus(pid));

    paf_close(context);

    return UTEST_SUCCESS;
}

#define PROP_COUNT (1000)
#define NAME_LEN (1000)
#define VALUE_LEN (1000)

TESTCASE(paf, crazy_large_props)
{
    struct paf_context *context = paf_attach(domain_name);

    struct paf_props *large_props = paf_props_create();
    size_t i;
    for (i = 0; i < PROP_COUNT; i++) {
        char name[NAME_LEN+1];
        memset(name, 'n', NAME_LEN);
        snprintf(name, NAME_LEN+1, "%zd", i);
        name[NAME_LEN] = '\0';

        char value[VALUE_LEN+1];
        memset(value, 'b', VALUE_LEN);
        value[VALUE_LEN] = '\0';

        paf_props_add_str(large_props, name, value);
    }

    CHKINTEQ(paf_publish(context, large_props), PAF_ERR_PROPS_TOO_LARGE);

    struct paf_props *small_props = paf_props_create();
    int64_t service_id = paf_publish(context, small_props);

    CHKINTEQ(paf_modify(context, service_id, large_props),
             PAF_ERR_PROPS_TOO_LARGE);

    paf_props_destroy(small_props);
    paf_props_destroy(large_props);
    paf_close(context);

    return UTEST_SUCCESS;
}

#define FILTER_SIZE (1024*1024)

TESTCASE(paf, crazy_large_filter)
{
    struct paf_context *context = paf_attach(domain_name);

    char *filter = ut_malloc(FILTER_SIZE+1);

    memset(filter, 'a', FILTER_SIZE);
    filter[0] = '(';
    filter[FILTER_SIZE-3] = '=';
    filter[FILTER_SIZE-2] = '*';
    filter[FILTER_SIZE-1] = ')';
    filter[FILTER_SIZE] = '\0';

    CHKINTEQ(paf_subscribe(context, filter, count_match_cb, NULL),
             PAF_ERR_FILTER_TOO_LARGE);

    ut_free(filter);

    paf_close(context);

    return UTEST_SUCCESS;
}

TESTCASE(paf, escape)
{
    char *s = paf_filter_escape("foo");
    CHKSTREQ(s, "foo");
    free(s);

    s = paf_filter_escape("");
    CHKSTREQ(s, "");
    free(s);

    s = paf_filter_escape("\\");
    CHKSTREQ(s, "\\\\");
    free(s);

    s = paf_filter_escape("*foo*");
    CHKSTREQ(s, "\\*foo\\*");
    free(s);

    s = paf_filter_escape("a=()b");
    CHKSTREQ(s, "a\\=\\(\\)b");
    free(s);

    s = paf_filter_escape("<>");
    CHKSTREQ(s, "\\<\\>");
    free(s);

    return UTEST_SUCCESS;
}

TESTCASE(paf, strerror)
{
    CHKSTREQ(paf_strerror(PAF_ERR), "Generic error");
    CHKSTREQ(paf_strerror(PAF_ERR_PROPS_TOO_LARGE),
             "Service properties too large");
    CHKSTREQ(paf_strerror(PAF_ERR_BUFFER_TOO_SMALL),
             "Buffer too small");
    CHKSTREQ(paf_strerror(PAF_ERR_FILTER_TOO_LARGE),
             "Filter too large");
    CHKSTREQ(paf_strerror(PAF_ERR_INVALID_FILTER_SYNTAX),
             "Invalid filter syntax");
    CHKSTREQ(paf_strerror(-234234234), "Unknown error");

    CHK(PAF_IS_ERR(PAF_ERR_INVALID_FILTER_SYNTAX));
    CHK(!PAF_IS_ERR(0));

    return UTEST_SUCCESS;
}
