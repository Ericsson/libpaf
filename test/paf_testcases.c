/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <xcm.h>
#include <xcm_addr.h>
#include <xcm_version.h>

#include "testutil.h"
#include "utest.h"
#include "util.h"

#include <paf.h>

//#define PAFD_DEBUG

static bool is_in_valgrind(void)
{
    return getenv("IN_VALGRIND") ? true : false;
}

#define REQUIRE_NOT_IN_VALGRIND \
    if (is_in_valgrind())	\
	return UTEST_NOT_RUN

#define CERT_BASE_DIR "./test/cert"

#define SERVER_CERT_DIR CERT_BASE_DIR "/server"
#define SERVER_CERT SERVER_CERT_DIR "/cert.pem"
#define SERVER_KEY SERVER_CERT_DIR "/key.pem"
#define SERVER_TC SERVER_CERT_DIR "/tc.pem"

#define CLIENT_CERT_DIR CERT_BASE_DIR "/client"
#define CLIENT_CERT CLIENT_CERT_DIR "/cert.pem"
#define CLIENT_KEY CLIENT_CERT_DIR "/key.pem"
#define CLIENT_TC CLIENT_CERT_DIR "/tc.pem"

#define EMPTY_CRL CLIENT_CERT_DIR "/empty-crl.pem"
#define REVOKED_SERVER_CERT_CRL CLIENT_CERT_DIR "/revoked-server-crl.pem"

#define UNTRUSTED_CLIENT_CERT_DIR CERT_BASE_DIR "/untrusted_client"
#define UNTRUSTED_CLIENT_CERT UNTRUSTED_CLIENT_CERT_DIR "/cert.pem"
#define UNTRUSTED_CLIENT_KEY UNTRUSTED_CLIENT_CERT_DIR "/key.pem"
#define UNTRUSTED_CLIENT_TC UNTRUSTED_CLIENT_CERT_DIR "/tc.pem"

#define REQUIRE_NO_LOCAL_PORT_BIND (1U << 0)

static bool is_proto(const char *addr, const char *proto)
{
    char actual_proto[16];
    xcm_addr_parse_proto(addr, actual_proto, sizeof(actual_proto));

    return strcmp(actual_proto, proto) == 0;
}

static bool is_tcp(const char *addr)
{
    return is_proto(addr, XCM_TCP_PROTO);
}

static bool is_tls(const char *addr)
{
    return is_proto(addr, XCM_TLS_PROTO) || is_proto(addr, XCM_UTLS_PROTO);
}

static bool is_tcp_based(const char *addr)
{
    return is_tcp(addr) || is_tls(addr);
}

static pid_t run_server(const char *net_ns, const char *addr)
{
    pid_t p = fork();

    if (p < 0)
        return -1;
    else if (p == 0) {

	if (setenv("XCM_TLS_CERT", SERVER_CERT_DIR, 1) < 0)
	    exit(EXIT_FAILURE);

	if (net_ns != NULL && ut_net_ns_enter(net_ns) < 0)
	    exit(EXIT_FAILURE);

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

struct server {
    char *net_ns;
    char *addr;
    char *local_addr;
    pid_t pid;
} server;

static struct server servers[NUM_SERVERS];

static int assure_server_up(struct server *server);

static void server_clear(struct server *server)
{
    ut_free(server->net_ns);
    ut_free(server->addr);
    ut_free(server->local_addr);
    server->net_ns = NULL;
    server->addr = NULL;
}

static int server_start(struct server *server)
{
    if (server->pid > 0)
	return UTEST_SUCCESS;

    pid_t server_pid = run_server(server->net_ns, server->addr);

    if (server_pid < 0)
        return UTEST_FAILED;
    if (assure_server_up(server) < 0)
        return UTEST_FAILED;

    server->pid = server_pid;

    return UTEST_SUCCESS;
}

static int start_servers(void)
{
    int i;
    for (i = 0; i < NUM_SERVERS; i++) {
	int rc = server_start(&servers[i]);
	if (rc < 0)
	    return rc;
    }
    return UTEST_SUCCESS;
}

static int signal_server(struct server *server, int signo)
{
    return server->pid >= 0 ? kill(server->pid, signo) : -1;
}

static int signal_servers(int signo)
{
    int rc = 0;
    int i;
    for (i = 0; i < NUM_SERVERS; i++) {
	struct server *server = &servers[i];
	if (server->pid > 0 && signal_server(server, signo) < 0)
	    rc = -1;
    }
    return rc;
}

static int server_stop(struct server *server)
{
    if (signal_server(server, SIGTERM) < 0)
	return -1;

    if (tu_waitstatus(server->pid) < 0)
	return -1;

    server->pid = -1;

    return 0;
}

static int stop_servers(void)
{
    int rc = 0;
    int i;

    for (i = 0; i < NUM_SERVERS; i++) {
	struct server *server = &servers[i];
	if (server->pid > 0 && server_stop(server) < 0)
	    rc = -1;
    }

    return rc;
}

static uint16_t gen_tcp_port(void)
{
    return tu_randint(15000, 25000);
}

static char *localhost_port_addr(const char *proto, uint16_t port)
{
    return ut_asprintf("%s:127.0.0.1:%d", proto, port);
}

static char *gen_localhost_port_addr(const char *proto)
{
    return localhost_port_addr(proto, gen_tcp_port());
}

static char *random_tls_addr(void)
{
    return gen_localhost_port_addr("tls");
}

static char *random_tcp_addr(void)
{
    return gen_localhost_port_addr("tcp");
}

static char *random_ux_addr(void)
{
    return ut_asprintf("ux:%d-%d", getpid(), tu_randint(0, INT_MAX));
}

static char *random_addr(void)
{
    int type = tu_randint(0, 2);

    switch (type) {
    case 0:
	return random_tls_addr();
    case 1:
	return random_tcp_addr();
    default:
	return random_ux_addr();
    }
}

static char *random_local_addr(const char *addr,
			       bool force_kernel_allocated_port)
{
    if (!is_tcp_based(addr))
	return NULL;

    bool has_local = tu_randbool();

    if (!has_local)
	return NULL;

    uint16_t port;
    if (force_kernel_allocated_port || tu_randbool())
	port = 0;
    else
	port = gen_tcp_port();

    char proto[16];
    xcm_addr_parse_proto(addr, proto, sizeof(proto));

    return localhost_port_addr(proto, port);
}

static char *random_net_ns(void)
{
    return ut_asprintf("ns-%d-%d", getpid(), tu_randint(0, INT_MAX));
}

static int write_nl_domains_file(const char *filename, struct server *servers,
				 size_t num_servers)
{
    FILE *domains_file = fopen(filename, "w");

    if (domains_file == NULL)
	return -1;

    int i;
    for (i = 0; i < num_servers; i++)
	if (fprintf(domains_file, "%s\n", servers[i].addr) < 0)
	    return -1;

    if (fclose(domains_file) < 0)
	return -1;

    return 0;
}

static int write_json_domain_file(const char *filename,
				  const char *cert_file,
				  const char *key_file,
				  const char *tc_file,
				  const char *crl_file,
				  struct server *servers, size_t num_servers)
{
    FILE *domains_file = fopen(filename, "w");

    if (domains_file == NULL)
	return -1;

    fprintf(domains_file, "{\n  \"servers\": [\n");

    if (cert_file != NULL && key_file != NULL && tc_file != NULL &&
	crl_file != NULL && unsetenv("XCM_TLS_CERT") < 0)
	return -1;

    int i;
    for (i = 0; i < num_servers; i++) {
	struct server *server = &servers[i];
	fprintf(domains_file, "    {\n"
		"      \"address\": \"%s\"", server->addr);

	if (server->local_addr != NULL)
	    fprintf(domains_file, ",\n"
		    "      \"localAddress\": \"%s\"", server->local_addr);

	if (server->net_ns != NULL)
	    fprintf(domains_file, ",\n"
		    "      \"networkNamespace\": \"%s\"", server->net_ns);

	if (is_tls(server->addr) && cert_file != NULL)
	    fprintf(domains_file, ",\n"
		    "      \"tlsCertificateFile\": \"%s\"", cert_file);
	if (is_tls(server->addr) && key_file != NULL)
	    fprintf(domains_file, ",\n"
		    "      \"tlsKeyFile\": \"%s\"", key_file);
	if (is_tls(server->addr) && tc_file != NULL)
	    fprintf(domains_file, ",\n"
		    "      \"tlsTrustedCaFile\": \"%s\"", tc_file);
	if (is_tls(server->addr) && crl_file != NULL)
	    fprintf(domains_file, ",\n"
		    "      \"tlsCrlFile\": \"%s\"", crl_file);

	fprintf(domains_file, "\n"
		"    }");

	if (i != (num_servers - 1))
	    fprintf(domains_file, ",");

        fprintf(domains_file, "\n");
    }

    fprintf(domains_file, "  ]\n}\n");

    if (fclose(domains_file) < 0)
	return -1;

    return 0;
}

static int cert_setup(const char *ns_name)
{
    int rc;

    rc = tu_executef_es("cp %s %s/cert_%s.pem && "
			"cp %s %s/key_%s.pem && "
			"cp %s %s/tc_%s.pem",
			CLIENT_CERT, CLIENT_CERT_DIR, ns_name,
			CLIENT_KEY, CLIENT_CERT_DIR, ns_name,
			CLIENT_TC, CLIENT_CERT_DIR, ns_name);
    if (rc != 0)
	return -1;

    rc = tu_executef_es("cp %s %s/cert_%s.pem && "
			"cp %s %s/key_%s.pem && "
			"cp %s %s/tc_%s.pem",
			SERVER_CERT, SERVER_CERT_DIR, ns_name,
			SERVER_KEY, SERVER_CERT_DIR, ns_name,
			SERVER_TC, SERVER_CERT_DIR, ns_name);
    if (rc != 0)
	return -1;

    return 0;
}

static int cert_teardown(const char *ns_name)
{
    int rc = tu_executef_es("rm %s/cert_%s.pem %s/key_%s.pem %s/tc_%s.pem "
			    "%s/cert_%s.pem %s/key_%s.pem %s/tc_%s.pem",
			    CLIENT_CERT_DIR, ns_name, CLIENT_CERT_DIR,
			    ns_name, CLIENT_CERT_DIR, ns_name,
			    SERVER_CERT_DIR, ns_name, SERVER_CERT_DIR,
			    ns_name, SERVER_CERT_DIR, ns_name);

    return rc != 0 ? -1 : 0;
}

static int domain_setup(unsigned int setup_flags)
{
    domains_dir = ut_asprintf("./test/domains/%d", getpid());
    CHKNOERR(tu_executef_es("mkdir -p %s", domains_dir));

    domain_name = ut_asprintf("testdomain-%d", getpid());

    domains_filename = ut_asprintf("%s/%s", domains_dir, domain_name);

    bool use_net_ns = tu_has_sys_admin_capability() && tu_randbool();

    int i;
    for (i = 0; i < NUM_SERVERS; i++) {
	struct server *server = &servers[i];

	if (use_net_ns && tu_randbool()) {
	    server->net_ns = random_net_ns();
	    cert_setup(server->net_ns);
	} else
	    server->net_ns = NULL;

	server->addr = random_addr();
	server->local_addr =
	    random_local_addr(server->addr,
			      setup_flags & REQUIRE_NO_LOCAL_PORT_BIND);
	server->pid = -1;

	if (server->net_ns != NULL && tu_add_net_ns(server->net_ns) < 0)
	    return UTEST_FAILED;
    }

    if (tu_randbool() && !use_net_ns)
	CHKNOERR(write_nl_domains_file(domains_filename, servers,
				       NUM_SERVERS));
    else {
	bool tls_conf = tu_randbool();

	if (tls_conf)
	    CHKNOERR(write_json_domain_file(domains_filename, CLIENT_CERT,
					    CLIENT_KEY, CLIENT_TC,
					    NULL, servers, NUM_SERVERS));
	else
	    CHKNOERR(write_json_domain_file(domains_filename, NULL, NULL,
					    NULL, NULL, servers, NUM_SERVERS));
    }

    return UTEST_SUCCESS;
}

#define LAG (is_in_valgrind() ? 2.0 : 0.25)

#define AVG_RESCAN_PERIOD (2)
#define MAX_RESCAN_PERIOD (AVG_RESCAN_PERIOD * 1.5 + LAG)

#define PAF_RECONNECT_MAX (0.1)
#define MAX_RECONNECT_PERIOD (PAF_RECONNECT_MAX + LAG)

#define DETACH_TIMEOUT (0.5)
#define MAX_DETACH_TIME (DETACH_TIMEOUT + LAG)

#define TTL (1)

static int setenv_double(const char *name, double value)
{
    char value_s[128];
    snprintf(value_s, sizeof(value_s), "%.6f", value);
    if (setenv(name, value_s, 1) < 0)
	return -1;
    return 0;
}

static int setup(unsigned int setup_flags)
{
    int rc = domain_setup(setup_flags);
    if (rc < 0)
	return rc;
    
    if (setenv("XCM_TLS_CERT", CLIENT_CERT_DIR, 1) < 0)
	return UTEST_FAILED;

    if (tu_executef_es("test -f %s/cert.pem", CLIENT_CERT_DIR) != 0)
	return UTEST_FAILED;

    if (setenv("PAF_DOMAINS", domains_dir, 1) < 0)
	return UTEST_FAILED;

    if (setenv_double("PAF_RESCAN", AVG_RESCAN_PERIOD) < 0)
	return UTEST_FAILED;

    if (setenv_double("PAF_RECONNECT_MAX", PAF_RECONNECT_MAX) < 0)
	return UTEST_FAILED;

    if (setenv_double("PAF_TTL", TTL) < 0)
	return UTEST_FAILED;

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
    for (i = 0; i < NUM_SERVERS; i++) {
	struct server *server = &servers[i];

	if (server->net_ns != NULL) {
	    cert_teardown(server->net_ns);
	    tu_del_net_ns(server->net_ns);
	}

	server_clear(server);
    }
}

static int teardown(unsigned setup_flags)
{
    stop_servers();

    domain_teardown();

    return UTEST_SUCCESS;
}

#define MAX_FDS (64)

#define MAX_PROCESS_CALLS (10000)

static int wait_for_all(struct paf_context **contexts, size_t num_contexts,
                        double duration)
{
    double now = ut_ftime(CLOCK_REALTIME);
    double deadline = now + duration;
    int process_calls = 0;

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

	    process_calls++;

	    /* MAX_PROCESS_CALLS is set so it is more than high enough
	       for all test cases in this suite. If exceeded,
	       something is wrong (e.g., the fd is not being properly
	       deactivated by a paf_process() call. */
	    if (process_calls > MAX_PROCESS_CALLS)
		return -1;
	}
    }

    return 0;
}

static int wait_for(struct paf_context *context, double duration)
{
    return wait_for_all(&context, 1, duration);
}

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

#define TCLIENT "./test/tclient.py"

static int tclient(const struct server *server,
		   const char *cmd_fmt, ...)
{
    va_list ap;
    va_start(ap, cmd_fmt);

    int old_ns_fd = -1;
    if (server->net_ns != NULL) {
	old_ns_fd = ut_net_ns_enter(server->net_ns);
	if (old_ns_fd < 0)
	    return -1;
    }

    char *old_cert_dir = NULL;

    char *env = getenv("XCM_TLS_CERT");
    if (env != NULL)
	old_cert_dir = ut_strdup(env);

    if (setenv("XCM_TLS_CERT", CLIENT_CERT_DIR, 1) < 0)
	return -1;

    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "%s %s ", TCLIENT, server->addr);

    vsnprintf(cmd + strlen(cmd), sizeof(cmd) - strlen(cmd),
	      cmd_fmt, ap);

    int rc = tu_executef_es(cmd);

    if (old_cert_dir != NULL) {
	if (setenv("XCM_TLS_CERT", old_cert_dir, 1) < 0)
	    return -1;
	ut_free(old_cert_dir);
    } else if (unsetenv("XCM_TLS_CERT") < 0)
	return -1;

    if (server->net_ns != NULL && ut_net_ns_return(old_ns_fd) < 0)
	return -1;

    return rc;
}

static int assure_server_up(struct server *server)
{
    return tclient(server, "assure-up");
}

static int assure_client_from(struct server *server,
			      const char *client_remote_addr)
{
    return tclient(server, "assure-client-from %s", client_remote_addr);
}


static int assure_client_count(struct server *server, int count)

{
    return tclient(server, "assure-client-count %d", count);
}

static int wait_for_client_count(struct paf_context *context, double duration,
				 struct server *server, int count)
{
    double deadline = ut_ftime(CLOCK_REALTIME) + duration;
    for (;;) {
	int rc = assure_client_count(server, count);
	if (rc == 0)
	    return UTEST_SUCCESS;
	if (ut_ftime(CLOCK_REALTIME) > deadline)
	    return UTEST_FAILED;
	wait_for(context, 0.1);
    }
}

static int server_assure_service(struct server *server, int64_t service_id,
				 const struct paf_props *props)
{
    char cmd[4096];

    strcpy(cmd, "assure-service");

    if (service_id >= 0)
        snprintf(cmd+strlen(cmd), sizeof(cmd)-strlen(cmd),
                 " %"PRIx64" ", service_id);
    else
        snprintf(cmd+strlen(cmd), sizeof(cmd)-strlen(cmd),
                 " any ");

    paf_props_foreach(props, add_prop, cmd);

    return tclient(server, cmd);
}

static int assure_service(int64_t service_id, const struct paf_props *props)
{
    int i;
    for (i = 0; i < NUM_SERVERS; i++) {
	int rc = server_assure_service(&servers[i], service_id,
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
	    return UTEST_FAILED;
	wait_for(context, 0.1);
    }
}

static int server_assure_service_count(struct server *server, int count)
{
    return tclient(server, "assure-service-count %d", count);
}

static int assure_service_count(int count)
{
    int i;
    for (i = 0; i < NUM_SERVERS; i++) {
	int rc = server_assure_service_count(&servers[i], count);
	if (rc < 0)
	    return rc;
    }
    return UTEST_SUCCESS;
}

static int wait_for_service_count(struct paf_context *context, double duration,
				  int count)
{
    double deadline = ut_ftime(CLOCK_REALTIME) + duration;
    for (;;) {
	int rc = assure_service_count(count);
	if (rc == 0)
	    return UTEST_SUCCESS;
	if (ut_ftime(CLOCK_REALTIME) > deadline)
	    return UTEST_FAILED;
	wait_for(context, 0.1);
    }
}

static int server_assure_subscription(struct server *server, int64_t sub_id,
				      const char *filter)
{
    return tclient(server, "assure-subscription %"PRIx64" '%s'", sub_id,
		   filter);
}

static int assure_subscription(int64_t sub_id, const char *filter)
{
    int i;
    for (i = 0; i < NUM_SERVERS; i++) {
	int rc = server_assure_subscription(&servers[i], sub_id, filter);
	if (rc < 0)
	    return rc;
    }
    return UTEST_SUCCESS;
}

TESTSUITE(paf, setup, teardown)

/* See 'match_with_most_servers_down' on why this flag is needed. */
TESTCASE_F(paf, publish_flaky_servers, REQUIRE_NO_LOCAL_PORT_BIND)
{
    struct paf_context *context = paf_attach(domain_name);

    CHK(context != NULL);

    const int64_t cellid = 17;

    struct paf_props *props = paf_props_create();
    paf_props_add_str(props, "name", "foo");
    paf_props_add_int64(props, "cellid", cellid);

    int64_t service_id = paf_publish(context, props);

    CHKNOERR(start_servers());

    CHK(service_id >= 0);

    CHKNOERR(wait_for_service(context, MAX_RECONNECT_PERIOD,
			      service_id, props));

    CHKNOERR(stop_servers());

    CHKNOERR(wait_for(context, 0.25));

    CHKNOERR(start_servers());

    CHKNOERR(wait_for_service(context, MAX_RECONNECT_PERIOD,
			      service_id, props));

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

    CHKNOERR(start_servers());

    int64_t service_ids[MANY];
    int i;
    for (i = 0; i < MANY; i++) {
        struct paf_props *props = paf_props_clone(base_props);
        paf_props_add_int64(props, "num", i);
        service_ids[i] = paf_publish(context, props);
        paf_props_destroy(props);
        CHK(service_ids[i] >= 0);
    }

    CHKNOERR(wait_for_service_count(context, 5.0, MANY));

    for (i = 0; i < 10; i++) {
        int num = rand() % MANY;
        struct paf_props *props = paf_props_clone(base_props);
        paf_props_add_int64(props, "num", num);
        CHKNOERR(assure_service(service_ids[num], props));
        paf_props_destroy(props);
    }

    for (i = 0; i < MANY; i++)
        paf_unpublish(context, service_ids[i]);

    CHKNOERR(wait_for_service_count(context, 5.0, 0));

    paf_close(context);

    paf_props_destroy(base_props);

    CHKNOERR(stop_servers());

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
	check_publish_latency(domain_name, MAX_RECONNECT_PERIOD + 1);

    CHKNOERR(client_pid);

    tu_msleep(100);

    CHKNOERR(start_servers());

    CHKNOERR(tu_waitstatus(client_pid));

    CHKNOERR(stop_servers());

    return UTEST_SUCCESS;
}

TESTCASE(paf, connect_publish_latency_no_retry)
{
    REQUIRE_NOT_IN_VALGRIND;

    CHKNOERR(start_servers());
    tu_msleep(100);

    pid_t client_pid =
	check_publish_latency(domain_name, 0.05);

    CHKNOERR(client_pid);

    CHKNOERR(tu_waitstatus(client_pid));

    CHKNOERR(stop_servers());

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
        CHKNOERR(start_servers());

    int64_t service_id = paf_publish(context, orig_props);

    CHK(service_id >= 0);

    CHKNOERR(wait_for(context, MAX_RECONNECT_PERIOD));

    struct paf_props *mod_props = paf_props_create();
    paf_props_add_str(mod_props, "name", "foo");
    paf_props_add_int64(mod_props, "cellid", 99);

    CHKNOERR(paf_modify(context, service_id, mod_props));

    if (mode == sync_mode_unsynced)
        CHKNOERR(start_servers());

    CHKNOERR(wait_for(context, MAX_RECONNECT_PERIOD));

    CHKNOERR(assure_service(service_id, mod_props));

    CHKNOERR(stop_servers());

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

/* See 'match_with_most_servers_down' on why this flag is needed. */
TESTCASE_F(paf, subscribe_flaky_server, REQUIRE_NO_LOCAL_PORT_BIND)
{
    struct paf_context *context = paf_attach(domain_name);

    int hits = 0;

    const char *filter_s = "(name=foo)";
    int64_t sub_id = paf_subscribe(context, filter_s, count_match_cb, &hits);

    struct paf_props *props = paf_props_create();
    paf_props_add_str(props, "name", "foo");

    pid_t bg_pid = bg_publisher(domain_name, props, 5.0);

    CHKNOERR(bg_pid);

    CHKNOERR(start_servers());

    do {
	CHKNOERR(wait_for(context, 0.1));
    } while (hits != 1 ||
	     assure_service(-1, props) < 0 ||
	     assure_subscription(sub_id, filter_s) < 0);

    CHKNOERR(stop_servers());

    CHKNOERR(wait_for(context, 0.1));

    CHKNOERR(start_servers());

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

    CHKNOERR(start_servers());

    struct paf_props *props = paf_props_create();
    paf_props_add_str(props, "name", "bar");

    int64_t service_id = paf_publish(context, props);

    paf_props_destroy(props);

    CHKNOERR(service_id);

    while (hits == 0)
        CHKNOERR(wait_for(context, 0.1));

    CHKINTEQ(hits, 1);

    paf_close(context);

    CHKNOERR(stop_servers());

    return UTEST_SUCCESS;
}

/* The scenario tested here does not work reliably when the libpaf
   client is asked to bind to a local port. If you shut down the
   servers before the connection is accepted, the kernel TCP socket
   may end up in TIME_WAIT, which will prevent its local socket
   ([address, port]-combination) from being reused (regardless of
   SO_REUSEADDR is set or not). */
TESTCASE_F(paf, match_with_most_servers_down, REQUIRE_NO_LOCAL_PORT_BIND)
{
    CHKNOERR(start_servers());

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
	server_stop(&servers[i]);

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

    CHKNOERR(start_servers());

    struct paf_props *props = paf_props_create();
    paf_props_add_str(props, NAME, VALUE);

    int64_t service_id = paf_publish(context, props);

    paf_props_destroy(props);

    CHKNOERR(service_id);

    while (hits == 0)
        CHKNOERR(wait_for(context, 0.1));

    CHKINTEQ(hits, 1);

    paf_close(context);

    CHKNOERR(stop_servers());

    return UTEST_SUCCESS;
}

enum timeout_mode
{
    timeout_mode_server_unavailable,
    timeout_mode_client_disconnect
};

static int test_timeout_ttl(enum timeout_mode mode, int64_t ttl)
{
    struct paf_context *sub_context = paf_attach(domain_name);

    int hits = 0;
    int64_t sub_id = paf_subscribe(sub_context, NULL, count_match_cb, &hits);

    CHKNOERR(sub_id);

    CHKNOERR(start_servers());

    struct paf_context *pub_context = paf_attach(domain_name);

    struct paf_props *props = paf_props_create();

    int64_t service_id = paf_publish(pub_context, props);
    CHKNOERR(service_id);

    if (ttl != TTL)
	paf_set_ttl(pub_context, service_id, ttl);

    paf_props_destroy(props);

    do {
        struct paf_context *contexts[] = { pub_context, sub_context };
        CHKNOERR(wait_for_all(contexts, 2, 0.1));
    } while (hits != 1);

    double start = ut_ftime(CLOCK_REALTIME);

    if (mode == timeout_mode_server_unavailable)
        CHKNOERR(stop_servers());
    else
        paf_close(pub_context);

    do {
        if (mode == timeout_mode_server_unavailable)
            CHKNOERR(wait_for(pub_context, 0.01));
        CHKNOERR(wait_for(sub_context, 0.01));
    } while (hits == 1);

    double latency = ut_ftime(CLOCK_REALTIME) - start;

    CHKINTEQ(hits, 2);

    CHK(latency > ttl);
    CHK(latency < (ttl+0.5));

    paf_close(sub_context);

    if (mode == timeout_mode_server_unavailable)
        paf_close(pub_context);
    else
        CHKNOERR(stop_servers());

    return UTEST_SUCCESS;
}

static int test_timeout(enum timeout_mode mode)
{
    int rc;
    if ((rc = test_timeout_ttl(mode, TTL)) < 0)
	return rc;
    if ((rc = test_timeout_ttl(mode, TTL * 2)) < 0)
	return rc;
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
    CHKNOERR(start_servers());

    struct paf_context *context = paf_attach(domain_name);

    const char *invalid_filter_s = "(name=foo))";

    CHKINTEQ(paf_subscribe(context, invalid_filter_s, count_match_cb, NULL),
             PAF_ERR_INVALID_FILTER_SYNTAX);

    paf_close(context);

    CHKNOERR(stop_servers());

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

    CHKNOERR(start_servers());

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

    CHKNOERR(start_servers());

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

    CHKNOERR(start_servers());

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

    CHKNOERR(stop_servers());

    paf_props_destroy(props);
    paf_close(context);

    return UTEST_SUCCESS;
}

TESTCASE(paf, no_matches_after_unsubscribe)
{
    struct paf_context *context = paf_attach(domain_name);

    CHKNOERR(start_servers());

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

    CHKNOERR(stop_servers());

    return UTEST_SUCCESS;
}

static int test_detach(bool with_server, bool manual_unpublish,
                       size_t service_count)
{
    struct paf_context *context = paf_attach(domain_name);

    if (with_server)
        CHKNOERR(start_servers());

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
        CHKNOERR(stop_servers());
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

TESTCASE(paf, detach_unresponsive_server)
{
    CHKNOERR(start_servers());

    struct paf_context *context = paf_attach(domain_name);

    CHK(context != NULL);

    struct paf_props *props = paf_props_create();
    CHKNOERR(paf_publish(context, props));

    CHKNOERR(wait_for_service_count(context, LAG, 1));

    CHKNOERR(signal_servers(SIGSTOP));

    paf_detach(context);

    CHKINTEQ(wait_for(context, MAX_DETACH_TIME), PAF_ERR_DETACHED);

    CHKNOERR(signal_servers(SIGCONT));

    paf_props_destroy(props);
    paf_close(context);

    return UTEST_SUCCESS;
}

TESTCASE(paf, create_domains_file)
{
    CHKNOERR(start_servers());
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
    struct server server_a = {
	.addr = random_addr()
    };
    struct server server_b = {
	.addr = random_addr()
    };

    CHKNOERR(server_start(&server_a));
    CHKNOERR(server_start(&server_b));

    CHKNOERR(tu_executef_es("echo '%s' > %s", server_a.addr,
			    domains_filename));

    struct paf_context *context = paf_attach(domain_name);

    struct paf_props *props = paf_props_create();
    paf_props_add_str(props, "name", "abc");
    int64_t service_id = paf_publish(context, props);
    CHKNOERR(service_id);

    CHKNOERR(wait_for(context, LAG));

    CHKNOERR(server_assure_service(&server_a, service_id, props));
    CHK(server_assure_service(&server_b, service_id, props) < 0);

    CHKNOERR(tu_executef_es("echo '%s' > %s", server_b.addr,
			    domains_filename));

    CHKNOERR(wait_for(context, MAX_RESCAN_PERIOD));

    CHKNOERR(server_assure_service(&server_b, service_id, props));
    CHK(server_assure_service(&server_a, service_id, props) < 0);

    paf_detach(context);

    paf_props_destroy(props);
    paf_close(context);

    server_stop(&server_a);
    server_stop(&server_b);

    server_clear(&server_a);
    server_clear(&server_b);

    return UTEST_SUCCESS;
}

TESTCASE(paf, change_domain_tls_conf)
{
    char *tls_addr = random_tls_addr();

    struct server server = {
	.addr = tls_addr,
	.pid = -1
    };

    CHKNOERR(write_json_domain_file(domains_filename,
				    UNTRUSTED_CLIENT_CERT, UNTRUSTED_CLIENT_KEY,
				    UNTRUSTED_CLIENT_TC, NULL,
				    &server, 1));

    struct paf_context *context = paf_attach(domain_name);

    struct paf_props *props = paf_props_create();
    int64_t service_id = paf_publish(context, props);
    CHKNOERR(service_id);

    CHKNOERR(server_start(&server));

    CHKNOERR(wait_for(context, MAX_RECONNECT_PERIOD));

    CHK(server_assure_service(&server, service_id, props) < 0);


    CHKNOERR(write_json_domain_file(domains_filename, CLIENT_CERT, CLIENT_KEY,
				    CLIENT_TC, NULL, &server, 1));

    CHKNOERR(wait_for(context, MAX_RESCAN_PERIOD));

    CHKNOERR(server_assure_service(&server, service_id, props));

    server_stop(&server);

    paf_detach(context);

    paf_props_destroy(props);
    paf_close(context);

    ut_free(tls_addr);

    return UTEST_SUCCESS;
}

TESTCASE(paf, certificate_revocation)
{
    bool supports_crl_attr =
	xcm_version_api_major() >= 1 || xcm_version_api_minor() >= 24;

    if (!supports_crl_attr)
	return UTEST_NOT_RUN;

    char *tls_addr = random_tls_addr();

    struct server server = {
	.addr = tls_addr,
	.pid = -1
    };

    CHKNOERR(write_json_domain_file(domains_filename,
				    CLIENT_CERT, CLIENT_KEY,
				    CLIENT_TC, EMPTY_CRL,
				    &server, 1));

    CHKNOERR(server_start(&server));

    struct paf_context *context = paf_attach(domain_name);

    CHKNOERR(wait_for_client_count(context, 2, &server, 1));

    CHKNOERR(write_json_domain_file(domains_filename,
				    CLIENT_CERT, CLIENT_KEY,
				    CLIENT_TC, REVOKED_SERVER_CERT_CRL,
				    &server, 1));

    CHKNOERR(wait_for(context, MAX_RESCAN_PERIOD));

    CHKNOERR(assure_client_count(&server, 0));

    paf_close(context);

    ut_free(tls_addr);

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
	return UTEST_FAILED;
    if (setenv_double("PAF_RECONNECT_MIN", reconnect_min) < 0)
	return UTEST_FAILED;

    pid_t pid = fake_server(duration, reconnect_min, reconnect_max,
			    servers[0].addr);

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

TESTCASE(paf, local_addr)
{
    char *addr = random_tcp_addr();
    char *local_addr = random_tcp_addr();

    struct server server = {
	.addr = addr,
	.local_addr = local_addr,
	.pid = -1
    };

    CHKNOERR(server_start(&server));

    CHKNOERR(write_json_domain_file(domains_filename, NULL, NULL, NULL, NULL,
				    &server, 1));

    struct paf_context *context = paf_attach(domain_name);

    CHKNOERR(wait_for(context, 0.5));

    CHKNOERR(assure_client_from(&server, local_addr));

    paf_close(context);

    ut_free(addr);
    ut_free(local_addr);

    return UTEST_SUCCESS;
}

#define DNS_MANY_LOCALHOST "local.friendlyfire.se"

TESTCASE(paf, multi_homed_server)
{
    bool supports_dns_algorithm_attr =
	xcm_version_api_major() >= 1 || xcm_version_api_minor() >= 24;

    if (!supports_dns_algorithm_attr)
	return UTEST_NOT_RUN;

    uint16_t port = gen_tcp_port();
    char server_server_addr[128];
    char client_server_addr[128];

    /* DNS_LOCALHOST resolves to a number of local addresses,
       including 127.0.0.2. */
    snprintf(server_server_addr, sizeof(server_server_addr),
	     "tcp:127.0.0.2:%d", port);

    /* Client will use DNS, which will produce a number of IP
       addresses for this particular name. All IPs should be tried,
       until XCM gives up, since "dns.algorithm" should be set to
       "happy_eyeballs" (although "sequential" will also do, for the
       purpose of this test). */
    snprintf(client_server_addr, sizeof(client_server_addr),
	     "tcp:%s:%d", DNS_MANY_LOCALHOST, port);

    struct server server_server = {
	.addr = server_server_addr,
	.pid = -1
    };

    struct server client_server = {
	.addr = client_server_addr,
	.pid = -1
    };

    CHKNOERR(server_start(&server_server));

    CHKNOERR(write_json_domain_file(domains_filename, NULL, NULL, NULL, NULL,
				    &client_server, 1));

    struct paf_context *context = paf_attach(domain_name);

    do {
	CHKNOERR(wait_for(context, 0.1));
    } while (assure_client_count(&server_server, 1) < 0);

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
