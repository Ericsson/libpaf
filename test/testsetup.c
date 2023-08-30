/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Ericsson AB
 */

#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <xcm_addr.h>

#include "util.h"
#include "testutil.h"

#include "testsetup.h"

struct server ts_servers[TS_NUM_SERVERS];

char *ts_domains_dir;
char *ts_domain_name;
char *ts_domains_filename;

bool ts_is_proto(const char *addr, const char *proto)
{
    char actual_proto[16];
    xcm_addr_parse_proto(addr, actual_proto, sizeof(actual_proto));

    return strcmp(actual_proto, proto) == 0;
}

bool ts_is_tcp(const char *addr)
{
    return ts_is_proto(addr, XCM_TCP_PROTO);
}

bool ts_is_tls(const char *addr)
{
    return ts_is_proto(addr, XCM_TLS_PROTO) ||
	ts_is_proto(addr, XCM_UTLS_PROTO);
}

bool ts_is_tcp_based(const char *addr)
{
    return ts_is_tcp(addr) || ts_is_tls(addr);
}

static pid_t run_server(const char *net_ns, const char *addr)
{
    pid_t p = fork();

    if (p < 0)
        return -1;
    else if (p == 0) {

	if (setenv("XCM_TLS_CERT", TS_SERVER_CERT_DIR, 1) < 0)
	    exit(EXIT_FAILURE);

	if (net_ns != NULL && ut_net_ns_enter(net_ns) < 0)
	    exit(EXIT_FAILURE);

	const char *pafd = TS_DEFAULT_PAFD_BIN;

	const char *pafd_env = getenv(TS_PAFD_ENV);

	if (pafd_env != NULL)
	    pafd = pafd_env;

#ifdef PAFD_DEBUG
        execlp(pafd, pafd, "-l", "debug", addr, NULL);
#else
        execlp(pafd, pafd, addr, NULL);
#endif
        exit(EXIT_FAILURE);
    } else
        return p;
}

int ts_server_start(struct server *server)
{
    if (server->pid > 0)
	return 0;

    pid_t server_pid = run_server(server->net_ns, server->addr);

    if (server_pid < 0)
        return -1;
    if (ts_assure_server_up(server) < 0)
        return -1;

    server->pid = server_pid;

    return 0;
}

int ts_start_servers(void)
{
    int i;
    for (i = 0; i < TS_NUM_SERVERS; i++) {
	int rc = ts_server_start(&ts_servers[i]);
	if (rc < 0)
	    return rc;
    }
    return 0;
}

int ts_server_signal(struct server *server, int signo)
{
    return server->pid >= 0 ? kill(server->pid, signo) : -1;
}

int ts_signal_servers(int signo)
{
    int rc = 0;
    int i;
    for (i = 0; i < TS_NUM_SERVERS; i++) {
	struct server *server = &ts_servers[i];
	if (server->pid > 0 && ts_server_signal(server, signo) < 0)
	    rc = -1;
    }
    return rc;
}

int ts_server_stop(struct server *server)
{
    if (ts_server_signal(server, SIGTERM) < 0)
	return -1;

    if (tu_waitstatus(server->pid) < 0)
	return -1;

    server->pid = -1;

    return 0;
}

int ts_stop_servers(void)
{
    int rc = 0;
    int i;

    for (i = 0; i < TS_NUM_SERVERS; i++) {
	struct server *server = &ts_servers[i];
	if (server->pid > 0 && ts_server_stop(server) < 0)
	    rc = -1;
    }

    return rc;
}

void ts_server_clear(struct server *server)
{
    ut_free(server->net_ns);
    ut_free(server->addr);
    ut_free(server->local_addr);
    server->net_ns = NULL;
    server->addr = NULL;
}

uint16_t ts_random_tcp_port(void)
{
    return tu_randint(15000, 25000);
}

static char *localhost_port_addr(const char *proto, uint16_t port)
{
    int b = tu_randint(1, 254);
    int c = tu_randint(1, 254);
    int d = tu_randint(1, 254);

    return ut_asprintf("%s:127.%d.%d.%d:%d", proto, b, c, d, port);
}

static char *gen_localhost_port_addr(const char *proto)
{
    return localhost_port_addr(proto, ts_random_tcp_port());
}

char *ts_random_tls_addr(void)
{
    return gen_localhost_port_addr("tls");
}

char *ts_random_tcp_addr(void)
{
    return gen_localhost_port_addr("tcp");
}

char *ts_random_ux_addr(void)
{
    return ut_asprintf("ux:%d-%d", getpid(), tu_randint(0, INT_MAX));
}

char *ts_random_addr(void)
{
    int type = tu_randint(0, 2);

    switch (type) {
    case 0:
	return ts_random_tls_addr();
    case 1:
	return ts_random_tcp_addr();
    default:
	return ts_random_ux_addr();
    }
}

static char *random_local_addr(const char *addr,
			       bool force_kernel_allocated_port)
{
    if (!ts_is_tcp_based(addr))
	return NULL;

    bool has_local = tu_randbool();

    if (!has_local)
	return NULL;

    uint16_t port;
    if (force_kernel_allocated_port || tu_randbool())
	port = 0;
    else
	port = ts_random_tcp_port();

    char proto[16];
    xcm_addr_parse_proto(addr, proto, sizeof(proto));

    return localhost_port_addr(proto, port);
}

static char *random_net_ns(void)
{
    return ut_asprintf("ns-%d-%d", getpid(), tu_randint(0, INT_MAX));
}

int ts_write_nl_domains_file(const char *filename, struct server *servers,
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

int ts_write_json_domain_file(const char *filename, const char *cert_file,
			      const char *key_file, const char *tc_file,
			      const char *crl_file, struct server *servers,
			      size_t num_servers)
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

	if (ts_is_tls(server->addr) && cert_file != NULL)
	    fprintf(domains_file, ",\n"
		    "      \"tlsCertificateFile\": \"%s\"", cert_file);
	if (ts_is_tls(server->addr) && key_file != NULL)
	    fprintf(domains_file, ",\n"
		    "      \"tlsKeyFile\": \"%s\"", key_file);
	if (ts_is_tls(server->addr) && tc_file != NULL)
	    fprintf(domains_file, ",\n"
		    "      \"tlsTrustedCaFile\": \"%s\"", tc_file);
	if (ts_is_tls(server->addr) && crl_file != NULL)
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
			TS_CLIENT_CERT, TS_CLIENT_CERT_DIR, ns_name,
			TS_CLIENT_KEY, TS_CLIENT_CERT_DIR, ns_name,
			TS_CLIENT_TC, TS_CLIENT_CERT_DIR, ns_name);
    if (rc != 0)
	return -1;

    rc = tu_executef_es("cp %s %s/cert_%s.pem && "
			"cp %s %s/key_%s.pem && "
			"cp %s %s/tc_%s.pem",
			TS_SERVER_CERT, TS_SERVER_CERT_DIR, ns_name,
			TS_SERVER_KEY, TS_SERVER_CERT_DIR, ns_name,
			TS_SERVER_TC, TS_SERVER_CERT_DIR, ns_name);
    if (rc != 0)
	return -1;

    return 0;
}

static int cert_teardown(const char *ns_name)
{
    int rc = tu_executef_es("rm %s/cert_%s.pem %s/key_%s.pem %s/tc_%s.pem "
			    "%s/cert_%s.pem %s/key_%s.pem %s/tc_%s.pem",
			    TS_CLIENT_CERT_DIR, ns_name, TS_CLIENT_CERT_DIR,
			    ns_name, TS_CLIENT_CERT_DIR, ns_name,
			    TS_SERVER_CERT_DIR, ns_name, TS_SERVER_CERT_DIR,
			    ns_name, TS_SERVER_CERT_DIR, ns_name);

    return rc != 0 ? -1 : 0;
}

int ts_domain_setup(unsigned int setup_flags)
{
    ts_domains_dir = ut_asprintf("./test/domains/%d", getpid());
    if (tu_executef_es("mkdir -p %s", ts_domains_dir) < 0)
	return -1;

    ts_domain_name = ut_asprintf("testdomain-%d", getpid());

    ts_domains_filename = ut_asprintf("%s/%s", ts_domains_dir, ts_domain_name);

    bool use_net_ns = tu_has_sys_admin_capability() && tu_randbool();

    int i;
    for (i = 0; i < TS_NUM_SERVERS; i++) {
	struct server *server = &ts_servers[i];

	if (use_net_ns && tu_randbool()) {
	    server->net_ns = random_net_ns();
	    cert_setup(server->net_ns);
	} else
	    server->net_ns = NULL;

	server->addr = ts_random_addr();
	server->local_addr =
	    random_local_addr(server->addr,
			      setup_flags & REQUIRE_NO_LOCAL_PORT_BIND);
	server->pid = -1;

	if (server->net_ns != NULL && tu_add_net_ns(server->net_ns) < 0)
	    return -1;
    }

    if (tu_randbool() && !use_net_ns) {
	if (ts_write_nl_domains_file(ts_domains_filename, ts_servers,
				     TS_NUM_SERVERS) < 0)
	    return -1;
    } else {
	bool tls_conf = tu_randbool();

	if (tls_conf) {
	    if (ts_write_json_domain_file(ts_domains_filename, TS_CLIENT_CERT,
					  TS_CLIENT_KEY, TS_CLIENT_TC,
					  NULL, ts_servers, TS_NUM_SERVERS) < 0)
		return -1;
	} else {
	    if (ts_write_json_domain_file(ts_domains_filename, NULL, NULL, NULL,
					  NULL, ts_servers, TS_NUM_SERVERS) < 0)
		return -1;
	}
    }

    return 0;
}

void ts_domain_teardown(void)
{
    tu_executef("rm -f %s", ts_domains_filename);
    tu_executef("rmdir %s", ts_domains_dir);

    ut_free(ts_domains_dir);
    ut_free(ts_domain_name);
    ut_free(ts_domains_filename);

    int i;
    for (i = 0; i < TS_NUM_SERVERS; i++) {
	struct server *server = &ts_servers[i];

	if (server->net_ns != NULL) {
	    cert_teardown(server->net_ns);
	    tu_del_net_ns(server->net_ns);
	}

	ts_server_clear(server);
    }
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

    if (setenv("XCM_TLS_CERT", TS_CLIENT_CERT_DIR, 1) < 0)
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

int ts_assure_server_up(struct server *server)
{
    return tclient(server, "assure-up");
}

int ts_assure_client_from(struct server *server, const char *client_remote_addr)
{
    return tclient(server, "assure-client-from %s", client_remote_addr);
}


int ts_assure_client_count(struct server *server, int count)

{
    return tclient(server, "assure-client-count %d", count);
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

int ts_server_assure_service(struct server *server, int64_t service_id,
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

int ts_assure_service(int64_t service_id, const struct paf_props *props)
{
    int i;
    for (i = 0; i < TS_NUM_SERVERS; i++) {
	int rc = ts_server_assure_service(&ts_servers[i], service_id,
					  props);
	if (rc < 0)
	    return rc;
    }
    return 0;
}

int ts_server_assure_service_count(struct server *server, int count)
{
    return tclient(server, "assure-service-count %d", count);
}

int ts_assure_service_count(int count)
{
    int i;
    for (i = 0; i < TS_NUM_SERVERS; i++) {
	int rc = ts_server_assure_service_count(&ts_servers[i], count);
	if (rc < 0)
	    return rc;
    }
    return 0;
}

int ts_server_assure_subscription(struct server *server, int64_t sub_id,
				  const char *filter)
{
    return tclient(server, "assure-subscription %"PRIx64" '%s'", sub_id,
		   filter);
}

int ts_assure_subscription(int64_t sub_id, const char *filter)
{
    int i;
    for (i = 0; i < TS_NUM_SERVERS; i++) {
	int rc = ts_server_assure_subscription(&ts_servers[i], sub_id, filter);
	if (rc < 0)
	    return rc;
    }
    return 0;
}
