/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Ericsson AB
 */

#ifndef TESTSETUP_H
#define TESTSETUP_H

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

#include "paf_props.h"

//#define PAFD_DEBUG

#define TS_DEFAULT_PAFD_BIN "pafd"
#define TS_PAFD_ENV "PAFD"

#define TS_CERT_BASE_DIR "./test/cert"

#define TS_SERVER_CERT_DIR TS_CERT_BASE_DIR "/server"
#define TS_SERVER_CERT TS_SERVER_CERT_DIR "/cert.pem"
#define TS_SERVER_KEY TS_SERVER_CERT_DIR "/key.pem"
#define TS_SERVER_TC TS_SERVER_CERT_DIR "/tc.pem"

#define TS_CLIENT_CERT_DIR TS_CERT_BASE_DIR "/client"
#define TS_CLIENT_CERT TS_CLIENT_CERT_DIR "/cert.pem"
#define TS_CLIENT_KEY TS_CLIENT_CERT_DIR "/key.pem"
#define TS_CLIENT_TC TS_CLIENT_CERT_DIR "/tc.pem"

#define TS_EMPTY_CRL TS_CLIENT_CERT_DIR "/empty-crl.pem"
#define TS_REVOKED_SERVER_CERT_CRL TS_CLIENT_CERT_DIR "/revoked-server-crl.pem"

#define TS_UNTRUSTED_CLIENT_CERT_DIR TS_CERT_BASE_DIR "/untrusted_client"
#define TS_UNTRUSTED_CLIENT_CERT TS_UNTRUSTED_CLIENT_CERT_DIR "/cert.pem"
#define TS_UNTRUSTED_CLIENT_KEY TS_UNTRUSTED_CLIENT_CERT_DIR "/key.pem"
#define TS_UNTRUSTED_CLIENT_TC TS_UNTRUSTED_CLIENT_CERT_DIR "/tc.pem"

#define REQUIRE_NO_LOCAL_PORT_BIND (1U << 0)

bool ts_is_proto(const char *addr, const char *proto);
bool ts_is_tcp(const char *addr);
bool ts_is_tls(const char *addr);
bool ts_is_tcp_based(const char *addr);

#define TS_NUM_SERVERS (3)

struct server {
    char *net_ns;
    char *addr;
    char *local_addr;
    pid_t pid;
};

extern struct server ts_servers[TS_NUM_SERVERS];

extern char *ts_domains_dir;
extern char *ts_domain_name;
extern char *ts_domains_filename;

int ts_server_start(struct server *server);
int ts_start_servers(void);

int ts_server_pause(struct server *server);
int ts_pause_servers(void);

int ts_server_unpause(struct server *server);
int ts_unpause_servers(void);

int ts_server_stop(struct server *server);
int ts_stop_servers(void);

int ts_server_signal(struct server *server, int signo);
int ts_signal_servers(int signo);
void ts_server_clear(struct server *server);

uint16_t ts_random_tcp_port(void);
char *ts_random_tls_addr(void);
char *ts_random_tcp_addr(void);
char *ts_random_ux_addr(void);
char *ts_random_addr(void);

int ts_write_nl_domains_file(const char *filename, struct server *servers,
			     size_t num_servers);
int ts_write_json_domain_file(const char *filename, const char *cert_file,
			      const char *key_file, const char *tc_file,
			      const char *crl_file, int64_t proto_version_min,
			      int64_t proto_version_max,
			      struct server *servers, size_t num_servers);

int ts_domain_setup(unsigned int flags);
void ts_domain_teardown(void);

int ts_assure_server_up(struct server *server);
int ts_assure_client_from(struct server *server,
			  const char *client_remote_addr);
int ts_assure_client_count(struct server *server, int count);
int ts_server_assure_service(struct server *server, int64_t service_id,
			     const struct paf_props *props);
int ts_assure_service(int64_t service_id, const struct paf_props *props);
int ts_server_assure_service_count(struct server *server, int count);
int ts_assure_service_count(int count);
int ts_server_assure_subscription(struct server *server, int64_t sub_id,
				  const char *filter);
int ts_assure_subscription(int64_t sub_id, const char *filter);
int ts_assure_supports_v3(void);
int ts_server_assure_supports_v3(struct server *server);

#endif
