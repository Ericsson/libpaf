/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020-2021 Ericsson AB
 */

#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <jansson.h>

#include <xcm_addr.h>

#include "conf.h"
#include "log_domain_conf.h"
#include "util.h"

#include "domain_conf.h"

static int get_domain_filename(const char *domain, char *filename,
			       ssize_t capacity)
{
    const char *domains_dir = conf_get_domains_dir();

    if (snprintf(filename, capacity, "%s/%s", domains_dir, domain) >= capacity)
        return -1;

    return 0;
}

static bool has_server_addr(struct domain_conf *conf, const char *server_addr)
{
    size_t i;

    for (i = 0; i < conf->num_servers; i++)
	if (strcmp(conf->servers[i]->addr, server_addr) == 0)
	    return true;

    return false;
}

static int add_server(struct domain_conf *conf, const char *filename,
		      const char *net_ns, const char *addr,
		      const char *cert_file, const char *key_file,
		      const char *tc_file, const char *log_ref)
{
    char proto[64];

    if (has_server_addr(conf, addr)) {
	log_domain_conf_repeated_addr(log_ref, filename, addr);
	return -1;
    }

    if (xcm_addr_parse_proto(addr, proto, sizeof(proto)) < 0) {
	log_domain_conf_invalid_addr(log_ref, filename, addr);
	return -1;
    }

    size_t new_num_servers = conf->num_servers + 1;
    conf->servers =
	ut_realloc(conf->servers, sizeof(struct server *) * new_num_servers);

    conf->servers[conf->num_servers] =
	server_conf_create(net_ns, addr, cert_file, key_file, tc_file);

    conf->num_servers = new_num_servers;

    return 0;
}

#define ADDR_SEP '\n'
#define COMMENT_CHAR '#'

static struct domain_conf *custom_to_conf(const char *filename,
					  const char *data,
					  const char *log_ref)
{
    struct domain_conf *conf = ut_calloc(sizeof(struct domain_conf));

    const char *start = data;
    char *end;

    do {
	end = strchr(start, ADDR_SEP);

	if (end != NULL)
	    *end = '\0';

	if (strlen(start) > 0 && !ut_str_begins_with(start, COMMENT_CHAR)
	    && add_server(conf, filename, NULL, start, NULL, NULL, NULL,
			  log_ref) < 0) {
	    domain_conf_destroy(conf);
	    return NULL;
	}

	start = end + 1;
    } while (end != NULL);

    return conf;
}

static const char *get_server_key(const char *filename, json_t* server,
				  const char *name, bool mandantory,
				  const char *log_ref)
{
    json_t *obj = json_object_get(server, name);

    if ((obj == NULL && mandantory) || (obj != NULL && !json_is_string(obj))) {
	log_domain_conf_missing_server_field(log_ref, filename, name);
	return NULL;
    }

    return json_string_value(obj);
}

static bool is_tls_addr(const char *addr)
{
    return strncmp("tls", addr, 3) == 0 ||
	strncmp("utls", addr, 4) == 0;
}

static struct domain_conf *json_to_conf(const char *filename,
					const char *data,
					const char *log_ref)
{
    json_error_t json_err;
    json_t *root = json_loads(data, 0, &json_err);

    if (root == NULL) {
        log_domain_conf_json_err(log_ref, filename, &json_err);
	goto err;
    }

    if (!json_is_object(root)) {
	log_domain_conf_root_not_object(log_ref, filename);
	goto err_free_root;
    }

    json_t* servers = json_object_get(root, "servers");

    if (servers == NULL || !json_is_array(servers)) {
	log_domain_conf_missing_servers(log_ref, filename);
	goto err_free_root;
    }

    struct domain_conf *conf = ut_calloc(sizeof(struct domain_conf));

    size_t i;
    for (i = 0; i < json_array_size(servers); i++) {
	json_t *server = json_array_get(servers, i);

	if (!json_is_object(server)) {
	    log_domain_conf_server_not_object(log_ref, filename);
	    goto err_free_conf;
	}

	const char *addr =
	    get_server_key(filename, server, "address", true, log_ref);
	if (addr == NULL)
	    goto err_free_conf;

	const char *cert_file =
	    get_server_key(filename, server, "tlsCertificateFile", false,
			   log_ref);
	const char *key_file =
	    get_server_key(filename, server, "tlsKeyFile", false,
			   log_ref);
	const char *tc_file =
	    get_server_key(filename, server, "tlsTrustedCaFile", false,
			   log_ref);

	if (!is_tls_addr(addr) && (cert_file != NULL || key_file != NULL ||
				   tc_file != NULL)) {
	    log_domain_conf_tls_conf_for_non_tls(log_ref, filename, addr);
	    goto err_free_conf;
	}

	const char *net_ns =
	    get_server_key(filename, server, "networkNamespace", false,
			   log_ref);

	if (add_server(conf, filename, net_ns, addr, cert_file, key_file,
		       tc_file, log_ref) < 0)
	    goto err_free_conf;
    }

    json_decref(root);

    return conf;

err_free_conf:
    domain_conf_destroy(conf);
err_free_root:
    json_decref(root);
err:
    return NULL;
}

static bool is_ws(char c)
{
    return c == '\n' || c == '\r' || c == ' ' || c == '\t';
}

static bool looks_like_json_object(const char *data)
{
    /* see RFC 7159, section 2 for grammar */

    const char *p = data;

    while (*p != '\0') {
	if (*p == '{')
	    return true;
	if (!is_ws(*p))
	    return false;
	p++;
    }

    return false;
}

#define MAX_DOMAIN_DATA_SIZE (64*1024)

struct domain_conf *domain_conf_read(const char *domain,
				     struct timespec *mtime,
				     const char *log_ref)
{
    char domain_filename[PATH_MAX];
    struct domain_conf *conf = NULL;

    if (get_domain_filename(domain, domain_filename,
			    sizeof(domain_filename)) < 0)
	goto out;

    int domain_file = open(domain_filename, O_RDONLY);

    if (domain_file < 0) {
	log_domain_conf_read_error(log_ref, domain_filename, errno);
	goto out;
    }

    struct stat st;
    if (fstat(domain_file, &st) < 0) {
	log_domain_conf_read_error(log_ref, domain_filename, errno);
	goto out_close;
    }

    if (ut_timespec_lte(&st.st_mtim, mtime)) {
	log_domain_conf_unchanged(log_ref, domain_filename);
	errno = 0;
	goto out_close;
    }

    char *data = ut_malloc(MAX_DOMAIN_DATA_SIZE + 1);

    ssize_t len = ut_read_file(domain_file, data, MAX_DOMAIN_DATA_SIZE);

    if (len < 0)
	goto out_free;

    data[len] = '\0';

    if (looks_like_json_object(data))
	conf = json_to_conf(domain_filename, data, log_ref);
    else
	conf = custom_to_conf(domain_filename, data, log_ref);

    if (conf == NULL) {
	errno = EINVAL;
	goto out_free;
    }

    *mtime = st.st_mtim;

out_free:
    ut_free(data);
out_close:
    UT_PROTECT_ERRNO(close(domain_file));
out:
    return conf;
}

void domain_conf_destroy(struct domain_conf *conf)
{
    if (conf != NULL) {
	size_t i;

	for (i = 0; i < conf->num_servers; i++)
	    server_conf_destroy(conf->servers[i]);

	ut_free(conf->servers);

	ut_free(conf);
    }
}

bool domain_conf_has_server(struct domain_conf *conf,
			    const struct server_conf *server)
{
    size_t i;

    for (i = 0; i < conf->num_servers; i++)
	if (server_conf_equals(conf->servers[i], server))
	    return true;

    return false;
}
