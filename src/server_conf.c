#include "server_conf.h"
#include "util.h"

#include <string.h>

static char *dup_non_null(const char *str)
{
    if (str == NULL)
	return NULL;

    return ut_strdup(str);
}

static bool str_equals(const char *s0,
		       const char *s1)
{
    if (s0 == NULL)
	return s1 == NULL;
    if (s1 == NULL)
	return s0 == NULL;
    return strcmp(s0, s1) == 0;
}

bool server_conf_equals(const struct server_conf *server0,
			const struct server_conf *server1)
{
    return strcmp(server0->addr, server1->addr) == 0 &&
	str_equals(server0->cert_file, server1->cert_file) &&
	str_equals(server0->key_file, server1->key_file) &&
	str_equals(server0->tc_file, server1->tc_file);
}

struct server_conf *server_conf_create(const char *addr,
				       const char *cert_file,
				       const char *key_file,
				       const char *tc_file)
{
    struct server_conf *server = ut_malloc(sizeof(struct server_conf));

    *server = (struct server_conf) {
	.addr = ut_strdup(addr),
	.cert_file = dup_non_null(cert_file),
	.key_file = dup_non_null(key_file),
	.tc_file = dup_non_null(tc_file)
    };

    return server;
}

void server_conf_destroy(struct server_conf *server)
{
    if (server != NULL) {
	ut_free(server->addr);

	ut_free(server->cert_file);
	ut_free(server->key_file);
	ut_free(server->tc_file);

	ut_free(server);
    }
}

struct server_conf *server_conf_clone(const struct server_conf *original)
{
    return server_conf_create(original->addr, original->cert_file,
			      original->key_file, original->tc_file);
}
	
