#ifndef SERVER_CONF_H
#define SERVER_CONF_H

#include <stdbool.h>

struct server_conf
{
    char *net_ns;
    char *addr;
    char *cert_file;
    char *key_file;
    char *tc_file;
};

struct server_conf *server_conf_create(const char *net_ns,
				       const char *addr,
				       const char *cert_file,
				       const char *key_file,
				       const char *tc_file);
void server_conf_destroy(struct server_conf *server);

bool server_conf_equals(const struct server_conf *server0,
			const struct server_conf *server1);

struct server_conf *server_conf_clone(const struct server_conf *server);

#endif
