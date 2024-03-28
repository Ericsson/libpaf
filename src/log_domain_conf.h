/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2021 Ericsson AB
 */

#ifndef LOG_DOMAIN_CONF_H
#define LOG_DOMAIN_CONF_H

#include "log.h"

#define log_domain_conf_debug(domain, fmt, ...)	\
    log_debug(domain, fmt, ##__VA_ARGS__)

#define log_domain_conf_error(domain, fmt, ...)	\
    log_error(domain, fmt, ##__VA_ARGS__)

#define log_domain_conf_unchanged(domain, filename)		      \
    log_domain_conf_debug(domain, "Domain file \"%s\" is unchanged.", \
			  filename)

#define log_domain_conf_read_error(domain, filename, read_errno)	\
    do {								\
	if (read_errno == ENOENT)					\
	    log_domain_conf_debug(domain,				\
				  "Domain file \"%s\" does not exist.",	\
				  filename);				\
	else								\
	    log_domain_conf_error(domain, "Error reading domain file " \
				  "\"%s\": %s (%d).", filename,		\
				  strerror(read_errno), read_errno);	\
    } while (0)
	
#define log_domain_conf_json_err(domain, filename, json_err)	       \
    log_domain_conf_error(domain, "Error parsing JSON domain file "   \
			  "\"%s\" at (%d, %d): %s.", filename,	       \
			  (json_err)->line, (json_err)->column,	       \
			  (json_err)->text)

#define log_domain_conf_parse_error(domain, filename, reason, ...)	\
    do {								\
	char buf[8192];							\
	snprintf(buf, sizeof(buf), "Error parsing domain file "		\
		 "\"%s\": %s.", filename, reason);			\
	log_domain_conf_debug(domain, buf, ##__VA_ARGS__);		\
    } while (0)

#define log_domain_conf_root_not_object(domain, filename)		\
    log_domain_conf_parse_error(domain, filename, "root not JSON object")

#define log_domain_conf_missing_servers(domain, filename)		\
    log_domain_conf_parse_error(domain, filename, "domain object missing " \
				"\"servers\" array.")

#define log_domain_conf_server_not_object(domain, filename)		\
    log_domain_conf_parse_error(domain, filename, "\"servers\" array " \
				"element is not a JSON object")

#define log_domain_conf_missing_server_field(domain, filename, name)	\
    log_domain_conf_parse_error(domain, filename, "server object "	\
				"is missing field \"%s\"", name)

#define log_domain_conf_server_field_wrong_type(domain, filename,	\
						name, type)		\
    log_domain_conf_parse_error(domain, filename, "server field \"%s\" " \
				"is not a %s", name, type)

#define log_domain_conf_repeated_addr(domain, filename, addr)		\
    log_domain_conf_error(domain, "Domain file \"%s\" contains repeated " \
			  "server address \"%s\".", filename, addr)

#define log_domain_conf_invalid_addr(domain, filename, addr)		\
    log_domain_conf_error(domain, "Domain file \"%s\" contains invalid " \
			  "server address \"%s\".", filename, addr)

#define log_domain_conf_tls_conf_for_non_tls(domain, filename, addr)	\
    log_domain_conf_error(domain, "Domain file \"%s\" contains TLS "	\
			  "configuration for non-TLS address \"%s\".",	\
			  filename, addr)

#define log_domain_conf_repeated_addrs(domain, filename, addr)		\
    log_domain_conf_error(domain, "Server address \"%s\" has multiple " \
			  "occurrences in domain file \"%s\".", addr,	\
			  filename)

#define log_domain_conf_min_version_larger_than_max(domain, min, max)	\
    log_domain_conf_error(domain, "Minimum protocol version (%"PRId64	\
			  ") is set lower than maximum (%"PRId64 ").",	\
			  min, max);

#endif
