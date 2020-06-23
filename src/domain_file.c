/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "util.h"

#include "domain_file.h"

#define DOMAINS_ENV "PAF_DOMAINS"
#define DEFAULT_DOMAINS_DIR "/run/paf/domains.d"

static int get_domain_filename(const char *domain, char *filename,
			       size_t capacity)
{
    const char *domains_dir = getenv(DOMAINS_ENV);

    if (domains_dir == NULL)
        domains_dir = DEFAULT_DOMAINS_DIR;

    if (snprintf(filename, capacity, "%s/%s", domains_dir, domain) >= capacity)
        return -1;

    return 0;
}

#define ADDR_SEP '\n'
#define COMMENT_CHAR '#'

static void add_addr(char ***addrs, ssize_t *addrs_len, const char *addr)
{
    *addrs = ut_realloc(*addrs, sizeof(char **) * (*addrs_len + 1));

    (*addrs)[*addrs_len] = ut_strdup(addr);
    (*addrs_len)++;
}

#define MAX_DOMAIN_FILE_SIZE (64*1024)

ssize_t domain_file_get_addrs(const char *domain, struct timespec *mtime,
			      char ***addrs)
{
    char domain_filename[PATH_MAX];
    ssize_t rc = -1;

    if (get_domain_filename(domain, domain_filename,
			    sizeof(domain_filename)) < 0)
	goto out;

    int domain_file = open(domain_filename, O_RDONLY);

    if (domain_file < 0)
	goto out;

    struct stat st;
    if (fstat(domain_file, &st) < 0)
	goto out_close;

    if (ut_timespec_lte(&st.st_mtim, mtime)) {
	errno = 0;
	goto out_close;
    }

    char *data = ut_malloc(MAX_DOMAIN_FILE_SIZE + 1);

    ssize_t len = ut_read_file(domain_file, data, MAX_DOMAIN_FILE_SIZE);

    if (len < 0)
	goto out_free;

    data[len] = '\0';

    *addrs = NULL;
    ssize_t addr_len = 0;
    char *start = data;
    char *end;

    do {
	end = strchr(start, ADDR_SEP);

	if (end != NULL)
	    *end = '\0';

	if (strlen(start) > 0 && !ut_str_begins_with(start, COMMENT_CHAR))
	    add_addr(addrs, &addr_len, start);

	start = end + 1;
    } while (end != NULL);

    *mtime = st.st_mtim;
    rc = addr_len;

out_free:
    ut_free(data);
out_close:
    UT_PROTECT_ERRNO(close(domain_file));
out:
    return rc;
}

void domain_file_free_addrs(char **addrs, ssize_t count)
{
    if (addrs != NULL) {
	ssize_t i;
	for (i = 0; i < count; i++)
	    ut_free(addrs[i]);
	ut_free(addrs);
    }
}
