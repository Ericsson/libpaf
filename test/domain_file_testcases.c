/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#include <limits.h>

#include "utest.h"

#include "util.h"
#include "testutil.h"

#include "domain_file.h"

#define TEST_DIR "./test/domains.d"

static char domain_dir[PATH_MAX];
static char domain_name[NAME_MAX];

static void gen_domain(char *domain, size_t capacity)
{
    size_t len = tu_randint(1, capacity-1);
    size_t i;
    for (i = 0; i < len; i++)
	domain[i] = tu_randint('a', 'z');
    domain[len] = '\0';
}

static int setup(void)
{
    snprintf(domain_dir, sizeof(domain_dir), "./test/domains.d-%d", getpid());
    gen_domain(domain_name, sizeof(domain_name));

    CHKNOERR(tu_executef_es("mkdir -p %s", domain_dir));

    if (setenv("PAF_DOMAINS", domain_dir, 1) < 0)
	return UTEST_FAIL;

    return UTEST_SUCCESS;
}

static int teardown(void)
{
    tu_executef("rm -f %s/%s", domain_dir, domain_name);
    tu_executef("rmdir %s", domain_dir);

    CHKNOERR(unsetenv("PAF_DOMAINS"));

    return UTEST_SUCCESS;
}

TESTSUITE(domain_file, setup, teardown)

TESTCASE(domain_file, read_file)
{
    const char *addr0 = "ux:foo";
    const char *addr1 = "tls:127.0.0.1:4711";

    tu_executef("echo \"%s\n# A comment\n%s\n\" > %s/%s", addr0, addr1,
		domain_dir, domain_name);

    char **addrs = NULL;
    /* new (future, even) mtime */
    struct timespec mtime = {
	.tv_sec = time(NULL) + 2
    };

    errno = 1234;
    CHK(domain_file_get_addrs(domain_name, &mtime, &addrs) < 0);
    CHKERRNOEQ(0);

    mtime.tv_sec = 0;
    ssize_t addrs_len = domain_file_get_addrs(domain_name, &mtime, &addrs);
    CHKINTEQ(addrs_len, 2);

    CHKSTREQ(addrs[0], addr0);
    CHKSTREQ(addrs[1], addr1);

    domain_file_free_addrs(addrs, 2);

    errno = 1234;
    CHK(domain_file_get_addrs(domain_name, &mtime, &addrs) < 0);
    CHKERRNOEQ(0);

    tu_executef("chmod a-rwx %s/%s", domain_dir, domain_name);
    mtime.tv_sec = time(NULL) - 1;
    CHK(domain_file_get_addrs(domain_name, &mtime, &addrs) < 0);
    CHKERRNOEQ(EACCES);
    tu_executef("chmod u+rw %s/%s", domain_dir, domain_name);

    return UTEST_SUCCESS;
}

TESTCASE(domain_file, read_empty_file)
{
    tu_executef("touch %s/%s", domain_dir, domain_name);

    char **addrs = NULL;
    struct timespec mtime = { 0 };

    CHKINTEQ(domain_file_get_addrs(domain_name, &mtime, &addrs), 0);

    return UTEST_SUCCESS;
}

TESTCASE(domain_file, read_file_wo_newline)
{
    const char *addr = "tcp:10.10.10.10:10";

    tu_executef("echo \"%s\" > %s/%s", addr, domain_dir, domain_name);

    char **addrs = NULL;
    struct timespec mtime = { 0 };

    CHKINTEQ(domain_file_get_addrs(domain_name, &mtime, &addrs), 1);
    CHKSTREQ(addr, addrs[0]);

    domain_file_free_addrs(addrs, 1);

    return UTEST_SUCCESS;
}
