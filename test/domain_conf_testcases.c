/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020-2021 Ericsson AB
 */

#include <limits.h>

#include "utest.h"

#include "util.h"
#include "testutil.h"

#include "domain_conf.h"

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

TESTSUITE(domain_conf, setup, teardown)

TESTCASE(domain_conf, read_file)
{
    const char *addr0 = "ux:foo";
    const char *addr1 = "tls:127.0.0.1:4711";

    tu_executef("echo \"%s\n# A comment\n%s\n\" > %s/%s", addr0, addr1,
		domain_dir, domain_name);

    /* new (future, even) mtime */
    struct timespec mtime = {
	.tv_sec = time(NULL) + 2
    };

    errno = 1234;
    struct domain_conf *conf = domain_conf_read(domain_name, &mtime, NULL);
    CHK(conf == NULL);
    CHKERRNOEQ(0);

    mtime.tv_sec = 0;
    conf = domain_conf_read(domain_name, &mtime, NULL);
    CHK(conf != NULL);
    CHKINTEQ(conf->num_servers, 2);

    CHKSTREQ(conf->servers[0]->addr, addr0);
    CHKSTREQ(conf->servers[1]->addr, addr1);

    domain_conf_destroy(conf);

    errno = 1234;
    conf = domain_conf_read(domain_name, &mtime, NULL);
    CHK(conf == NULL);
    CHKERRNOEQ(0);

    tu_executef("chmod a-rwx %s/%s", domain_dir, domain_name);
    mtime.tv_sec = time(NULL) - 1;
    conf = domain_conf_read(domain_name, &mtime, NULL);
    CHK(conf == NULL);
    CHKERRNOEQ(EACCES);
    tu_executef("chmod u+rw %s/%s", domain_dir, domain_name);

    return UTEST_SUCCESS;
}

TESTCASE(domain_conf, json_read_file)
{
    const char *addr0 = "ux:foo";
    const char *addr1 = "tls:127.0.0.1:4711";
    const char *addr2 = "tls:127.0.42.1:42";
    const char *cert_file = "/asdf/cert.pem";
    const char *key_file = "/asdf/key.pem";
    const char *tc_file = "/asdf/cabundle.pem";

    struct timespec mtime = {
	.tv_sec = time(NULL) - 1
    };

    tu_executef("echo '"
		"{\n"
		"  \"servers\": [\n"
		"    {\n"
		"      \"address\": \"%s\"\n"
		"    },\n"
		"    {\n"
		"      \"address\": \"%s\"\n"
		"    },\n"
		"    {\n"
		"      \"address\": \"%s\",\n"
		"      \"tlsCertificateFile\": \"%s\",\n"
		"      \"tlsKeyFile\": \"%s\",\n"
		"      \"tlsTrustedCaFile\": \"%s\"\n"
		"    }\n"
		"  ]\n"
		"}\n' > %s/%s", addr0, addr1, addr2, cert_file, key_file,
		tc_file, domain_dir, domain_name);

    struct domain_conf *conf = domain_conf_read(domain_name, &mtime, NULL);
    CHK(conf != NULL);
    CHKINTEQ(conf->num_servers, 3);

    CHKSTREQ(conf->servers[0]->addr, addr0);
    CHKNULL(conf->servers[0]->cert_file);
    CHKNULL(conf->servers[0]->key_file);
    CHKNULL(conf->servers[0]->tc_file);

    CHKSTREQ(conf->servers[1]->addr, addr1);
    CHKNULL(conf->servers[1]->cert_file);
    CHKNULL(conf->servers[1]->key_file);
    CHKNULL(conf->servers[1]->tc_file);

    CHKSTREQ(conf->servers[2]->addr, addr2);
    CHKSTREQ(conf->servers[2]->cert_file, cert_file);
    CHKSTREQ(conf->servers[2]->key_file, key_file);
    CHKSTREQ(conf->servers[2]->tc_file, tc_file);

    domain_conf_destroy(conf);

    return UTEST_SUCCESS;
}

TESTCASE(domain_conf, repeated_server_addr)
{
    const char *addr = "tls:127.0.0.1:4711";

    tu_executef("echo \"%s\n# A comment\n%s\n\" > %s/%s", addr, addr,
		domain_dir, domain_name);

    struct timespec mtime = { 0 };

    struct domain_conf *conf = domain_conf_read(domain_name, &mtime, NULL);
    CHK(conf == NULL);

    return UTEST_SUCCESS;
}

TESTCASE(domain_conf, json_repeated_addr)
{
    struct timespec mtime = {
	.tv_sec = time(NULL) - 1
    };

    tu_executef("echo '"
		"{\n"
		"  \"servers\": [\n"
		"    {\n"
		"      \"address\": \"ux:foo\"\n"
		"    },\n"
		"    {\n"
		"      \"address\": \"ux:bar\"\n"
		"    },\n"
		"    {\n"
		"      \"address\": \"ux_foo\"\n"
		"    }\n"
		"  ]\n"
		"}\n' > %s/%s", domain_dir, domain_name);

    struct domain_conf *conf = domain_conf_read(domain_name, &mtime, NULL);
    CHK(conf == NULL);
    CHKERRNOEQ(EINVAL);

    return UTEST_SUCCESS;
}

TESTCASE(domain_conf, read_empty_file)
{
    tu_executef("touch %s/%s", domain_dir, domain_name);

    struct timespec mtime = { 0 };

    struct domain_conf *conf = domain_conf_read(domain_name, &mtime, NULL);
    CHK(conf != NULL);
    CHKINTEQ(conf->num_servers, 0);

    domain_conf_destroy(conf);

    return UTEST_SUCCESS;
}

TESTCASE(domain_conf, read_file_wo_newline)
{
    const char *addr = "tcp:10.10.10.10:10";

    tu_executef("echo \"%s\" > %s/%s", addr, domain_dir, domain_name);

    struct timespec mtime = { 0 };

    struct domain_conf *conf = domain_conf_read(domain_name, &mtime, NULL);
    CHK(conf != NULL);
    CHKINTEQ(conf->num_servers, 1);
    CHKSTREQ(addr, conf->servers[0]->addr);

    domain_conf_destroy(conf);

    return UTEST_SUCCESS;
}

TESTCASE(domain_conf, json_missing_address)
{
    struct timespec mtime = {
	.tv_sec = time(NULL) - 1
    };

    tu_executef("echo '"
		"{\n"
		"  \"servers\": [\n"
		"    {\n"
		"    },\n"
		"    {\n"
		"      \"address\": \"ux:foo\"\n"
		"    }\n"
		"  ]\n"
		"}\n' > %s/%s", domain_dir, domain_name);

    struct domain_conf *conf = domain_conf_read(domain_name, &mtime, NULL);
    CHK(conf == NULL);
    CHKERRNOEQ(EINVAL);

    domain_conf_destroy(conf);

    return UTEST_SUCCESS;
}

TESTCASE(domain_conf, invalid_json)
{
    struct timespec mtime = {
	.tv_sec = time(NULL) - 1
    };

    tu_executef("echo '"
		"{\n"
		"  \"servers\": [\n"
		"    {\n"
		"      \"address\": \"ux:foo\"\n"
		"    }\n"
		"  \n"
		"}\n' > %s/%s", domain_dir, domain_name);

    struct domain_conf *conf = domain_conf_read(domain_name, &mtime, NULL);
    CHK(conf == NULL);
    CHKERRNOEQ(EINVAL);

    domain_conf_destroy(conf);

    return UTEST_SUCCESS;
}

TESTCASE(domain_conf, json_invalid_address_format)
{
    struct timespec mtime = {
	.tv_sec = time(NULL) - 1
    };

    tu_executef("echo '"
		"{\n"
		"  \"servers\": [\n"
		"    {\n"
		"    },\n"
		"    {\n"
		"      \"address\": \"http://foo\"\n"
		"    }\n"
		"  ]\n"
		"}\n' > %s/%s", domain_dir, domain_name);

    struct domain_conf *conf = domain_conf_read(domain_name, &mtime, NULL);
    CHK(conf == NULL);
    CHKERRNOEQ(EINVAL);

    domain_conf_destroy(conf);

    return UTEST_SUCCESS;
}

