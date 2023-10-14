/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Ericsson AB
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "session.h"
#include "util.h"

static void usage(const char *name)
{
    printf("Usage: %s [OPTIONS] <addr>\n", name);
    printf("OPTIONS:\n");
    printf("    -i <client_id>  Manually specify the client id.\n");
    printf("    -h              Show this help.\n"); 
}

int main(int argc, char **argv)
{
    int64_t client_id = -1;
    int c;

    while ((c = getopt(argc, argv, "i:h")) != -1)
    switch (c) {
    case 'i': {
	if (ut_parse_uint63(optarg, 16, &client_id) < 0) {
	    fprintf(stderr, "\"%s\" is not a non-negative integer in "
		    "hexadecimal format.\n", optarg);
	    exit(EXIT_FAILURE);
	}
	break;
    }
    case 'h':
	usage(argv[0]);
	exit(EXIT_SUCCESS);
	break;
    case '?':
	exit(EXIT_FAILURE);
    }

    int num_args = argc - optind;

    if (num_args != 1) {
	usage(argv[0]);
	exit(EXIT_FAILURE);
    }

    const char *addr = argv[optind];

    int rc = session_init(client_id, addr);

    if (rc < 0)
	goto out;

    rc = session_run();

    session_deinit();

out:
    exit(rc == 0 ? EXIT_SUCCESS: EXIT_FAILURE);
}
