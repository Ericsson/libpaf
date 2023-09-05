/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#include <assert.h>
#include <inttypes.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <paf.h>

static void usage(const char *name)
{
    printf("%s <domain> publish [<prop-name> <prop-value>]\n", name);
    printf("%s <domain> subscribe [<query>]\n", name);
}

static double ftime(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec+((double)t.tv_nsec)/1e9;
}

/* normally you would hook into a proper eventloop (like libevent), but
   to avoid such a depenceny, we are using "raw" poll() here */
static int wait_for(struct paf_context *context, double duration)
{
    double now = ftime();
    double deadline = now + duration;

    for (; now < deadline; now = ftime()) {
        double left = deadline - now;

        int fd = paf_fd(context);
        if (fd < 0)
            return -1;

        struct pollfd pollfd = {
            .fd = fd,
            .events = POLLIN
        };

        int rc = poll(&pollfd, 1, left * 1000);

        if (rc == 0) /* timeout */
            return 0;
        else if (rc < 0)
            return -1;

        paf_process(context);
    }

    return 0;
}

static struct paf_context *connect(const char *domain_name)
{
    struct paf_context *context = paf_attach(domain_name);

    if (!context) {
        printf("Unable to create context.\n");
        exit(EXIT_FAILURE);
    }

    return context;
}

static void publish(const char *domain_name, const char **args, int num_args)
{
    if (num_args % 2 != 0) {
        printf("Invalid properties list length.\n");
        exit(EXIT_FAILURE);
    }

    struct paf_props *props = paf_props_create();
    size_t num_props = num_args / 2;

    size_t i;
    for (i = 0; i < num_props; i++) {
        const char *prop_name = args[i*2];
        const char *prop_value = args[i*2+1];
        paf_props_add_str(props, prop_name, prop_value);
    }

    struct paf_context *context = connect(domain_name);

    int64_t service_id = paf_publish(context, props);

    assert(service_id >=0);
    printf("Service %"PRIx64" published.\n", service_id);

    wait_for(context, 1e9);

    paf_close(context);
}

static void print_prop(const char *prop_name,
                       const struct paf_value *prop_value,
                       void *user)
{
    printf("    %s: ", prop_name);
    if (paf_value_is_str(prop_value))
        printf("\"%s\"\n", paf_value_str(prop_value));
    else
        printf("%"PRId64"\n", paf_value_int64(prop_value));
}

static void match_cb(enum paf_match_type match_type, int64_t service_id,
                     const struct paf_props *props, void *user)
{
    printf("Match:\n");
    printf("  Type: ");
    switch (match_type) {
    case paf_match_type_appeared:
        printf("Appeared\n");
        break;
    case paf_match_type_modified:
        printf("Modified\n");
        break;
    case paf_match_type_disappeared:
        printf("Disappeared\n");
        break;
    }
    printf("  Service Id: %"PRIx64"\n", service_id);

    if (props != NULL && paf_props_num_values(props) > 0) {
        printf("  Properties:\n");
        paf_props_foreach(props, print_prop, NULL);
    }
}

static void subscribe(const char *domain_name, const char *query)
{
    struct paf_context *context = connect(domain_name);

    int64_t sub_id =
        paf_subscribe(context, query, match_cb, NULL);
    assert(sub_id >= 0);

    wait_for(context, 1e9);

    paf_close(context);
}

int main(int argc, char **argv)
{
    if (argc >=3 && strcmp(argv[2], "publish") == 0)
        publish(argv[1], (const char **)&argv[3], argc - 3);
    else if ((argc == 3 || argc == 4) && strcmp(argv[2], "subscribe") == 0) {
        const char *filter = NULL;
        if (argc == 4)
            filter = argv[3];
        subscribe(argv[1], filter);
    } else {
        usage(argv[0]);
        exit(EXIT_FAILURE);
    }
}
