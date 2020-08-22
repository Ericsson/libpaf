/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#include <assert.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <unistd.h>

#include <xcm.h>

#include <paf.h>
#include <paf_err.h>

#include "conf.h"
#include "domain_file.h"
#include "epoll_reg.h"
#include "filter.h"
#include "link.h"
#include "list.h"
#include "log_ctx.h"
#include "msg.h"
#include "proto_ta.h"
#include "ptimer.h"
#include "sd.h"
#include "util.h"

enum ctx_state {
    ctx_state_operational,
    ctx_state_detaching,
    ctx_state_detached
};

struct paf_context
{
    int64_t client_id;

    char *domain;

    enum ctx_state state;

    struct epoll_reg epoll_reg;

    struct ptimer *mono_timer;
    struct ptimer *rt_timer;

    struct sd *sd;
    int64_t sd_tmo;

    struct timespec domain_file_mtime;
    double rescan_period;
    int64_t rescan_tmo;

    struct link_list links;
    int64_t next_link_id;
    bool processing;

    char *log_ref;
};

#define SLABEL(name)                            \
    case ctx_state_ ## name:			\
    return #name

static const char *ctx_state_str(enum ctx_state state)
{
    switch (state) {
        SLABEL(operational);
        SLABEL(detaching);
        SLABEL(detached);
    default:
        assert(0);
    }
}

static bool str_eq(const char *a, const char *b)
{
    return strcmp(a, b) == 0;
}

static struct link *get_link(struct paf_context *ctx, const char *link_addr)
{
    return LIST_FIND_FUN(&ctx->links, domain_addr, link_addr, entry,
			 str_eq);
}

static bool has_link(struct paf_context *ctx, const char *link_addr)
{
    return get_link(ctx, link_addr) != NULL;
}

static int64_t get_next_link_id(struct paf_context *ctx)
{
    return ctx->next_link_id++;
}

static void setup_link(struct paf_context *ctx, const char *link_addr)
{
    int64_t link_id = get_next_link_id(ctx);
    log_ctx_link_setup(ctx, link_addr, link_id);
    struct link *link = link_create(link_id, ctx->client_id, link_addr,
				    ctx->sd, ctx->mono_timer,
				    ctx->epoll_reg.epoll_fd, ctx->log_ref);
    LIST_INSERT_HEAD(&ctx->links, link, entry);
}

static void teardown_link(struct paf_context *ctx, struct link *link)
{
    log_ctx_link_teardown(ctx, link->domain_addr, link->link_id);
    LIST_REMOVE(link, entry);
    link_destroy(link);
}

static void teardown_link_by_addr(struct paf_context *ctx,
				  const char *link_addr)
{
    struct link *link = get_link(ctx, link_addr);
    teardown_link(ctx, link);
}

static void rescan_domain_file(struct paf_context *ctx)
{
    char **addrs = NULL;

    UT_SAVE_ERRNO;
    ssize_t addrs_len =
	domain_file_get_addrs(ctx->domain, &ctx->domain_file_mtime, &addrs);
    UT_RESTORE_ERRNO(get_errno);

    if (addrs_len < 0) {
	if (get_errno != 0)
	    log_ctx_domain_file_error(ctx, get_errno);
	else
	    log_ctx_domain_file_unchanged(ctx);
	return;
    }

    /* create links added to the domains file */
    ssize_t i;
    for (i = 0; i < addrs_len; i++) {
	if (!has_link(ctx, addrs[i]))
	    setup_link(ctx, addrs[i]);
    }

    /* destroy links removed from the domains file */
    struct link *link = LIST_FIRST(&ctx->links);
    while (link != NULL) {
	struct link *next = LIST_NEXT(link, entry);
	if (!ut_str_ary_has(addrs, addrs_len, link->domain_addr))
	    teardown_link_by_addr(ctx, link->domain_addr);
	link = next;
    }

    domain_file_free_addrs(addrs, addrs_len);
}

static void conf_rescan_tmo(struct paf_context *ctx)
{
    ptimer_cancel(ctx->mono_timer, &ctx->rescan_tmo);

    if (ctx->rescan_period > 0)
	ctx->rescan_tmo =
	    ptimer_install_rel(ctx->mono_timer, ctx->rescan_period);
}

static void conf_sd_tmo(struct paf_context *ctx)
{
    ptimer_cancel(ctx->rt_timer, &ctx->sd_tmo);

    if (sd_has_timeout(ctx->sd)) {
	double abs_tmo = sd_next_timeout(ctx->sd);
	assert(abs_tmo >= 0);

	log_ctx_sd_timeout(ctx, ctx->rt_timer->clk_id, abs_tmo);

	ctx->sd_tmo = ptimer_install_abs(ctx->rt_timer, abs_tmo);
    }
}

struct paf_context *paf_attach(const char *domain)
{
    int64_t client_id = ut_rand_id();

    char *log_ref = ut_asprintf("client: %"PRIx64" domain: %s",
				client_id, domain);

    int epoll_fd = epoll_create1(0);
    if (epoll_fd < 0)
        goto err_free_log_ref;

    struct ptimer *mono_timer =
	ptimer_create(CLOCK_MONOTONIC, epoll_fd, log_ref);
    if (mono_timer == NULL)
        goto err_close_epoll_fd;

    struct ptimer *rt_timer =
	ptimer_create(CLOCK_REALTIME, epoll_fd, log_ref);
    if (rt_timer == NULL)
        goto err_destroy_mono_timer;

    struct paf_context *ctx = ut_malloc(sizeof(struct paf_context));

    char *ctx_domain = ut_strdup(domain);

    *ctx = (struct paf_context) {
	.client_id = client_id,
        .domain = ctx_domain,
	.state = ctx_state_operational,
	.mono_timer = mono_timer,
	.rt_timer = rt_timer,
        .sd = sd_create(ctx_domain),
        .sd_tmo = -1,
	.rescan_period = ut_frandomize(conf_get_rescan_period()),
	.rescan_tmo = -1,
	.next_link_id = 0,
	.processing = false,
	.log_ref = log_ref
    };

    epoll_reg_init(&ctx->epoll_reg, epoll_fd, log_ref);
    LIST_INIT(&ctx->links);

    log_ctx_start(ctx, ctx->epoll_reg.epoll_fd);

    rescan_domain_file(ctx);

    conf_rescan_tmo(ctx);

    return ctx;

err_destroy_mono_timer:
    ptimer_destroy(mono_timer);
err_close_epoll_fd:
    UT_PROTECT_ERRNO(close(epoll_fd));
err_free_log_ref:
    ut_free(log_ref);
    return NULL;
}

static void verify_normal_calls_allowed(struct paf_context *ctx)
{
    assert(!ctx->processing && ctx->state != ctx_state_detaching &&
           ctx->state != ctx_state_detached);
}

int paf_fd(struct paf_context *ctx)
{
    return ctx->epoll_reg.epoll_fd;
}

int paf_process(struct paf_context *ctx)
{
    assert(!ctx->processing);

    log_ctx_processing(ctx, ctx_state_str(ctx->state));

    int rc = 0;

    ctx->processing = true;

    struct link *link = LIST_FIRST(&ctx->links);
    while (link != NULL) {
	struct link *next = LIST_NEXT(link, entry);
	int rc = link_process(link);
	if (rc < 0) {
	    /* links are not allowed to fail unless explicitly
	     * detached */
	    assert(ctx->state == ctx_state_detaching);
	    assert(rc == LINK_ERR_DETACHED);
	    teardown_link(ctx, link);
	}
	link = next;
    }

    if (ctx->state == ctx_state_operational) {
	if (ptimer_has_expired(ctx->mono_timer, ctx->rescan_tmo)) {
	    rescan_domain_file(ctx);
	    conf_rescan_tmo(ctx);
	}
	conf_sd_tmo(ctx);
    } else {
	ptimer_cancel(ctx->mono_timer, &ctx->rescan_tmo);
	ptimer_cancel(ctx->rt_timer, &ctx->sd_tmo);
    }

    if (ctx->state == ctx_state_operational ||
	ctx->state == ctx_state_detaching) {
	double now = ut_ftime(CLOCK_REALTIME);
	sd_process(ctx->sd, now);
    }


    if (ctx->state == ctx_state_detaching && LIST_EMPTY(&ctx->links)) {
	log_ctx_detached(ctx);
	ctx->state = ctx_state_detached;
    }

    if (ctx->state == ctx_state_detached)
	rc = PAF_ERR_DETACHED;

    ctx->processing = false;

    return rc;
}

#define JSON_INT_WIRE_SIZE (25)
#define JSON_STR_WIRE_OVERHEAD (5)
/* Keep it half of XCM maximum message size, to be on the safe side */
#define MAX_WIRE_SIZE (1<<15)

static void estimate_wire_size(const char *prop_name,
                               const struct paf_value *prop_value,
                               void *user)
{
    size_t *size = user;

    (*size) += (strlen(prop_name) + JSON_STR_WIRE_OVERHEAD);
    if (paf_value_is_str(prop_value))
        (*size) += (strlen(paf_value_str(prop_value)) + JSON_STR_WIRE_OVERHEAD);
    else
        (*size) += JSON_INT_WIRE_SIZE;
}

static bool oversized_props(const struct paf_props *props)
{
    size_t size = 0;
    paf_props_foreach(props, estimate_wire_size, &size);

    return size > MAX_WIRE_SIZE;
}

int64_t paf_publish(struct paf_context *ctx, const struct paf_props *props)
{
    verify_normal_calls_allowed(ctx);

    if (oversized_props(props))
        return PAF_ERR_PROPS_TOO_LARGE;

    int64_t service_id = sd_add_service(ctx->sd, props, conf_get_ttl());

    log_ctx_publish(ctx, service_id, props);

    return service_id;
}

int paf_modify(struct paf_context *ctx, int64_t service_id,
               const struct paf_props *new_props)
{
    verify_normal_calls_allowed(ctx);

    if (oversized_props(new_props))
        return PAF_ERR_PROPS_TOO_LARGE;

    struct service *service = sd_get_service(ctx->sd, service_id);
    assert(service != NULL);

    log_ctx_modify(ctx, service->service_id, service->props, new_props);

    sd_modify_service(ctx->sd, service_id, new_props, NULL);

    return 0;
}

void paf_unpublish(struct paf_context *ctx, int64_t service_id)
{ 
    verify_normal_calls_allowed(ctx);

    log_ctx_unpublish(ctx, service_id);

    sd_remove_service(ctx->sd, service_id);
}

#define MAX_FILTER_SIZE (MAX_WIRE_SIZE/4)

int64_t paf_subscribe(struct paf_context *ctx, const char *filter_str,
                      paf_match_cb match_cb, void *user)
{
    verify_normal_calls_allowed(ctx);

    if (filter_str != NULL) {
	if (!filter_is_valid(filter_str))
	    return PAF_ERR_INVALID_FILTER_SYNTAX;
	if (strlen(filter_str) > MAX_FILTER_SIZE)
	    return PAF_ERR_FILTER_TOO_LARGE;
    }

    int64_t sub_id = sd_add_sub(ctx->sd, filter_str, match_cb, user);

    log_ctx_subscribe(ctx, sub_id, filter_str);

    return sub_id;
}

void paf_unsubscribe(struct paf_context *ctx, int64_t sub_id)
{ 
    verify_normal_calls_allowed(ctx);

    log_ctx_unsubscribe(ctx, sub_id);

    sd_remove_sub(ctx->sd, sub_id);
}

void paf_detach(struct paf_context *ctx)
{
    verify_normal_calls_allowed(ctx);

    log_ctx_detaching(ctx);

    sd_remove_all_services(ctx->sd);

    struct link *link;
    LIST_FOREACH(link, &ctx->links, entry)
	link_detach(link);

    ctx->state = ctx_state_detaching;
}

void paf_close(struct paf_context *ctx)
{
    if (ctx != NULL) {
        assert(!ctx->processing);

        log_ctx_close(ctx);

	struct link *link;
	while ((link = LIST_FIRST(&ctx->links)) != NULL) {
	    LIST_REMOVE(link, entry);
	    link_destroy(link);
	}

	ptimer_destroy(ctx->mono_timer);
	ptimer_destroy(ctx->rt_timer);

        UT_PROTECT_ERRNO(close(ctx->epoll_reg.epoll_fd));

        sd_destroy(ctx->sd);
        ut_free(ctx->domain);
	ut_free(ctx->log_ref);
        ut_free(ctx);
    }
}

char *paf_filter_escape(const char *s)
{
    return filter_escape(s);
}
