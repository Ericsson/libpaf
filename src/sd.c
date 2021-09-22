/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#include <assert.h>
#include <float.h>
#include <stdbool.h>
#include <unistd.h>

#include "util.h"
#include "log_sd.h"

#include "sd.h"

const char *sd_obj_type_str(enum sd_obj_type type)
{
    switch (type) {
    case sd_obj_type_service:
	return "service";
    case sd_obj_type_sub:
	return "subscription";
    default:
        assert(0);
    }
}

#define CLABEL(name)				     \
    case sd_change_type_ ## name:		     \
    return #name

const char *sd_change_type_str(enum sd_change_type type)
{
    switch (type) {
        CLABEL(added);
        CLABEL(modified);
        CLABEL(removed);
    default:
        assert(0);
    }
}

struct sd *sd_create(const char *log_ref)
{
    struct sd *sd = ut_malloc(sizeof(struct sd));

    LIST_INIT(&sd->services);
    LIST_INIT(&sd->subs);
    LIST_INIT(&sd->listeners);

    sd->log_ref = log_ref;

    return sd;
}

static void notify_listeners(struct sd_listener_list *listeners,
			     enum sd_obj_type obj_type, int64_t obj_id,
			     enum sd_change_type change_type)
{
    struct sd_listener *listener;
    LIST_FOREACH(listener, listeners, entry)
	listener->cb(obj_type, obj_id, change_type, listener->user);
}

int64_t sd_add_service(struct sd *sd, const struct paf_props *props,
		       int64_t ttl)
{
    int64_t service_id = ut_rand_id();

    struct service *service = service_create(service_id, 0, props, ttl);

    LIST_INSERT_HEAD(&sd->services, service, entry);

    notify_listeners(&sd->listeners, sd_obj_type_service, service_id,
		     sd_change_type_added);

    return service_id;
}

void sd_modify_service(struct sd *sd, int64_t service_id,
		       const struct paf_props *new_props,
		       const int64_t *new_ttl)

{
    struct service *service = sd_get_service(sd, service_id);
    assert(service != NULL);

    bool changed = service_modify(service, new_props, new_ttl);

    if (changed)
	notify_listeners(&sd->listeners, sd_obj_type_service,
			 service->service_id, sd_change_type_modified);
}

static void remove_service(struct sd *sd, struct service *service)
{
    LIST_REMOVE(service, entry);

    notify_listeners(&sd->listeners, sd_obj_type_service,
		     service->service_id, sd_change_type_removed);

    service_destroy(service);
}

void sd_remove_service(struct sd *sd, int64_t service_id)
{
    struct service *service = sd_get_service(sd, service_id);
    assert(service != NULL);

    remove_service(sd, service);
}

void sd_remove_all_services(struct sd *sd)
{
    struct service *service;
    while ((service = LIST_FIRST(&sd->services)) != NULL)
	remove_service(sd, service);
}

struct service *sd_get_service(struct sd *sd, int64_t service_id)
{
    struct service *service;
    LIST_FOREACH(service, &sd->services, entry)
        if (service->service_id == service_id)
            return service;
    return NULL;
}

int64_t sd_add_sub(struct sd *sd, const char *filter_str,
		   paf_match_cb match_cb, void *user)
{
    int64_t sub_id = ut_rand_id();
    struct sub *sub =
        sub_create(sub_id, filter_str, sd->log_ref, match_cb, user);

    LIST_INSERT_HEAD(&sd->subs, sub, entry);

    notify_listeners(&sd->listeners, sd_obj_type_sub, sub_id,
		     sd_change_type_added);
    return sub_id;
}

void sd_remove_sub(struct sd *sd, int64_t sub_id)
{
    struct sub *sub = sd_get_sub(sd, sub_id);
    assert(sub != NULL);

    LIST_REMOVE(sub, entry);

    notify_listeners(&sd->listeners, sd_obj_type_sub, sub->sub_id,
		     sd_change_type_removed);

    sub_destroy(sub);
}

struct sub *sd_get_sub(struct sd *sd, int64_t sub_id)
{
    struct sub *sub;
    LIST_FOREACH(sub, &sd->subs, entry)
        if (sub->sub_id == sub_id)
            return sub;
    return NULL;
}

void sd_report_match(struct sd *sd, int64_t source_id, int64_t sub_id,
		     enum paf_match_type match_type, int64_t service_id,
		     const int64_t *generation, const struct paf_props *props,
		     const int64_t *ttl, const double *orphan_since)
{
    struct sub *sub = sd_get_sub(sd, sub_id);
    assert(sub != NULL);

    sub_report_match(sub, source_id, match_type, service_id, generation,
		     props, ttl, orphan_since);
}

void sd_orphan_all_from_source(struct sd *sd, int64_t source_id, double now)
{
    struct sub *sub;
    LIST_FOREACH(sub, &sd->subs, entry)
	sub_orphan_all_from_source(sub, source_id, now);
}

struct sd_listener *sd_add_listener(struct sd *sd, sd_listener_cb cb,
				    void *user)
{
    struct sd_listener *listener = ut_malloc(sizeof(struct sd_listener));

    *listener = (struct sd_listener) {
	.cb = cb,
	.user = user
    };

    LIST_INSERT_HEAD(&sd->listeners, listener, entry);
    return listener;
}

void sd_remove_listener(struct sd *sd __attribute__((unused)),
			struct sd_listener *listener)
{
    LIST_REMOVE(listener, entry);
    ut_free(listener);
}

bool sd_has_timeout(struct sd *sd)
{
    struct sub *sub;

    LIST_FOREACH(sub, &sd->subs, entry)
	if (sub_has_orphan(sub))
	    return true;

    return false;
}

double sd_next_timeout(struct sd *sd)
{
    double candidate = DBL_MAX;

    struct sub *sub;
    LIST_FOREACH(sub, &sd->subs, entry) {
	if (!sub_has_orphan(sub))
            continue;
        double t = sub_next_orphan_timeout(sub);
	if (t < candidate)
            candidate = t;
    }

    return candidate;
}

static void purge_orphans(struct sd *sd, double now)
{
    struct sub *sub;

    LIST_FOREACH(sub, &sd->subs, entry)
        sub_purge_orphans(sub, now);
}

void sd_process(struct sd *sd, double now)
{
    purge_orphans(sd, now);
}

void sd_destroy(struct sd *sd)
{
    if (sd != NULL) {
        struct service *service;
        while ((service = LIST_FIRST(&sd->services)) != NULL) {
            LIST_REMOVE(service, entry);
            service_destroy(service);
        }

        struct sub *sub;
        while ((sub = LIST_FIRST(&sd->subs)) != NULL) {
            LIST_REMOVE(sub, entry);
            sub_destroy(sub);
        }

        struct sd_listener *listener;
        while ((listener = LIST_FIRST(&sd->listeners)) != NULL)
	    sd_remove_listener(sd, listener);

        ut_free(sd);
    }
}
