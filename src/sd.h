/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#ifndef SD_H
#define SD_H

#include <inttypes.h>
#include <sys/queue.h>
#include <sys/types.h>

#include <paf_props.h>

#include "sub.h"
#include "service.h"

enum sd_obj_type {
    sd_obj_type_service,
    sd_obj_type_sub
};

const char *sd_obj_type_str(enum sd_obj_type type);

enum sd_change_type {
    sd_change_type_added,
    sd_change_type_modified,
    sd_change_type_removed
};

const char *sd_change_type_str(enum sd_change_type type);

typedef void (*sd_listener_cb)(enum sd_obj_type obj_type, int64_t obj_id,
			       enum sd_change_type change_type, void *user);

struct sd_listener
{
    sd_listener_cb cb;
    void *user;

    LIST_ENTRY(sd_listener) entry;
};

LIST_HEAD(sd_listener_list, sd_listener);

struct sd
{
    struct service_list services;
    struct sub_list subs;
    struct sd_listener_list listeners;

    const char *log_ref;
};

struct sd *sd_create(const char *log_ctx);

int64_t sd_add_service(struct sd *sd, const struct paf_props *props,
		       int64_t ttl);
void sd_modify_service(struct sd *sd, int64_t service_id,
		       const struct paf_props *new_props,
		       const int64_t *new_ttl);
void sd_remove_service(struct sd *sd, int64_t service_id);
void sd_remove_all_services(struct sd *sd);
struct service *sd_get_service(struct sd *sd, int64_t service_id);

int64_t sd_add_sub(struct sd *sd, const char *filter_str,
		   paf_match_cb match_cb, void *user);
void sd_remove_sub(struct sd *sd, int64_t sub_id);
struct sub *sd_get_sub(struct sd *sd, int64_t sub_id);
void sd_report_match(struct sd *sd, int64_t source_id, int64_t sub_id,
		     enum paf_match_type match_type, int64_t service_id,
		     const int64_t *generation, const struct paf_props *props,
		     const int64_t *ttl, const double *orphan_since);
void sd_orphan_all_from_source(struct sd *sd, int64_t source_id, double now);

struct sd_listener *sd_add_listener(struct sd *sd, sd_listener_cb cb,
				    void *user);
void sd_remove_listener(struct sd *sd, struct sd_listener *listener);

bool sd_has_timeout(struct sd *sd);
double sd_next_timeout(struct sd *sd);
void sd_process(struct sd *sd, double now);

void sd_destroy(struct sd *sd);

#endif
