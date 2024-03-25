/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#ifndef PTIMER_H
#define PTIMER_H

#include <time.h>
#include <stdbool.h>
#include <stdint.h>

#include "list.h"
#include "epoll_reg.h"

struct tmo
{
    int64_t id;
    double expiry_time;

    LIST_ENTRY(tmo) entry;
};

LIST_HEAD(tmo_list, tmo);

struct ptimer
{
    clockid_t clk_id;
    int fd;
    struct epoll_reg epoll_reg;
    struct tmo_list tmos;
    int64_t next_tmo_id;

    char *log_ref;
};

struct ptimer *ptimer_create(clockid_t clk_id, int epoll_fd,
			     const char *log_ref);

int64_t ptimer_schedule_abs(struct ptimer *timer, double abs_tmo);
int64_t ptimer_schedule_rel(struct ptimer *timer, double rel_tmo);

void ptimer_reschedule_rel(struct ptimer *timer, double rel_tmo,
			   int64_t *tmo_id);

bool ptimer_has_expired(struct ptimer *timer, int64_t tmo_id);
double ptimer_time_left(struct ptimer *timer, int64_t tmo_id);
void ptimer_cancel(struct ptimer *timer, int64_t *tmo_id);
void ptimer_ack(struct ptimer *timer, int64_t *tmo_id);

void ptimer_destroy(struct ptimer *timer);

#endif
