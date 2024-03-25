/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#include <assert.h>
#include <sys/timerfd.h>

#include "epoll_reg.h"
#include "log_ptimer.h"
#include "util.h"

#include "ptimer.h"

static struct tmo *tmo_create(int64_t tmo_id, double expiry_time)
{
    struct tmo *tmo = ut_malloc(sizeof(struct tmo));
    *tmo = (struct tmo) {
	.id = tmo_id,
	.expiry_time = expiry_time
    };
    return tmo;
}

static void tmo_destroy(struct tmo *tmo)
{
    ut_free(tmo);
}

struct ptimer *ptimer_create(clockid_t clk_id, int epoll_fd,
			     const char *log_ref)
{
    int fd = timerfd_create(clk_id, TFD_NONBLOCK);

    if (fd < 0) {
	log_ptimer_timer_fd_creation_failed(log_ref, errno);
	return NULL;
    }

    struct ptimer *timer = ut_malloc(sizeof(struct ptimer));

    *timer = (struct ptimer) {
	.clk_id = clk_id,
	.fd = fd,
	.log_ref = ut_asprintf("%s clk_id: %d timer fd: %d", log_ref,
			       clk_id, fd)
    };
    epoll_reg_init(&timer->epoll_reg, epoll_fd, log_ref);
    epoll_reg_add(&timer->epoll_reg, timer->fd, EPOLLIN);

    LIST_INIT(&timer->tmos);

    log_ptimer_created(timer);

    return timer;
}

static void set_timer_fd(struct ptimer *timer, struct itimerspec *ts)
{
    if (timerfd_settime(timer->fd, TFD_TIMER_ABSTIME, ts, NULL) < 0) {
	log_ptimer_settime_failed(timer, errno);
	/* resource exhaustion - best off dead */
	abort();
    }
}

static void arm_timer_fd(struct ptimer *timer, double rel_timeout)
{
    if (rel_timeout < 0)
	rel_timeout = 0;

    struct itimerspec ts = {};
    if (rel_timeout > 0)
        ut_f_to_timespec(rel_timeout, &ts.it_value);

    /* negative or near-zero timeout means we should wake up as
       soon as possible, but a all-zero it_value will result in the
       opposite */
    if (ts.it_value.tv_sec == 0 && ts.it_value.tv_nsec == 0)
	ts.it_value.tv_nsec = 1;

    log_ptimer_arm(timer, rel_timeout);

    set_timer_fd(timer, &ts);
}

static void disarm_timer_fd(struct ptimer *timer)
{
    struct itimerspec ts = {};

    log_ptimer_disarm(timer);

    set_timer_fd(timer, &ts);
}

static void update_epoll(struct ptimer *timer)
{
    if (LIST_EMPTY(&timer->tmos))
	disarm_timer_fd(timer);
    else {
	struct tmo *candidate = LIST_FIRST(&timer->tmos);
	struct tmo *tmo = candidate;
	while ((tmo = LIST_NEXT(tmo, entry)) != NULL)
	    if (tmo->expiry_time < candidate->expiry_time)
		candidate = tmo;

	arm_timer_fd(timer, candidate->expiry_time);
    }
}

static int64_t next_tmo_id(struct ptimer *timer)
{
    return timer->next_tmo_id++;
}

static void remove_tmo(struct ptimer *timer, struct tmo *tmo)
{
    LIST_REMOVE(tmo, entry);
    tmo_destroy(tmo);
    update_epoll(timer);
}

static int64_t schedule_abs(struct ptimer *timer, double abs_tmo)
{
    int tmo_id = next_tmo_id(timer);

    struct tmo *tmo = tmo_create(tmo_id, abs_tmo);

    LIST_INSERT_HEAD(&timer->tmos, tmo, entry);

    update_epoll(timer);

    return tmo_id;
}

int64_t ptimer_schedule_abs(struct ptimer *timer, double abs_tmo)
{
    int64_t tmo_id = schedule_abs(timer, abs_tmo);

    log_ptimer_schedule_abs(timer, tmo_id, abs_tmo);

    return tmo_id;
}

int64_t ptimer_schedule_rel(struct ptimer *timer, double rel_tmo)
{
    if (rel_tmo < 0)
	rel_tmo = 0;

    int64_t tmo_id = schedule_abs(timer, ut_ftime(timer->clk_id) + rel_tmo);

    log_ptimer_schedule_rel(timer, tmo_id, rel_tmo);

    return tmo_id;
}

void ptimer_reschedule_rel(struct ptimer *timer, double rel_tmo,
			   int64_t *tmo_id)
{
    if (*tmo_id >= 0)
	ptimer_cancel(timer, tmo_id);
    *tmo_id = ptimer_schedule_rel(timer, rel_tmo);
}

bool ptimer_has_expired(struct ptimer *timer, int64_t tmo_id)
{
    struct tmo *tmo = LIST_FIND(&timer->tmos, id, tmo_id, entry);

    if (tmo == NULL)
	return false;

    double now = ut_ftime(timer->clk_id);

    return now > tmo->expiry_time;
}

static bool try_cancel(struct ptimer *timer, int64_t tmo_id)
{
    struct tmo *tmo = LIST_FIND(&timer->tmos, id, tmo_id, entry);
    if (tmo != NULL) {
	remove_tmo(timer, tmo);
	return true;
    }
    return false;
}

void ptimer_cancel(struct ptimer *timer, int64_t *tmo_id)
{
    if (try_cancel(timer, *tmo_id))
	log_ptimer_cancel(timer, *tmo_id);
    *tmo_id = -1;
}

void ptimer_ack(struct ptimer *timer, int64_t *tmo_id)
{
    log_ptimer_ack(timer, *tmo_id);

    bool existed = try_cancel(timer, *tmo_id);
    assert(existed);

    *tmo_id = -1;
}

static void destroy_tmos(struct ptimer *timer)
{
    struct tmo *tmo;
    while ((tmo = LIST_FIRST(&timer->tmos)) != NULL) {
	LIST_REMOVE(tmo, entry);
	tmo_destroy(tmo);
    }
}

void ptimer_destroy(struct ptimer *timer)
{
    if (timer != NULL) {
	epoll_reg_reset(&timer->epoll_reg);
	UT_PROTECT_ERRNO(close(timer->fd));
	destroy_tmos(timer);
	log_ptimer_destroyed(timer);
	ut_free(timer->log_ref);
	ut_free(timer);
    }
}
