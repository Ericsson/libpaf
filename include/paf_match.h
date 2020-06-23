/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#ifndef PAF_MATCH_H
#define PAF_MATCH_H
#ifdef __cplusplus
extern "C" {
#endif

/*!
 * @file paf_match.h
 * @brief Pathfinder Client Library's Subscription Match-related Data Structure.
 */

#include <stdint.h>
#include <sys/types.h>

#include <paf_props.h>

/** Type of subscription match. */
enum paf_match_type {
    /**
     * A service matched that was previously unseen in this
     * subscription, either because it's newly published, because it
     * had its properties changed in such a way they begun to match
     * this subscriptions's search filter, or because the information
     * about the service's existence hadn't propagated so far as to
     * this context.
     */
    paf_match_type_appeared,
    /**
     * A service previously seen in this subscription, which have had
     * its properties modified, but in such a way they still matching
     * the subscription filter.
     */
    paf_match_type_modified,
    /**
     * A service previously seen in this subscription was either
     * unpublished or had its properties changed in such a way it no
     * longer matched the subscription filter.
     */
    paf_match_type_disappeared
};

/**
 * Callback to notify the application of matching services.
 *
 * A subscription callback may not call back into any paf.h core API
 * functions taking the current context as it's input
 * (e.g. paf_subscribe(), paf_unsubscribe() etc). Such calls must be
 * defered to after the callback has returned. Calls to other
 * Pathfinder API functions, for example functions in paf_props.h or
 * paf_value.h may be made.
 *
 * @param[in] service_id The service id of the matching service.
 * @param[in] props The properties of the matching service. NULL for disappeared type matches.
 * @param[in] match_type The type of match.
 * @param[in] user An application-supplied pointer (see paf_subscribe()).
 */
typedef void (*paf_match_cb)(enum paf_match_type match_type,
                             int64_t service_id,
                             const struct paf_props *props,
                             void *user);

#ifdef __cplusplus
}
#endif
#endif
