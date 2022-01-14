/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER com_ericsson_paf

#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "./paf_lttng.h"

#if !defined(_PAF_LTTNG_H) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define _PAF_LTTNG_H

#include <lttng/tracepoint.h>

TRACEPOINT_EVENT(
    com_ericsson_paf,
    paf_debug,
    TP_ARGS(
	    const char *, context,
	    const char *, msg
    ),
    TP_FIELDS(
	      ctf_string(context, context)
	      ctf_string(msg, msg)
    )
)

TRACEPOINT_EVENT(
    com_ericsson_paf,
    paf_error,
    TP_ARGS(
	    const char *, context,
	    const char *, msg
    ),
    TP_FIELDS(
	      ctf_string(context, context)
	      ctf_string(msg, msg)
    )
)

TRACEPOINT_LOGLEVEL(com_ericsson_paf, paf_debug, TRACE_DEBUG)
TRACEPOINT_LOGLEVEL(com_ericsson_paf, paf_error, TRACE_ERR)

#endif

#include <lttng/tracepoint-event.h>
