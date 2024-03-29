/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Ericsson AB
 */

#ifndef LOG_CONN_H
#define LOG_CONN_H

#include "log.h"

#define log_conn_debug(conn, fmt, ...)		\
    log_obj_debug(conn, fmt, ##__VA_ARGS__)

#define log_conn_error(conn, fmt, ...)		\
    log_obj_error(conn, fmt, ##__VA_ARGS__)

#define log_conn_connect(conn, addr)				      \
    log_conn_debug(conn, "Connection establishment initiated toward " \
		   "\"%s\".", addr)

#define log_conn_proto_min_version_too_large(conn, configured_min,	\
					     supported_max)		\
    log_conn_debug(conn, "Configured minimum protocol version (%"PRId64") " \
		   "is larger than maximum supported (%"PRId64").", \
		   configured_min, supported_max)

#define log_conn_proto_max_version_too_small(conn, configured_max,	\
					     supported_min)		\
    log_conn_debug(conn, "Configured maximum protocol version (%"PRId64") " \
		   "is smaller than minimum supported (%"PRId64").", \
		   configured_max, supported_min)

#define log_conn_proto_version_range(conn, min, max) \
    log_conn_debug(conn, "Connection protocol version range is %"PRId64 \
		   "-%"PRId64".", min, max)

#define log_conn_connect_failed(conn, xcm_errno)			\
    log_conn_debug(conn, "Connection establishment failed; errno %d (%s).", \
		   xcm_errno, strerror(xcm_errno))

#define log_conn_failed_to_disable_tcp_keepalive(conn, xcm_errno)	\
    log_conn_debug(conn, "Failed to disable TCP keepalive; errno %d (%s).", \
		   xcm_errno, strerror(xcm_errno))

#define log_conn_disabled_tcp_keepalive(conn, xcm_errno)	\
    log_conn_debug(conn, "Disabled TCP keepalive.")

#define log_conn_close(conn)			\
    log_conn_debug(conn, "Connection closed.")

#define log_conn_out_msg(conn, msg_str)				\
    log_conn_debug(conn, "Outgoing message: %s.", msg_str)

#define log_conn_in_msg(conn, msg_str)				\
    log_conn_debug(conn, "Incoming response: %s.", msg_str)

#define log_conn_ta_failure(conn, ta_id, reason)			\
    do {                                                                \
        if (reason != NULL)                                             \
            log_conn_debug(conn, "Transaction id %"PRIx64		\
			   " failed: \"%s\".", ta_id, reason);		\
        else                                                            \
            log_conn_debug(conn, "Transaction id %"PRIx64		\
			   " failed.", ta_id);				\
    } while (0)

#define log_conn_eof(conn)				\
    log_conn_debug(conn, "Server closed XCM connection.")

#define log_conn_net_ns_entered(conn, ns_name)				\
    log_conn_debug(conn, "Entered network namespace \"%s\".", ns_name)

#define log_conn_net_ns_returned(conn, ns_name)				\
    log_conn_debug(conn, "Returned from network namespace \"%s\".", ns_name)

#define log_conn_net_ns_op_failed(conn, op_name, ns_name, net_ns_errno) \
    log_conn_debug(conn, "Failed to %s network namespace \"%s\"; "	\
		   "errno %d (%s).", op_name, ns_name, net_ns_errno,	\
		   strerror(net_ns_errno))

#define log_conn_net_ns_enter_failed(conn, ns_name, net_ns_errno)	\
    log_conn_net_ns_op_failed(conn, "enter", ns_name, net_ns_errno)

#define log_conn_net_ns_return_failed(conn, ns_name, net_ns_errno)	\
    log_conn_net_ns_op_failed(conn, "return from", ns_name,		\
			      net_ns_errno)

#define log_conn_op_error(conn, op_name, xcm_errno)		      \
    log_conn_debug(conn, "Fatal error while %s on XCM connection; "   \
		   "errno %d (%s).", op_name, xcm_errno,	      \
		   strerror(xcm_errno))

#define log_conn_receive_error(conn, xcm_errno) \
    log_conn_op_error(conn, "receiving", xcm_errno)

#define log_conn_send_error(conn, xcm_errno) \
    log_conn_op_error(conn, "sending", xcm_errno)

#define log_conn_processing(conn)			\
    log_conn_debug(conn, "Processing connection.")

#endif
