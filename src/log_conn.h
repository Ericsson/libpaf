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

#define log_conn_connect_failed(conn, xcm_errno)			\
    log_conn_debug(conn, "Connection establishment failed; errno %d (%s).", \
		   xcm_errno, strerror(xcm_errno))

#define log_conn_close(conn)				\
    log_conn_debug(conn, "Connection closed.");

#define log_conn_request(conn, request_str)			\
    log_conn_debug(conn, "Outgoing request: %s.", request_str)

#define log_conn_response(conn, response_str)				\
    log_conn_debug(conn, "Incoming response: %s.", response_str)

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
