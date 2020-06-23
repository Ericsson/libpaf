/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#ifndef LOG_TA
#define LOG_TA

#include "log.h"

#define log_ta_invalid_json(log_ref)		\
    log_debug(log_ref, "Error parsning JSON.")

#define log_ta_missing_field(log_ref, field)				\
    log_debug(log_ref, "Response message is missing the required "	\
              "\"%s\" field.", field)

#define log_ta_unknown_ta(log_ref, ta_id)				\
    log_debug(log_ref, "Received server response in unknown transaction %" \
              PRId64".", ta_id)

#define log_ta_invalid_cmd(log_ref, actual_cmd, expected_cmd, ta_id)	\
    log_debug(log_ref, "Known transaction %"PRId64" was \"%s\" cmd, not " \
              "the expected \"%s\".", ta_id, actual_cmd, expected_cmd)

#define log_ta_incorrect_field_type(log_ref, field, field_type)		\
    log_debug(log_ref, "Response message field \"%s\" is not of the "	\
              "required %s type.", field, field_type)

#define log_ta_invalid_message_type(log_ref, msg_type_str)	    \
    log_debug(log_ref, "Server response contained invalid message " \
              "type \"%s\".", msg_type_str)

#define log_ta_invalid_prop_name(log_ref)				\
    log_debug(log_ref, "Invalid type of message service property name.")

#define log_ta_invalid_prop_value(log_ref)				\
    log_debug(log_ref, "Invalid type of message service property value.")

#define log_ta_invalid_match_type(log_ref, match_type_str)		\
    log_debug(log_ref, "Invalid match type \"%s\".", match_type_str)

#define log_ta_valid_ta(log_ref, ta_id, cmd, msg_type_str)		\
    log_debug(log_ref, "Found matching transaction id %"PRId64" for \"%s\" " \
              "response of type \"%s\".", ta_id, cmd, msg_type_str)

#define log_ta_invalid_state(log_ref, ta_id, msg_type_str, ia_type_str,	\
                          ta_state_str)                                 \
    log_debug(log_ref, "Received invalid \"%s\" type response in %s-type " \
              "transaction %"PRId64" in state %s.", msg_type_str,       \
              ia_type_str, ta_id, ta_state_str)

#endif
