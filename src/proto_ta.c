/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#include <assert.h>
#include <stdarg.h>
#include <string.h>

#include <jansson.h>

#include <paf_props.h>
#include <paf_match.h>

#include "util.h"
#include "log_ta.h"

#include "proto_ta.h"

UT_STATIC_ASSERT(json_int_is_64, sizeof(json_int_t) == sizeof(int64_t));

#define SLABEL(prefix, name)                    \
    case prefix ## _ ## name:                   \
    return "" #name ""

/* Older libjansson versions lacks the json_array_foreach macro */
#ifndef json_array_foreach
#define json_array_foreach(array, i, value)               \
    for (i = 0; i < json_array_size(array) &&             \
             (value = json_array_get(array, i)); i++)
#endif

static const char *proto_msg_type_str(enum proto_msg_type type)
{
    switch (type) {
        SLABEL(proto_msg_type, request);
        SLABEL(proto_msg_type, accept);
        SLABEL(proto_msg_type, notify);
        SLABEL(proto_msg_type, complete);
        SLABEL(proto_msg_type, fail);
    default:
        return "undefined";
    }
}

static const char *proto_ta_state_str(enum proto_ta_state state)
{
    switch (state) {
        SLABEL(proto_ta_state, idle);
        SLABEL(proto_ta_state, requesting);
        SLABEL(proto_ta_state, accepted);
        SLABEL(proto_ta_state, completed);
        SLABEL(proto_ta_state, failed);
    default:
        return "undefined";
    }
}

static const char *proto_ia_type_str(enum proto_ia_type type)
{
    switch (type) {
        SLABEL(proto_ia_type, single_response);
        SLABEL(proto_ia_type, multi_response);
        SLABEL(proto_ia_type, two_way);
    default:
        return "undefined";
    }
}

static json_t *create_message(const char *cmd, int64_t ta_id,
			      const char *msg_type)
{
    json_t *msg = json_object();
    json_object_set_new(msg, PROTO_FIELD_TA_CMD, json_string(cmd));
    json_object_set_new(msg, PROTO_FIELD_TA_ID, json_integer(ta_id));
    json_object_set_new(msg, PROTO_FIELD_MSG_TYPE, json_string(msg_type));
    return msg;
}

static json_t *create_request(const char *cmd, int64_t ta_id)
{
    return create_message(cmd, ta_id, PROTO_MSG_TYPE_REQUEST);
}

static json_t *create_inform(const char *cmd, int64_t ta_id)
{
    return create_message(cmd, ta_id, PROTO_MSG_TYPE_INFORM);
}

static const struct proto_ta_type hello_ta =
{
    .cmd = PROTO_CMD_HELLO,
    .ia_type = proto_ia_type_single_response,
    .request_fields = {
        { PROTO_FIELD_CLIENT_ID, proto_field_type_int64 },
        { PROTO_FIELD_PROTO_MIN_VERSION, proto_field_type_int64 },
        { PROTO_FIELD_PROTO_MAX_VERSION, proto_field_type_int64 }
    },
    .complete_fields = {
        { PROTO_FIELD_PROTO_VERSION, proto_field_type_int64 }
    },
    .opt_fail_fields = {
        { PROTO_FIELD_FAIL_REASON, proto_field_type_str }
    }
};

static const struct proto_ta_type track_ta =
{
    .cmd = PROTO_CMD_TRACK,
    .ia_type = proto_ia_type_two_way,
    .notify_fields = {
        { PROTO_FIELD_TRACK_TYPE, proto_field_type_track_type }
    },
    .inform_fields = {
        { PROTO_FIELD_TRACK_TYPE, proto_field_type_track_type }
    },
    .opt_fail_fields = {
        { PROTO_FIELD_FAIL_REASON, proto_field_type_str }
    }
};

static const struct proto_ta_type publish_ta =
{
    .cmd = PROTO_CMD_PUBLISH,
    .ia_type = proto_ia_type_single_response,
    .request_fields = {
        { PROTO_FIELD_SERVICE_ID, proto_field_type_int64 },
        { PROTO_FIELD_GENERATION, proto_field_type_int64 },
        { PROTO_FIELD_SERVICE_PROPS, proto_field_type_props },
        { PROTO_FIELD_TTL, proto_field_type_int64 }
    },
    .opt_fail_fields = {
        { PROTO_FIELD_FAIL_REASON, proto_field_type_str }
    }
};

static const struct proto_ta_type unpublish_ta =
{
    .cmd = PROTO_CMD_UNPUBLISH,
    .ia_type = proto_ia_type_single_response,
    .request_fields = {
        { PROTO_FIELD_SERVICE_ID, proto_field_type_int64 }
    },
    .opt_fail_fields = {
        { PROTO_FIELD_FAIL_REASON, proto_field_type_str }
    }
};

static const struct proto_ta_type subscribe_ta =
{
    .cmd = PROTO_CMD_SUBSCRIBE,
    .ia_type = proto_ia_type_multi_response,
    .request_fields = {
        { PROTO_FIELD_SUBSCRIPTION_ID, proto_field_type_int64 }
    },
    .opt_request_fields = {
        { PROTO_FIELD_FILTER, proto_field_type_str }
    },
    .notify_fields = {
        { PROTO_FIELD_MATCH_TYPE, proto_field_type_match_type },
        { PROTO_FIELD_SERVICE_ID, proto_field_type_int64 }
    },
    .opt_notify_fields = {
        { PROTO_FIELD_GENERATION, proto_field_type_int64 },
        { PROTO_FIELD_SERVICE_PROPS, proto_field_type_props },
        { PROTO_FIELD_TTL, proto_field_type_int64 },
        { PROTO_FIELD_ORPHAN_SINCE, proto_field_type_number }
    },
    .opt_fail_fields = {
        { PROTO_FIELD_FAIL_REASON, proto_field_type_str }
    }
};

static const struct proto_ta_type unsubscribe_ta =
{
    .cmd = PROTO_CMD_UNSUBSCRIBE,
    .ia_type = proto_ia_type_single_response,
    .request_fields = {
        { PROTO_FIELD_SUBSCRIPTION_ID, proto_field_type_int64 }
    },
    .opt_fail_fields = {
        { PROTO_FIELD_FAIL_REASON, proto_field_type_str }
    }
};

static const struct proto_ta_type subscriptions_ta =
{
    .cmd = PROTO_CMD_SUBSCRIPTIONS,
    .ia_type = proto_ia_type_multi_response,
    .notify_fields = {
        { PROTO_FIELD_SUBSCRIPTION_ID, proto_field_type_int64 },
        { PROTO_FIELD_CLIENT_ID, proto_field_type_int64 }
    },
    .opt_notify_fields = {
        { PROTO_FIELD_FILTER, proto_field_type_str }
    },
    .opt_fail_fields = {
        { PROTO_FIELD_FAIL_REASON, proto_field_type_str }
    }
};

static const struct proto_ta_type services_ta =
{
    .cmd = PROTO_CMD_SERVICES,
    .ia_type = proto_ia_type_multi_response,
    .opt_request_fields = {
        { PROTO_FIELD_FILTER, proto_field_type_str }
    },
    .notify_fields = {
        { PROTO_FIELD_SERVICE_ID, proto_field_type_int64 },
        { PROTO_FIELD_GENERATION, proto_field_type_int64 },
        { PROTO_FIELD_SERVICE_PROPS, proto_field_type_props },
        { PROTO_FIELD_TTL, proto_field_type_int64 },
        { PROTO_FIELD_CLIENT_ID, proto_field_type_int64 }
    },
    .opt_notify_fields = {
        { PROTO_FIELD_ORPHAN_SINCE, proto_field_type_number }
    },
    .opt_fail_fields = {
        { PROTO_FIELD_FAIL_REASON, proto_field_type_str }
    }
};

static const struct proto_ta_type ping_ta =
{
    .cmd = PROTO_CMD_PING,
    .ia_type = proto_ia_type_single_response,
    .opt_fail_fields = {
        { PROTO_FIELD_FAIL_REASON, proto_field_type_str }
    }
};

static const struct proto_ta_type clients_v2_ta =
{
    .cmd = PROTO_CMD_CLIENTS,
    .ia_type = proto_ia_type_multi_response,
    .notify_fields = {
        { PROTO_FIELD_CLIENT_ID, proto_field_type_int64 },
        { PROTO_FIELD_CLIENT_ADDR, proto_field_type_str },
        { PROTO_FIELD_TIME, proto_field_type_int64 },
    },
    .opt_fail_fields = {
        { PROTO_FIELD_FAIL_REASON, proto_field_type_str }
    }
};

static const struct proto_ta_type clients_v3_ta =
{
    .cmd = PROTO_CMD_CLIENTS,
    .ia_type = proto_ia_type_multi_response,
    .notify_fields = {
        { PROTO_FIELD_CLIENT_ID, proto_field_type_int64 },
        { PROTO_FIELD_CLIENT_ADDR, proto_field_type_str },
        { PROTO_FIELD_TIME, proto_field_type_int64 },
        { PROTO_FIELD_IDLE, proto_field_type_number },
        { PROTO_FIELD_PROTO_VERSION, proto_field_type_int64 },
    },
    .opt_notify_fields = {
        { PROTO_FIELD_LATENCY, proto_field_type_number }
    },
    .opt_fail_fields = {
        { PROTO_FIELD_FAIL_REASON, proto_field_type_str }
    }
};

struct proto_ta *create_ta(const struct proto_ta_type *ta_type,
			   int64_t ta_id, const char *log_ref,
			   proto_response_cb cb, void *user)
{
    struct proto_ta *ta = ut_malloc(sizeof(struct proto_ta));

    *ta = (struct proto_ta) {
        .type = ta_type,
        .ta_id = ta_id,
        .state = proto_ta_state_idle,
        .log_ref = ut_asprintf("%s: ta id: 0x%"PRIx64, log_ref, ta_id),
        .cb = cb,
        .user = user
    };

    return ta;
}

#define GEN_PROTO_CREATE(cmd) \
    struct proto_ta *proto_ta_ ## cmd(int64_t ta_id, const char *log_ref, \
                                      proto_response_cb cb, void *user) \
    {                                                                 \
        return create_ta(&cmd ## _ta, ta_id, log_ref, cb, user);        \
    }
    

GEN_PROTO_CREATE(hello)
GEN_PROTO_CREATE(track)
GEN_PROTO_CREATE(publish)
GEN_PROTO_CREATE(unpublish)
GEN_PROTO_CREATE(subscribe)
GEN_PROTO_CREATE(unsubscribe)
GEN_PROTO_CREATE(subscriptions)
GEN_PROTO_CREATE(services)
GEN_PROTO_CREATE(ping)
GEN_PROTO_CREATE(clients_v2)
GEN_PROTO_CREATE(clients_v3)

static void prop_to_json(const char *prop_name,
                         const struct paf_value *prop_value, void *user)
{
    json_t *json_props = user;

    json_t *value;

    if (paf_value_is_int64(prop_value))
        value = json_integer(paf_value_int64(prop_value));
    else {
        assert(paf_value_is_str(prop_value));
        value = json_string(paf_value_str(prop_value));
    }
    json_t *value_list = json_object_get(json_props, prop_name);

    if (!value_list) {
        value_list = json_array();
        json_object_set_new(json_props, prop_name, value_list);
    }

    json_array_append_new(value_list, value);
}

static json_t *props_to_json(const struct paf_props *props)
{
    json_t *json_props = json_object();

    paf_props_foreach(props, prop_to_json, json_props);

    return json_props;
}

#define SET_FIELD(request, field, ap)					\
    do {								\
	switch ((field)->type) {					\
	case proto_field_type_int64: {					\
	    json_object_set_new(request, (field)->name,			\
				json_integer(va_arg(ap, int64_t)));	\
	    break;							\
	}								\
	case proto_field_type_number: {					\
	    json_object_set_new(request, (field)->name,			\
				json_real(va_arg(ap, double)));		\
	    break;							\
	}								\
	case proto_field_type_str:					\
	    json_object_set_new(request, (field)->name,			\
				json_string(va_arg(ap, const char *))); \
	    break;							\
	case proto_field_type_props: {					\
	    const struct paf_props *props =				\
		va_arg(ap, const struct paf_props *);			\
	    json_t *json_props = props_to_json(props);			\
	    json_object_set_new(request, (field)->name, json_props);	\
	    break;							\
	}								\
	case proto_field_type_track_type: {				\
	    const bool *is_query = va_arg(ap, const bool *);		\
	    const char *is_query_s =					\
		*is_query ? PROTO_TRACK_TYPE_QUERY : PROTO_TRACK_TYPE_REPLY; \
	    json_object_set_new(request, (field)->name,			\
				json_string(is_query_s));		\
	    break;							\
	}								\
	default:							\
	    assert(0);							\
	    break;							\
	}								\
    } while (0)

struct msg *proto_ta_produce_request(struct proto_ta *ta, ...)
{
    assert (ta->state == proto_ta_state_idle);

    json_t *request = create_request(ta->type->cmd, ta->ta_id);

    const struct proto_field *fields = ta->type->request_fields;
    const struct proto_field *opt_fields = ta->type->opt_request_fields;

    va_list ap;
    va_start(ap, ta);

    int i;
    for (i = 0; fields != NULL && fields[i].name != NULL; i++)
	SET_FIELD(request, &fields[i], ap);

    for (i = 0; opt_fields != NULL && opt_fields[i].name != NULL; i++)
	SET_FIELD(request, &opt_fields[i], ap);

    va_end(ap);

    ta->state = proto_ta_state_requesting;

    char *data = json_dumps(request, 0);

    json_decref(request);

    return msg_create_prealloc(data);
}

struct msg *proto_ta_produce_inform(struct proto_ta *ta, ...)
{
    assert (ta->state == proto_ta_state_accepted);

    json_t *inform = create_inform(ta->type->cmd, ta->ta_id);

    const struct proto_field *fields = ta->type->inform_fields;
    const struct proto_field *opt_fields = ta->type->opt_inform_fields;

    va_list ap;
    va_start(ap, ta);

    int i;
    for (i = 0; fields != NULL && fields[i].name != NULL; i++)
	SET_FIELD(inform, &fields[i], ap);

    for (i = 0; opt_fields != NULL && opt_fields[i].name != NULL; i++)
	SET_FIELD(inform, &opt_fields[i], ap);

    va_end(ap);

    char *data = json_dumps(inform, 0);

    json_decref(inform);

    return msg_create_prealloc(data);
}

static int get_field(json_t *msg, const char *name,
                     bool opt, const char *log_ref, json_t **value)
{
    *value = json_object_get(msg, name);
    if (*value == NULL && !opt) {
        log_ta_missing_field(log_ref, name);
        return -1;
    }
    return 0;
}

#define GEN_TYPED_GET(type)                                   \
    static int get_ ## type(json_t *msg, const char *name, bool opt,    \
                            const char *log_ref, json_t **value)        \
    {                                                                   \
        json_t *type;                                           \
        if (get_field(msg, name, opt, log_ref, &type) < 0)      \
            return -1;                                          \
        if (type != NULL && !json_is_## type(type)) {           \
            log_ta_incorrect_field_type(log_ref, name, #type);	\
            return -1;                                          \
        }                                                       \
        *value = type;                                          \
        return 0;                                               \
    }

GEN_TYPED_GET(integer)
GEN_TYPED_GET(number)
GEN_TYPED_GET(string)
GEN_TYPED_GET(object)

enum proto_msg_type get_msg_type(json_t *msg, const char *log_ref)
{
    json_t *msg_type;
    if (get_string(msg, PROTO_FIELD_MSG_TYPE, false, log_ref,
                   &msg_type) < 0)
        return proto_msg_type_undefined;
    if (strcmp(json_string_value(msg_type), PROTO_MSG_TYPE_REQUEST) == 0)
        return proto_msg_type_request;
    if (strcmp(json_string_value(msg_type), PROTO_MSG_TYPE_ACCEPT) == 0)
        return proto_msg_type_accept;
    if (strcmp(json_string_value(msg_type), PROTO_MSG_TYPE_NOTIFY) == 0)
        return proto_msg_type_notify;
    if (strcmp(json_string_value(msg_type), PROTO_MSG_TYPE_COMPLETE) == 0)
        return proto_msg_type_complete;
    if (strcmp(json_string_value(msg_type), PROTO_MSG_TYPE_FAIL) == 0)
        return proto_msg_type_fail;

    log_ta_invalid_message_type(log_ref, json_string_value(msg_type));

    return proto_msg_type_undefined;
}

static struct paf_props *json_to_props(json_t *json_props, const char* log_ref)
{
    struct paf_props *props = paf_props_create();

    const char *prop_name;
    json_t *json_prop_values;
    json_object_foreach(json_props, prop_name, json_prop_values) {
        if (!json_is_array(json_prop_values)) {
            log_ta_invalid_prop_name(log_ref);
            goto err_cleanup;
        }

        size_t i;
        json_t *json_prop_value;
        json_array_foreach(json_prop_values, i, json_prop_value) {
            struct paf_value *prop_value;
            if (json_is_integer(json_prop_value))
                prop_value =
                    paf_value_int64_create(json_integer_value(json_prop_value));
            else if (json_is_string(json_prop_value)) {
                prop_value =
                    paf_value_str_create(json_string_value(json_prop_value));
            } else {
                log_ta_invalid_prop_value(log_ref);
                goto err_cleanup;
            }
            paf_props_add(props, prop_name, prop_value);
            paf_value_destroy(prop_value);
        }
    }

    return props;

 err_cleanup:

    paf_props_destroy(props);

    return NULL;
}

static void free_fields(const struct proto_field *fields,
			void **args, size_t num_args)
{
    size_t i;
    for (i = 0; i < num_args; i++) {
        switch (fields[i].type) {
        case proto_field_type_int64:
        case proto_field_type_number:
        case proto_field_type_str:
        case proto_field_type_match_type:
        case proto_field_type_track_type:
            ut_free(args[i]);
            break;
        case proto_field_type_props:
            paf_props_destroy(args[i]);
            break;
        default:
            assert(0);
            break;
        }
	args[i] = NULL;
    }
}

static int get_fields(json_t *response, const struct proto_field *fields,
                      bool opt, const char *log_ref, void **args)
{
    int num_args = 0;

    int i;
    for (i = 0; fields != NULL && fields[i].name != NULL; i++) {

        void *arg = NULL;

        switch (fields[i].type) {
        case proto_field_type_int64: {
            json_t *json_int;
            int rc = get_integer(response, fields[i].name, opt, log_ref,
                                 &json_int);
            if (rc < 0)
                goto err_free_args;
            else if (json_int != NULL) {
                int64_t *nint = ut_malloc(sizeof(int64_t));
                *nint = json_integer_value(json_int);
                arg = nint;
            }
            break;
        }
        case proto_field_type_number: {
            json_t *json_number;
            int rc = get_number(response, fields[i].name, opt, log_ref,
                                &json_number);
            if (rc < 0)
                goto err_free_args;
            else if (json_number != NULL) {
                double *nnum = ut_malloc(sizeof(double));
                *nnum = json_number_value(json_number);
                arg = nnum;
            }
            break;
        }
        case proto_field_type_str: {
            json_t *json_str;
            int rc = get_string(response, fields[i].name, opt, log_ref,
                                &json_str);
            if (rc < 0)
                goto err_free_args;
            if (json_str != NULL)
                arg = ut_strdup(json_string_value(json_str));
            break;
        }
        case proto_field_type_props: {
            json_t *json_props;
            int rc = get_object(response, fields[i].name, opt, log_ref,
                                &json_props);
            if (rc < 0)
                goto err_free_args;
            else if (json_props != NULL) {
                struct paf_props *props = json_to_props(json_props, log_ref);
                if (props == NULL)
                    goto err_free_args;
                arg = props;
            }

            break;
        }
        case proto_field_type_match_type: {
            json_t *json_match_type;
            int rc = get_string(response, fields[i].name, opt, log_ref,
                                &json_match_type);
            if (rc < 0)
                goto err_free_args;
            else if (json_match_type != NULL) {
                const char *match_type_str = json_string_value(json_match_type);

                enum paf_match_type match_type;
                if (strcmp(match_type_str, PROTO_MATCH_TYPE_APPEARED) == 0)
                    match_type = paf_match_type_appeared;
                else if (strcmp(match_type_str, PROTO_MATCH_TYPE_MODIFIED) == 0)
                    match_type = paf_match_type_modified;
                else if (strcmp(match_type_str, PROTO_MATCH_TYPE_DISAPPEARED)
			 == 0)
                    match_type = paf_match_type_disappeared;
                else {
                    log_ta_invalid_match_type(log_ref, match_type_str);
                    goto err_free_args;
                }
                arg = ut_dup(&match_type, sizeof(enum paf_match_type));
            }

            break;
        }
        case proto_field_type_track_type: {
            json_t *json_track_type;
            int rc = get_string(response, fields[i].name, opt, log_ref,
                                &json_track_type);
            if (rc < 0)
                goto err_free_args;
            else if (json_track_type != NULL) {
                const char *track_type_str = json_string_value(json_track_type);

		bool is_query;
                if (strcmp(track_type_str, PROTO_TRACK_TYPE_QUERY) == 0)
                    is_query = true;
                else if (strcmp(track_type_str, PROTO_TRACK_TYPE_REPLY) == 0)
		    is_query = false;
                else {
                    log_ta_invalid_track_type(log_ref, track_type_str);
                    goto err_free_args;
                }
                arg = ut_dup(&is_query, sizeof(bool));
            }

            break;
        }
        default:
            assert(0);
            break;
        }

        args[num_args++] = arg;

    }

    args[num_args] = NULL;

    return num_args;

 err_free_args:
    free_fields(fields, args, num_args);

    return -1;
}

static int ta_consume_response(struct proto_ta *ta,
			       enum proto_msg_type msg_type, json_t *response)
{
    const struct proto_field *fields = NULL;
    const struct proto_field *opt_fields = NULL;

    if (msg_type == proto_msg_type_accept &&
	ta->state == proto_ta_state_requesting &&
	(ta->type->ia_type == proto_ia_type_multi_response ||
	 ta->type->ia_type == proto_ia_type_two_way)) {
	ta->state = proto_ta_state_accepted;
    } else if (msg_type == proto_msg_type_notify &&
	       ta->state == proto_ta_state_accepted) {
	fields = ta->type->notify_fields;
	opt_fields = ta->type->opt_notify_fields;
    } else if (msg_type == proto_msg_type_complete &&
	       ((ta->state == proto_ta_state_requesting &&
		 ta->type->ia_type == proto_ia_type_single_response) ||
		(ta->state == proto_ta_state_accepted &&
		 (ta->type->ia_type == proto_ia_type_multi_response ||
		  ta->type->ia_type == proto_ia_type_two_way)))) {
	fields = ta->type->complete_fields;
	ta->state = proto_ta_state_completed;
    } else if (msg_type == proto_msg_type_fail) {
	ta->state = proto_ta_state_failed;
	opt_fields = ta->type->opt_fail_fields;
    } else {
	log_ta_invalid_state(ta->log_ref, ta->ta_id,
			     proto_msg_type_str(msg_type),
			     proto_ia_type_str(ta->type->ia_type),
			     proto_ta_state_str(ta->state));
	ta->state = proto_ta_state_failed;
    }

    void *args[MAX_FIELDS+1] = {};
    void *opt_args[MAX_FIELDS+1] = {};

    int num_args = get_fields(response, fields, false, ta->log_ref, args);
    if (num_args < 0)
	ta->state = proto_ta_state_failed;

    int num_opt_args = get_fields(response, opt_fields, true, ta->log_ref,
                                  opt_args);
    if (num_opt_args < 0)
	ta->state = proto_ta_state_failed;

    bool terminated = false;

    if (ta->state == proto_ta_state_failed) {
	msg_type = proto_msg_type_fail;
	terminated = true;
    } else if (ta->state == proto_ta_state_completed)
	terminated = true;

    /* remove it from the list to allow callback function to clear the
       transaction list (i.e. restart the link) */
    if (terminated)
	LIST_REMOVE(ta, entry);

    ta->cb(ta->ta_id, msg_type, args, opt_args, ta->user);

    if (terminated)
	proto_ta_destroy(ta);

    free_fields(opt_fields, opt_args, num_opt_args);
    free_fields(fields, args, num_args);
    json_decref(response);

    return 0;
}

int proto_ta_consume_response(struct proto_ta_list *ta_list,
                              struct msg *response_msg, const char *log_ref)
{
    json_error_t json_err;
    json_t *response = json_loads(response_msg->data, 0, &json_err);
    msg_free(response_msg);

    if (response == NULL) {
        log_ta_invalid_json(log_ref, &json_err);
	goto err;
    }

    json_t *cmd;
    if (get_string(response, PROTO_FIELD_TA_CMD, false, log_ref, &cmd) < 0)
        goto err_free_response;

    json_t *ta_id;
    if (get_integer(response, PROTO_FIELD_TA_ID, false, log_ref, &ta_id) < 0)
        goto err_free_response;

    enum proto_msg_type msg_type = get_msg_type(response, log_ref);
    if (msg_type == proto_msg_type_undefined ||
        msg_type == proto_msg_type_request)
        goto err_free_response;

    struct proto_ta *ta;
    LIST_FOREACH(ta, ta_list, entry) {
        if (ta->ta_id == json_integer_value(ta_id)) {
            if (strcmp(ta->type->cmd, json_string_value(cmd)) != 0) {
                log_ta_invalid_cmd(log_ref, json_string_value(cmd),
				   ta->type->cmd, ta->ta_id);
                goto err_free_response;
            }
            log_ta_valid_ta(log_ref, ta->ta_id, ta->type->cmd,
			    proto_msg_type_str(msg_type));
	    return ta_consume_response(ta, msg_type, response);
        }
    }

    log_ta_unknown_ta(log_ref, (int64_t)json_integer_value(ta_id));

err_free_response:
    json_decref(response);
err:
    return -1;
}

void proto_ta_destroy(struct proto_ta *ta)
{
    if (ta != NULL) {
	ut_free(ta->log_ref);
	ut_free(ta);
    }
}

