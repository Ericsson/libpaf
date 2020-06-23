/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#include <string.h>
#include <assert.h>

#include "util.h"

#include <paf_value.h>

enum value_type {
    value_type_int64,
    value_type_str
};

struct paf_value
{
    enum value_type type;
    union {
        int64_t value_int64;
        char *value_str;
    };
};

bool paf_value_is_int64(const struct paf_value *value)
{
    return value->type == value_type_int64;
}

bool paf_value_is_str(const struct paf_value *value)
{
    return value->type == value_type_str;
}
    
static struct paf_value *create_value(enum value_type type)
{
    struct paf_value *value = malloc(sizeof(struct paf_value));

    *value = (struct paf_value) {
        .type = type
    };

    return value;
}

struct paf_value *paf_value_int64_create(int64_t value_int64)
{
    struct paf_value *value = create_value(value_type_int64);
    value->value_int64 = value_int64;
    return value;
}
    
int64_t paf_value_int64(const struct paf_value *value)
{
    assert(paf_value_is_int64(value));

    return value->value_int64;
}

struct paf_value *paf_value_str_create(const char *str)
{
    struct paf_value *value = create_value(value_type_str);
    value->value_str = ut_strdup(str);
    return value;
}

const char *paf_value_str(const struct paf_value *value)
{
    assert(paf_value_is_str(value));

    return value->value_str;
}

bool paf_value_equal(const struct paf_value *a, const struct paf_value *b)
{
    if (a->type != b->type)
        return false;

    switch (a->type) {
    case value_type_int64:
        return a->value_int64 == b->value_int64;
    case value_type_str:
        return strcmp(a->value_str, b->value_str) == 0;
    default:
        assert(0);
    }
}

struct paf_value *paf_value_clone(const struct paf_value *orig)
{
    switch (orig->type) {
    case value_type_int64:
        return paf_value_int64_create(orig->value_int64);
    case value_type_str:
        return paf_value_str_create(orig->value_str);
    default:
        assert(0);
    }
}    

void paf_value_destroy(struct paf_value *value)
{
    if (value != NULL) {
        if (value->type == value_type_str)
            ut_free(value->value_str);
        ut_free(value);
    }
}
