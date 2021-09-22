/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#include <assert.h>
#include <sys/types.h>
#include <string.h>

#include "util.h"

#include <paf_props.h>

struct paf_props
{
    char **names;
    struct paf_value **values;
    size_t num;
};

struct paf_props *paf_props_create(void)
{
    struct paf_props *props = ut_malloc(sizeof(struct paf_props));
    *props = (struct paf_props) { };
    return props;
}

static void props_add(struct paf_props *props, const char *name,
                      struct paf_value *value)
{
    assert(name != NULL);

    size_t new_idx = props->num;
    props->num++;

    props->names =
        ut_realloc(props->names, sizeof(const char *) * props->num);
    props->values =
        ut_realloc(props->values, sizeof(struct paf_value *) * props->num);

    props->names[new_idx] = ut_strdup(name);
    props->values[new_idx] = value;
}

void paf_props_add(struct paf_props *props, const char *name,
                   const struct paf_value *value)
{
    props_add(props, name, paf_value_clone(value));
}

void paf_props_add_int64(struct paf_props *props, const char *name,
                         int64_t value)
{
    props_add(props, name, paf_value_int64_create(value));
}

void paf_props_add_str(struct paf_props *props, const char *name,
                       const char *value)
{
    props_add(props, name, paf_value_str_create(value));
}

static bool props_has(const struct paf_props *props, const char *prop_name,
                      const struct paf_value *prop_value)
{
    size_t i;
    for (i = 0; i<props->num; i++)
        if (strcmp(props->names[i], prop_name) == 0 &&
            paf_value_equal(props->values[i], prop_value))
            return true;
    return false;
}

bool paf_props_equal(const struct paf_props *a, const struct paf_props *b)
{
    if (a->num != b->num)
        return false;

    size_t i;
    for (i = 0; i < a->num; i++)
        if (!props_has(b, a->names[i], a->values[i]))
            return false;
    return true;
}

size_t paf_props_num_values(const struct paf_props *props)
{
    return props->num;
}

size_t paf_props_num_names(const struct paf_props *props)
{
    size_t count = 0;
    size_t i;
    for (i = 0; i < props->num; i++) {
        bool duplicate = false;
        size_t j;
        for (j = 0; j < i; j++)
            if (strcmp(props->names[j], props->names[i]) == 0) {
                duplicate = true;
                break;
            }
        if (!duplicate)
            count++;
    }
    return count;
}

struct paf_props *paf_props_clone(const struct paf_props *orig)
{
    struct paf_props *copy = paf_props_create();

    size_t i;
    for (i = 0; i<orig->num; i++)
        paf_props_add(copy, orig->names[i], orig->values[i]);

    return copy;
}    

const struct paf_value *paf_props_get_one(const struct paf_props *props,
                                          const char *prop_name)
{
    size_t i;
    for (i = 0; i < props->num; i++)
        if (strcmp(props->names[i], prop_name) == 0)
            return props->values[i];
    return NULL;
}

size_t paf_props_get(const struct paf_props *props, const char *prop_name,
                     const struct paf_value** values, size_t capacity)
{
    size_t len;
    size_t i;
    for (i = 0, len = 0; i < props->num; i++)
        if (strcmp(props->names[i], prop_name) == 0) {
            if (len < capacity)
                values[len] = props->values[i];
            len++;
        }
    return len;
}

void paf_props_foreach(const struct paf_props *props, paf_props_foreach_cb cb,
                       void *user)
{
    size_t i;
    for (i = 0; i<props->num; i++)
        cb(props->names[i], props->values[i], user);
}

void paf_props_destroy(struct paf_props *props)
{
    if (props != NULL) {
        size_t i;
        for (i = 0; i<props->num; i++) {
            ut_free(props->names[i]);
            paf_value_destroy(props->values[i]);
        }
        ut_free(props->names);
        ut_free(props->values);
        ut_free(props);
    }
}
