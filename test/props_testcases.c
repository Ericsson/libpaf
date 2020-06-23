/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#include "utest.h"

#include <paf_props.h>

TESTSUITE(props, NULL, NULL)

static int assure(const struct paf_props *props_a,
                  const struct paf_props *props_b, bool equal)
{
    bool res_0 = paf_props_equal(props_a, props_b);
    bool res_1 = paf_props_equal(props_b, props_a);

    if (res_0 != res_1)
        return -1;

    if (res_0 != equal)
        return -1;
    return 0;
}

static int assure_equal(const struct paf_props *props_a,
                        const struct paf_props *props_b)

{
    return assure(props_a, props_b, true);
}

static int assure_not_equal(const struct paf_props *props_a,
                            const struct paf_props *props_b)

{
    return assure(props_a, props_b, false);
}

TESTCASE(props, add_get_one)
{
    struct paf_props *props = paf_props_create();
    CHKINTEQ(paf_props_num_values(props), 0);

    paf_props_add_str(props, "name", "foo");
    CHKINTEQ(paf_props_num_values(props), 1);

    const struct paf_value *name_value = paf_props_get_one(props, "name");

    CHK(name_value != NULL);
    CHK(paf_value_is_str(name_value));
    CHKSTREQ(paf_value_str(name_value), "foo");

    paf_props_add_int64(props, "age", 4711);
    paf_props_add_int64(props, "name", -99);
    CHKINTEQ(paf_props_num_values(props), 3);

    name_value = paf_props_get_one(props, "name");

    CHK(name_value != NULL);
    if (paf_value_is_str(name_value))
        CHKSTREQ(paf_value_str(name_value), "foo");
    else
        CHKINTEQ(paf_value_int64(name_value), -99);

    paf_props_destroy(props);

    return UTEST_SUCCESS;
}

TESTCASE(props, add_get)
{
    struct paf_props *props = paf_props_create();

    paf_props_add_str(props, "value", "bar");
    paf_props_add_str(props, "name", "foo");
    paf_props_add_int64(props, "value", 42);
    CHKINTEQ(paf_props_num_values(props), 3);
    CHKINTEQ(paf_props_num_names(props), 2);

    const struct paf_value *values[16];

    CHKINTEQ(paf_props_get(props, "name", NULL, 0), 1);

    CHKINTEQ(paf_props_get(props, "name", values, 1), 1);
    CHK(paf_value_is_str(values[0]));
    CHK(strcmp(paf_value_str(values[0]), "foo") == 0);

    CHKINTEQ(paf_props_get(props, "value", values, 1), 2);
    if (paf_value_is_str(values[0]))
        CHKSTREQ(paf_value_str(values[0]), "bar");
    else
        CHKINTEQ(paf_value_int64(values[0]), 42);

    memset(values, 0, sizeof(values));
    CHKINTEQ(paf_props_get(props, "value", values, 2), 2);
    CHK((paf_value_is_str(values[0]) && paf_value_is_int64(values[1])) ||
        (paf_value_is_str(values[1]) && paf_value_is_int64(values[0])));

    CHKINTEQ(paf_props_get(props, "value", NULL, 0), 2);

    paf_props_destroy(props);

    return UTEST_SUCCESS;
}

static void hash_prop(const char *prop_name,
                      const struct paf_value *prop_value,
                      void *user)
{
    int64_t *sum = user;

    (*sum) += strlen(prop_name);
    if (paf_value_is_str(prop_value))
        (*sum) += strlen(paf_value_str(prop_value));
    else
        (*sum) += paf_value_int64(prop_value);
}

TESTCASE(props, foreach)
{
    int64_t actual_sum;
    int64_t expected_sum = 0;
    struct paf_props *props = paf_props_create();

    actual_sum = 0;
    paf_props_foreach(props, hash_prop, &actual_sum);
    CHKINTEQ(actual_sum, expected_sum);

    paf_props_add_int64(props, "foo", 42);
    expected_sum += (strlen("foo") + 42);

    actual_sum = 0;
    paf_props_foreach(props, hash_prop, &actual_sum);
    CHKINTEQ(actual_sum, expected_sum);

    paf_props_add_str(props, "foobar", "kex");
    expected_sum += (strlen("foobar") + strlen("kex"));

    actual_sum = 0;
    paf_props_foreach(props, hash_prop, &actual_sum);
    CHKINTEQ(actual_sum, expected_sum);

    paf_props_add_int64(props, "foo", 99);
    expected_sum += (strlen("foo") + 99);

    actual_sum = 0;
    paf_props_foreach(props, hash_prop, &actual_sum);
    CHKINTEQ(actual_sum, expected_sum);

    paf_props_destroy(props);

    return UTEST_SUCCESS;
}

TESTCASE(props, equal_props_considered_unordered)
{
    struct paf_props *props_0 = paf_props_create();

    paf_props_add_int64(props_0, "name0", 4711);
    paf_props_add_str(props_0, "name1", "foo");

    struct paf_props *props_1 = paf_props_create();

    paf_props_add_str(props_1, "name1", "foo");
    paf_props_add_int64(props_1, "name0", 4711);

    CHKNOERR(assure_equal(props_0, props_1));

    paf_props_destroy(props_0);
    paf_props_destroy(props_1);

    return UTEST_SUCCESS;
}

TESTCASE(props, equal_same_name_different_value)
{
    struct paf_props *props_0 = paf_props_create();
    paf_props_add_int64(props_0, "age", 99);
    paf_props_add_str(props_0, "name", "foo");

    struct paf_props *props_1 = paf_props_create();
    paf_props_add_int64(props_0, "age", 99);
    paf_props_add_int64(props_1, "name", 42);

    CHKNOERR(assure_not_equal(props_0, props_1));

    paf_props_destroy(props_0);
    paf_props_destroy(props_1);

    return UTEST_SUCCESS;
}

TESTCASE(props, equal_different_num)
{
    struct paf_props *props_0 = paf_props_create();
    paf_props_add_str(props_0, "name", "foo");

    struct paf_props *props_1 = paf_props_create();
    paf_props_add_str(props_1, "name", "foo");
    paf_props_add_int64(props_1, "age", 99);

    CHKNOERR(assure_not_equal(props_0, props_1));

    paf_props_destroy(props_0);
    paf_props_destroy(props_1);

    return UTEST_SUCCESS;
}

TESTCASE(props, equal_multivalue_property)
{
    struct paf_props *props_0 = paf_props_create();
    paf_props_add_int64(props_0, "age", 99);
    paf_props_add_int64(props_0, "age", 42);
    paf_props_add_str(props_0, "name", "foo");

    struct paf_props *props_1 = paf_props_create();
    paf_props_add_str(props_1, "name", "foo");
    paf_props_add_int64(props_1, "age", 42);
    paf_props_add_int64(props_1, "age", 99);

    CHKNOERR(assure_equal(props_0, props_1));

    paf_props_destroy(props_0);
    paf_props_destroy(props_1);

    return UTEST_SUCCESS;
}

TESTCASE(props, equal_empty)
{
    struct paf_props *props_0 = paf_props_create();
    struct paf_props *props_1 = paf_props_create();

    CHKNOERR(assure_equal(props_0, props_1));

    paf_props_add_int64(props_1, "name", 4711);

    CHKNOERR(assure_not_equal(props_0, props_1));

    paf_props_destroy(props_0);
    paf_props_destroy(props_1);

    return UTEST_SUCCESS;
}

TESTCASE(props, clone)
{
    struct paf_props *props_orig = paf_props_create();
    paf_props_add_str(props_orig, "name", "foo");
    paf_props_add_int64(props_orig, "name", 4711);
    paf_props_add_int64(props_orig, "value", 42);

    struct paf_props *props_clone = paf_props_clone(props_orig);

    CHKNOERR(assure_equal(props_orig, props_clone));

    paf_props_destroy(props_orig);
    paf_props_destroy(props_clone);

    return UTEST_SUCCESS;
}

