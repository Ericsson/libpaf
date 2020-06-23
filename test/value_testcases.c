/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#include "utest.h"

#include <paf_value.h>

TESTSUITE(value, NULL, NULL)

TESTCASE(value, int64_equal)
{
    struct paf_value *int_17_value = paf_value_int64_create(-17);
    struct paf_value *int_42_0_value = paf_value_int64_create(42);
    struct paf_value *int_42_1_value = paf_value_int64_create(42);

    CHK(paf_value_equal(int_17_value, int_17_value));

    CHK(!paf_value_equal(int_17_value, int_42_0_value));

    CHK(paf_value_equal(int_42_0_value, int_42_1_value));

    paf_value_destroy(int_17_value);
    paf_value_destroy(int_42_0_value);
    paf_value_destroy(int_42_1_value);

    return UTEST_SUCCESS;

}

TESTCASE(value, str_equal)
{
    struct paf_value *str_a_value = paf_value_str_create("a");
    struct paf_value *str_b_0_value = paf_value_str_create("boo");
    struct paf_value *str_b_1_value = paf_value_str_create("boo");

    CHK(paf_value_equal(str_a_value, str_a_value));

    CHK(!paf_value_equal(str_a_value, str_b_0_value));

    CHK(paf_value_equal(str_b_0_value, str_b_1_value));

    paf_value_destroy(str_a_value);
    paf_value_destroy(str_b_0_value);
    paf_value_destroy(str_b_1_value);

    return UTEST_SUCCESS;

}

TESTCASE(value, equal_different_type)
{
    struct paf_value *int_value = paf_value_int64_create(42);
    struct paf_value *str_value = paf_value_str_create("foo");

    CHK(!paf_value_equal(int_value, str_value));

    paf_value_destroy(int_value);
    paf_value_destroy(str_value);

    return UTEST_SUCCESS;
}
