/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#include "utest.h"

#include "util.h"

#include "filter.h"

TESTSUITE(filter, NULL, NULL)

TESTCASE(filter, validate_simple)
{
    CHK(filter_is_valid("(foo=xx)"));
    CHK(filter_is_valid("(foo=9)"));

    CHK(!filter_is_valid("(=xx)"));
    CHK(!filter_is_valid("(foo=)"));
    CHK(!filter_is_valid(""));
    CHK(!filter_is_valid(" (name=foo)"));
    CHK(!filter_is_valid("(name=foo) "));

    return UTEST_SUCCESS;
}

TESTCASE(filter, validate_substring)
{
    CHK(filter_is_valid("(foo=*)"));
    CHK(filter_is_valid("(foo=foo*bar)"));
    CHK(filter_is_valid("(foo=foo*bar*)"));
    CHK(filter_is_valid("(foo=*foo*bar*)"));

    CHK(!filter_is_valid("(foo=***)"));

    return UTEST_SUCCESS;
}

TESTCASE(filter, validate_comparison)
{
    CHK(filter_is_valid("(foo>9)"));
    CHK(filter_is_valid("(foo<9)"));
    CHK(filter_is_valid("(foo>9342434)"));
    CHK(filter_is_valid("(9<9)"));
    CHK(filter_is_valid("(bar>-4)"));

    CHK(!filter_is_valid("(foo>)"));
    CHK(!filter_is_valid("(foo>"));
    CHK(!filter_is_valid("(foo> 9)"));
    CHK(!filter_is_valid("(foo<9 )"));
    CHK(!filter_is_valid("(foo<9a)"));

    return UTEST_SUCCESS;
}

TESTCASE(filter, validate_not)
{
    CHK(filter_is_valid("(!(foo>9))"));

    CHK(!filter_is_valid("!(name=foo)"));
    CHK(!filter_is_valid("(!(name=foo)"));

    return UTEST_SUCCESS;
}

#define TEST_OP(op)                                                \
    CHK(filter_is_valid("(" op "(name=foo)(value=*))"));           \
    CHK(filter_is_valid("(" op "(name=foo)(value=*)(number>5))")); \
                                                                   \
    CHK(!filter_is_valid("(" op "(name=foo))"));                   \
    CHK(!filter_is_valid(op "(name=foo))"));                    \

TESTCASE(filter, validate_and)
{
    TEST_OP("&")

    return UTEST_SUCCESS;
}

TESTCASE(filter, validate_or)
{
    TEST_OP("|")

    return UTEST_SUCCESS;
}

