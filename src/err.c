/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#include <paf_err.h>

const char *paf_strerror(int64_t return_code)
{
    switch (return_code) {
    case PAF_ERR:
        return "Generic error";
    case PAF_ERR_PROPS_TOO_LARGE:
        return "Service properties too large";
    case PAF_ERR_BUFFER_TOO_SMALL:
        return "Buffer too small";
    case PAF_ERR_FILTER_TOO_LARGE:
        return "Filter too large";
    case PAF_ERR_INVALID_FILTER_SYNTAX:
        return "Invalid filter syntax";
    default:
        return "Unknown error";
    }
}
