/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#ifndef PAF_ERR_H
#define PAF_ERR_H
#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

const char *paf_strerror(int64_t return_code);

#define PAF_ERR (-1)
#define PAF_ERR_PROPS_TOO_LARGE (-2)
#define PAF_ERR_BUFFER_TOO_SMALL (-3)
#define PAF_ERR_FILTER_TOO_LARGE (-4)
#define PAF_ERR_INVALID_FILTER_SYNTAX (-5)
#define PAF_ERR_DETACHED (-6)

#define PAF_IS_ERR(x) ((x) < 0 ? true : false)

#ifdef __cplusplus
}
#endif
#endif
