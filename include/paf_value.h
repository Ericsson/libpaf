/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#ifndef PAF_VALUE_H
#define PAF_VALUE_H
#ifdef __cplusplus
extern "C" {
#endif

/*!
 * @file paf_value.h
 * @brief Pathfinder Property Value API.
 *
 * Service properties can be either integer or a string.
 */

#include <stdbool.h>
#include <stdint.h>

struct paf_value;


/**
 * Checks if the value is an integer.
 *
 * @return Returns true if @p value is an integer, or false otherwise.
 */
bool paf_value_is_int64(const struct paf_value *value);
/**
 * Checks if the value is a string.
 *
 * @return Returns true if @p value is a string, or false otherwise.
 */
bool paf_value_is_str(const struct paf_value *value);

/**
 * Creates an integer value.
 *
 * @param[in] value The 64-bit value used to initialize @p value.
 *
 * @return Returns a value instance of the integer type.
 */
struct paf_value *paf_value_int64_create(int64_t value);

/**
 * Retrieves the integer value of @p value.
 *
 * @param[in] value A value of type integer.
 *
 * @return Returns the 64-bit signed value of @p value.
 */
int64_t paf_value_int64(const struct paf_value *value);

/**
 * Creates a string value.
 *
 * @param[in] value The string to be copied and used to initialize @p value.
 *
 * @return Returns a value instance of the string type.
 */
struct paf_value *paf_value_str_create(const char *value);

/**
 * Retrieves the string of @p value.
 *
 * The returned point should not be written to, and not bee freed by
 * the caller.
 *
 * @param[in] value A value of type string.
 *
 * @return Returns a read-only pointer to the string value of @p value.
 */
const char *paf_value_str(const struct paf_value *value);

/**
 * Compares two values for equality.
 *
 * The values must be of the same type and have the same value in
 * order to be considered equal.
 *
 * @param[in] value_a A value.
 * @param[in] value_b Another (or the same) value.
 *
 * @return Returns true if @p value_a and @p value_b are equal, false otherwise.
 */
bool paf_value_equal(const struct paf_value *value_a,
                     const struct paf_value *value_b);


/**
 * Returns a copy of the supplied value.
 *
 * @param[in] orig The value to be copied.
 *
 * @return Returns a copy of the value.
 */
struct paf_value *paf_value_clone(const struct paf_value *orig);

/**
 * Destroys a value instance.
 *
 * This function destroys the value instance and frees all the
 * resources associated with it.
 *
 * @param[in] value The value.
 */
void paf_value_destroy(struct paf_value *value);

#ifdef __cplusplus
}
#endif
#endif
