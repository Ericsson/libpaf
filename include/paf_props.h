/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#ifndef PAF_PROPS_H
#define PAF_PROPS_H
#ifdef __cplusplus
extern "C" {
#endif

/*!
 * @file paf_props.h
 * @brief Pathfinder Service Properties API.
 *
 * Service properties are a multimap. Thus, each property name may be
 * assoicated to one or more values.
 */

#include <sys/types.h>

#include <paf_value.h>

struct paf_props;

/**
 * Create a service properties instance.
 *
 * @return An empty service properties instance.
 */
struct paf_props *paf_props_create(void);


/**
 * Add a property.
 *
 * This function adds a property to @p props.
 *
 * Both the @p name and the @p value will be copied, and thus will
 * still be owned by the caller at call completion.
 *
 * @param[in] props The service properties instance.
 * @param[in] name The name of the property to be added.
 * @param[in] value The value of the property to be added.
 */
void paf_props_add(struct paf_props *props, const char *name,
                   const struct paf_value *value);

/**
 * Add a property with an integer value.
 *
 * This function adds a property with an integer value to @p
 * props.
 *
 * @param[in] props The service properties instance.
 * @param[in] name The name of the property to be added.
 * @param[in] value The value of the property to be added.
 */
void paf_props_add_int64(struct paf_props *props, const char *name,
                         int64_t value);

/**
 * Add a property with a string value.
 *
 * This function adds a property with a string value to @p props.
 *
 * @param[in] props The service properties instance.
 * @param[in] name The name of the property to be added.
 * @param[in] value The value of the property to be added.
 */
void paf_props_add_str(struct paf_props *props, const char *name,
                       const char *value);

/**
 * Retrieve all values for a particular property.
 *
 * This function retrieves the zero-or-more values associated with
 * the supplied @p prop_name, and stores them in @p values.
 *
 * If @p values' capacity is to small to hold pointers to all values,
 * as many values as can fit will be stored. The actual number of
 * values present in @p props will be returned regardless.
 *
 * In case @p capacity is 0, @p props may be left NULL. Such a call may
 * be useful to allow pre-allocation of a suitably-sized @p values
 * array, before the actual paf_props_get() call.
 *
 * @param[in] props The service properties instance.
 * @param[in] prop_name The name of the property whose values is to be retrieved.
 * @param[out] values A pointer to an user-allocated array of paf_value pointers.
 * @param[in] capacity The number of elements @p values can hold.
 *
 * @return Returns the number of values associated with @p prop_name (even in the case this number is larger than @p capacity).
 */
size_t paf_props_get(const struct paf_props *props, const char *prop_name,
                     const struct paf_value **values, size_t capacity);
/**
 * Retrieve a value for a particular property.
 *
 * This function returns a value associated with the supplied @p
 * prop_name.
 *
 * @param[in] props The service properties instance.
 * @param[in] prop_name The name of the property whose value is to be retrieved.
 *
 * @return Returns one of the values associated with @p prop_name, or NULL in case there is none.
 */
const struct paf_value *paf_props_get_one(const struct paf_props *props,
                                          const char *prop_name);

/**
 * Callback function prototype used for iteration.
 */
typedef void (*paf_props_foreach_cb)(const char *prop_name,
                                     const struct paf_value *prop_value,
                                     void *user);

/**
 * Iterate over all name-value pairs.
 *
 * This function calls the supplied callback function @p cb
 * for each property name-value pair in @p props.
 *
 * @p props may not be modified during the iteration.
 *
 * @param[in] props The service properties instance.
 * @param[in] cb The callback function.
 * @param[in] user An opaque pointer, supplied back to the application in every @p cb call.
 */
void paf_props_foreach(const struct paf_props *props, paf_props_foreach_cb cb,
                       void *user);

/**
 * Compares two property multimaps for equality (by value).
 *
 * @param[in] props_a A service properties instance.
 * @param[in] props_b A service properties instance.
 *
 * @return Returns true if @p props_a and @p props_b are equal, false otherwise.
 */
bool paf_props_equal(const struct paf_props *props_a,
                     const struct paf_props *props_b);

/**
 * Returns the total number of property name-value pairs.
 *
 * This function returns the total number of name-value pairs in the
 * properties instance.
 *
 * @param[in] props The service properties instance.
 *
 * @return Returns the total number of values.
 */
size_t paf_props_num_values(const struct paf_props *props);

/**
 * Returns the total number of property names in the properties instance.
 *
 * @param[in] props The service properties instance.
 *
 * @return Returns the total number of names.
 */
size_t paf_props_num_names(const struct paf_props *props);

/**
 * Returns a copy of the supplied properties instance.
 *
 * @param[in] orig The service properties instance to be copied.
 *
 * @return Returns a copy of the properties instance.
 */
struct paf_props *paf_props_clone(const struct paf_props *orig);

/**
 * Destroys a properties instance.
 *
 * This function destroys the properties instance and frees all the
 * resources associated with it.
 *
 * @param[in] props The service properties instance.
 */
void paf_props_destroy(struct paf_props *props);

#ifdef __cplusplus
}
#endif
#endif
