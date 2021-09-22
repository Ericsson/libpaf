/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#ifndef LIST_H
#define LIST_H

#include <sys/queue.h>

#define LIST_FIND_FUN(list, needle_name, needle_value, field, eq_fun)	\
    ({									\
        typeof(needle_value) value = needle_value;			\
	typeof((list)->lh_first) elem = NULL;				\
	LIST_FOREACH(elem, list, field)					\
	    if (eq_fun(elem->needle_name, value))			\
		break;							\
	elem;								\
    })

#define LIST_ELEM_EQ(a, b) ((a) == (b))

#define LIST_FIND(list, needle_name, needle_value, field)		\
    LIST_FIND_FUN(list, needle_name, needle_value, field, LIST_ELEM_EQ)

#define LIST_EXISTS(list, needle_name, needle_value, field) \
    (LIST_FIND(list, needle_name, needle_value, field) != NULL)

#define LIST_COUNT(list, field)			\
    ({						\
        size_t _count = 0;			\
	typeof((list)->lh_first) _elem;		\
	LIST_FOREACH(_elem, list, field)	\
	    _count++;				\
	_count;					\
    })

#endif
