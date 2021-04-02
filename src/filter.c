/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#include <string.h>

#include "util.h"

#include <paf.h>

#define BEGIN_EXPR '('
#define END_EXPR ')'
#define ANY '*'
#define ESCAPE '\\'

#define NOT '!'
#define AND '&'
#define OR '|'
#define EQUAL '='
#define GREATER_THAN '>'
#define LESS_THAN '<'

#define SPECIAL_CHARS "()*\\!&|=<>"

struct input
{
    const char* data;
    size_t offset;
};

static int input_current(struct input *input)
{
    char c = input->data[input->offset];

    if (c == '\0')
        return -1;

    return c;
}

static int input_is_current(struct input *input, char expected)
{
    int actual = input_current(input);
    if (actual < 0)
        return 1;

    return actual == expected;
}

static int input_expect(struct input *input, char expected)
{
    int rc = input_is_current(input, expected);

    if (rc < 0)
        return -1;

    input->offset++;

    return rc;
}

static int input_skip(struct input *input)
{
    char next = input->data[input->offset];

    if (next == '\0')
        return -1;

    input->offset++;

    return 0;
}

static size_t input_left(struct input *input)
{
    return strlen(input->data) - input->offset;
}

static bool is_int_char(char c)
{
    switch (c) {
    case '0':
    case '1':
    case '2':
    case '3':
    case '4':
    case '5':
    case '6':
    case '7':
    case '8':
    case '9':
    case '-':
        return true;
    default:
        return false;
    }
}

static ssize_t parse_str_or_int(struct input *input, bool *is_int_p)
{
    bool escaped = false;
    ssize_t len = 0;
    bool is_int = true;

    for (;;) {
        int in_c = input_current(input);
        if (in_c < 0)
            return -1;

        bool special = strchr(SPECIAL_CHARS, (char)in_c) != NULL;

        if (escaped) {
            if (!special)
                return -1;
            if (input_skip(input) < 0)
                return -1;
            len++;
            escaped = false;
        } else {
            if (in_c == ESCAPE)
                escaped = true;
            else if (special) {
                if (is_int_p != NULL)
                    *is_int_p = is_int;
                return len;
            } else {
                len++;
                if (!is_int_char(in_c))
                    is_int = false;
            }

            if (input_skip(input) < 0)
                return -1;
        }
    }
}

static ssize_t parse_str(struct input *input)
{
    return parse_str_or_int(input, NULL);
}

static int parse_equal(struct input *input)
{
    if (input_expect(input, EQUAL) < 0)
        return -1;

    ssize_t value_len = parse_str(input);
    if (value_len < 0)
        return -1;

    int is_any = input_is_current(input, ANY);

    if (is_any < 0)
        return -1;
    else if (!is_any)
        return value_len == 0 ? -1 : 0;

    if (input_skip(input) < 0)
        return -1;

    do {
        ssize_t value_len = parse_str(input);

        is_any = input_is_current(input, ANY);
        if (is_any < 0)
            return -1;

        if (is_any) {
            if (value_len == 0)
                return -1;
            if (input_skip(input) < 0)
                return -1;
        }
    } while (is_any);

    return 0;
}

static int parse_greater_and_less_than(struct input *input, char op)
{
    if (input_expect(input, op) < 0)
        return -1;

    bool is_int;
    ssize_t value_len = parse_str_or_int(input, &is_int);

    if (value_len <= 0 || !is_int)
        return -1;

    return 0;
}

static int parse_simple(struct input *input)
{
    ssize_t key_len = parse_str(input);

    if (key_len <= 0)
        return -1;

    int c = input_current(input);
    if (c < 0)
        return -1;
    else if (c == EQUAL)
        return parse_equal(input);
    else if (c == GREATER_THAN)
        return parse_greater_and_less_than(input, GREATER_THAN);
    else if (c == LESS_THAN)
        return parse_greater_and_less_than(input, LESS_THAN);
    else
        return -1;
}

static int parse(struct input *input);

static int parse_not(struct input* input)
{
    if (input_expect(input, NOT) < 0)
        return -1;
    if (input_expect(input, BEGIN_EXPR) < 0)
        return -1;

    if (parse(input) < 0)
        return -1;

    if (input_expect(input, END_EXPR) < 0)
        return -1;

    return 0;
}

static int parse_composite(struct input *input, char op)
{
    if (input_expect(input, op) < 0)
        return -1;

    size_t num_operands = 0;

    for (;;) {
        int c = input_current(input);
        if (c < 0)
            return -1;
        else if (c == BEGIN_EXPR) {
            if (input_skip(input) < 0)
                return -1;
            if (parse(input) < 0)
                return -1;
            num_operands++;
            if (input_expect(input, END_EXPR) < 0)
                return -1;
        } else if(c == END_EXPR) {
            if (num_operands < 2)
                return -1;
            return 0;
        } else
            return -1;
    }
}

static int parse(struct input *input)
{
    int c = input_current(input);
    if (c < 0)
        return -1;

    if (c == AND)
        return parse_composite(input, AND);
    else if (c == OR)
        return parse_composite(input, OR);
    else if (c == NOT)
        return parse_not(input);
    else
        return parse_simple(input);
}

bool filter_is_valid(const char *s)
{
    struct input input = {
        .data = s
    };

    if (input_expect(&input, BEGIN_EXPR) < 0)
        return false;

    if (parse(&input) < 0)
        return false;

    if (input_expect(&input, END_EXPR) < 0)
        return false;

    if (input_left(&input) > 0)
        return false;

    return true;
}

char *filter_escape(const char *s)
{
    /* worst case is that all characters are escaped */
    char *output = ut_malloc(2 * strlen(s) + 1);
    size_t offset = 0;
    size_t i;
    for (i = 0; i < strlen(s); i++) {
        char c = s[i];
        if (strchr(SPECIAL_CHARS, c) != NULL)
            output[offset++] = ESCAPE;
        output[offset++] = c;
    }
    output[offset] = '\0';
    return output;
}
