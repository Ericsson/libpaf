/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Ericsson AB
 */

#include <assert.h>
#include <ctype.h>
#include <string.h>

#include "util.h"

#include "cmdline.h"

struct input
{
    const char *data;
    size_t consumed;
};

static int input_peek_char(struct input *input, char *c)
{
    char next_c = input->data[input->consumed];

    if (next_c == '\0')
	return -1;

    *c = next_c;

    return 0;
}

static void input_skip_char(struct input *input)
{
    assert(input->data[input->consumed] != '\0');
    input->consumed++;
}

static void input_skip_space(struct input *input)
{
    char c;

    while (input_peek_char(input, &c) == 0 && isspace(c))
	input_skip_char(input);
}

static char *input_get_word(struct input *input)
{
    input_skip_space(input);

    char *word = ut_calloc(strlen(input->data) - input->consumed + 1);

    char c;
    while (input_peek_char(input, &c) == 0 && !isspace(c)) {
	word[strlen(word)] = c;
	input_skip_char(input);
    }

    if (strlen(word) == 0) {
	ut_free(word);
	return NULL;
    }
	
    return word;
}

struct cmdline
{
    char *name;
    char **args;
    size_t num_args;
};

struct cmdline *cmdline_parse(const char *line)
{
    struct cmdline *cmdline = ut_calloc(sizeof(struct cmdline));

    struct input input = {
	.data = line
    };

    cmdline->name = input_get_word(&input);

    if (cmdline->name == NULL) {
	cmdline_destroy(cmdline);
	return NULL;
    }

    for (;;) {
	char *arg = input_get_word(&input);

	if (arg == NULL)
	    break;

	cmdline->args = ut_realloc(cmdline->args, sizeof(char *) * cmdline->num_args + 1);
	cmdline->args[cmdline->num_args] = arg;
	cmdline->num_args++;
    }

    return cmdline;
}

void cmdline_destroy(struct cmdline *cmdline)
{
    if (cmdline != NULL) {
	ut_free(cmdline->name);

	size_t i;
	for (i = 0; i < cmdline->num_args; i++)
	    ut_free(cmdline->args[i]);

	ut_free(cmdline->args);

	ut_free(cmdline);
    }
}

const char *cmdline_get_name(struct cmdline *cmdline)
{
    return cmdline->name;
}

size_t cmdline_get_num_args(struct cmdline *cmdline)
{
    return cmdline->num_args;
}

const char *const *cmdline_get_args(struct cmdline *cmdline)
{
    return (const char *const *)cmdline->args;
}
