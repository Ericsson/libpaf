/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Ericsson AB
 */

#include <readline/history.h>
#include <readline/readline.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/queue.h>

#include "util.h"

#include "cli.h"
#include "cmdline.h"

struct cmd
{
    char *name;
    size_t min_num_args;
    size_t max_num_args;
    char *help;
    cli_run_cb run_cb;
    void *run_cb_data;
	
    TAILQ_ENTRY(cmd) entry;
};

TAILQ_HEAD(cmd_list, cmd);

struct cli
{
    char *prompt;
    struct cmd_list cmds;
    bool should_exit;
    int return_code;
};

static struct cli cli;

static struct cmd *cmd_create(const char *name, size_t min_num_args,
			      size_t max_num_args, const char *help,
			      cli_run_cb run_cb, void *run_cb_data)
{
    struct cmd *cmd = ut_malloc(sizeof(struct cmd));

    *cmd = (struct cmd) {
	.name = ut_strdup(name),
	.min_num_args = min_num_args,
	.max_num_args = max_num_args,
	.help = ut_strdup(help),
	.run_cb = run_cb,
	.run_cb_data = run_cb_data
    };

    return cmd;
}

static void cmd_destroy(struct cmd *cmd)
{
    if (cmd != NULL) {
	ut_free(cmd->name);
	ut_free(cmd->help);
	ut_free(cmd);
    }
}

static struct cmd *find_cmd(const char *cmd_name)
{
    struct cmd *cmd;
    TAILQ_FOREACH(cmd, &cli.cmds, entry)
	if (strcmp(cmd->name, cmd_name) == 0)
	    return cmd;

    return NULL;
}

#define HELP_CMD "help"
#define HELP_CMD_HELP							\
    HELP_CMD " [<command>]\n"						\
    "    Display an overview, or help text for a particular <commmand>.\n"

#define HELP_CMDS_PER_LINE 5

static void help_cmd(const char *cmd, const char *const *args, size_t num,
		     void *cb_data)
{
    if (num == 0) {
	printf("Available commands (type help <topic>):\n");

	size_t i = 0;
	struct cmd *cmd;
	TAILQ_FOREACH(cmd, &cli.cmds, entry) {
	    printf("%-16s", cmd->name);
	    i++;
	    if (i % HELP_CMDS_PER_LINE == 0)
		printf("\n");
	}

	if (i % HELP_CMDS_PER_LINE != 0)
	    printf("\n");
	
    } else {
	struct cmd *target_cmd = find_cmd(args[0]);

	if (target_cmd == NULL)
	    printf("No such command \"%s\".\n", args[0]);
	else
	    printf("%s", target_cmd->help);
    }
    fflush(stdout);
}

static void run_cmd(struct cmdline *cmdline)
{
    const char *cmd_name = cmdline_get_name(cmdline);

    struct cmd *cmd = find_cmd(cmd_name);

    if (cmd == NULL) {
	printf("Unknown command \"%s\".\n", cmd_name);
	return;
    }

    size_t num_args = cmdline_get_num_args(cmdline);

    if (num_args < cmd->min_num_args) {
	printf("%s requires at least %zd arguments.\n", cmd->name,
	       cmd->min_num_args);
	return;
    }
    if (num_args > cmd->max_num_args) {
	printf("%s requires at most %zd arguments.\n", cmd->name,
	       cmd->max_num_args);
	return;
    }

    cmd->run_cb(cmd_name, cmdline_get_args(cmdline), num_args,
		cmd->run_cb_data);
}

static char *generate_cmd_name(const char *text, int state)
{
    static size_t scanned;

    if (state == 0) /* first call */
	scanned = 0;

    size_t i = 0;
    struct cmd *cmd;
    TAILQ_FOREACH(cmd, &cli.cmds, entry) {
	if (i++ < scanned)
	    continue;

	bool match = strncmp(cmd->name, text, strlen(text)) == 0;
	scanned++;

	if (match)
	    return ut_strdup(cmd->name);
    }

    return NULL;
}

static char **cmd_name_completion(const char *text, int start, int end)
{
    rl_attempted_completion_over = 1;

    if (start != 0)
	return NULL;

    return rl_completion_matches(text, generate_cmd_name);
}

static void handle_line(char *line)
{
    if (line == NULL) {
	cli_exit(0);
	return;
    }

    if (strlen(line) == 0)
	goto out_free;

    add_history(line);

    struct cmdline *cmdline = cmdline_parse(line);

    if (cmdline == NULL)
	goto out_free;

    run_cmd(cmdline);

    cmdline_destroy(cmdline);

out_free:
    free(line);
}

void cli_init(const char *prompt)
{
    cli = (struct cli) {
	.prompt = ut_strdup(prompt)
    };

    TAILQ_INIT(&cli.cmds);

    rl_callback_handler_install(prompt, handle_line);

    rl_attempted_completion_function = cmd_name_completion;

    cli_register(HELP_CMD, 0, 1, HELP_CMD_HELP, help_cmd, NULL);
};

void cli_deinit(void)
{
    ut_free(cli.prompt);

    struct cmd *cmd;
    while ((cmd = TAILQ_FIRST(&cli.cmds)) != NULL) {
	TAILQ_REMOVE(&cli.cmds, cmd, entry);
	cmd_destroy(cmd);
    }

    rl_callback_handler_remove();
}

void cli_exit(int return_code)
{
    cli.should_exit = true;
    cli.return_code = return_code;
}

bool cli_has_exited(int *return_code)
{
    if (cli.should_exit)
	*return_code = cli.return_code;

    return cli.should_exit;
}

void cli_register(const char *name, size_t min_num_args, size_t max_num_args,
		  const char *help, cli_run_cb run_cb, void *run_cb_data)
{
    struct cmd *cmd = cmd_create(name, min_num_args, max_num_args, help,
				 run_cb, run_cb_data);

    TAILQ_INSERT_TAIL(&cli.cmds, cmd, entry);
}

void cli_read_input(void)
{
    rl_callback_read_char();
}
