#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>

#ifndef _MSC_VER
#include <unistd.h>
#else
#include <process.h>
#endif

#ifdef HAVE_EVIL
#include <Evil.h>
#endif

#include "Ecore.h"
#include "ecore_private.h"

static int app_argc = 0;
static char **app_argv = NULL;

/**
 * Set up the programs command-line arguments.
 * @param argc The same as passed as argc to the programs main() function
 * @param argv The same as passed as argv to the programs main() function
 *
 * A call to this function will store the programs command-line arguments
 * for later use by ecore_app_restart() or ecore_app_args_get().
 */
EAPI void ecore_app_args_set(int argc, const char **argv)
{
	if ((argc < 1) || (!argv))
		return;
	app_argc = argc;
	app_argv = (char **) argv;
}

/**
 * Return the programs stored command-line arguments.
 * @param argc A pointer to the return value to hold argc
 * @param argv A pointer to the return value to hold argv
 *
 * When called, this funciton returns the arguments for the program stored by
 * ecore_app_args_set(). The integer pointed to by @p argc will be filled, if
 * the pointer is not NULL, and the string array pointer @p argv will be filled
 * also if the pointer is not NULL. The values they are filled with will be the
 * same set by ecore_app_args_set().
 */
EAPI void ecore_app_args_get(int *argc, char ***argv)
{
	if (argc)
		*argc = app_argc;
	if (argv)
		*argv = app_argv;
}

/**
 * Restart the program executable with the command-line arguments stored.
 *
 * This function will restart & re-execute this program in place of itself
 * using the command-line arguments stored by ecore_app_args_set(). This is
 * an easy way for a program to restart itself for cleanup purposes,
 * configuration reasons or in the event of a crash.
 */
EAPI void ecore_app_restart(void)
{
	char *args[4096];
	int i;

	if ((app_argc < 1) || (!app_argv))
		return;
	if (app_argc >= 4096)
		return;
	for (i = 0; i < app_argc; i++)
		args[i] = app_argv[i];
	args[i] = NULL;
	execvp(app_argv[0], args);
}
