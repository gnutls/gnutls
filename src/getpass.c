#include <config.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#ifndef _WIN32
# include <termios.h>
# include <unistd.h>
#endif

#define OUT_STREAM stdout

const char *read_pass(char *msg)
{
#ifndef _WIN32
	struct termios old, new;
#endif
	static char input[128];
	char *p;

	fputs(msg, stderr);

#ifndef _WIN32
	/* Turn echoing off and fail if we can't. */
	if (tcgetattr(fileno(OUT_STREAM), &old) != 0) {
		perror("tcgetattr");
		exit(1);
	}

	new = old;
	new.c_lflag &= ~ECHO;
	if (tcsetattr(fileno(OUT_STREAM), TCSAFLUSH, &new) != 0) {
		perror("tcsetattr");
		exit(1);
	}
#endif

	/* Read the password. */
	p = fgets(input, sizeof(input), stdin);

#ifndef _WIN32
	/* Restore terminal. */
	(void) tcsetattr(fileno(OUT_STREAM), TCSAFLUSH, &old);
#endif

	if (p == NULL || strlen(p) == 0 || p[0] == '\n')
		return NULL;

	/* overwrite the newline */
	input[strlen(p) - 1] = 0;

	return p;
}
