/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2018, Joyent, Inc.
 */

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define	ZHYVE_CMD_FILE	"/var/run/bhyve/zhyve.cmd"

extern int bhyve_main(int, char **);
const char *cmdname;

/*
 * Much like basename() but does not alter the path passed to it.
 */
static void
get_cmdname(const char *path)
{
	cmdname = strchr(path, '/');
	if (cmdname == NULL) {
		cmdname = path;
		return;
	}
	assert(*cmdname == '/');
	cmdname++;
}

/*
 * Do a read of the specified size or return an error.  Returns 0 on success
 * and -1 on error.  Sets errno to EINVAL if EOF is encountered.  For other
 * errors, see read(2).
 */
static int
full_read(int fd, char *buf, size_t len)
{
	ssize_t nread = 0;
	size_t totread = 0;

	while (totread < len) {
		nread = read(fd, buf + totread, len - totread);
		if (nread == 0) {
			errno = EINVAL;
			return (-1);
		}
		if (nread < 0) {
			if (errno == EINTR || errno == EAGAIN) {
				continue;
			}
			return (-1);
		}
		totread += nread;
	}
	assert(totread == len);

	return (0);
}

/*
 * Reads the command line options from the file named by path, one option per
 * line.  On return, (*argv)[0] references the global variable cmdname.  The
 * remaining members of *argv reference memory allocated from a single
 * allocation.  If there is a need to free this memory, free((*argvp)[1]) then
 * free(*argvp).
 */
static int
parse_options_file(const char *path, int *argcp, char ***argvp)
{
	int fd = -1;
	struct stat stbuf;
	char *buf = NULL;
	int argc;
	char **argv = NULL;
	char *nl;
	int i;

	if ((fd = open(path, O_RDONLY)) < 0 ||
	    fstat(fd, &stbuf) != 0 ||
	    (buf = malloc(stbuf.st_size + 1)) == NULL ||
	    full_read(fd, buf, stbuf.st_size) != 0) {
		goto fail;
	}

	buf[stbuf.st_size] = '\0';
	for (argc = 1, nl = buf; nl != NULL; nl = strchr(nl, '\n')) {
		if (nl[1] == '\0')
			break;
		argc++;
	}

	if ((argv = malloc(sizeof (*argv) * argc + 1)) == NULL) {
		goto fail;
	}

	argv[0] = (char *)cmdname;
	for (i = 1, nl = buf; i < argc; i++) {
		argv[i] = nl;
		nl = strchr(nl, '\n');
		if (nl == NULL) {
			i++;
			break;
		}
		*nl = '\0';
		nl++;
	}
	assert(i == argc);
	argv[argc] = NULL;

	/*
	 * If the file had no arguments, it won't be referenced by argv and as
	 * such could not be freed by the caller.
	 */
	if (argc == 1) {
		free(buf);
	}

	*argcp = argc;
	*argvp = argv;
	return (0);

fail:
	if (fd != -1) {
		(void) close(fd);
	}
	free(buf);
	free(argv);

	return (-1);
}

int
main(int argc, char **argv)
{
	int zargc;
	char **zargv;

	get_cmdname(argv[0]);
	if (strcmp(cmdname, "zhyve") != 0) {
		return (bhyve_main(argc, argv));
	}

	if (parse_options_file(ZHYVE_CMD_FILE, &zargc, &zargv) != 0) {
		(void) fprintf(stderr, "%s: failed to parse %s: %s\n",
		    cmdname, ZHYVE_CMD_FILE, strerror(errno));
		return (1);
	}

	return (bhyve_main(zargc, zargv));
}
