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
#include <libnvpair.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define	ZHYVE_CMD_FILE	"/var/run/bhyve/zhyve.cmd"

/*
 * This log file is on tmpfs and does not survive halt.  For startup failures:
 *
 *   dtrace -wn 'syscall:::entry
 *       /execname == "zhyve"/
 *       { stop(); system("truss -t write -wall -f -p %d\n", pid); exit(0);}'
 *
 * If there's more than one zhyve instance on the zone, also filter on zonename.
 */
#define	ZHYVE_LOG_FILE	"/var/run/bhyve/zhyve.log"

extern int bhyve_main(int, char **);
const char *cmdname;

/*
 * Much like basename() but does not alter the path passed to it.
 */
static void
get_cmdname(const char *path)
{
	cmdname = strrchr(path, '/');
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
 * Reads the command line options from the packed nvlist in the file referenced
 * by path.  On success, 0 is returned and the members of *argv reference memory
 * allocated from an nvlist.  On failure, -1 is returned.
 */
static int
parse_options_file(const char *path, uint *argcp, char ***argvp)
{
	int fd = -1;
	struct stat stbuf;
	char *buf = NULL;
	nvlist_t *nvl = NULL;
	int ret;

	if ((fd = open(path, O_RDONLY)) < 0 ||
	    fstat(fd, &stbuf) != 0 ||
	    (buf = malloc(stbuf.st_size)) == NULL ||
	    full_read(fd, buf, stbuf.st_size) != 0 ||
	    nvlist_unpack(buf, stbuf.st_size, &nvl, 0) != 0 ||
	    nvlist_lookup_string_array(nvl, "zyhve_args", argvp, argcp) != 0) {
		nvlist_free(nvl);
		ret = -1;
	} else {
		ret = 0;
	}

	free(buf);
	(void) close(fd);

	return (ret);
}

int
main(int argc, char **argv)
{
	uint zargc;
	char **zargv;
	int fd;

	get_cmdname(argv[0]);
	if (strcmp(cmdname, "zhyve") != 0) {
		return (bhyve_main(argc, argv));
	}

	fd = open("/dev/null", O_WRONLY);
	assert(fd >= 0);
	if (fd != STDIN_FILENO) {
		(void) dup2(fd, STDIN_FILENO);
		(void) close(fd);
	}
	fd = open(ZHYVE_LOG_FILE, O_WRONLY|O_CREAT, 0644);
	assert(fd >= 0);
	(void) dup2(fd, STDOUT_FILENO);
	(void) dup2(fd, STDERR_FILENO);
	if (fd != STDOUT_FILENO && fd != STDERR_FILENO) {
		(void) close(fd);
	}

	if (parse_options_file(ZHYVE_CMD_FILE, &zargc, &zargv) != 0) {
		(void) fprintf(stderr, "%s: failed to parse %s: %s\n",
		    cmdname, ZHYVE_CMD_FILE, strerror(errno));
		return (1);
	}

	return (bhyve_main(zargc, zargv));
}
