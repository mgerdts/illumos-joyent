/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright (c) 2018, Joyent, Inc.
 */

/*
 * Usage:
 *
 * bootwait zonename
 *
 * This program enters the specified zone and waits for the removal of a file.
 * The file is created by boot.c as part of the boot hook.  This program is used
 * in a postboot hook to detect when the zone is ready to perform its duties.
 * Something in the zone (i.e. bhyve) is expected to remove the wait file when
 * it considers the boot to be complete.
 *
 * This program returns 0 on success or non-zero on failure.
 *
 * In the event that the zone is halted (e.g. due to death of its init process),
 * this process will be killed, resulting in a non-zero exit value.
 */

#include <errno.h>
#include <libzonecfg.h>
#include <port.h>
#include <stdio.h>
#include <string.h>
#include <zone.h>

#include "bhyve_brand.h"

int
main(int argc, char **argv)
{
	const char *prog = argv[0];
	const char *zonename = argv[1];
	int portfd;
	struct file_obj fobj = { 0 };
	port_event_t pev;
	timespec_t timeout = { 0 };
	zoneid_t zid;

	if (argc != 2) {
		(void) fprintf(stderr, "Usage: %s zonename\n", prog);
		return (1);
	}

	if ((zid = getzoneidbyname(zonename)) == ZONE_ID_UNDEFINED) {
		(void) fprintf(stderr, "%s: No zone id for zone '%s'\n", prog,
		    zonename);
		return (1);
	}

	if (zone_enter(zid) == -1) {
		(void) fprintf(stderr, "%s: Unable to enter zone %s: %s\n",
		    prog, zonename, strerror(errno));
		return (1);
	}

	if ((portfd = port_create()) == -1) {
		(void) fprintf(stderr, "%s: port_create: %s\n", prog,
		    strerror(errno));
		return (1);
	}

	/*
	 * Start watching for removals. We say that we are watching for
	 * FILE_MODIFIED, but we really only care about the FILE_DELETE
	 * exception.
	 */
	fobj.fo_name = BHYVE_BOOT_WAIT_FILE;

	for (;;) {
		if (port_associate(portfd, PORT_SOURCE_FILE, (uintptr_t)&fobj,
		    FILE_MODIFIED, NULL) == -1) {
			if (errno == ENOENT) {
				/* Already removed */
				return (0);
			}
			(void) fprintf(stderr, "%s: port_associate: %s\n", prog,
			    strerror(errno));
			return (1);
		}

		if (port_get(portfd, &pev, &timeout) == -1) {
			(void) fprintf(stderr, "%s: port_get: %s\n", prog,
			    strerror(errno));
			return (1);
		}

		if ((pev.portev_events & FILE_DELETE) != 0) {
			break;
		}
	}

	return (0);
}
