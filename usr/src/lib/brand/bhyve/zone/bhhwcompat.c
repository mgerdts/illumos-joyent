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
 * Copyright 2018, Joyent, Inc.
 */

/*
 * Exit 0 if the current hardware is bhyve-compatible, non-zero otherwise.
 * A '-v' option can be used to print the incompatibility reason provided by
 * the kernel.
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>

/*
 * We can't include uts/i86pc/sys/vmm_dev.h into a user-level program, so we
 * have to copy the ioctl definition we need.
 */
#define	VMM_IOC_BASE		(('V' << 16) | ('M' << 8))
#define	VMM_VM_SUPPORTED	(VMM_IOC_BASE | 0x03)

static void
usage()
{
	fprintf(stderr, "bhhwcompat [-v]\n");
	exit(1);
}

int
main(int argc, char *argv[])
{
	int fd, c;
	char emsg[128];
	boolean_t verbose = B_FALSE;

	while ((c = getopt(argc, argv, "v")) != -1) {
		switch (c) {
		case 'v':
			verbose = B_TRUE;
			break;
		default:
			usage();
		}
	}

	if ((fd = open("/dev/vmm/ctl", O_RDONLY | O_EXCL)) < 0) {
		if (verbose)
			fprintf(stderr, "missing /dev/vmm/ctl\n");
		exit(1);
	}

	emsg[0] = '\0';
	if (ioctl(fd, VMM_VM_SUPPORTED, emsg) < 0)  {
		if (verbose)
			fprintf(stderr, "%s\n", emsg);
		exit(1);
	}

	(void) close(fd);
	return (0);
}
