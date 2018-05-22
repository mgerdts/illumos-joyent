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

#ifndef INC_BRAND_BHYVE_H
#define	INC_BRAND_BHYVE_H

/* These paths must be relative to the zone root. */
#define	BHYVE_DIR		"var/run/bhyve"
#define	BHYVE_ARGS_FILE		BHYVE_DIR "/zhyve.cmd"
#define	BHYVE_BOOT_WAIT_FILE	BHYVE_DIR "/bootwait"

#endif
