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
 * This program runs as a child of zoneadmd, which sets a variety of
 * _ZONECFG_<resource>_<instance> properties so that child processes don't have
 * to parse xml.
 */

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <libnvpair.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <zone.h>

/* These two paths must be relative to the zone root. */
#define	BHYVE_DIR		"var/run/bhyve"
#define	BHYVE_ARGS_FILE		BHYVE_DIR "/" "zhyve.cmd"

#define ZH_MAXARGS		100

boolean_t debug;

#define	dprintf(x) if (debug) (void)printf x

char *
get_zcfg_var(char *rsrc, char *inst, char *prop)
{
	char envvar[MAXNAMELEN];
	char *ret;

	if (prop == NULL) {
		if (snprintf(envvar, sizeof (envvar), "_ZONECFG_%s_%s",
		    rsrc, inst) >= sizeof (envvar)) {
			return (NULL);
		}
	} else {
		if (snprintf(envvar, sizeof (envvar), "_ZONECFG_%s_%s_%s",
		    rsrc, inst, prop) >= sizeof (envvar)) {
			return (NULL);
		}
	}

	ret = getenv(envvar);

	dprintf(("%s: '%s=%s'\n", __func__, envvar, ret ? ret : "<null>"));

	return (ret);
}

int
add_arg(int *argc, char **argv, char *val)
{
	if (*argc >= ZH_MAXARGS) {
		(void) printf("Error: too many arguments\n");
		return (1);
	}
	argv[*argc] = strdup(val);
	assert(argv[*argc] != NULL);
	dprintf(("%s: argv[%d]='%s'\n", __func__, *argc, argv[*argc]));
	(*argc)++;
	return (0);
}

int
add_cpu(int *argc, char **argv)
{
	char *val;

	if ((val = get_zcfg_var("attr", "vcpus", NULL)) != NULL) {
		if (add_arg(argc, argv, "-c") != 0 ||
		    add_arg(argc, argv, val) != 0) {
			return (1);
		}
	}
	return (0);
}

int
add_ram(int *argc, char **argv)
{
	char *val;

	if ((val = get_zcfg_var("attr", "ram", NULL)) != NULL) {
		if (add_arg(argc, argv, "-m") != 0 ||
		    add_arg(argc, argv, val) != 0) {
			return (1);
		}
	}
	return (0);
}

int
add_disks(int *argc, char **argv)
{
	char *disks;
	char *disk;
	char *lasts;
	const int pcislot = 2;
	int nextpcifn = 2;		/* 0 for temp cd, 1 for boot */
	char slotconf[MAXNAMELEN];
	char *boot = NULL;

	if ((disks = get_zcfg_var("device", "resources", NULL)) == NULL) {
		return (0);
	}

	for (disk = strtok_r(disks, " ", &lasts); disk != NULL;
	    disk = strtok_r(NULL, " ", &lasts)) {
		int pcifn;
		char *path;
		char *val;

		/* zoneadmd is not careful about a trailing delimiter. */
		if (disk[0] == '\0') {
			continue;
		}

		if ((path = get_zcfg_var("device", disk, "path")) == NULL) {
			(void) printf("Error: disk %s has no path\n", disk);
			return (-1);
		}

		/* Allow at most one "primary" disk */
		val = get_zcfg_var("device", disk, "boot");
		if (val != NULL && strcmp(val, "true") == 0) {
			if (boot != NULL) {
				(void) printf("Error: "
				    "multiple boot disks: %s %s\n",
				    boot, path);
				return (-1);
			}
			boot = path;
			pcifn = 0;
		} else {
			pcifn = nextpcifn;
			nextpcifn++;
		}

		/* XXX-mg handle non-virtio? */
		if (snprintf(slotconf, sizeof (slotconf),
		    "%d:%d,virtio-blk,%s", pcislot, pcifn, path) >=
		    sizeof (slotconf)) {
			(void) printf("Error: disk path '%s' too long\n", path);
			return (-1);
		}

		if (add_arg(argc, argv, "-s") != 0 ||
		    add_arg(argc, argv, slotconf) != 0) {
			return (-1);
		}
	}

	return (0);
}

int
add_nets(int *argc, char **argv)
{
	char *nets;
	char *net;
	char *lasts;
	const int pcislot = 3;
	int nextpcifn = 1;		/* 0 reserved for primary */
	char slotconf[MAXNAMELEN];
	char *primary = NULL;

	if ((nets = get_zcfg_var("net", "resources", NULL))== NULL) {
		return (0);
	}

	for (net = strtok_r(nets, " ", &lasts); net != NULL;
	    net = strtok_r(NULL, " ", &lasts)) {
		int pcifn;
		char *val;

		/* zoneadmd is not careful about a trailing delimiter. */
		if (net[0] == '\0') {
			continue;
		}

		/* Allow at most one "primary" net */
		val = get_zcfg_var("net", net, "primary");
		if (val != NULL && strcmp(val, "true") == 0) {
			if (primary != NULL) {
				(void) printf("Error: "
				    "multiple primary nets: %s %s\n",
				    primary, net);
				return (-1);
			}
			primary = net;
			pcifn = 0;
		} else {
			pcifn = nextpcifn;
			nextpcifn++;
		}

		/* XXX-mg handle non-virtio-viona? */
		if (snprintf(slotconf, sizeof (slotconf),
		    "%d:%d,virtio-net-viona,%s", pcislot, pcifn, net) >=
		    sizeof (slotconf)) {
			(void) printf("Error: net '%s' too long\n", net);
			return (-1);
		}

		if (add_arg(argc, argv, "-s") != 0 ||
		    add_arg(argc, argv, slotconf) != 0) {
			return (-1);
		}
	}

	return (0);
}

int
add_lpc(int *argc, char **argv)
{
	char *lpcdevs[] = { "bootrom", "com1", "com2", NULL };
	int i;
	char *val;
	char conf[MAXPATHLEN];

	if (add_arg(argc, argv, "-s") != 0 ||
	    add_arg(argc, argv, "1,lpc") != 0) {
		return (-1);
	}

	for (i = 0; lpcdevs[i] != NULL; i++) {
		if ((val = get_zcfg_var("attr", lpcdevs[i], NULL)) == NULL) {
			continue;
		}
		if (snprintf(conf, sizeof (conf), "%s,%s", lpcdevs[i], val) >=
		    sizeof (conf)) {
			(void) printf("Error: value of attr '%s' too long\n",
			    lpcdevs[i]);
			return (-1);
		}
		if (add_arg(argc, argv, "-l") != 0 ||
		    add_arg(argc, argv, conf) != 0) {
			return (-1);
		}
	}

	return (0);
}

/*
 * XXX-mg  Make this configurable in zonecfg
 */
int
add_vnc(int *argc, char **argv)
{
	if (add_arg(argc, argv, "-s") != 0 ||
	    add_arg(argc, argv, "29,fbuf,socket=/tmp/vm.vnc") != 0 ||
	    add_arg(argc, argv, "-s") != 0 ||
	    add_arg(argc, argv, "30,xhci,tablet") != 0) {
		return (-1);
	}
	return (0);
}

/* Must be called last */
int
add_vmname(int *argc, char **argv)
{
	char *val = getenv("_ZONECFG_vmname");

	if (val == NULL || val[0] == '\0') {
		val = "SYSbhyve-unknown";
	}
	if (add_arg(argc, argv, val) != 0) {
		return (-1);
	}
	return (0);
}

/*
 * Write the entire buffer or return an error.  This function could be more
 * paranoid and call fdsync() at the end.  That's not really need for this use
 * case because it is being written to tmpfs.
 */
int
full_write(int fd, char *buf, size_t buflen)
{
	ssize_t nwritten;
	size_t totwritten = 0;

	while (totwritten < buflen) {
		nwritten = write(fd, buf + totwritten, buflen - totwritten);
		if (nwritten < 0) {
			if (errno == EAGAIN || errno == EINTR) {
				continue;
			}
			return (-1);
		}
		assert(nwritten > 0);
		totwritten += nwritten;
	}
	assert(totwritten == buflen);

	return (0);
}

void
init_debug(void)
{
	char *val = getenv("_ZONEADMD_brand_debug");

	debug = (val != NULL && val[0] != '\0');
}


int
main(int argc, char **argv)
{
	int fd;
	char *zhargv[ZH_MAXARGS] = {
		"zhyve",		/* Squats on argv[0] */
		"-P", "-H",		/* Guest exits on pause and halt isns */
		NULL };
	int zhargc;
	nvlist_t *nvl;
	char *nvbuf;
	size_t nvbuflen;
	char zoneroot[MAXPATHLEN];
	int zrfd;
	char *zonename;
	char *zonepath;

	init_debug();

	if (argc != 3) {
		(void) printf("Error: bhyve boot program called with "
		    "%d args, expecting 2\n", argc - 1);
		return (1);
	}
	zonename = argv[1];
	zonepath = argv[2];

	for (zhargc = 0; zhargv[zhargc] != NULL; zhargc++) {
		dprintf(("def_arg: argv[%d]='%s'\n", zhargc, zhargv[zhargc]));
	}

	if (add_lpc(&zhargc, (char **)&zhargv) != 0 ||
	    add_cpu(&zhargc, (char **)&zhargv) != 0 ||
	    add_ram(&zhargc, (char **)&zhargv) != 0 ||
	    add_disks(&zhargc, (char **)&zhargv) != 0 ||
	    add_nets(&zhargc, (char **)&zhargv) != 0 ||
	    add_vnc(&zhargc, (char **)&zhargv) != 0 ||
	    add_vmname(&zhargc, (char **)&zhargv) != 0) {
		return (1);
	}

	/*
	 * This and other dynamically allocated resources are intentionally
	 * leaked.  It's a short-lived program and it will all get mopped up on
	 * exit.
	 */
	if (nvlist_alloc(&nvl, NV_UNIQUE_NAME, 0) != 0 ||
	    nvlist_add_string_array(nvl, "zhyve_args", zhargv, zhargc) != 0) {
		(void) printf("Error: failed to create nvlist: %s\n",
		    strerror(errno));
		return (1);
	}

	if (debug) {
		dprintf(("packing nvlist:\n"));
		nvlist_print(stdout, nvl);
	}

	if (nvlist_pack(nvl, &nvbuf, &nvbuflen, NV_ENCODE_XDR, 0) != 0) {
		(void) printf("Error: failed to pack nvlist\n");
		return (1);
	}

	if (snprintf(zoneroot, sizeof (zoneroot), "%s/root", zonepath) >=
	    sizeof (zoneroot)) {
		(void) printf("Error: zonepath '%s' too long\n", zonepath);
		return (1);
	}

	if ((zrfd = open(zoneroot, O_RDONLY|O_SEARCH)) < 0) {
		(void) printf("Error: cannot open zone root '%s': %s\n",
		    zoneroot, strerror(errno));
		return (1);
	}

	/*
	 * This mkdirat() and the subsequent openat() are only safe because the
	 * zone root is always under the global zone's exclusive control (always
	 * read-only in all zones) and the writable directory is a tmpfs file
	 * system that was just mounted and no zone code has run yet.
	 */
	if (mkdirat(zrfd, BHYVE_DIR, 0700) != 0 && errno != EEXIST) {
		(void) printf("Error: failed to create directory %s "
		    "in zone: %s\n" BHYVE_DIR, strerror(errno));
		return (1);
	}

	fd = openat(zrfd, BHYVE_ARGS_FILE, O_WRONLY|O_CREAT|O_EXCL, 0600);
	if (fd < 0) {
		(void) printf("Error: failed to create file %s in zone: %s\n",
		    BHYVE_ARGS_FILE, strerror(errno));
		return (1);
	}
	if (full_write(fd, nvbuf, nvbuflen) != 0) {
		(void) printf("Error: failed to write %s: %s\n",
		    BHYVE_ARGS_FILE, strerror(errno));
		(void) unlink(BHYVE_ARGS_FILE);
		return (1);
	}

	return (0);
}
