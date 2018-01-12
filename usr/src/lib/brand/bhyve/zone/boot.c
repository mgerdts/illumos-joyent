/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2018, Joyent, Inc.
 */

/*
 * This program runs as a child of zoneadmd.  zoneadmd has initialized the
 * environment with the following:
 *
 * _ZONECFG_attr_dataset_uuid=fbd0d30b-65e1-ea38-ec78-8dad1c41d143
 * _ZONECFG_attr_ram=8192
 * _ZONECFG_attr_resolvers=8.8.8.8,8.8.4.4
 * _ZONECFG_attr_vcpus=4
 * _ZONECFG_attr_vm_autoboot=false
 * _ZONECFG_attr_vm_version=1
 * _ZONECFG_device_/dev/zvol/rdsk/zones/b2_disk0_boot=true
 * _ZONECFG_device_/dev/zvol/rdsk/zones/b2_disk0_image_size=10240
 * _ZONECFG_device_/dev/zvol/rdsk/zones/b2_disk0_image_uuid=6aac0370-...
 * _ZONECFG_device_/dev/zvol/rdsk/zones/b2_disk0_media=disk
 * _ZONECFG_device_/dev/zvol/rdsk/zones/b2_disk0_model=virtio
 * _ZONECFG_net_net0_address=
 * _ZONECFG_net_net0_allowed_address=172.26.17.202
 * _ZONECFG_net_net0_defrouter=
 * _ZONECFG_net_net0_gateway=172.26.17.1
 * _ZONECFG_net_net0_gateways=172.26.17.1
 * _ZONECFG_net_net0_global_nic=external
 * _ZONECFG_net_net0_ip=172.26.17.202
 * _ZONECFG_net_net0_ips=172.26.17.202/24
 * _ZONECFG_net_net0_mac_addr=02:08:20:84:61:a2
 * _ZONECFG_net_net0_model=virtio
 * _ZONECFG_net_net0_netmask=255.255.255.0
 * _ZONECFG_net_net0_physical=net0
 * _ZONECFG_net_net0_primary=true
 * _ZONECFG_net_net0_vlan_id=3317
 * _ZONECFG_net_resources=net0 
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

#define	BHYVE_DIR		"/var/run/bhyve"
#define	BHYVE_ARGS_FILE		BHYVE_DIR "zhyve.args"
#define ROMFILE			"/usr/share/bhyve/BHYVE_UEFI.fd"
#define ZH_MAXARGS		100


/* ARGSUSED */
int
close_3plus(void *data, int fd)
{
	if (fd < 3)
		return (0);
	return (close(fd));
}

int
enter_zone(char *zonename)
{
	zoneid_t zoneid;

	/* Clean up things that can cause zone_enter() to fail. */
	(void) chdir("/");
	(void) fdwalk(close_3plus, NULL);

	if ((zoneid = getzoneidbyname(zonename)) == -1) {
		(void) fprintf(stderr, "Error: zone %s has no kernel state\n",
		    zonename);
		return (1);
	}

	return (zone_enter(zoneid));
}

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
	(void) printf("%s: '%s=%s'\n", __func__, envvar, ret ? ret : "<null>");

	return (ret);
}

int
add_arg(int *argc, char **argv, char *val)
{
	if (*argc >= ZH_MAXARGS) {
		(void) fprintf(stderr, "Error: too many arguments\n");
		return (1);
	}
	argv[*argc] = val;
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
			(void) fprintf(stderr, "Error: disk %s has no path\n",
			    disk);
			return (-1);
		}

		/* Allow at most one "primary" disk */
		val = get_zcfg_var("device", disk, "boot");
		if (val != NULL && strcmp(val, "true") == 0) {
			if (boot != NULL) {
				(void) fprintf(stderr, "Error: "
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
			(void) fprintf(stderr,
			    "Error: disk path '%s' too long\n", path);
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
				(void) fprintf(stderr, "Error: "
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
			(void) fprintf(stderr, "Error: net '%s' too long\n",
			    net);
			return (-1);
		}

		if (add_arg(argc, argv, "-s") != 0 ||
		    add_arg(argc, argv, slotconf) != 0) {
			return (-1);
		}
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

int
main(int argc, char **argv)
{
	int fd;
	char *zhargv[ZH_MAXARGS] = {
		"zhyve",		/* Squats on argv[0] */
		"-P", "-H",		/* Guest exits on pause and halt isns */
		"-s", "1,lpc",		/* LPC PCI-ISA bridge at PCI 0:1:0 */
		"-l", "bootrom," ROMFILE,
		"-l", "com1,/dev/zconsole",
		NULL };
	int zhargc;
	nvlist_t *nvl;
	char *nvbuf;
	size_t nvbuflen;

	if (argc != 2) {
		(void) fprintf(stderr, "Error: bhyve boot program called with "
		    "%d args, expecting 1", argc - 1);
		return (1);
	}

	for (zhargc = 0; zhargv[zhargc] != NULL; zhargc++)
		;

	if (add_cpu(&zhargc, (char **)&zhargv) != 0 ||
	    add_ram(&zhargc, (char **)&zhargv) != 0 ||
	    add_disks(&zhargc, (char **)&zhargv) != 0 ||
	    add_nets(&zhargc, (char **)&zhargv) != 0) {
		return (1);
	}

	/*
	 * This and other dynamically allocated resources are intentionally
	 * leaked.  It's a short-lived program and it will all get mopped up on
	 * exit.
	 */
	if (nvlist_alloc(&nvl, NV_UNIQUE_NAME, 0) != 0 ||
	    nvlist_add_string_array(nvl, "zhyve_args", zhargv, zhargc) != 0) {
		(void) fprintf(stderr, "Error: failed to create nvlist: %s\n",
		    strerror(errno));
		return (1);
	}

	if (nvlist_pack(nvl, &nvbuf, &nvbuflen, NV_ENCODE_NATIVE, 0) != 0) {
		(void) fprintf(stderr, "Error: failed to pack nvlist\n");
		return (1);
	}

	/*
	 * Enter the zone so that we are immune to symlink attacks and similar
	 * while creating directories files.
	 */
	if (enter_zone(argv[1]) != 0) {
		return (1);
	}

	if (mkdir(BHYVE_DIR, 0700) != 0 && errno != EEXIST) {
		(void) fprintf(stderr, "Error: failed to create directory %s "
		    "in zone: %s\n" BHYVE_DIR, strerror(errno));
		return (1);
	}

	fd = open(BHYVE_ARGS_FILE, O_WRONLY|O_CREAT|O_EXCL, 0600);
	if (fd < 0) {
		(void) fprintf(stderr, "Error: failed to create file %s "
		    "in zone: %s\n" BHYVE_ARGS_FILE, strerror(errno));
		return (1);
	}
	if (full_write(fd, nvbuf, nvbuflen) != 0) {
		(void) fprintf(stderr, "Error: failed to write %s: %s\n",
		    BHYVE_ARGS_FILE, strerror(errno));
		(void) unlink(BHYVE_ARGS_FILE);
		return (1);
	}

	return (0);
}
