/*
 * COPYRIGHT 2015 Pluribus Networks Inc.
 *
 * All rights reserved. This copyright notice is Copyright Management
 * Information under 17 USC 1202 and is included to protect this work and
 * deter copyright infringement.  Removal or alteration of this Copyright
 * Management Information without the express written permission from
 * Pluribus Networks Inc is prohibited, and any such unauthorized removal
 * or alteration will be a violation of federal law.
 */
/*
 * Copyright (c) 2011 NetApp, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY NETAPP, INC ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL NETAPP, INC OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/cdefs.h>

#include <sys/param.h>
#include <sys/linker_set.h>
#include <sys/ioctl.h>
#include <sys/viona_io.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <assert.h>
#include <pthread.h>
#include <signal.h>
#include <poll.h>
#include <libdladm.h>
#include <libdllink.h>
#include <libdlvnic.h>

#include <machine/vmm.h>
#include <vmmapi.h>

#include "bhyverun.h"
#include "pci_emul.h"
#include "virtio.h"

#define	VIONA_RINGSZ	1024

/*
 * PCI config-space register offsets
 */
#define	VIONA_R_CFG0	24
#define	VIONA_R_CFG1	25
#define	VIONA_R_CFG2	26
#define	VIONA_R_CFG3	27
#define	VIONA_R_CFG4	28
#define	VIONA_R_CFG5	29
#define	VIONA_R_CFG6	30
#define	VIONA_R_CFG7	31
#define	VIONA_R_MAX	31

#define	VIONA_REGSZ	VIONA_R_MAX+1

/*
 * Queue definitions.
 */
#define	VIONA_RXQ	0
#define	VIONA_TXQ	1
#define	VIONA_CTLQ	2

#define	VIONA_MAXQ	3

/*
 * Debug printf
 */
static volatile int pci_viona_debug;
#define	DPRINTF(params) if (pci_viona_debug) printf params
#define	WPRINTF(params) printf params

/*
 * Per-device softc
 */
struct pci_viona_softc {
	struct pci_devinst *vsc_pi;
	pthread_mutex_t vsc_mtx;

	int		vsc_curq;
	int		vsc_status;
	int		vsc_isr;

	datalink_id_t	vsc_linkid;
	int		vsc_vnafd;

	/* Configurable parameters */
	char		vsc_linkname[MAXLINKNAMELEN];
	uint32_t	vsc_feature_mask;
	uint16_t	vsc_vq_size;

	uint32_t	vsc_features;
	uint8_t		vsc_macaddr[6];

	uint64_t	vsc_pfn[VIONA_MAXQ];
	uint16_t	vsc_msix_table_idx[VIONA_MAXQ];
};
#define	viona_ctx(sc)	((sc)->vsc_pi->pi_vmctx)

/*
 * Return the size of IO BAR that maps virtio header and device specific
 * region. The size would vary depending on whether MSI-X is enabled or
 * not.
 */
static uint64_t
pci_viona_iosize(struct pci_devinst *pi)
{
	if (pci_msix_enabled(pi))
		return (VIONA_REGSZ);
	else
		return (VIONA_REGSZ - (VTCFG_R_CFG1 - VTCFG_R_MSIX));
}

static uint16_t
pci_viona_qsize(struct pci_viona_softc *sc, int qnum)
{
	/* XXX no ctl queue currently */
	if (qnum == VIONA_CTLQ) {
		return (0);
	}

	return (sc->vsc_vq_size);
}

static void
pci_viona_ring_reset(struct pci_viona_softc *sc, int ring)
{
	int	error;

	assert(ring < VIONA_MAXQ);

	switch (ring) {
	case VIONA_RXQ:
	case VIONA_TXQ:
		error = ioctl(sc->vsc_vnafd, VNA_IOC_RING_RESET, ring);
		if (error != 0) {
			WPRINTF(("ioctl viona ring %u reset failed %d\n",
			    ring, error));
		} else {
			sc->vsc_pfn[ring] = 0;
		}
		break;
	case VIONA_CTLQ:
	default:
		break;
	}
}

static void
pci_viona_update_status(struct pci_viona_softc *sc, uint32_t value)
{

	if (value == 0) {
		DPRINTF(("viona: device reset requested !\n"));
		pci_viona_ring_reset(sc, VIONA_RXQ);
		pci_viona_ring_reset(sc, VIONA_TXQ);
	}

	sc->vsc_status = value;
}

static void *
pci_viona_poll_thread(void *param)
{
	struct pci_viona_softc *sc = param;
	pollfd_t	pollset;
	int			error;

	pollset.fd = sc->vsc_vnafd;
	pollset.events = POLLIN | POLLOUT;

	for (;;) {
		if (poll(&pollset, 1, -1) < 0) {
			if (errno == EINTR || errno == EAGAIN) {
				continue;
			} else {
				WPRINTF(("pci_viona_poll_thread poll()"
				    "error %d\n", errno));
				break;
			}
		}
		if (pollset.revents & POLLIN) {
			pci_generate_msix(sc->vsc_pi,
			    sc->vsc_msix_table_idx[VIONA_RXQ]);
			error = ioctl(sc->vsc_vnafd, VNA_IOC_INTR_CLR,
			    VIONA_RXQ);
			if (error != 0) {
				WPRINTF(("ioctl viona rx intr clear failed"
				    " %d\n", error));
			}
		}

		if (pollset.revents & POLLOUT) {
			pci_generate_msix(sc->vsc_pi,
			    sc->vsc_msix_table_idx[VIONA_TXQ]);
			error = ioctl(sc->vsc_vnafd, VNA_IOC_INTR_CLR,
			    VIONA_TXQ);
			if (error != 0) {
				WPRINTF(("ioctl viona tx intr clear failed"
				    " %d\n", error));
			}
		}
	}

	pthread_exit(NULL);
}

static void
pci_viona_ring_init(struct pci_viona_softc *sc, uint64_t pfn)
{
	int			qnum = sc->vsc_curq;
	vioc_ring_init_t	vna_ri;
	int			error;

	assert(qnum < VIONA_MAXQ);

	if (qnum == VIONA_CTLQ) {
		return;
	}

	sc->vsc_pfn[qnum] = (pfn << VRING_PFN);

	vna_ri.ri_index = qnum;
	vna_ri.ri_qsize = pci_viona_qsize(sc, qnum);
	vna_ri.ri_qaddr = (pfn << VRING_PFN);
	error = ioctl(sc->vsc_vnafd, VNA_IOC_RING_INIT, &vna_ri);

	if (error != 0) {
		WPRINTF(("ioctl viona ring %u init failed %d\n", qnum, error));
	}
}

static int
pci_viona_viona_init(struct vmctx *ctx, struct pci_viona_softc *sc)
{
	vioc_create_t		vna_create;
	int			error;

	sc->vsc_vnafd = open("/dev/viona/ctl", O_RDWR | O_EXCL);
	if (sc->vsc_vnafd == -1) {
		WPRINTF(("open viona ctl failed\n"));
		return (-1);
	}

	vna_create.c_linkid = sc->vsc_linkid;
	vna_create.c_vmfd = vm_get_device_fd(ctx);
	error = ioctl(sc->vsc_vnafd, VNA_IOC_CREATE, &vna_create);
	if (error != 0) {
		(void) close(sc->vsc_vnafd);
		WPRINTF(("ioctl viona create failed %d\n", error));
		return (-1);
	}

	return (0);
}

static int
pci_viona_parse_opts(struct pci_viona_softc *sc, char *opts)
{
	char *next, *cp, *vnic = NULL;
	int err = 0;

	sc->vsc_vq_size = VIONA_RINGSZ;
	sc->vsc_feature_mask = 0;

	for (;opts != NULL && *opts != '\0'; opts = next) {
		char *val;

		if ((cp = strchr(opts, ',')) != NULL) {
			*cp = '\0';
			next = cp + 1;
		} else {
			next = NULL;
		}

		if ((cp = strchr(opts, '=')) == NULL) {
			/* vnic chosen with bare name */
			if (vnic != NULL) {
				fprintf(stderr,
				    "viona: unexpected vnic name '%s'", opts);
				err = -1;
			} else {
				vnic = opts;
			}
			continue;
		}

		/* <param>=<value> handling */
		val = cp + 1;
		*cp = '\0';
		if (strcmp(opts, "feature_mask") == 0) {
			long num;

			errno = 0;
			num = strtol(val, NULL, 0);
			if (errno != 0 || num < 0) {
				fprintf(stderr,
				    "viona: invalid mask '%s'", val);
			} else {
				sc->vsc_feature_mask = num;
			}
		} else if (strcmp(opts, "vqsize") == 0) {
			long num;

			errno = 0;
			num = strtol(val, NULL, 0);
			if (errno != 0) {
				fprintf(stderr,
				    "viona: invalid vsqize '%s'", val);
				err = -1;
			} else if (num <= 2 || num > 32768) {
				fprintf(stderr,
				    "viona: vqsize out of range", num);
				err = -1;
			} else if ((1 << (ffs(num) - 1)) != num) {
				fprintf(stderr,
				    "viona: vqsize must be power of 2", num);
				err = -1;
			} else {
				sc->vsc_vq_size = num;
			}
		} else {
			fprintf(stderr,
			    "viona: unrecognized option '%s'", opts);
			err = -1;
		}
	}
	if (vnic == NULL) {
		fprintf(stderr, "viona: vnic name required");
		sc->vsc_linkname[0] = '\0';
		err = -1;
	} else {
		(void) strlcpy(sc->vsc_linkname, vnic, MAXLINKNAMELEN);
	}

	DPRINTF(("viona=%p dev=%s vqsize=%x feature_mask=%x\n", sc,
	    sc->vsc_linkname, sc->vsc_vq_size, sc->vsc_feature_mask));
	return (err);
}

static int
pci_viona_init(struct vmctx *ctx, struct pci_devinst *pi, char *opts)
{
	dladm_handle_t		handle;
	dladm_status_t		status;
	dladm_vnic_attr_t	attr;
	char			errmsg[DLADM_STRSIZE];
	int error;
	struct pci_viona_softc *sc;
	int i;

	if (opts == NULL) {
		printf("virtio-viona: vnic required\n");
		return (1);
	}

	sc = malloc(sizeof (struct pci_viona_softc));
	memset(sc, 0, sizeof (struct pci_viona_softc));

	pi->pi_arg = sc;
	sc->vsc_pi = pi;

	pthread_mutex_init(&sc->vsc_mtx, NULL);

	if (pci_viona_parse_opts(sc, opts) != 0) {
		free(sc);
		return (1);
	}

	if ((status = dladm_open(&handle)) != DLADM_STATUS_OK) {
		WPRINTF(("could not open /dev/dld"));
		free(sc);
		return (1);
	}

	if (dladm_name2info(handle, sc->vsc_linkname, &sc->vsc_linkid,
	    NULL, NULL, NULL) != DLADM_STATUS_OK) {
		WPRINTF(("dladm_name2info() for %s failed: %s\n", opts,
		    dladm_status2str(status, errmsg)));
		dladm_close(handle);
		free(sc);
		return (1);
	}

	if (dladm_vnic_info(handle, sc->vsc_linkid, &attr,
	    DLADM_OPT_ACTIVE) != DLADM_STATUS_OK) {
		WPRINTF(("dladm_vnic_info() for %s failed: %s\n", opts,
		    dladm_status2str(status, errmsg)));
		dladm_close(handle);
		free(sc);
		return (1);
	}

	memcpy(sc->vsc_macaddr, attr.va_mac_addr, ETHERADDRL);

	dladm_close(handle);

	error = pci_viona_viona_init(ctx, sc);
	if (error != 0) {
		free(sc);
		return (1);
	}

	error = pthread_create(NULL, NULL, pci_viona_poll_thread, sc);
	assert(error == 0);

	/* initialize config space */
	pci_set_cfgdata16(pi, PCIR_DEVICE, VIRTIO_DEV_NET);
	pci_set_cfgdata16(pi, PCIR_VENDOR, VIRTIO_VENDOR);
	pci_set_cfgdata8(pi, PCIR_CLASS, PCIC_NETWORK);
	pci_set_cfgdata16(pi, PCIR_SUBDEV_0, VIRTIO_TYPE_NET);
	pci_set_cfgdata16(pi, PCIR_SUBVEND_0, VIRTIO_VENDOR);

	/* MSI-X support */
	for (i = 0; i < VIONA_MAXQ; i++)
		sc->vsc_msix_table_idx[i] = VIRTIO_MSI_NO_VECTOR;

	/*
	 * BAR 1 used to map MSI-X table and PBA
	 */
	if (pci_emul_add_msixcap(pi, VIONA_MAXQ, 1)) {
		free(sc);
		return (1);
	}

	pci_emul_alloc_bar(pi, 0, PCIBAR_IO, VIONA_REGSZ);

	return (0);
}

static uint64_t
viona_adjust_offset(struct pci_devinst *pi, uint64_t offset)
{
	/*
	 * Device specific offsets used by guest would change based on
	 * whether MSI-X capability is enabled or not
	 */
	if (!pci_msix_enabled(pi)) {
		if (offset >= VTCFG_R_MSIX)
			return (offset + (VTCFG_R_CFG1 - VTCFG_R_MSIX));
	}

	return (offset);
}

static void
pci_viona_barupdate(struct pci_devinst *pi, int idx, int reg)
{
	struct pci_viona_softc *sc = pi->pi_arg;
	uint_t ioport;
	int err;

	/* Only care about updates to the virtio cfg area */
	if (idx != 0) {
		return;
	}

	assert(pi->pi_bar[idx].type == PCIBAR_IO);
	if (reg == 0) {
		ioport = 0;
	} else {
		ioport = pi->pi_bar[idx].addr;
		ioport += viona_adjust_offset(pi, VTCFG_R_QNOTIFY);
	}
	err = ioctl(sc->vsc_vnafd, VNA_IOC_SET_NOTIFY_IOP, ioport);
	if (err != 0) {
		DPRINTF(("viona: failed setting notify ioport (%x)\n", ioport));
	}
}

static void
pci_viona_qnotify(struct pci_viona_softc *sc, int ring)
{
	int error;

	switch (ring) {
	case VIONA_TXQ:
	case VIONA_RXQ:
		error = ioctl(sc->vsc_vnafd, VNA_IOC_RING_KICK, ring);
		if (error != 0) {
			WPRINTF(("ioctl viona ring %d kick failed %d\n",
			    ring, error));
		}
		break;
	case VIONA_CTLQ:
		DPRINTF(("viona: control qnotify!\n"));
		break;
	default:
		break;
	}
};

static void
pci_viona_write(struct vmctx *ctx, int vcpu, struct pci_devinst *pi,
    int baridx, uint64_t offset, int size, uint64_t value)
{
	struct pci_viona_softc *sc = pi->pi_arg;
	void *ptr;
	int err = 0;

	if (baridx == pci_msix_table_bar(pi) ||
	    baridx == pci_msix_pba_bar(pi)) {
		pci_emul_msix_twrite(pi, offset, size, value);
		return;
	}

	assert(baridx == 0);

	if (offset + size > pci_viona_iosize(pi)) {
		DPRINTF(("viona_write: 2big, offset %ld size %d\n",
		    offset, size));
		return;
	}

	pthread_mutex_lock(&sc->vsc_mtx);

	offset = viona_adjust_offset(pi, offset);

	switch (offset) {
	case VTCFG_R_GUESTCAP:
		assert(size == 4);
		value &= ~(sc->vsc_feature_mask);
		err = ioctl(sc->vsc_vnafd, VNA_IOC_SET_FEATURES, &value);
		if (err != 0) {
			WPRINTF(("ioctl feature negotiation returned"
			    " err = %d\n", err));
		} else {
			sc->vsc_features = value;
		}
		break;
	case VTCFG_R_PFN:
		assert(size == 4);
		pci_viona_ring_init(sc, value);
		break;
	case VTCFG_R_QSEL:
		assert(size == 2);
		assert(value < VIONA_MAXQ);
		sc->vsc_curq = value;
		break;
	case VTCFG_R_QNOTIFY:
		assert(size == 2);
		assert(value < VIONA_MAXQ);
		pci_viona_qnotify(sc, value);
		break;
	case VTCFG_R_STATUS:
		assert(size == 1);
		pci_viona_update_status(sc, value);
		break;
	case VTCFG_R_CFGVEC:
		assert(size == 2);
		sc->vsc_msix_table_idx[VIONA_CTLQ] = value;
		break;
	case VTCFG_R_QVEC:
		assert(size == 2);
		assert(sc->vsc_curq != VIONA_CTLQ);
		sc->vsc_msix_table_idx[sc->vsc_curq] = value;
		break;
	case VIONA_R_CFG0:
	case VIONA_R_CFG1:
	case VIONA_R_CFG2:
	case VIONA_R_CFG3:
	case VIONA_R_CFG4:
	case VIONA_R_CFG5:
		assert((size + offset) <= (VIONA_R_CFG5 + 1));
		ptr = &sc->vsc_macaddr[offset - VIONA_R_CFG0];
		/*
		 * The driver is allowed to change the MAC address
		 */
		sc->vsc_macaddr[offset - VIONA_R_CFG0] = value;
		if (size == 1) {
			*(uint8_t *)ptr = value;
		} else if (size == 2) {
			*(uint16_t *)ptr = value;
		} else {
			*(uint32_t *)ptr = value;
		}
		break;
	case VTCFG_R_HOSTCAP:
	case VTCFG_R_QNUM:
	case VTCFG_R_ISR:
	case VIONA_R_CFG6:
	case VIONA_R_CFG7:
		DPRINTF(("viona: write to readonly reg %ld\n\r", offset));
		break;
	default:
		DPRINTF(("viona: unknown i/o write offset %ld\n\r", offset));
		value = 0;
		break;
	}

	pthread_mutex_unlock(&sc->vsc_mtx);
}

static uint64_t
pci_viona_read(struct vmctx *ctx, int vcpu, struct pci_devinst *pi,
    int baridx, uint64_t offset, int size)
{
	struct pci_viona_softc *sc = pi->pi_arg;
	void *ptr;
	uint64_t value;
	int err = 0;

	if (baridx == pci_msix_table_bar(pi) ||
	    baridx == pci_msix_pba_bar(pi)) {
		return (pci_emul_msix_tread(pi, offset, size));
	}

	assert(baridx == 0);

	if (offset + size > pci_viona_iosize(pi)) {
		DPRINTF(("viona_read: 2big, offset %ld size %d\n",
		    offset, size));
		return (0);
	}

	pthread_mutex_lock(&sc->vsc_mtx);

	offset = viona_adjust_offset(pi, offset);

	switch (offset) {
	case VTCFG_R_HOSTCAP:
		assert(size == 4);
		err = ioctl(sc->vsc_vnafd, VNA_IOC_GET_FEATURES, &value);
		if (err != 0) {
			WPRINTF(("ioctl get host features returned"
			    " err = %d\n", err));
		}
		value &= ~sc->vsc_feature_mask;
		break;
	case VTCFG_R_GUESTCAP:
		assert(size == 4);
		value = sc->vsc_features; /* XXX never read ? */
		break;
	case VTCFG_R_PFN:
		assert(size == 4);
		value = sc->vsc_pfn[sc->vsc_curq] >> VRING_PFN;
		break;
	case VTCFG_R_QNUM:
		assert(size == 2);
		value = pci_viona_qsize(sc, sc->vsc_curq);
		break;
	case VTCFG_R_QSEL:
		assert(size == 2);
		value = sc->vsc_curq;  /* XXX never read ? */
		break;
	case VTCFG_R_QNOTIFY:
		assert(size == 2);
		value = sc->vsc_curq;  /* XXX never read ? */
		break;
	case VTCFG_R_STATUS:
		assert(size == 1);
		value = sc->vsc_status;
		break;
	case VTCFG_R_ISR:
		assert(size == 1);
		value = sc->vsc_isr;
		sc->vsc_isr = 0;	/* a read clears this flag */
		break;
	case VTCFG_R_CFGVEC:
		assert(size == 2);
		value = sc->vsc_msix_table_idx[VIONA_CTLQ];
		break;
	case VTCFG_R_QVEC:
		assert(size == 2);
		assert(sc->vsc_curq != VIONA_CTLQ);
		value = sc->vsc_msix_table_idx[sc->vsc_curq];
		break;
	case VIONA_R_CFG0:
	case VIONA_R_CFG1:
	case VIONA_R_CFG2:
	case VIONA_R_CFG3:
	case VIONA_R_CFG4:
	case VIONA_R_CFG5:
		assert((size + offset) <= (VIONA_R_CFG5 + 1));
		ptr = &sc->vsc_macaddr[offset - VIONA_R_CFG0];
		if (size == 1) {
			value = *(uint8_t *)ptr;
		} else if (size == 2) {
			value = *(uint16_t *)ptr;
		} else {
			value = *(uint32_t *)ptr;
		}
		break;
	case VIONA_R_CFG6:
		assert(size != 4);
		value = 0x01;	/* XXX link always up */
		break;
	case VIONA_R_CFG7:
		assert(size == 1);
		value = 0;	/* XXX link status in LSB */
		break;
	default:
		DPRINTF(("viona: unknown i/o read offset %ld\n\r", offset));
		value = 0;
		break;
	}

	pthread_mutex_unlock(&sc->vsc_mtx);

	return (value);
}

struct pci_devemu pci_de_viona = {
	.pe_emu = 	"virtio-net-viona",
	.pe_init =	pci_viona_init,
	.pe_barwrite =	pci_viona_write,
	.pe_barread =	pci_viona_read,
	.pe_barupdate =	pci_viona_barupdate
};
PCI_EMUL_SET(pci_de_viona);
