/*
 * COPYRIGHT 2013 Pluribus Networks Inc.
 *
 * All rights reserved. This copyright notice is Copyright Management
 * Information under 17 USC 1202 and is included to protect this work and
 * deter copyright infringement.  Removal or alteration of this Copyright
 * Management Information without the express written permission from
 * Pluribus Networks Inc is prohibited, and any such unauthorized removal
 * or alteration will be a violation of federal law.
 */
#ifndef	_VIONA_IO_H_
#define	_VIONA_IO_H_

#define	VNA_IOC			(('V' << 16)|('C' << 8))
#define	VNA_IOC_CREATE		(VNA_IOC | 0x01)
#define	VNA_IOC_DELETE		(VNA_IOC | 0x02)

#define	VNA_IOC_RING_INIT	(VNA_IOC | 0x10)
#define	VNA_IOC_RING_RESET	(VNA_IOC | 0x11)
#define	VNA_IOC_RING_KICK	(VNA_IOC | 0x12)
#define	VNA_IOC_RING_SET_MSI	(VNA_IOC | 0x13)
#define	VNA_IOC_RING_INTR_CLR	(VNA_IOC | 0x14)

#define	VNA_IOC_INTR_POLL	(VNA_IOC | 0x20)
#define	VNA_IOC_SET_FEATURES	(VNA_IOC | 0x21)
#define	VNA_IOC_GET_FEATURES	(VNA_IOC | 0x22)
#define	VNA_IOC_SET_NOTIFY_IOP	(VNA_IOC | 0x23)

typedef struct vioc_create {
	datalink_id_t	c_linkid;
	int		c_vmfd;
} vioc_create_t;

typedef struct vioc_ring_init {
	uint16_t	ri_index;
	uint16_t	ri_qsize;
	uint64_t	ri_qaddr;
} vioc_ring_init_t;

typedef struct vioc_ring_msi {
	uint16_t	rm_index;
	uint64_t	rm_addr;
	uint64_t	rm_msg;
} vioc_ring_msi_t;

enum viona_vq_id {
	VIONA_VQ_RX = 0,
	VIONA_VQ_TX = 1,
	VIONA_VQ_MAX = 2
};

typedef struct vioc_intr_poll {
	uint32_t	vip_status[VIONA_VQ_MAX];
} vioc_intr_poll_t;


#endif	/* _VIONA_IO_H_ */
