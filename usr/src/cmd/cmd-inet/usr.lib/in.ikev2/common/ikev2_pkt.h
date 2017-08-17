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
 * Copyright 2017 Jason King.
 * Copyright 2017 Joyent, Inc.
 */

#ifndef _IKEV2_PKT_H
#define	_IKEV2_PKT_H

#include <sys/types.h>

#include "ikev2.h"
#include "pkt.h"
#include "buf.h"

#ifdef __cplusplus
extern "C" {
#endif

struct pkt;
struct ikev2_sa;

#define	INBOUND_LOCAL_SPI(hdr) \
	(((hdr)->flags == IKEV2_FLAG_INITIATOR) ? \
	    (hdr)->responder_spi : (hdr)->initiator_spi)

#define	INBOUND_REMOTE_SPI(hdr) \
	(((hdr)->flags == IKEV2_FLAG_INITIATOR) ? \
	    (hdr)->initiator_spi : (hdr)->responder_spi)

pkt_t *ikev2_pkt_new_inbound(uchar_t *, size_t);
pkt_t *ikev2_pkt_new_initiator(struct ikev2_sa *, ikev2_exch_t);
pkt_t *ikev2_pkt_new_response(const pkt_t *);
void ikev2_pkt_free(pkt_t *);

boolean_t ikev2_add_sa(pkt_t *);
boolean_t ikev2_add_prop(pkt_t *, uint8_t, ikev2_spi_proto_t, uint64_t);
boolean_t ikev2_add_xform(pkt_t *, ikev2_xf_type_t, int);
boolean_t ikev2_add_xf_attr(pkt_t *, ikev2_xf_attr_type_t, uintptr_t);
boolean_t ikev2_add_xf_encr(pkt_t *, ikev2_xf_encr_t, uint16_t, uint16_t);
boolean_t ikev2_add_ke(pkt_t *restrict, uint_t, const uchar_t *restrict,
    size_t);
boolean_t ikev2_add_id_i(pkt_t *restrict, ikev2_id_type_t, ...);
boolean_t ikev2_add_id_r(pkt_t *restrict, ikev2_id_type_t, ...);
boolean_t ikev2_add_cert(pkt_t *restrict, ikev2_cert_t,
    const uchar_t *restrict, size_t);
boolean_t ikev2_add_certreq(pkt_t *restrict, ikev2_cert_t,
    const uchar_t *restrict, size_t);
boolean_t ikev2_add_auth(pkt_t *restrict, ikev2_auth_type_t,
    const uchar_t *restrict, size_t);
boolean_t ikev2_add_nonce(pkt_t *restrict, const uchar_t *restrict, size_t);
boolean_t ikev2_add_notify(pkt_t *restrict, ikev2_spi_proto_t, size_t,
    ikev2_notify_type_t, uint64_t, const uchar_t *restrict, size_t);

boolean_t ikev2_add_delete(pkt_t *, ikev2_spi_proto_t);
boolean_t ikev2_add_delete_spi(pkt_t *, uint64_t);

boolean_t ikev2_add_vendor(pkt_t *restrict, const uchar_t *restrict, size_t);

boolean_t ikev2_add_ts_i(pkt_t *);
boolean_t ikev2_add_ts_r(pkt_t *);
boolean_t ikev2_add_ts(pkt_t *restrict, ikev2_ts_type_t, uint8_t /* proto */,
    const sockaddr_u_t *restrict /* start */,
    const sockaddr_u_t *restrict /* end */);

boolean_t ikev2_add_sk(pkt_t *);

boolean_t ikev2_add_config(pkt_t *restrict, ikev2_cfg_type_t);
boolean_t ikev2_add_config_attr(pkt_t *restrict, ikev2_cfg_attr_type_t,
    const void *restrict);

boolean_t ikev2_pkt_decrypt(pkt_t *);

#ifdef __cplusplus
}
#endif

#endif /* _IKEV2_PKT_H */