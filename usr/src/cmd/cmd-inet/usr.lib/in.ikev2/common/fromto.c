/*
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/* Portions of the following are... */
/*
 * Copyright (C) 1995, 1996, 1997, and 1998 WIDE Project.
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
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * These functions provide an easy way to receive a packet with FULL address
 * information, and send one using precise addresses.
 */
#ifdef lint
/* We use X/Open style sockets */
#define	_XOPEN_SOURCE 600
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/int_fmtio.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include "buf.h"

#define	ABUF_OF(sa) (((sa)->ss_family == AF_INET) ?	\
	    (void *)&((struct sockaddr_in *)(sa))->sin_addr :	\
	    (void *)&((struct sockaddr_in6 *)(sa))->sin6_addr)

/* XXX temp */
#define	PRTDBG(x, ...)

/*
 * Receive packet, with src/dst information.  It is assumed that necessary
 * setsockopt()s (e.g. IP_SEC_OPT(NEVER)) have already performed on socket.
 */
ssize_t
recvfromto(int s, buf_t *buf, int flags,
    struct sockaddr_storage *from, socklen_t *fromlen,
    struct sockaddr_storage *to, socklen_t *tolen)
{
	int otolen;
	ssize_t len;
	socklen_t sslen;
	struct sockaddr_storage ss;
	struct msghdr m;
	struct iovec iov[2] = { 0 };
	uint32_t cmsgbuf[64] = { 0 };
	struct cmsghdr *cm = (struct cmsghdr *)cmsgbuf;
	struct in6_pktinfo *pi;
	struct sockaddr_in6 *sin6;
	struct sockaddr_in *sin;
#if 0
	char pbuf[INET6_ADDRSTRLEN + IFNAMSIZ + 2];
#endif

	sslen = sizeof (ss);
	if (getsockname(s, (struct sockaddr *)&ss, &sslen) < 0) {
		PRTDBG(D_NET, ("recvfromto() getsockname failure: %s",
		    strerror(errno)));
		return (-1);
	}

	/* Quick hack -- snapshot the current socket's port, at least. */
	(void) memcpy(to, &ss, sslen < *tolen ? sslen : *tolen);

	m.msg_name = (caddr_t)from;
	m.msg_namelen = *fromlen;
	iov[0].iov_base = (caddr_t)buf->ptr;
	iov[0].iov_len = buf->len;
	m.msg_iov = iov;
	m.msg_iovlen = 1;
	m.msg_control = (caddr_t)cm;
	m.msg_controllen = sizeof (cmsgbuf);
	if ((len = recvmsg(s, &m, flags)) < 0) {
		PRTDBG(D_NET, ("recvfromto() recvmsg failure: %s",
		    strerror(errno)));
		return (-1);
	}
	if (len > buf->len) {
		/*
		 * size_t and ssize_t should always be "long", but not in 32-
		 * bit apps for some bizarre reason.
		 */
		PRTDBG(D_NET, ("Received message of %ld, greater than %lu.\n",
		    (long)len, (ulong_t)buflen));
		errno = E2BIG;	/* Not returned from normal recvmsg()... */
		return (-1);
	}

	*fromlen = m.msg_namelen;

	otolen = *tolen;
	*tolen = 0;
	for (cm = (struct cmsghdr *)CMSG_FIRSTHDR(&m);
	    m.msg_controllen != 0 && cm;
	    cm = (struct cmsghdr *)CMSG_NXTHDR(&m, cm)) {
		if (ss.ss_family == AF_INET6 &&
		    cm->cmsg_level == IPPROTO_IPV6 &&
		    cm->cmsg_type == IPV6_PKTINFO &&
		    otolen >= sizeof (*sin6)) {
			/* LINTED */
			pi = (struct in6_pktinfo *)(CMSG_DATA(cm));
			*tolen = sizeof (*sin6);
			sin6 = (struct sockaddr_in6 *)to;
			(void) memset(sin6, 0, sizeof (*sin6));
			sin6->sin6_family = AF_INET6;
			sin6->sin6_addr = pi->ipi6_addr;
			/* XXX other cases, such as site-local? */
			if (IN6_IS_ADDR_LINKLOCAL(&sin6->sin6_addr))
				sin6->sin6_scope_id = pi->ipi6_ifindex;
			else
				sin6->sin6_scope_id = 0;
			sin6->sin6_port =
			    ((struct sockaddr_in6 *)&ss)->sin6_port;
			otolen = -1;	/* "to" already set */
			continue;
		}

		if (ss.ss_family == AF_INET && cm->cmsg_level == IPPROTO_IP &&
		    cm->cmsg_type == IP_RECVDSTADDR &&
		    otolen >= (int)sizeof (struct sockaddr_in)) {
			*tolen = sizeof (*sin);
			sin = (struct sockaddr_in *)to;
			(void) memset(sin, 0, sizeof (*sin));
			sin->sin_family = AF_INET;
			(void) memcpy(&sin->sin_addr, CMSG_DATA(cm),
			    sizeof (sin->sin_addr));
			sin->sin_port = ((struct sockaddr_in *)&ss)->sin_port;
			otolen = -1;	/* "to" already set */
			continue;
		}
	}

	PRTDBG(D_NET, ("Received packet from %s(%d)",
	    inet_ntop(ss.ss_family, ABUF_OF(from), pbuf, sizeof (pbuf)),
	    ntohs(((struct sockaddr_in *)from)->sin_port)));
	PRTDBG(D_NET, ("\t to %s(%d)",
	    inet_ntop(ss.ss_family, ABUF_OF(to), pbuf, sizeof (pbuf)),
	    ntohs(((struct sockaddr_in *)to)->sin_port)));
	return (len);
}

/* send packet, with fixing src/dst address pair. */
ssize_t
sendfromto(int s, const buf_t *buf, struct sockaddr_storage *src,
    struct sockaddr_storage *dst)
{
	uint32_t cmsgbuf[64] = { 0 };
	struct msghdr m = { 0 };
	struct iovec iov[2];
	struct cmsghdr *cm = (struct cmsghdr *)&cmsgbuf;
	struct in6_pktinfo *pi6;
	struct in_pktinfo *pi;

	if (src->ss_family != dst->ss_family) {
		PRTDBG(D_NET, ("sendfromto(): address family mismatch."));
		errno = EADDRNOTAVAIL;	/* XXX KEBE ASKS - Better ideas? */
		return (-1);
	}

	PRTDBG(D_NET, ("Sending packet from %s(%d)",
	    inet_ntop(src->ss_family, ABUF_OF(src), (char *)cmsgbuf,
	    sizeof (cmsgbuf)), ntohs(((struct sockaddr_in *)src)->sin_port)));
	PRTDBG(D_NET, ("\t to %s(%d)",
	    inet_ntop(dst->ss_family, ABUF_OF(dst), (char *)cmsgbuf,
	    sizeof (cmsgbuf)), ntohs(((struct sockaddr_in *)dst)->sin_port)));

	m.msg_name = (caddr_t)dst;
	iov[0].iov_base = buf->ptr;
	iov[0].iov_len = buf->len;
	m.msg_iov = iov;
	m.msg_iovlen = 1;
	m.msg_control = (caddr_t)cm;
	if (src->ss_family == AF_INET6) {
		/* v6 setup */
		struct sockaddr_in6 *src6;

		src6 = (struct sockaddr_in6 *)src;
		m.msg_namelen = sizeof (*src6);
		m.msg_controllen = CMSG_SPACE(sizeof (*pi6));
		cm->cmsg_len = CMSG_LEN(sizeof (*pi6));
		cm->cmsg_level = IPPROTO_IPV6;
		cm->cmsg_type = IPV6_PKTINFO;
		/* LINTED */
		pi6 = (struct in6_pktinfo *)CMSG_DATA(cm);
		pi6->ipi6_addr = src6->sin6_addr;
		if (IN6_IS_ADDR_LINKLOCAL(&src6->sin6_addr) ||
		    IN6_IS_ADDR_MULTICAST(&src6->sin6_addr)) {
			pi6->ipi6_ifindex = src6->sin6_scope_id;
		} else {
			pi6->ipi6_ifindex = 0;
		}
	} else if (src->ss_family == AF_INET) {
		/* v4 setup */
		struct sockaddr_in *src4;

		src4 = (struct sockaddr_in *)src;
		m.msg_namelen = sizeof (*src4);
		m.msg_controllen = CMSG_SPACE(sizeof (*pi));
		cm->cmsg_len = CMSG_LEN(sizeof (*pi));
		cm->cmsg_level = IPPROTO_IP;
		cm->cmsg_type = IP_PKTINFO;
		/* LINTED */
		pi = (struct in_pktinfo *)CMSG_DATA(cm);
		pi->ipi_addr = src4->sin_addr;
		/* Zero out the other fields for IPv4. */
		pi->ipi_spec_dst.s_addr = 0;
		pi->ipi_ifindex = 0;
	} else {
		errno = EAFNOSUPPORT;
		return (-1);
	}

	return (sendmsg(s, &m, 0));
}
