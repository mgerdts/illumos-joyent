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
 * Copyright (c) 2017, Joyent, Inc.
 */
#include <sys/types.h>
#include <sys/debug.h>
#include <pthread.h>
#include <string.h>
#include "defs.h"
#include "config.h"
#include "ikev2_enum.h"

pthread_rwlock_t cfg_lock = PTHREAD_RWLOCK_INITIALIZER;
config_t *config;

static boolean_t cfg_addr_match(const sockaddr_u_t,
    const config_addr_t *restrict);

config_t *
config_get(void)
{
	config_t *cfg = NULL;

	VERIFY0(pthread_rwlock_rdlock(&cfg_lock));
	cfg = config;
	CONFIG_REFHOLD(cfg);
	VERIFY0(pthread_rwlock_unlock(&cfg_lock));
	return (cfg);
}

void
config_xf_log(bunyan_logger_t *b, bunyan_level_t level, const char *msg,
    const config_xf_t *xf)
{
	char str[4][IKEV2_ENUM_STRLEN];
	getlog(level)(b, msg,
	    BUNYAN_T_STRING, "xf_encralg", ikev2_xf_encr_str(xf->xf_encr,
	    str[0], sizeof (str[0])),
	    BUNYAN_T_UINT32, "xf_minbits", (uint32_t)xf->xf_minbits,
	    BUNYAN_T_UINT32, "xf_maxbits", (uint32_t)xf->xf_maxbits,
	    BUNYAN_T_STRING, "xf_authalg", ikev2_xf_auth_str(xf->xf_auth,
	    str[1], sizeof (str[1])),
	    BUNYAN_T_STRING, "xf_authtype",
	    ikev2_auth_type_str(xf->xf_authtype, str[2], sizeof (str[2])),
	    BUNYAN_T_STRING, "xf_dh", ikev2_dh_str(xf->xf_dh, str[3],
	    sizeof (str[3])),
	    BUNYAN_T_END);
}

/*
 * Return the first rule that matches the given local and remote addresses.
 * If no rule matches, return the default rule.  The config is refheld on
 * return.
 */
config_rule_t *
config_get_rule(sockaddr_u_t local, sockaddr_u_t remote)
{
	config_t *cfg = config_get();

	for (size_t i = 0; cfg->cfg_rules[i] != NULL; i++) {
		config_rule_t *rule = cfg->cfg_rules[i];
		boolean_t local_match = B_FALSE;
		boolean_t remote_match = B_FALSE;

		for (size_t j = 0; j < rule->rule_nlocal_addr; j++) {
			if (cfg_addr_match(local, &rule->rule_local_addr[j])) {
				local_match = B_TRUE;
				break;
			}
		}
		for (size_t j = 0; j < rule->rule_nremote_addr; j++) {
			if (cfg_addr_match(remote,
			    &rule->rule_remote_addr[j])) {
				remote_match = B_TRUE;
				break;
			}
		}
		if (local_match && remote_match)
			return (rule);
	}

	return (&cfg->cfg_default);
}

boolean_t
config_addr_to_ss(config_addr_t *caddr, sockaddr_u_t saddr)
{
	switch (caddr->cfa_type) {
	case CFG_ADDR_IPV4_PREFIX:
	case CFG_ADDR_IPV4_RANGE:
	case CFG_ADDR_IPV6_PREFIX:
	case CFG_ADDR_IPV6_RANGE:
		return (B_FALSE);
	case CFG_ADDR_IPV4:
		saddr.sau_sin->sin_family = AF_INET;
		saddr.sau_sin->sin_port = htons(IPPORT_IKE);
		(void) memcpy(&saddr.sau_sin->sin_addr, &caddr->cfa_start4,
		    sizeof (in_addr_t));
		break;
	case CFG_ADDR_IPV6:
		saddr.sau_sin6->sin6_family = AF_INET6;
		saddr.sau_sin6->sin6_port = htons(IPPORT_IKE);
		(void) memcpy(&saddr.sau_sin6->sin6_addr, &caddr->cfa_start6,
		    sizeof (in6_addr_t));
		break;
	}
	return (B_TRUE);
}

static boolean_t
cfg_addr_match(const sockaddr_u_t l, const config_addr_t *restrict r)
{
	uint32_t mask;

	switch (r->cfa_type) {
	case CFG_ADDR_IPV4:
		if (l.sau_ss->ss_family != AF_INET)
			return (B_FALSE);
		if (l.sau_sin->sin_addr.s_addr != r->cfa_start4)
			return (B_FALSE);
		return (B_TRUE);
	case CFG_ADDR_IPV4_PREFIX:
		/* XXX: this needs testing */
		if (l.sau_ss->ss_family != AF_INET)
			return (B_FALSE);
		mask = (0xffffffff << (32 - r->cfa_endu.cfa_num)) &
		    0xffffffff;
		if ((l.sau_sin->sin_addr.s_addr & mask) ==
		    (r->cfa_start4 & mask))
			return (B_TRUE);
		return (B_FALSE);
	case CFG_ADDR_IPV4_RANGE:
		if (l.sau_ss->ss_family != AF_INET)
			return (B_FALSE);
		if (l.sau_sin->sin_addr.s_addr >= r->cfa_start4 &&
		    l.sau_sin->sin_addr.s_addr <= r->cfa_end4)
			return (B_TRUE);
		return (B_FALSE);
	case CFG_ADDR_IPV6:
		if (l.sau_ss->ss_family != AF_INET6)
			return (B_FALSE);
		if (IN6_ARE_ADDR_EQUAL(&l.sau_sin6->sin6_addr,
		    &r->cfa_start6))
			return (B_TRUE);
		return (B_FALSE);
	case CFG_ADDR_IPV6_PREFIX:
		if (l.sau_ss->ss_family != AF_INET6)
			return (B_FALSE);
		if (IN6_ARE_PREFIXEDADDR_EQUAL(&l.sau_sin6->sin6_addr,
		    &r->cfa_start6, r->cfa_endu.cfa_num))
			return (B_TRUE);
		return (B_FALSE);
	case CFG_ADDR_IPV6_RANGE:
		if (l.sau_ss->ss_family != AF_INET6)
			return (B_FALSE);
		for (size_t i = 0; i < 16; i++) {
			if ((l.sau_sin6->sin6_addr.s6_addr[i] <
			    r->cfa_start6.s6_addr[i]) ||
			    (l.sau_sin6->sin6_addr.s6_addr[i] >
			    r->cfa_end6.s6_addr[i]))
				return (B_FALSE);
		}
		return (B_TRUE);
	}
	return (B_FALSE);
}

void
cfg_rule_free(config_rule_t *rule)
{
	if (rule == NULL)
		return;

	if (rule->rule_xf != NULL) {
		for (size_t i = 0; rule->rule_xf[i] != NULL; i++) {
			free(rule->rule_xf[i]->xf_str);
			free(rule->rule_xf[i]);
		}
	}

	if (rule->rule_remote_id != NULL) {
		for (size_t i = 0; rule->rule_remote_id[i] != NULL; i++)
			free(rule->rule_remote_id[i]);
		free(rule->rule_remote_id);
	}

	free(rule->rule_xf);
	free(rule->rule_local_addr);
	free(rule->rule_remote_addr);
	free(rule->rule_label);
	free(rule);
}

void
cfg_free(config_t *cfg)
{
	if (cfg == NULL)
		return;

	size_t i;

	VERIFY3U(cfg->cfg_refcnt, ==, 0);

	for (i = 0;
	    cfg->cfg_cert_root != NULL && cfg->cfg_cert_root[i] != NULL;
	    i++)
		free(cfg->cfg_cert_root[i]);

	if (cfg->cfg_cert_trust != NULL) {
		for (i = 0; cfg->cfg_cert_trust[i] != NULL; i++)
			free(cfg->cfg_cert_trust[i]);
	}

	if (cfg->cfg_default.rule_xf != NULL) {
		for (i = 0; cfg->cfg_default.rule_xf[i] != NULL; i++)
			free(cfg->cfg_default.rule_xf[i]);
	}

	if (cfg->cfg_rules != NULL) {
		for (i = 0; cfg->cfg_rules[i] != NULL; i++)
			cfg_rule_free(cfg->cfg_rules[i]);
	}

	free(cfg->cfg_rules);
	free(cfg->cfg_default.rule_xf);
	free(cfg->cfg_proxy);
	free(cfg->cfg_socks);
	free(cfg->cfg_cert_root);
	free(cfg->cfg_cert_trust);
	free(cfg);
}
