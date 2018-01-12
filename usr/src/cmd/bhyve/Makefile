#
# COPYRIGHT 2014 Pluribus Networks Inc.
#
# All rights reserved. This copyright notice is Copyright Management
# Information under 17 USC 1202 and is included to protect this work and
# deter copyright infringement.  Removal or alteration of this Copyright
# Management Information without the express written permission from
# Pluribus Networks Inc is prohibited, and any such unauthorized removal
# or alteration will be a violation of federal law.
#
# Copyright (c) 2018, Joyent, Inc.
#

PROG =		bhyve
SHAREFILES =	BHYVE_UEFI.fd

USRSHAREDIR =		$(ROOT)/usr/share/bhyve
BHYVEUSRSHAREDIR =	$(ROOT)/usr/lib/brand/bhyve/root/usr/share/bhyve

USRSHAREFILES =		$(SHAREFILES:%=$(USRSHAREDIR)/%)
BHYVEUSRSHAREFILES =	$(SHAREFILES:%=$(BHYVEUSRSHAREDIR)/%)
$(USRSHAREFILES) :=	FILEMODE = 0444


include ../Makefile.cmd

$(BUILD64)SUBDIRS += $(MACH64)

all	:=	TARGET = all
install	:=	TARGET = install
clean	:=	TARGET = clean
clobber	:=	TARGET = clobber
lint	:=	TARGET = lint

.KEEP_STATE:

all clean clobber lint:	$(SUBDIRS)

install: $(SUBDIRS) $(BHYVEUSRSHAREFILES)
	-$(RM) $(ROOTUSRSBINPROG)
	-$(LN) $(ISAEXEC) $(ROOTUSRSBINPROG)

$(USRSHAREDIR)/%: %
	$(INS.file)

$(BHYVEUSRSHAREDIR)/%: $(USRSHAREDIR)/%
	$(RM) $@
	$(LN) $< $@

$(SUBDIRS):	FRC
	@cd $@; pwd; $(MAKE) CW_NO_SHADOW=true __GNUC= $(TARGET)

FRC:

include ../Makefile.targ
