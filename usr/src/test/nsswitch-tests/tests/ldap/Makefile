#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source.  A copy of the CDDL is also available via the Internet at
# http://www.illumos.org/license/CDDL.
#

# Copyright 2019 Joyent, Inc.

include $(SRC)/cmd/Makefile.cmd
include $(SRC)/test/Makefile.com

PROG1 = generalized_time
OBJS1 = $(PROG1).o ldap_common.o ldap_utils.o getservent.o list.o

ROOTOPTPKG = $(ROOT)/opt/nsswitch-tests
TESTDIR = $(ROOTOPTPKG)/tests/ldap
PROGS = $(PROG1)
CMDS = $(PROGS:%=$(TESTDIR)/%)

CPPFLAGS = -I$(SRC)/lib/nsswitch/ldap/common -I$(SRC)/lib/libsldap/common
LDFLAGS = -lsldap -lnsl -lldap -lavl -lscf
USDT_OBJS = provider.o
$(PROG1) := TARGET = $(PROG1)

CLEANFILES += $(PROGS) $(USDT_OBJS)
CLEANFILES += $(OBJS1)
CLOBBERFILES += $(CMDS)

.KEEP_STATE:

all: $(PROGS)

test: all
	for prog in $(PROGS); do ./$$prog; done

clean:
	$(RM) $(CLEANFILES)

lint:

install: all $(TESTDIR) $(CMDS)

$(PROG1): $(OBJS1) .WAIT $(USDT_OBJS)
	$(LINK.c) $(OBJS1) $(USDT_OBJS) -o $@
	$(POST_PROCESS)
	$(RM) $(USDT_OBJS)

%.o: $(SRC)/test/nsswitch-tests/ldap/common/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

%.o: $(SRC)/common/list/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

%.o: $(SRC)/lib/nsswitch/ldap/common/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)
	$(RM) $(USDT_OBJS)

%.o: $(SRC)/lib/nsswitch/ldap/common/%.d
	$(COMPILE.d) -o $@ -s $< $(TARGET).o

$(TESTDIR):
	$(INS.dir)

$(TESTDIR)/%: %
	$(INS.file)

include $(SRC)/cmd/Makefile.targ
