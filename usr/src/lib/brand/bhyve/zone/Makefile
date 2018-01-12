#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# Copyright (c) 2018, Joyent, Inc.
#

include $(SRC)/cmd/Makefile.cmd
include ../Makefile.bhyve
include $(SRC)/cmd/Makefile.cmd.64

PROGS =		statechange

PROG1 =		boot
OBJS1 =		boot.o
PROGS +=	$(PROG1)
OBJS +=		$(OBJS1)
CLEANFILES +=	$(PROG1) $(OBJS1)
$(PROG1) :=	LDLIBS += -lnvpair

PROG2 =		halt
OBJS2 =		halt.o
PROGS +=	$(PROG2)
OBJS +=		$(OBJS2)
CLEANFILES +=	$(PROG2) $(OBJS2)
$(PROG2) :=	LDLIBS += -lvmmapi


TEMPLATES =	SYSbhyve.xml
XMLDOCS =	config.xml platform.xml
CLOBBERFILES =	$(ROOTXMLDOCS) $(ROOTTEMPLATES) $(ROOTPROGS)

all: $(PROGS)

$(PROG1): $(OBJS1)
	$(LINK.c) -o $@ $(OBJS1) $(LDFLAGS) $(LDLIBS)
	$(POST_PROCESS)

$(PROG2): $(OBJS2)
	$(LINK.c) -o $@ $(OBJS2) $(LDFLAGS) $(LDLIBS)
	$(POST_PROCESS)

install: $(ROOTPROGS) $(ROOTXMLDOCS) $(ROOTTEMPLATES)

clean:
	$(RM) $(CLEANFILES)

lint:

include $(SRC)/cmd/Makefile.targ
