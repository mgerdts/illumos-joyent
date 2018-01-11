#
# COPYRIGHT 2013 Pluribus Networks Inc.
#
# All rights reserved. This copyright notice is Copyright Management
# Information under 17 USC 1202 and is included to protect this work and
# deter copyright infringement.  Removal or alteration of this Copyright
# Management Information without the express written permission from
# Pluribus Networks Inc is prohibited, and any such unauthorized removal
# or alteration will be a violation of federal law.

LIBRARY	= libvmmapi.a
VERS		= .1

BHYVELIBS	= libvmmapi.so$(VERS)

OBJECTS	= vmmapi.o expand_number.o

# include library definitions
include ../../Makefile.lib

# install this library in the root filesystem
include ../../Makefile.rootfs

SRCDIR		= ../common

LIBS		= $(DYNLIB) $(LINTLIB)

CPPFLAGS	= -I$(COMPAT)/freebsd -I$(CONTRIB)/freebsd \
	$(CPPFLAGS.master) -I$(SRC)/uts/i86pc

$(LINTLIB) :=	SRCS = $(SRCDIR)/$(LINTSRC)

LDLIBS		+= -lc

.KEEP_STATE:

all: $(LIBS)

lint: lintcheck

pics/%.o: $(CONTRIB)/freebsd/lib/libutil/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

pics/%.o: ../common/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

# include library targets
include ../../Makefile.targ
