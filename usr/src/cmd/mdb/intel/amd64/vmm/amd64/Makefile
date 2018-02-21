#
# COPYRIGHT 2013 Pluribus Networks Inc.
#
# All rights reserved. This copyright notice is Copyright Management
# Information under 17 USC 1202 and is included to protect this work and
# deter copyright infringement.  Removal or alteration of this Copyright
# Management Information without the express written permission from
# Pluribus Networks Inc is prohibited, and any such unauthorized removal
# or alteration will be a violation of federal law.

MODULE = vmm.so
MDBTGT = kvm

MODSRCS = vmm.c

include ../../../../../Makefile.cmd
include ../../../../../Makefile.cmd.64
include ../../../Makefile.amd64
include ../../../../Makefile.module

CPPFLAGS = -D_KERNEL -D_MACHDEP
CPPFLAGS += -I$(COMPAT)/freebsd -I$(COMPAT)/freebsd/amd64
CPPFLAGS += -I$(CONTRIB)/freebsd -I$(CONTRIB)/freebsd/amd64
CPPFLAGS += -I$(SRC)/uts/common -I$(SRC)/uts/i86pc
CPPFLAGS += -I$(SRC)/cmd/mdb/common

#CPPFLAGS += -_cc=-xdryrun

LINTTAGS += -erroff=E_FUNC_ARG_UNUSED
LINTTAGS += -erroff=E_STATIC_UNUSED
