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
# Copyright 2017 Joyent, Inc.
#
# Adapted from acpica/generate/unix/iasl/Makefile, which lacked a copyright
# notice.
#
PROG=		iasl

include ../../Makefile.cmd
include ../../Makefile.ctf

OBJS = acfileio.o adfile.o adisasm.o adwalk.o ahids.o ahpredef.o ahtable.o \
	ahuuids.o aslallocate.o aslanalyze.o aslascii.o aslbtypes.o aslcache.o \
	aslcodegen.o aslcompile.o aslcompilerlex.o aslcompilerparse.o \
	asldebug.o aslerror.o aslexternal.o aslfileio.o aslfiles.o aslfold.o \
	aslhelp.o aslhex.o asllength.o asllisting.o asllistsup.o aslload.o \
	asllookup.o aslmain.o aslmap.o aslmapenter.o aslmapoutput.o \
	aslmaputils.o aslmessages.o aslmethod.o aslnamesp.o asloffset.o \
	aslopcodes.o asloperands.o aslopt.o asloptions.o aslparseop.o aslpld.o \
	aslpredef.o aslprepkg.o aslprintf.o aslprune.o aslresource.o \
	aslrestype1.o aslrestype1i.o aslrestype2.o aslrestype2d.o \
	aslrestype2e.o aslrestype2q.o aslrestype2s.o aslrestype2w.o \
	aslstartup.o aslstubs.o asltransform.o asltree.o aslutils.o asluuid.o \
	aslwalks.o aslxref.o aslxrefout.o cmfsize.o cvcompiler.o cvdisasm.o \
	cvparser.o dbfileio.o dmbuffer.o dmcstyle.o dmdeferred.o dmextern.o \
	dmnames.o dmopcode.o dmresrc.o dmresrcl.o dmresrcl2.o dmresrcs.o \
	dmrestag.o dmswitch.o dmtable.o dmtables.o dmtbdump.o dmtbinfo.o \
	dmutils.o dmwalk.o dsargs.o dscontrol.o dsfield.o dsobject.o \
	dsopcode.o dspkginit.o dsutils.o dswexec.o dswload.o dswload2.o \
	dswscope.o dswstate.o dtcompile.o dtexpress.o dtfield.o dtio.o \
	dtparserlex.o dtparserparse.o dtsubtable.o dttable.o dttable1.o \
	dttable2.o dttemplate.o dtutils.o exconcat.o exconvrt.o excreate.o \
	exdump.o exmisc.o exmutex.o exnames.o exoparg1.o exoparg2.o exoparg3.o \
	exoparg6.o exprep.o exregion.o exresnte.o exresolv.o exresop.o  \
	exstore.o exstoren.o exstorob.o exsystem.o exutils.o getopt.o  \
	nsaccess.o nsalloc.o nsdump.o nsnames.o nsobject.o nsparse.o  \
	nssearch.o nsutils.o nswalk.o nsxfobj.o osunixxf.o prexpress.o \
	prmacros.o prparserlex.o prparserparse.o prscan.o prutils.o psargs.o \
	psloop.o psobject.o psopcode.o psopinfo.o psparse.o psscope.o pstree.o \
	psutils.o pswalk.o tbdata.o tbfadt.o tbinstal.o tbprint.o tbutils.o \
	tbxface.o tbxfload.o utaddress.o utalloc.o utascii.o utbuffer.o \
	utcache.o utcopy.o utdebug.o utdecode.o utdelete.o uterror.o utexcep.o \
	utglobal.o uthex.o utinit.o utlock.o utmath.o utmisc.o utmutex.o \
	utnonansi.o utobject.o utownerid.o utpredef.o utresdecode.o utresrc.o \
	utstate.o utstring.o utstrsuppt.o utstrtoul64.o utuuid.o utxface.o \
	utxferror.o
SRCS = $(OBJS:.o=.c)

ACPI_CMN_SRC		= $(SRC)/common/acpica

# Source used only by iasl
ASL_COMPILER		= compiler
ACPICA_DEBUGGER		= debugger
# Source used by kernel module and iasl
ACPICA_DISASSEMBLER	= $(ACPI_CMN_SRC)/disassembler
ACPICA_DISPATCHER	= $(ACPI_CMN_SRC)/dispatcher
ACPICA_EXECUTER		= $(ACPI_CMN_SRC)/executer
ACPICA_NAMESPACE	= $(ACPI_CMN_SRC)/namespace
ACPICA_PARSER		= $(ACPI_CMN_SRC)/parser
ACPICA_TABLES		= $(ACPI_CMN_SRC)/tables
ACPICA_UTILITIES	= $(ACPI_CMN_SRC)/utilities
# Source used by other programs and iasl
ACPICA_COMMON		= ../common

VPATH = $(ACPICA_DEBUGGER):$(ACPICA_DISASSEMBLER):\
	$(ACPICA_DISPATCHER):$(ACPICA_EXECUTER):$(ACPICA_NAMESPACE):\
	$(ACPICA_PARSER):$(ACPICA_TABLES):$(ACPICA_UTILITIES):\
	$(ACPICA_COMMON):$(ACPICA_OSL)

INTERMEDIATES = \
	aslcompiler.y \
	aslcompilerlex.c \
	aslcompilerparse.c \
	dtparserlex.c \
	dtparserparse.c \
	prparserlex.c \
	prparserparse.c \
	aslcompiler.y.h \
	dtparser.y.h \
	prparser.y.h

CERRWARN += -_gcc=-Wno-unused-function

CPPFLAGS += -I$(SRC)/uts/intel/sys/acpi -DACPI_ASL_COMPILER -I. \
	-D__EXTENSIONS__ -DACPI_USE_STANDARD_HEADERS \
	-DACPI_USE_SYSTEM_CLIBRARY

LEX_C_FILES = aslcompilerlex.c dtparserlex.c prparserlex.c
YACC_C_FILES = aslcompilerparse.c dtparserparse.c prparserparse.c
YACC_H_FILES = aslcompiler.y.h dtparser.y.h prparser.y.h
YACC_FILES = $(YACC_C_FILES) $(YACC_H_FILES)

aslcompilerlex.c aslcompilerparse.c aslcompiler.y.h := PARSER = AslCompiler
aslcompilerlex.c aslcompilerparse.c aslcompiler.y.h := LY_BASE = aslcompiler

dtparserlex.c dtparserparse.c dtparser.y.h := PARSER = DtParser
dtparserlex.c dtparserparse.c dtparser.y.h := LY_BASE = dtparser

prparserlex.c prparserparse.c prparser.y.h := PARSER = PrParser
prparserlex.c prparserparse.c prparser.y.h := LY_BASE = prparser

$(LEX_C_FILES) := LEXFILE = $(LY_BASE).l
$(LEX_C_FILES) := LEXFILE = $(LY_BASE).l
$(YACC_FILES) := YTABC = $(LY_BASE)parse.c

GM4FLAGS = -P

LFLAGS = -i -s

.KEEP_STATE:

all: $(YACC_FILES) .WAIT $(PROG)

aslcompiler.y: aslparser.y
	$(GM4) $(GM4FLAGS) aslparser.y > $@

$(LEX_C_FILES):
	$(FLEX) $(LFLAGS) -P$(PARSER) -o $@ $(LEXFILE)

%parse.h: %parse.c

%parse.c %.y.h: %.y
	_suffix=`echo $@ | awk -F. '{print $$NF}'` && \
	_d=`mktemp -d $(PARSER).XXXXXX` && \
	(cd $$_d && $(BISON) -y -v -d -p$(PARSER) ../$(LY_BASE).y) && \
	mv $$_d/y.tab.$$_suffix $@; \
	_ret=$$?; \
	rm -rf $$_d; \
	exit $$_ret

$(PROG): $(OBJS)
	$(LINK.c) -o $@ $(OBJS) ../common/acpi.a $(LDLIBS)
	$(POST_PROCESS)

install: all $(ROOTUSRSBINPROG)

clean:
	$(RM) $(OBJS) $(INTERMEDIATES) $(PROG)
	$(RM) -r AslCompiler.?????? DtParser.?????? PrParser.??????

lint:	lint_SRCS

include ../../Makefile.targ
