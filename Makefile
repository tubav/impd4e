#$$LIC$$
#
# $Id: Makefile.in 996 2009-03-19 18:14:44Z csc $
# 
# Makefile
SHELL = /bin/bash

srcdir = .
top_srcdir = .
prefix = /usr/local
exec_prefix = ${prefix}

bindir = ${exec_prefix}/bin
sbindir = ${exec_prefix}/sbin
libexecdir = ${exec_prefix}/libexec
datadir = ${datarootdir}
datarootdir = ${prefix}/share
libdir = ${exec_prefix}/lib
mandir = ${datarootdir}/man
includedir = ${prefix}/include
top_builddir = .

INSTALL = /usr/bin/install -c
INSTALL_PROGRAM = ${INSTALL}
INSTALL_DATA = ${INSTALL} -m 644
INSTALL_SCRIPT = ${INSTALL}
INSTALL_HEADER = $(INSTALL_DATA)
CC = gcc
EXEEXT = 
OBJEXT = o
PACKAGE = impd4e
VERSION = 1.0
install_sh = @install_sh@
OPENSSL = @OPENSSL@

DEFS = -DHAVE_CONFIG_H 
# define the max amount of interfaces that can be used in parallel (default=10)
DEFS += -DMAX_INTERFACES=10 

CPPFLAGS = 
LDFLAGS =  -L/usr/local/lib
LIBS =  -lpcap -lipfix -lmisc
CCOPT = -Wall -g
INCLS = -I. -I/usr/local/include
CFLAGS = $(CCOPT) $(INCLS) $(DEFS)

TARGETS = impd4e
OBJS = bobhash.o hash.o hsieh.o main.o twmx.o
DEPHDR = bobhash.h hash.h hsieh.h main.h templates.h twmx.h
CLEANFILES = $(OBJS) $(TARGETS) 

all: $(TARGETS)

clean:
	rm -f $(CLEANFILES)

distclean:
	rm -f $(CLEANFILES) $(DHPARAMS) Makefile

install:
	@[ -d ${libdir} ] || (mkdir -p ${libdir}; chmod 755 ${libdir})
	$(INSTALL_DATA) libipfix.a ${libdir}/
	$(INSTALL_DATA) $(LIBMISCDIR)/libmisc.a ${libdir}/
	@[ -d ${includedir} ] || (mkdir -p ${includedir}; chmod 755 ${includedir})
	$(INSTALL_HEADER) ipfix*.h ${includedir}/

impd4e: $(OBJS)
	$(CC) -o impd4e $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) $(OBJS) $(LIBS)

.c.o:
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $<
