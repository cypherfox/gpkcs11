## Process this file with automake to create a Makefile.in
##
## This file is part of GPKCS11. 
## (c) 1999-2001 TC TrustCenter GmbH 
##
## GPKCS11 is free software; you can redistribute it and/or modify
## it under the terms of the GNU General Public License as published by
## the Free Software Foundation; either version 2, or (at your option)
## any later version.
##  
## GPKCS11 is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
## GNU General Public License for more details.
##  
## You should have received a copy of the GNU General Public License
## along with GPKCS11; see the file COPYING.  If not, write to the Free
## Software Foundation, 59 Temple Place - Suite 330, Boston, MA 02111, USA.  
## 
## RCSID:       $Id$
## Source:      $Source$
## Last Delta:  $Date$ $Revision$ $Author$
## State:       $State$ $Locker$
## NAME:        Makefile.am
## SYNOPSIS:    -
## DESCRIPTION: Inputfile for automake, process to generate Makefile.in
## FILES:       -
## SEE/ALSO:    -
## AUTHOR:      lbe
## BUGS:        -
## 

if USE_OWN_GDBM
GDBM_DIR = gdbm-1.8.0
else
GDBM_DIR = 
endif

if USE_GUILE
CRYPTSH_DIR = cryptsh
else
CRYPTSH_DIR = 
endif

if USE_CEAY_TOKEN
CEAY_TOKEN_DIR = ceay_token
else 
CEAY_TOKEN_DIR =
endif

if USE_TCSC_TOKEN
TCSC_TOKEN_DIR = tcsc_token
else
TCSC_TOKEN_DIR = 
endif

if USE_DATA_TOKEN
DATA_TOKEN_DIR = data_token
else
DATA_TOKEN_DIR =
endif


SUBDIRS = $(GDBM_DIR) libgpkcs11 $(CRYPTSH_DIR) docs etc $(CEAY_TOKEN_DIR) tests # $(TCSC_TOKEN_DIR) $(DATA_TOKEN_DIR)

# noinst_PROGRAMS =  test_pkcs11 pkcs_run

#test_pkcs11_SOURCES= pkcs11_test.c
#test_pkcs11_LDADD= @DLOPEN@ @DLPREOPEN@ ./ceay_token/libceay_tok.la

#pkcs_run_SOURCES= pkcs_run.c

# noinst_JAVA = 

ACLOCAL = aclocal @PREFIX_ACLOCAL@


JAVAC = @JAVAC@
CLASSPATH_COMMAND = @CLASSPATH_COMMAND@

%.class: %.java
	$(JAVAC) $(CLASSPATH_COMMAND) $<

################################################################
# jim-jar: create a jar-file for SmartUpdate.
# unfortunately we cannot automate this for Win-NT
# urgently an autoconf for the use with VC-5.0 needs to be looked at.

#NT_BUILD=release
NT_BUILD=finalcheck

INSTALL_PACK_DIR := @PACKAGE@
INSTALL_ARCH_DIR := @PACKAGE@/@TARGET_ARCH@

PKCS_SO_LIB = libgpkcs11.so

$(PKCS_SO_LIB)::
	$(MAKE) -C libgpkcs11

$(INSTALL_PACK_DIR)::
	if test ! -d $(INSTALL_PACK_DIR) ; \
         then mkdir $(INSTALL_PACK_DIR) ; fi

$(INSTALL_ARCH_DIR): $(INSTALL_PACK_DIR)
	if test ! -d $(INSTALL_ARCH_DIR) ; \
         then mkdir $(INSTALL_ARCH_DIR) ; fi

dll-set: $(INSTALL_ARCH_DIR) ConfFile.class 
	for i in $(TOKEN_TARGETS); do $(MAKE) -C $$i dll-set ; done
	cp libgpkcs11/.libs/$(PKCS_SO_LIB) $(INSTALL_ARCH_DIR)/$(PKCS_SO_LIB)
	cp ConfFile.class $(INSTALL_PACK_DIR)

nt-copy::
	if test ! -d $(INSTALL_PACK_DIR) ; then mkdir $(INSTALL_PACK_DIR)/windows32 ; fi
	find $(top-builddir) -name "*.dll" -follow -exec cp {} $(INSTALL_PACK_DIR/windows32 \;

jim-jar: dll-set nt-copy
	@echo "Warning: before calling this target, create a Certificate first!"
	cp gpkcs11_install.js  $(INSTALL_PACK_DIR)
	signtool -Z"gpkcs11.jar" -i"gpkcs11_install.js" \
                 -k"Lutz' Dummy Object Sign Cert" $(INSTALL_PACK_DIR)

################################################################

EXTRA_DIST =  README.defines conf.h.win32 gpkcs11_install.js ConfFile.java \
              gdbm-1.8.0/dbminit.c gdbm-1.8.0/delete.c gdbm-1.8.0/fetch.c  \
              gdbm-1.8.0/store.c gdbm-1.8.0/seq.c gdbm-1.8.0/close.c       \
              gdbm-1.8.0/dbmopen.c gdbm-1.8.0/dbmdelete.c                  \
              gdbm-1.8.0/dbmfetch.c gdbm-1.8.0/dbmstore.c                  \
              gdbm-1.8.0/dbmseq.c gdbm-1.8.0/dbmclose.c                    \
              gdbm-1.8.0/dbmdirfno.c gdbm-1.8.0/dbmpagfno.c                \
              gdbm-1.8.0/dbmrdonly.c gdbm-1.8.0/gdbmopen.c                 \
              gdbm-1.8.0/gdbmdelete.c gdbm-1.8.0/gdbmfetch.c               \
              gdbm-1.8.0/gdbmstore.c gdbm-1.8.0/gdbmclose.c                \
              gdbm-1.8.0/gdbmreorg.c gdbm-1.8.0/gdbmseq.c                  \
              gdbm-1.8.0/gdbmsync.c gdbm-1.8.0/gdbmerrno.c                 \
              gdbm-1.8.0/gdbmfdesc.c gdbm-1.8.0/gdbmexists.c               \
              gdbm-1.8.0/gdbmsetopt.c gdbm-1.8.0/bucket.c                  \
              gdbm-1.8.0/falloc.c gdbm-1.8.0/findkey.c gdbm-1.8.0/global.c \
              gdbm-1.8.0/hash.c gdbm-1.8.0/update.c gdbm-1.8.0/version.c   \
              gdbm-1.8.0/testdbm.c gdbm-1.8.0/testndbm.c                   \
              gdbm-1.8.0/testgdbm.c gdbm-1.8.0/gdbmdefs.h                  \
              gdbm-1.8.0/extern.h gdbm-1.8.0/gdbmerrno.h                   \
              gdbm-1.8.0/systems.h gdbm-1.8.0/dbm.h gdbm-1.8.0/ndbm.h      \
              gdbm-1.8.0/gdbmconst.h gdbm-1.8.0/proto.h gdbm-1.8.0/COPYING \
              gdbm-1.8.0/ChangeLog gdbm-1.8.0/Makefile.in                  \
              gdbm-1.8.0/README gdbm-1.8.0/gdbm.3 gdbm-1.8.0/gdbm.texinfo  \
              gdbm-1.8.0/config.log gdbm-1.8.0/NEWS gdbm-1.8.0/INSTALL     \
              gdbm-1.8.0/gdbm.proto gdbm-1.8.0/gdbm.proto2                 \
              gdbm-1.8.0/conv2gdbm.c gdbm-1.8.0/configure                  \
              gdbm-1.8.0/configure.in gdbm-1.8.0/getopt.c                  \
              gdbm-1.8.0/getopt.h gdbm-1.8.0/samp1.cc                      \
              gdbm-1.8.0/autoconf.h.in gdbm-1.8.0/install-sh               \
              gdbm-1.8.0/mkinstalldirs gdbm-1.8.0/config.guess             \
              gdbm-1.8.0/config.sub gdbm-1.8.0/aclocal.m4                  \
              gdbm-1.8.0/ltconfig gdbm-1.8.0/ltmain.sh                     \
              gdbm-1.8.0/autoconf.h gdbm-1.8.0/libtool                     \
              gdbm-1.8.0/config.status gdbm-1.8.0/Makefile                 \
              gdbm-1.8.0/gdbm.h \
              windows/gpkcs11/gpkcs11.dsw \
              windows/gpkcs11/ceay_token/ceay_token.dsp \
              windows/gpkcs11/libgpkcs11/libgpkcs11.dsp \
              windows/gpkcs11/gdbm/gdbm.dsp \
              windows/gpkcs11/openssl/openssl.dsp \
              windows/gpkcs11/gpkcs11_test/gpkcs11_test.dsp \
              windows/gpkcs11/gpkcs11_test/gpkcs11_test.c \
              win_gdbm/README win_gdbm/autoconf.h win_gdbm/autoconf.h.in   \
              win_gdbm/conv2gdbm.c win_gdbm/gdbm.h win_gdbm/systems.h      \
              win_gdbm/gdbm.mak win_gdbm/gdbmreorg.c win_gdbm/samp1.cc
