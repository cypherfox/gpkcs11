## Process this file with automake to create a Makefile.in
##
## Copyright (c) TC TrustCenter for Security in Data Networks GmbH - all rights reserved
## RCSID:       $Id$
## Source:      $Source$
## Last Delta:  $Date$ $Revision$ $Author$
## State:       $State$ $Locker$
## NAME:        Makefile.am
## SYNOPSIS:    -
## DESCRIPTION: -
## FILES:       -
## SEE/ALSO:    -
## AUTHOR:      lbe
## BUGS: *      -
## HISTORY:     $Log$
## HISTORY:     Revision 1.14  2000/09/19 09:14:49  lbe
## HISTORY:     write flag for pin change onto SC, support Auth Pin path
## HISTORY:
## HISTORY:     Revision 1.13  2000/07/24 15:43:53  lbe
## HISTORY:     added the files for snacc usage
## HISTORY:
## HISTORY:     Revision 1.12  2000/02/07 14:04:08  lbe
## HISTORY:     release 0.6 and clean up of files
## HISTORY:
## HISTORY:     Revision 1.11  2000/01/12 15:01:53  lbe
## HISTORY:     changes for clean CoMMi on linux
## HISTORY:
## HISTORY:     Revision 1.10  1999/12/03 09:35:43  jzu
## HISTORY:     logging-bug fixed
## HISTORY:
## HISTORY:     Revision 1.9  1999/12/01 13:44:45  lbe
## HISTORY:     debug build system for missing central lib directory and debug afchine changes
## HISTORY:
## HISTORY:     Revision 1.8  1999/11/25 16:46:49  lbe
## HISTORY:     moved all lib version defines into the conf.h
## HISTORY:
## HISTORY:     Revision 1.7  1999/11/02 13:47:14  lbe
## HISTORY:     change of structures and bug fix in slot.c, add more files for tcsc_token: emptyfuncs and general_data
## HISTORY:
## HISTORY:     Revision 1.6  1999/10/08 13:00:09  lbe
## HISTORY:     release version 0.5.5
## HISTORY:
## HISTORY:     Revision 1.5  1999/10/06 07:57:18  lbe
## HISTORY:     solved netscape symbol clash problem
## HISTORY:
## HISTORY:     Revision 1.4  1999/06/16 09:46:01  lbe
## HISTORY:     reorder files
## HISTORY:
## HISTORY:     Revision 1.3  1999/06/10 08:30:17  lbe
## HISTORY:     clean up INCLUDES handling
## HISTORY:
## HISTORY:     Revision 1.2  1999/06/08 10:17:56  lbe
## HISTORY:     change from gdbm-1.7.3 to gdbm-1.8.0
## HISTORY:
## HISTORY:     Revision 1.1  1999/06/04 15:16:56  lbe
## HISTORY:     change to libtool/automake complete (except for __umoddi prob)
## HISTORY:
## 

LCRYPT_VERSION= 0.9.4
LCRYPT_MINOR= 9
LCRYPT_MAJOR= 0

# create libraries with libtool 
lib_LTLIBRARIES = libceay_tok.la

libceay_tok_la_SOURCES  = ceay_token.c ctok_encrypt.c ctok_decrypt.c ctok_mem.c TCCGenKey.c cryptdb.c

libceay_tok_la_LDFLAGS = -module -version-info 1:1 -L./

libceay_tok_la_LIBADD = -L${top_builddir}/gdbm-1.8.0/.libs -lgdbm \
                        -L${top_builddir}/libgpkcs11/.libs -lgpkcs11 -lcrypto \
                        @LIBS@
libceay_tok_la_DEPENDENCIES = libcrypto.so

noinst_HEADERS = ceay_token.h ctok_mem.h cryptdb.h TCCGenKey.h

INCLUDES = -I. -I.. -I$(srcdir) -I$(srcdir)/openssl/include -I$(top_srcdir)/gdbm-1.8.0 -I$(top_builddir)/gdbm-1.8.0 -I$(top_srcdir)/libgpkcs11 @INCLUDES@

install-exec-local: 
	$(INSTALL_PROGRAM) -m 755 libcrypto.so.$(LCRYPT_VERSION) $(libdir)/libcrypto.so.$(LCRYPT_VERSION)
	rm -f $(libdir)/libcrypto.so.$(LCRYPT_MAJOR).$(LCRYPT_MINOR)
	ln -s libcrypto.so.$(LCRYPT_VERSION) $(libdir)/libcrypto.so.$(LCRYPT_MAJOR).$(LCRYPT_MINOR)
	rm -f $(libdir)/libcrypto.so.$(LCRYPT_MAJOR)
	ln -s libcrypto.so.$(LCRYPT_VERSION) $(libdir)/libcrypto.so.$(LCRYPT_MAJOR)
	rm -f $(libdir)/libcrypto.so
	ln -s libcrypto.so.$(LCRYPT_VERSION) $(libdir)/libcrypto.so

libcrypto.so: libcrypto.so.$(LCRYPT_VERSION)
	rm -f libcrypto.so
	ln -s libcrypto.so.$(LCRYPT_VERSION) libcrypto.so

INSTALL_PACK_DIR := $(top_builddir)/@PACKAGE@/@TARGET_ARCH@

dll-set: libcrypto.so $(LTLIBRARIES) 
	cp libcrypto.so $(INSTALL_PACK_DIR)
	cp .libs/libceay_tok.so $(INSTALL_PACK_DIR)

libcrypto.so.$(LCRYPT_VERSION):
	cd $(srcdir)/openssl && make clean && sh ./config -shared --prefix=$(prefix) \
            --openssldir=$(prefix)/ssl && make shlib && \
            cp shlib_dir/libcrypto.so* ../ && make clean 

clean-local:
	rm -f libcrypto.*
	make -C openssl clean	

EXTRA_DIST= shared_openssl-0.9.4.diff symbol_transform.pl symbol_list.txt 
