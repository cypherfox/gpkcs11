# Process this file with automake to create a Makefile.in
#
# Copyright (c) TC TrustCenter for Security in Data Networks GmbH - all rights reserved
# RCSID:       $Id$
# Source:      $Source$
# Last Delta:  $Date$ $Revision$ $Author$
# State:       $State$ $Locker$
# NAME:        Makefile.am
# SYNOPSIS:    -
# DESCRIPTION: -
# FILES:       -
# SEE/ALSO:    -
# AUTHOR:      lbe
# BUGS: *      -
# HISTORY:     $Log$
# HISTORY:     Revision 1.8  2000/02/07 14:04:08  lbe
# HISTORY:     release 0.6 and clean up of files
# HISTORY:
# HISTORY:     Revision 1.7  2000/01/12 15:01:53  lbe
# HISTORY:     changes for clean CoMMi on linux
# HISTORY:
# HISTORY:     Revision 1.6  2000/01/07 10:24:43  lbe
# HISTORY:     introduce changes for release
# HISTORY:
# HISTORY:     Revision 1.5  1999/11/24 17:15:25  lbe
# HISTORY:     fix3 incomplete incl. path
# HISTORY:
# HISTORY:     Revision 1.4  1999/11/24 16:41:45  lbe
# HISTORY:     fix2 incomplete incl. path
# HISTORY:
# HISTORY:     Revision 1.3  1999/11/24 16:40:50  lbe
# HISTORY:     fix incomplete incl. path
# HISTORY:
# HISTORY:     Revision 1.2  1999/10/06 07:57:20  lbe
# HISTORY:     solved netscape symbol clash problem
# HISTORY:
# HISTORY:     Revision 1.1  1999/08/02 12:40:21  lbe
# HISTORY:     more CVS cleanup
# HISTORY:
#
bin_PROGRAMS= cryptsh

lib_LTLIBRARIES = libcrproxy.la

noinst_HEADERS= pkcs11_guile.h request.h pkcs11_proxy.h

cryptsh_SOURCES= pkcs11_guile.c @EXTRA_CRYPTSH_SOURCES@ # GenCert.c 
cryptsh_LDADD= @DLOPEN@ @GUILE_LIBS@ -lm -lgcc
cryptsh_DEPENDENCIES = @EXTRA_CRYPTSH_OBJECTS@

EXTRA_cryptsh_SOURCES= utils.c request.c

libcrproxy_la_SOURCES = pkcs11_proxy.c error.c

EXTRA_DIST =  pkcs11_init.scm pkcs11_serv.scm do_cryptsh.scm rassoc.scm create_cert.scm \
              list_objects.scm find_objects.scm

INCLUDES = @INCLUDES@ -I$(top_srcdir)/libgpkcs11

error.c: ../libgpkcs11/error.c
	ln -s ../libgpkcs11/error.c .
