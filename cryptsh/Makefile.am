# Process this file with automake to create a Makefile.in
#
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
## DESCRIPTION: input file for automake, process to generate Makefile.in
## FILES:       -
## SEE/ALSO:    -
## AUTHOR:      lbe
## BUGS:        -

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
