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
## DESCRIPTION: -
## FILES:       -
## SEE/ALSO:    -
## AUTHOR:      lbe
## BUGS:        -
## 

# create libraries with libtool 
lib_LTLIBRARIES = libceay_tok.la

libceay_tok_la_SOURCES  = ceay_token.c ctok_encrypt.c ctok_decrypt.c ctok_mem.c TCCGenKey.c cryptdb.c

libceay_tok_la_LDFLAGS = -module -version-info 1:1 -L./

libceay_tok_la_LIBADD = -L${top_builddir}/gdbm-1.8.0/.libs -lgdbm \
                        -L${top_builddir}/libgpkcs11/.libs -lgpkcs11 \
                        @LIBS@

noinst_HEADERS = ceay_token.h ctok_mem.h cryptdb.h TCCGenKey.h

INCLUDES = -I. -I.. -I$(srcdir) -I@OPENSSL_INCLUDES@ -I$(top_srcdir)/gdbm-1.8.0 -I$(top_builddir)/gdbm-1.8.0 -I$(top_srcdir)/libgpkcs11 @INCLUDES@

EXTRA_DIST= shared_openssl-0.9.4.diff symbol_transform.pl symbol_list.txt 
