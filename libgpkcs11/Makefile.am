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
lib_LTLIBRARIES = libgpkcs11.la libplogger.la libdummy.la # libcrypto_dummy.la

noinst_HEADERS = dll_wrap.h pkcs11_error.h hash.h init.h \
                 internal.h mutex.h obj_defaults.h \
                 objects.h pkcs11_logger.h \
                 slot.h utils.h fkt_dummy.h thread.h

include_HEADERS = cryptoki.h pkcs11f.h pkcs11t.h pkcs11.h 

libgpkcs11_la_SOURCES = getInfo.c     init.c        objects.c     sessions.c \
                        hash.c        mutex.c       other_fkts.c  slot.c     \
                        digest.c      random.c      key_mng.c     encrypt.c  \
                        decrypt.c     sign.c        dual.c        thread.c \
                        verify.c      error.c       utils.c       

libgpkcs11_la_LDFLAGS= -module -version-info 2:1
libgpkcs11_la_LIBADD= @DLOPEN@ -L../ceay_token -lm -ldl 

#     ### secondary libraries ###

#libcrypto_dummy_la_SOURCES = crypto_dummy.c

libplogger_la_SOURCES = pkcs11_logger.c

libdummy_la_SOURCES = fkt_dummy.c   

###### extra stuff that does not trigger a automake reaction but is just included ###

TC_LIB_VERSION = @TC_LIB_VERSION@

INCLUDES = @INCLUDES@ -I. -I.. -I$(srcdir) 

DEFS := @DEFS@ -D_REENTRANT 

