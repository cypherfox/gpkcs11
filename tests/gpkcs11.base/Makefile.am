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
# BUGS:        -
# 

#global options to the workings of automake

LDFLAGS= @LDFLAGS@ -L$(top_builddir)/libgpkcs11/.libs
INCLUDES= @INCLUDES@ -I$(top_builddir) -I$(top_srcdir)/libgpkcs11
DEFS=@DEFS@
 
#CCLD= @CCLD@
#CXXLD= @CXXLD@
 
# fill this with the programms that are generated
check_PROGRAMS = c_setpin test_rsa test_decrypt test_sign t_session_obj_delete1 \
	t_session_obj_delete2 # run_cipher

LDADD = -lgpkcs11 -lpthread

test_rsa_SOURCES = test_rsa.c

test_decrypt_SOURCES = test_decrypt.c

test_sign_SOURCES = test_sign.c

c_setpin_SOURCES = c_setpin.c

t_session_obj_delete1_SOURCES = t_session_obj_delete1.c

t_session_obj_delete2_SOURCES = t_session_obj_delete2.c

# run_cipher_SOURCE = run_cipher.c

EXTRA_DIST = C_SetPin.exp test_rsa.exp test_decrypt.exp


