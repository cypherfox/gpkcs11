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
## HISTORY:     Revision 1.7  2000/09/19 09:15:05  lbe
## HISTORY:     write flag for pin change onto SC, support Auth Pin path
## HISTORY:
## HISTORY:     Revision 1.6  2000/07/24 15:44:28  lbe
## HISTORY:     added the files for snacc usage
## HISTORY:
## HISTORY:     Revision 1.5  2000/06/05 11:43:57  lbe
## HISTORY:     tcsc token breakup, return pSlotCount in SlotList, code for event handling deactivated
## HISTORY:
## HISTORY:     Revision 1.4  2000/03/15 19:22:00  lbe
## HISTORY:     first try for tc-pkcs11 0.6.1: now works multi-app clean with tc_scard and can handle private decrypt in tcsc_token
## HISTORY:
## HISTORY:     Revision 1.3  2000/03/08 09:59:09  lbe
## HISTORY:     fix SIGBUS in cryptdb, improve readeability for C_FindObject log output
## HISTORY:
## HISTORY:     Revision 1.2  2000/02/07 14:04:12  lbe
## HISTORY:     release 0.6 and clean up of files
## HISTORY:
## HISTORY:     Revision 1.1  2000/01/31 18:09:07  lbe
## HISTORY:     lockdown prior to win_gdbm change
## HISTORY:
## 

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


