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
## HISTORY:     Revision 1.8  2000/07/31 17:41:09  lbe
## HISTORY:     lockdown for release of protected auth path
## HISTORY:
## HISTORY:     Revision 1.7  2000/06/05 11:43:42  lbe
## HISTORY:     tcsc token breakup, return pSlotCount in SlotList, code for event handling deactivated
## HISTORY:
## HISTORY:     Revision 1.6  2000/05/12 13:13:15  lbe
## HISTORY:     zwischen durchmal B-)
## HISTORY:
## HISTORY:     Revision 1.5  2000/02/07 14:04:10  lbe
## HISTORY:     release 0.6 and clean up of files
## HISTORY:
## HISTORY:     Revision 1.4  1999/11/25 16:46:51  lbe
## HISTORY:     moved all lib version defines into the conf.h
## HISTORY:
## HISTORY:     Revision 1.3  1999/11/02 13:47:17  lbe
## HISTORY:     change of structures and bug fix in slot.c, add more files for tcsc_token: emptyfuncs and general_data
## HISTORY:
## HISTORY:     Revision 1.2  1999/10/06 07:57:22  lbe
## HISTORY:     solved netscape symbol clash problem
## HISTORY:
## HISTORY:     Revision 1.1  1999/08/02 12:40:25  lbe
## HISTORY:     more CVS cleanup
## HISTORY:
## 

# create libraries with libtool
lib_LTLIBRARIES = libgpkcs11.la libplogger.la libdummy.la # libcrypto_dummy.la

noinst_HEADERS = dll_wrap.h error.h hash.h init.h \
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

