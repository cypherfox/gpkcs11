/* -*- c -*- */
/*
 * This file is part of GPKCS11. 
 * (c) 1999 TC TrustCenter for Security in DataNetworks GmbH 
 *
 * GPKCS11 is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *  
 * GPKCS11 is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *  
 * You should have received a copy of the GNU General Public License
 * along with TC-PKCS11; see the file COPYING.  If not, write to the Free
 * Software Foundation, 59 Temple Place - Suite 330, Boston, MA 02111, USA.  
 */
/*
 * RCSID:       $Id$
 * Source:      $Source$
 * Last Delta:  $Date$ $Revision$ $Author$
 * State:       $State$ $Locker$
 * NAME:        ceay_token.c
 * SYNOPSIS:    -
 * DESCRIPTION: -
 * FILES:       -
 * SEE/ALSO:    -
 * AUTHOR:      lbe
 * BUGS: *      -
 * HISTORY:     $Log$
 * HISTORY:     Revision 1.1.1.1  2000/10/15 16:49:03  cypherfox
 * HISTORY:     import of gpkcs11-0.7.2, first version for SourceForge
 * HISTORY:
 * HISTORY:     Revision 1.16  2000/07/24 15:43:53  lbe
 * HISTORY:     added the files for snacc usage
 * HISTORY:
 * HISTORY:     Revision 1.15  2000/05/12 13:13:12  lbe
 * HISTORY:     zwischen durchmal B-)
 * HISTORY:
 * HISTORY:     Revision 1.14  2000/03/08 09:59:05  lbe
 * HISTORY:     fix SIGBUS in cryptdb, improve readeability for C_FindObject log output
 * HISTORY:
 * HISTORY:     Revision 1.13  2000/02/08 16:12:45  lbe
 * HISTORY:     last changes from beta testers
 * HISTORY:
 * HISTORY:     Revision 1.12  2000/01/31 18:08:59  lbe
 * HISTORY:     lockdown prior to win_gdbm change
 * HISTORY:
 * HISTORY:     Revision 1.11  2000/01/07 10:24:42  lbe
 * HISTORY:     introduce changes for release
 * HISTORY:
 * HISTORY:     Revision 1.10  1999/12/10 16:58:40  jzu
 * HISTORY:     new data-token (2)
 * HISTORY:
 * HISTORY:     Revision 1.9  1999/12/01 13:44:45  lbe
 * HISTORY:     debug build system for missing central lib directory and debug afchine changes
 * HISTORY:
 * HISTORY:     Revision 1.8  1999/12/01 11:37:21  lbe
 * HISTORY:     write back changes by afchine
 * HISTORY:
 * HISTORY:     Revision 1.7  1999/11/25 16:46:49  lbe
 * HISTORY:     moved all lib version defines into the conf.h
 * HISTORY:
 * HISTORY:     Revision 1.6  1999/11/02 13:47:14  lbe
 * HISTORY:     change of structures and bug fix in slot.c, add more files for tcsc_token: emptyfuncs and general_data
 * HISTORY:
 * HISTORY:     Revision 1.5  1999/10/08 13:00:09  lbe
 * HISTORY:     release version 0.5.5
 * HISTORY:
 * HISTORY:     Revision 1.4  1999/10/06 07:57:18  lbe
 * HISTORY:     solved netscape symbol clash problem
 * HISTORY:
 * HISTORY:     Revision 1.3  1999/07/20 17:39:57  lbe
 * HISTORY:     fix bug in gdbm Makefile: there is not allways an 'install' around
 * HISTORY:
 * HISTORY:     Revision 1.2  1999/06/16 09:46:01  lbe
 * HISTORY:     reorder files
 * HISTORY:
 * HISTORY:     Revision 1.1  1999/06/04 14:58:36  lbe
 * HISTORY:     change to libtool/automake complete (except for __umoddi prob)
 * HISTORY:
 * HISTORY:     Revision 1.24  1999/03/18 14:10:20  lbe
 * HISTORY:     entered patches from externals
 * HISTORY:
 * HISTORY:     Revision 1.23  1999/03/01 14:36:42  lbe
 * HISTORY:     merged changes from the weekend
 * HISTORY:
 * HISTORY:     Revision 1.22  1999/02/18 11:12:42  lbe
 * HISTORY:     added support for CKM_RSA_X_509 and did some additional work on the tests
 * HISTORY:
 * HISTORY:     Revision 1.21  1999/01/22 08:35:31  lbe
 * HISTORY:     full build with new perisistant storage complete
 * HISTORY:
 * HISTORY:     Revision 1.20  1999/01/19 12:19:35  lbe
 * HISTORY:     first release lockdown
 * HISTORY:
 * HISTORY:     Revision 1.19  1999/01/14 16:29:34  lbe
 * HISTORY:     include statement for TCCGenKey changes
 * HISTORY:     so dependency can checked by make.
 * HISTORY:
 * HISTORY:     Revision 1.18  1999/01/13 16:13:59  lbe
 * HISTORY:     clampdown for persistent storage complete
 * HISTORY:
 * HISTORY:     Revision 1.17  1999/01/11 16:20:51  lbe
 * HISTORY:     *** empty log message ***
 * HISTORY:
 * HISTORY:     Revision 1.16  1998/12/07 13:18:46  lbe
 * HISTORY:     TC_free von parametern für Zeile und Datei befreit.
 * HISTORY:
 * HISTORY:     Revision 1.15  1998/12/02 10:46:24  lbe
 * HISTORY:     work on persistent storage.
 * HISTORY:
 * HISTORY:     Revision 1.14  1998/11/26 10:14:52  lbe
 * HISTORY:     added persistent storage
 * HISTORY:
 * HISTORY:     Revision 1.13  1998/11/13 10:10:27  lbe
 * HISTORY:     added persistent storage.
 * HISTORY:
 * HISTORY:     Revision 1.12  1998/11/10 09:43:29  lbe
 * HISTORY:     hash iter geaendert: hashtabelle braucht nicht mehr an fkts uebergeben werden.
 * HISTORY:
 * HISTORY:     Revision 1.11  1998/11/04 17:12:36  lbe
 * HISTORY:     debug-lockdown
 * HISTORY:
 * HISTORY:     Revision 1.10  1998/11/03 16:00:16  lbe
 * HISTORY:     auto-lockdown
 * HISTORY:
 * HISTORY:     Revision 1.9  1998/10/19 10:56:09  lbe
 * HISTORY:     check in before change to des_ecb code (buggy)
 * HISTORY:
 * HISTORY:     Revision 1.8  1998/10/12 10:00:14  lbe
 * HISTORY:     clampdown
 * HISTORY:
 * HISTORY:     Revision 1.7  1998/09/11 14:06:46  lbe
 * HISTORY:     lockdown for some dangerous hacks
 * HISTORY:
 * HISTORY:     Revision 1.6  1998/08/05 09:01:06  lbe
 * HISTORY:     *** empty log message ***
 * HISTORY:
 * HISTORY:     Revision 1.5  1998/07/30 15:29:43  lbe
 * HISTORY:     Win32 Port
 * HISTORY:
 * HISTORY:     Revision 1.4  1998/07/23 15:16:24  lbe
 * HISTORY:     works
 * HISTORY:
 * HISTORY:     Revision 1.3  1998/07/13 15:36:34  lbe
 * HISTORY:     Funktionen für SSL vervollständigt
 * HISTORY:
 * HISTORY:     Revision 1.2  1998/07/06 09:41:31  lbe
 * HISTORY:     DES funktionen hinzugefügt
 * HISTORY:
 * HISTORY:     Revision 1.1  1998/07/02 17:06:47  lbe
 * HISTORY:     Initial revision
 * HISTORY:
 */
 
static char RCSID[]="$Id$";
const char* ceay_token_c_version(){return RCSID;}

/* Stupid Windows-isms */
#ifndef CK_I_library_build
#define  CK_I_library_build
#endif /* CK_I_library_build */

#include "ceay_token.h"
#include "objects.h"
#include "error.h"
#include "mutex.h"
#include "init.h"
#include "ctok_mem.h"

#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <errno.h>

/* to stop execution for debugging */
#ifndef CK_Win32
#include <signal.h>
#include <sys/types.h>
#include <unistd.h>
#endif /* !CK_Win32 */

/* for bn.h */
#include <stdio.h>

/* random generator */
#include <openssl/rand.h>

/* En-,Decrypt, Sign and Verify */
#include <openssl/rc4.h>

/* digesting */
#include <openssl/md2.h>

/* key manipulation */
#include <openssl/evp.h>
#include <openssl/x509.h>

/* TC-Utils RSA key gen */
#include "TCCGenKey.h"

/* #define CK_I_RSA_PKCS_SIZE_OFFSET 11 */
/* this variable is defined in the SSL routines, but needed to in here */
int des_rw_mode;

/* {{{ Global constants for template/object creation */
CK_CHAR CK_Ceay_empty_str[] = "";
CK_BYTE CK_Ceay_empty_bytes[] = "";
CK_BBOOL CK_Ceay_true = TRUE;
CK_BBOOL CK_Ceay_false = FALSE;
CK_ULONG CK_Ceay_ulEmpty = 0;
/* }}} */
/* {{{ Key Templates */

static CK_OBJECT_CLASS CK_I_secret_key_class = CKO_SECRET_KEY;
static CK_OBJECT_CLASS CK_I_public_key_class = CKO_PUBLIC_KEY;
static CK_OBJECT_CLASS CK_I_private_key_class = CKO_PRIVATE_KEY;

/* Schlüsselgrößen */
static CK_BYTE CK_I_eight      =  8;
static CK_BYTE CK_I_sixteen    = 16;
static CK_BYTE CK_I_twentyfour = 24; 
static CK_BYTE CK_I_fortyeight = 48;
 
/* {{{ Generic Secret Key Template */
/* Template of default object (that are not global defaults) */
static CK_KEY_TYPE CK_I_generic_keyType = CKK_GENERIC_SECRET;
static CK_CHAR CK_I_generic_secret_label[] = "An generic secret key object";

/* empty key with the proper defaults and correct number of entries 
 * for a generic secret key object 
 */
static CK_ATTRIBUTE CK_I_generic_empty_key[] ={
  {CKA_CLASS, &CK_I_secret_key_class, sizeof(CK_I_secret_key_class)},
  {CKA_KEY_TYPE, &CK_I_generic_keyType, sizeof(CK_I_generic_keyType)},
  {CKA_LABEL, CK_I_generic_secret_label, sizeof(CK_I_generic_secret_label)},
  {CKA_TOKEN, &CK_Ceay_true, sizeof(CK_Ceay_true)},
  {CKA_ENCRYPT, &CK_Ceay_true, sizeof(CK_Ceay_true)},
  {CKA_DECRYPT, &CK_Ceay_true, sizeof(CK_Ceay_true)},
  {CKA_LOCAL, &CK_Ceay_true, sizeof(CK_Ceay_true)},
  {CKA_DERIVE, &CK_Ceay_false, sizeof(CK_Ceay_false)},
  {CKA_SENSITIVE, &CK_Ceay_true, sizeof(CK_Ceay_true)},
  {CKA_ALWAYS_SENSITIVE, &CK_Ceay_true, sizeof(CK_Ceay_true)},
  {CKA_EXTRACTABLE, &CK_Ceay_true, sizeof(CK_Ceay_true)},
  {CKA_NEVER_EXTRACTABLE, &CK_Ceay_false, sizeof(CK_Ceay_false)},
};

static CK_I_OBJ_PTR CK_I_generic_empty_key_obj = NULL_PTR;

#define CK_I_generic_empty_key_count 12

/* }}} */
/* {{{ SSL3_PRE_MASTER Template */
/* Template of default object (that are not global defaults) */
static CK_KEY_TYPE CK_I_ssl3_pre_master_keyType = CKK_GENERIC_SECRET;
static CK_CHAR CK_I_ssl3_pre_master_label[] = "An SSL3 Pre-Master secret key object";
static CK_VERSION ssl_version = {3,0};

/* empty key with the proper defaults and correct number of entries 
 * for a ssl3_pre_master key object 
 */
static CK_ATTRIBUTE CK_I_ssl3_pre_master_empty_key[] ={
  {CKA_CLASS, &CK_I_secret_key_class, sizeof(CK_I_secret_key_class)},
  {CKA_KEY_TYPE, &CK_I_ssl3_pre_master_keyType, sizeof(CK_I_ssl3_pre_master_keyType)},
  {CKA_LABEL, CK_I_ssl3_pre_master_label, sizeof(CK_I_ssl3_pre_master_label)},
  {CKA_TOKEN, &CK_Ceay_true, sizeof(CK_Ceay_true)},
  {CKA_ENCRYPT, &CK_Ceay_true, sizeof(CK_Ceay_true)},
  {CKA_DECRYPT, &CK_Ceay_true, sizeof(CK_Ceay_true)},
  {CKA_LOCAL, &CK_Ceay_true, sizeof(CK_Ceay_true)},
  {CKA_DERIVE, &CK_Ceay_false, sizeof(CK_Ceay_false)},
  {CKA_SENSITIVE, &CK_Ceay_true, sizeof(CK_Ceay_true)},
  {CKA_ALWAYS_SENSITIVE, &CK_Ceay_true, sizeof(CK_Ceay_true)},
  {CKA_EXTRACTABLE, &CK_Ceay_true, sizeof(CK_Ceay_true)},
  {CKA_NEVER_EXTRACTABLE, &CK_Ceay_false, sizeof(CK_Ceay_false)},
  {CKA_VALUE, NULL_PTR, 0},
  {CKA_VALUE_LEN, &CK_I_fortyeight, sizeof(CK_I_fortyeight)},
  {CKA_SSL_VERSION, &ssl_version, sizeof(ssl_version)},
};

static CK_I_OBJ_PTR  CK_I_ssl3_pre_master_empty_key_obj = NULL_PTR;

#define CK_I_ssl3_pre_master_empty_key_count 15

/* }}} */
/* {{{ DES Template */
/* Template of default object (that are not global defaults) */
static CK_KEY_TYPE CK_I_des_keyType = CKK_DES;
static CK_CHAR CK_I_des_label[] = "An DES secret key object";

/* empty key with the proper defaults and correct number of entries 
 * for a des key object 
 */
static CK_ATTRIBUTE CK_I_des_empty_key[] ={
  {CKA_CLASS, &CK_I_secret_key_class, sizeof(CK_I_secret_key_class)},
  {CKA_KEY_TYPE, &CK_I_des_keyType, sizeof(CK_I_des_keyType)},
  {CKA_LABEL, CK_I_des_label, sizeof(CK_I_des_label)},
  {CKA_TOKEN, &CK_Ceay_true, sizeof(CK_Ceay_true)},
  {CKA_ENCRYPT, &CK_Ceay_true, sizeof(CK_Ceay_true)},
  {CKA_DECRYPT, &CK_Ceay_true, sizeof(CK_Ceay_true)},
  {CKA_LOCAL, &CK_Ceay_true, sizeof(CK_Ceay_true)},
  {CKA_DERIVE, &CK_Ceay_false, sizeof(CK_Ceay_false)},
  {CKA_SENSITIVE, &CK_Ceay_true, sizeof(CK_Ceay_true)},
  {CKA_ALWAYS_SENSITIVE, &CK_Ceay_true, sizeof(CK_Ceay_true)},
  {CKA_EXTRACTABLE, &CK_Ceay_true, sizeof(CK_Ceay_true)},
  {CKA_NEVER_EXTRACTABLE, &CK_Ceay_false, sizeof(CK_Ceay_false)},
  {CKA_VALUE, NULL_PTR, 0},
  {CKA_VALUE_LEN, &CK_I_eight, sizeof(CK_I_eight)},
};

static CK_I_OBJ_PTR CK_I_des_empty_key_obj = NULL_PTR;

#define CK_I_des_empty_key_count 14

/* }}} */
/* {{{ DES3 Template */
/* Template of default object (that are not global defaults) */
static CK_KEY_TYPE CK_I_des3_keyType = CKK_DES3;
static CK_CHAR CK_I_des3_label[] = "An Trippel DES secret key object";

/* empty key with the proper defaults and correct number of entries 
 * for a des key object 
 */
static CK_ATTRIBUTE CK_I_des3_empty_key[] ={
  {CKA_CLASS, &CK_I_secret_key_class, sizeof(CK_I_secret_key_class)},
  {CKA_KEY_TYPE, &CK_I_des3_keyType, sizeof(CK_I_des3_keyType)},
  {CKA_LABEL, CK_I_des3_label, sizeof(CK_I_des3_label)},
  {CKA_TOKEN, &CK_Ceay_true, sizeof(CK_Ceay_true)},
  {CKA_ENCRYPT, &CK_Ceay_true, sizeof(CK_Ceay_true)},
  {CKA_DECRYPT, &CK_Ceay_true, sizeof(CK_Ceay_true)},
  {CKA_LOCAL, &CK_Ceay_true, sizeof(CK_Ceay_true)},
  {CKA_DERIVE, &CK_Ceay_false, sizeof(CK_Ceay_false)},
  {CKA_SENSITIVE, &CK_Ceay_true, sizeof(CK_Ceay_true)},
  {CKA_ALWAYS_SENSITIVE, &CK_Ceay_true, sizeof(CK_Ceay_true)},
  {CKA_EXTRACTABLE, &CK_Ceay_true, sizeof(CK_Ceay_true)},
  {CKA_NEVER_EXTRACTABLE, &CK_Ceay_false, sizeof(CK_Ceay_false)},
  {CKA_VALUE, NULL_PTR, 0},
  {CKA_VALUE_LEN, &CK_I_twentyfour, sizeof(CK_I_twentyfour)},
};

static CK_I_OBJ_PTR CK_I_des3_empty_key_obj = NULL_PTR;

#define CK_I_des3_empty_key_count 14

/* }}} */
/* {{{ IDEA Template */
/* Template of default object (that are not global defaults) */
static CK_KEY_TYPE CK_I_idea_keyType = CKK_IDEA;
static CK_CHAR CK_I_idea_label[] = "An IDEA secret key object";

/* empty key with the proper defaults and correct number of entries 
 * for a des key object 
 */
static CK_ATTRIBUTE CK_I_idea_empty_key[] ={
  {CKA_CLASS, &CK_I_secret_key_class, sizeof(CK_I_secret_key_class)},
  {CKA_KEY_TYPE, &CK_I_idea_keyType, sizeof(CK_I_idea_keyType)},
  {CKA_LABEL, CK_I_idea_label, sizeof(CK_I_idea_label)},
  {CKA_TOKEN, &CK_Ceay_true, sizeof(CK_Ceay_true)},
  {CKA_ENCRYPT, &CK_Ceay_true, sizeof(CK_Ceay_true)},
  {CKA_DECRYPT, &CK_Ceay_true, sizeof(CK_Ceay_true)},
  {CKA_LOCAL, &CK_Ceay_true, sizeof(CK_Ceay_true)},
  {CKA_DERIVE, &CK_Ceay_false, sizeof(CK_Ceay_false)},
  {CKA_SENSITIVE, &CK_Ceay_true, sizeof(CK_Ceay_true)},
  {CKA_ALWAYS_SENSITIVE, &CK_Ceay_true, sizeof(CK_Ceay_true)},
  {CKA_EXTRACTABLE, &CK_Ceay_true, sizeof(CK_Ceay_true)},
  {CKA_NEVER_EXTRACTABLE, &CK_Ceay_false, sizeof(CK_Ceay_false)},
  {CKA_VALUE, NULL_PTR, 0},
  {CKA_VALUE_LEN, &CK_I_sixteen, sizeof(CK_I_sixteen)},
};

static CK_I_OBJ_PTR CK_I_idea_empty_key_obj = NULL_PTR;

#define CK_I_idea_empty_key_count 14

/* }}} */
/* {{{ RC4 Template */
/* Template of default object (that are not global defaults) */
static CK_KEY_TYPE CK_I_rc4_keyType = CKK_RC4;
static CK_CHAR CK_I_rc4_label[] = "An RC4 secret key object";

/* empty key with the proper defaults and correct number of entries 
 * for a rc4 key object 
 */
static CK_ATTRIBUTE CK_I_rc4_empty_key[] ={
  {CKA_CLASS, &CK_I_secret_key_class, sizeof(CK_I_secret_key_class)},
  {CKA_KEY_TYPE, &CK_I_rc4_keyType, sizeof(CK_I_rc4_keyType)},
  {CKA_LABEL, CK_I_rc4_label, sizeof(CK_I_rc4_label)},
  {CKA_TOKEN, &CK_Ceay_true, sizeof(CK_Ceay_true)},
  {CKA_ENCRYPT, &CK_Ceay_true, sizeof(CK_Ceay_true)},
  {CKA_DECRYPT, &CK_Ceay_true, sizeof(CK_Ceay_true)},
  {CKA_LOCAL, &CK_Ceay_true, sizeof(CK_Ceay_true)},
  {CKA_DERIVE, &CK_Ceay_false, sizeof(CK_Ceay_false)},
  {CKA_SENSITIVE, &CK_Ceay_true, sizeof(CK_Ceay_true)},
  {CKA_ALWAYS_SENSITIVE, &CK_Ceay_true, sizeof(CK_Ceay_true)},
  {CKA_EXTRACTABLE, &CK_Ceay_true, sizeof(CK_Ceay_true)},
  {CKA_NEVER_EXTRACTABLE, &CK_Ceay_false, sizeof(CK_Ceay_false)},
  {CKA_VALUE, NULL_PTR, 0},
  {CKA_VALUE_LEN, &CK_Ceay_ulEmpty, sizeof(CK_Ceay_ulEmpty)},
};

static CK_I_OBJ_PTR CK_I_rc4_empty_key_obj = NULL_PTR;

#define CK_I_rc4_empty_key_count 14

/* }}} */
/* {{{ RC2 Template */
/* Template of default object (that are not global defaults) */
static CK_KEY_TYPE CK_I_rc2_keyType = CKK_RC2;
static CK_CHAR CK_I_rc2_label[] = "An RC2 secret key object";

/* empty key with the proper defaults and correct number of entries 
 * for a rc2 key object 
 */
static CK_ATTRIBUTE CK_I_rc2_empty_key[] ={
  {CKA_CLASS, &CK_I_secret_key_class, sizeof(CK_I_secret_key_class)},
  {CKA_KEY_TYPE, &CK_I_rc2_keyType, sizeof(CK_I_rc2_keyType)},
  {CKA_LABEL, CK_I_rc2_label, sizeof(CK_I_rc2_label)},
  {CKA_TOKEN, &CK_Ceay_true, sizeof(CK_Ceay_true)},
  {CKA_ENCRYPT, &CK_Ceay_true, sizeof(CK_Ceay_true)},
  {CKA_DECRYPT, &CK_Ceay_true, sizeof(CK_Ceay_true)},
  {CKA_LOCAL, &CK_Ceay_true, sizeof(CK_Ceay_true)},
  {CKA_DERIVE, &CK_Ceay_false, sizeof(CK_Ceay_false)},
  {CKA_SENSITIVE, &CK_Ceay_true, sizeof(CK_Ceay_true)},
  {CKA_ALWAYS_SENSITIVE, &CK_Ceay_true, sizeof(CK_Ceay_true)},
  {CKA_EXTRACTABLE, &CK_Ceay_true, sizeof(CK_Ceay_true)},
  {CKA_NEVER_EXTRACTABLE, &CK_Ceay_false, sizeof(CK_Ceay_false)},
  {CKA_VALUE, NULL_PTR, 0},
  {CKA_VALUE_LEN, &CK_Ceay_ulEmpty, sizeof(CK_Ceay_ulEmpty)},
};

static CK_I_OBJ_PTR CK_I_rc2_empty_key_obj = NULL_PTR;

#define CK_I_rc2_empty_key_count 14
/* }}} */
/* {{{ RSA Template */

/* Template of default object (that are not global defaults) */
static CK_KEY_TYPE CK_I_rsa_keyType = CKK_RSA;
static CK_CHAR CK_I_rsa_public_label[] = "An RSA public key object";
static CK_CHAR CK_I_rsa_private_label[] = "An RSA private key object";
static CK_BYTE CK_I_rsa_default_public_exp[] = {3};

/* empty key with the proper defaults and correct number of entries 
 * for a rsa key object 
 */
static CK_ATTRIBUTE CK_I_rsa_empty_public_key[] ={
  {CKA_CLASS, &CK_I_public_key_class, sizeof(CK_I_public_key_class)},
  {CKA_TOKEN, &CK_Ceay_true, sizeof(CK_Ceay_true)},
  {CKA_LABEL, CK_I_rsa_public_label, sizeof(CK_I_rsa_public_label)},
  {CKA_DERIVE, &CK_Ceay_false, sizeof(CK_Ceay_false)},
  {CKA_LOCAL, &CK_Ceay_true, sizeof(CK_Ceay_true)},
  {CKA_ENCRYPT, &CK_Ceay_true, sizeof(CK_Ceay_true)},
  {CKA_KEY_TYPE, &CK_I_rsa_keyType, sizeof(CK_I_rsa_keyType)},
  {CKA_VERIFY, &CK_Ceay_true, sizeof(CK_Ceay_true)},
  {CKA_VERIFY_RECOVER, &CK_Ceay_true, sizeof(CK_Ceay_true)},
  {CKA_WRAP, &CK_Ceay_true, sizeof(CK_Ceay_true)},
  {CKA_PUBLIC_EXPONENT, &CK_I_rsa_default_public_exp, sizeof(CK_I_rsa_default_public_exp)},
};

static CK_ATTRIBUTE CK_I_rsa_empty_private_key[] ={
  {CKA_CLASS, &CK_I_private_key_class, sizeof(CK_I_private_key_class)},
  {CKA_TOKEN, &CK_Ceay_true, sizeof(CK_Ceay_true)},
  {CKA_LABEL, CK_I_rsa_private_label, sizeof(CK_I_rsa_private_label)},
  {CKA_DERIVE, &CK_Ceay_false, sizeof(CK_Ceay_false)},
  {CKA_LOCAL, &CK_Ceay_true, sizeof(CK_Ceay_true)},
  {CKA_KEY_TYPE, &CK_I_rsa_keyType, sizeof(CK_I_rsa_keyType)},
  {CKA_DECRYPT, &CK_Ceay_true, sizeof(CK_Ceay_true)},
  {CKA_SIGN, &CK_Ceay_true, sizeof(CK_Ceay_true)},
  {CKA_SIGN_RECOVER, &CK_Ceay_true, sizeof(CK_Ceay_true)},
  {CKA_UNWRAP, &CK_Ceay_true, sizeof(CK_Ceay_true)},
  {CKA_SENSITIVE, &CK_Ceay_true, sizeof(CK_Ceay_true)},
  {CKA_EXTRACTABLE, &CK_Ceay_false, sizeof(CK_Ceay_false)},
  {CKA_ALWAYS_SENSITIVE, &CK_Ceay_true, sizeof(CK_Ceay_true)},
  {CKA_NEVER_EXTRACTABLE, &CK_Ceay_true, sizeof(CK_Ceay_true)},
  {CKA_PUBLIC_EXPONENT, &CK_I_rsa_default_public_exp, sizeof(CK_I_rsa_default_public_exp)},
};

#define CK_I_rsa_empty_public_key_count 11
#define CK_I_rsa_empty_private_key_count 15

static CK_I_OBJ_PTR CK_I_rsa_empty_public_key_obj = NULL_PTR;
static CK_I_OBJ_PTR CK_I_rsa_empty_private_key_obj = NULL_PTR;

/* }}} */
/* {{{ DSA Template */

/* Template of default object (that are not global defaults) */
static CK_KEY_TYPE CK_I_DSA_keyType = CKK_DSA;
static CK_CHAR CK_I_DSA_public_label[] = "An DSA public key object";
static CK_CHAR CK_I_DSA_private_label[] = "An DSA private key object";

/* empty key with the proper defaults and correct number of entries 
 * for a DSA key object 
 */
static CK_ATTRIBUTE CK_I_dsa_empty_public_key[] ={
  {CKA_CLASS, &CK_I_public_key_class, sizeof(CK_I_public_key_class)},
  {CKA_TOKEN, &CK_Ceay_true, sizeof(CK_Ceay_true)},
  {CKA_LABEL, CK_I_DSA_public_label, sizeof(CK_I_DSA_public_label)},
  {CKA_LOCAL, &CK_Ceay_true, sizeof(CK_Ceay_true)},
  {CKA_KEY_TYPE, &CK_I_DSA_keyType, sizeof(CK_I_DSA_keyType)},
  {CKA_VERIFY, &CK_Ceay_true, sizeof(CK_Ceay_true)},
};

static CK_ATTRIBUTE CK_I_dsa_empty_private_key[] ={
  {CKA_CLASS, &CK_I_private_key_class, sizeof(CK_I_private_key_class)},
  {CKA_TOKEN, &CK_Ceay_true, sizeof(CK_Ceay_true)},
  {CKA_LABEL, CK_I_DSA_private_label, sizeof(CK_I_DSA_private_label)},
  {CKA_LOCAL, &CK_Ceay_true, sizeof(CK_Ceay_true)},
  {CKA_KEY_TYPE, &CK_I_DSA_keyType, sizeof(CK_I_DSA_keyType)},
  {CKA_SIGN, &CK_Ceay_true, sizeof(CK_Ceay_true)},
  {CKA_SENSITIVE, &CK_Ceay_true, sizeof(CK_Ceay_true)},
  {CKA_EXTRACTABLE, &CK_Ceay_true, sizeof(CK_Ceay_true)},
  {CKA_ALWAYS_SENSITIVE, &CK_Ceay_true, sizeof(CK_Ceay_true)},
  {CKA_NEVER_EXTRACTABLE, &CK_Ceay_false, sizeof(CK_Ceay_false)},
};

#define CK_I_dsa_empty_public_key_count 6
#define CK_I_dsa_empty_private_key_count 10

static CK_I_OBJ_PTR CK_I_dsa_empty_public_key_obj = NULL_PTR;
static CK_I_OBJ_PTR CK_I_dsa_empty_private_key_obj = NULL_PTR;

/* }}} */

/* }}} */

static const unsigned char *salt[]= {
  (const unsigned char *)"A",
  (const unsigned char *)"BB",
  (const unsigned char *)"CCC"
};

/* {{{ Mechanism Infos */
/* ### mechanism information ### */

/* Mechanism List */
CK_MECHANISM_TYPE ceay_mechanism_list[CK_I_CEAY_MECHANISM_NUM] = {
  CKM_RSA_PKCS_KEY_PAIR_GEN,           /*  1 */
  CKM_RSA_PKCS,                        /*  2 */
  CKM_RSA_X_509,                       /*  3 */
#ifdef USE_ALL_CRYPT
  CKM_SHA_1,                           /*  4 */
  CKM_MD5,                             /*  5 */
  CKM_MD2,                             /*  6 */
  CKM_DSA_KEY_PAIR_GEN,                /*  7 */
  CKM_DSA,                             /*  8 */
  CKM_RC4_KEY_GEN,                     /*  9 */
  CKM_RC2_KEY_GEN,                     /* 10 */
  CKM_DES_KEY_GEN,                     /* 11 */
  CKM_DES3_KEY_GEN,                    /* 12 */
  CKM_IDEA_KEY_GEN,                    /* 13 */
  CKM_SSL3_PRE_MASTER_KEY_GEN,         /* 14 */
  CKM_SSL3_MASTER_KEY_DERIVE,          /* 15 */
  CKM_SSL3_KEY_AND_MAC_DERIVE,         /* 16 */
  CKM_SSL3_MD5_MAC,                    /* 17 */
  CKM_SSL3_SHA1_MAC,                   /* 18 */
  CKM_RC2_ECB,                         /* 19 */
  CKM_RC2_CBC,                         /* 20 */
  CKM_RC4,                             /* 21 */
  CKM_DES_ECB,                         /* 22 */
  CKM_DES_CBC,                         /* 23 */
  CKM_IDEA_ECB,                        /* 24 */
  CKM_IDEA_CBC,                        /* 25 */
  CKM_DES3_ECB,                        /* 26 */
  CKM_DES3_CBC,                        /* 27 */
  CKM_SHA1_RSA_PKCS,                   /* 28 */
  CKM_DSA_SHA1,                        /* 29 */
#endif
};

/* Mechanism Infos: ulMinKeySize, ulMaxKeySize, flags */
CK_MECHANISM_INFO ceay_mechanism_info_list[CK_I_CEAY_MECHANISM_NUM]= {  
  { 508, 4096, CKF_GENERATE_KEY_PAIR },                       /* CKM_RSA_PKCS_KEY_PAIR_GEN */
  { 508, 4096, (CKF_ENCRYPT|CKF_DECRYPT|CKF_SIGN|CKF_SIGN_RECOVER|CKF_VERIFY|
		CKF_VERIFY_RECOVER|CKF_WRAP|CKF_UNWRAP) },    /* CKM_RSA_PKCS */  
  { 508, 4096, (CKF_ENCRYPT|CKF_DECRYPT|CKF_SIGN|CKF_SIGN_RECOVER|CKF_VERIFY|
		CKF_VERIFY_RECOVER|CKF_WRAP|CKF_UNWRAP) },    /* CKM_RSA_X_509 */  
#ifdef USE_ALL_CRYPT
  {   0,    0, CKF_DIGEST },                                  /* CKM_SHA_1 */
  {   0,    0, CKF_DIGEST },                                  /* CKM_MD5 */
  {   0,    0, CKF_DIGEST },                                  /* CKM_MD2 */
  { 512, 1024, CKF_GENERATE_KEY_PAIR },                       /* CKM_DSA_KEY_PAIR_GEN */
  { 512, 1024, (CKF_SIGN|CKF_VERIFY) },                       /* CKM_DSA */  
  {   8, 2048, CKF_GENERATE },                                /* CKM_RC4_KEY_GEN, key sizes in bits*/
  {   8, 1024, CKF_GENERATE},                                 /* CKM_RC2_KEY_GEN, key size in bits */
  {   0,    0, CKF_GENERATE},                                 /* CKM_DES_KEY_GEN */
  {   0,    0, CKF_GENERATE},                                 /* CKM_DES3_KEY_GEN */
  {   0,    0, CKF_GENERATE},                                 /* CKM_IDEA_KEY_GEN */
  {  48,   48, CKF_GENERATE},                                 /* CKM_SSL3_PRE_MASTER_KEY_GEN */
  {  48,   48, CKF_DERIVE},                                   /* CKM_SSL3_MASTER_KEY_DERIVE */
  {   0,    0, CKF_DERIVE},                                   /* CKM_SSL3_KEY_AND_MAC_DERIVE */
  {   0,    0, CKF_SIGN|CKF_VERIFY},                          /* CKM_SSL3_MD5_MAC */
  {   0,    0, CKF_SIGN|CKF_VERIFY},                          /* CKM_SSL3_SHA1_MAC */
  {   1, 1024, CKF_ENCRYPT|CKF_DECRYPT|CKF_WRAP|CKF_UNWRAP},  /* CKM_RC2_ECB */
  {   1, 1024, CKF_ENCRYPT|CKF_DECRYPT},                      /* CKM_RC2_CBC */
  {   8, 2048, CKF_ENCRYPT|CKF_DECRYPT|CKF_WRAP|CKF_UNWRAP }, /* CKM_RC4 */
  {   0,    0, CKF_ENCRYPT|CKF_DECRYPT|CKF_WRAP|CKF_UNWRAP},  /* CKM_DES_ECB */
  {   0,    0, CKF_ENCRYPT|CKF_DECRYPT},                      /* CKM_DES_CBC */
  {   0,    0, CKF_ENCRYPT|CKF_DECRYPT|CKF_WRAP|CKF_UNWRAP},  /* CKM_IDEA_ECB */
  {   0,    0, CKF_ENCRYPT|CKF_DECRYPT},                      /* CKM_IDEA_CBC */
  {   0,    0, CKF_ENCRYPT|CKF_DECRYPT|CKF_WRAP|CKF_UNWRAP},  /* CKM_DES3_ECB */
  {   0,    0, CKF_ENCRYPT|CKF_DECRYPT},                      /* CKM_DES3_CBC */
  { 508, 4096, CKF_SIGN|CKF_VERIFY },                         /* CKM_SHA1_RSA_PKCS */
  { 512, 1024, CKF_SIGN|CKF_VERIFY },                         /* CKM_DSA_SHA1 */
#endif
};
/* }}} */

/* used in OpenSession to get the number of opened sessions */
CK_TOKEN_INFO Ceay_token_info;

/* {{{ CI_Ceay_GetTokenInfo */

CK_DEFINE_FUNCTION(CK_RV, CI_Ceay_GetTokenInfo)(
  CK_I_SLOT_DATA_PTR slot_data,
  CK_TOKEN_INFO_PTR pInfo    /* receives the token information */
)
{
  /* We don't have a HW clock, lets supply a sane value */
  memcpy((pInfo->utcTime), "                ", 16);  

  return CKR_OK;
}

/* }}} */
/* {{{ CI_Ceay_GetMechanismList */

CK_DEFINE_FUNCTION(CK_RV, CI_Ceay_GetMechanismList)(
  CK_MECHANISM_TYPE_PTR pMechanismList,  /* gets mech. array */
  CK_ULONG_PTR          pulCount         /* gets # of mechs. */
)
{
  CK_RV rv = CKR_OK;
  int i;

  if(pMechanismList == NULL_PTR) /* only query the number of slots */
    {
      *pulCount= CK_I_CEAY_MECHANISM_NUM;
       CI_VarLogEntry("CI_Ceay_GetMechanismList", 
		      "computing needed size of List-Array (%lu)", rv, 0,
		      CK_I_CEAY_MECHANISM_NUM);
      return rv;
    }
  
  if (*pulCount < CK_I_CEAY_MECHANISM_NUM)
    {
      *pulCount= CK_I_CEAY_MECHANISM_NUM;
      rv = CKR_BUFFER_TOO_SMALL;
      CI_LogEntry("CI_Ceay_GetMechanismList", "checking size of List-Array", rv, 0);
      return rv;
    }
  
  /* copy the mechanims list */
  for(i=0;i<CK_I_CEAY_MECHANISM_NUM;i++)
    pMechanismList[i] = ceay_mechanism_list[i];
  
  *pulCount= CK_I_CEAY_MECHANISM_NUM;

  return rv;
}

/* }}} */
/* {{{ CI_Ceay_GetMechanismInfo */

CK_DEFINE_FUNCTION(CK_RV, CI_Ceay_GetMechanismInfo)(
  CK_MECHANISM_TYPE     type,    /* type of mechanism */
  CK_MECHANISM_INFO_PTR pInfo    /* receives mechanism info */
)
{
  int i;

  /* find the position in the array */
  for(i=0; i<CK_I_CEAY_MECHANISM_NUM;i++)
    if(ceay_mechanism_list[i] == type) break;
  
  if(i==CK_I_CEAY_MECHANISM_NUM) return CKR_MECHANISM_INVALID;
  
  /* copy the correct mechanism info */
      
  pInfo->ulMinKeySize = ceay_mechanism_info_list[i].ulMinKeySize;
  pInfo->ulMaxKeySize = ceay_mechanism_info_list[i].ulMaxKeySize;
  pInfo->flags = ceay_mechanism_info_list[i].flags;
  
  return CKR_OK;
}

/* }}} */
/* {{{ CI_Ceay_InitToken */
CK_DEFINE_FUNCTION(CK_RV, CI_Ceay_InitToken)(
  CK_CHAR_PTR    pPin,      /* the SO's initial PIN */
  CK_ULONG       ulPinLen,  /* length in bytes of the PIN */
  CK_CHAR_PTR    pLabel     /* 32-byte token label (blank padded) */
)
{
  CK_RV rv = CKR_OK;
  CK_CHAR_PTR db_file;
  CK_I_CRYPT_DB_PTR cryptdb;

  /* check if there is a session open with the token */
  if( (IMPL_DATA(session_list) != NULL_PTR) &&
      (IMPL_DATA(session_list)->entries >0))
      {
	rv = CKR_GENERAL_ERROR;
	CI_LogEntry("CI_Ceay_InitToken", 
		    "Session open with token", rv ,3);
	return rv;
      }
  
  /* TODO: if the cache is loaded remove it wholesale. (there are no objects 
   * looking at it) 
   */
  /* for now just fail if there is a persistent cache, as the removal of objects from the
   * application object list is not working properly 
   */
  if(IMPL_DATA(persistent_cache) != NULL_PTR)
    {
      CI_LogEntry("CI_Ceay_InitToken", "cache already loaded", rv ,3);

      /* remove cache */

      return CKR_GENERAL_ERROR;
    }

  /* open/create the persistent storage */
  rv = CI_GetConfigString(CEAY_CONFIG_SECTION, "PersistentDataFile",&db_file);
  if(rv != CKR_OK)
    {
      CI_LogEntry("CI_Ceay_InitToken","Error reading field from config file.",rv,0);      
      return rv;
    }

  cryptdb = CDB_Open(db_file);
  if(cryptdb == NULL_PTR)
    { 
      rv = CKR_GENERAL_ERROR;
      CI_LogEntry("CI_Ceay_TokenObjDelete","Could not open/create the database file", 
		  rv ,0);
      return rv;
    }

  /* remove all objects */
  rv = CDB_DeleteAllObjects(cryptdb);
  if (rv != CKR_OK)
    {
      CI_LogEntry("CI_Ceay_TokenObjDelete","Setting PIN failed", 
		  rv ,0);
      TC_free(cryptdb);
      return rv;
    }

  /* save SO PIN to cryptdb */
  rv = CDB_SetPin(cryptdb, TRUE, pPin, ulPinLen);
  if (rv != CKR_OK)
    {
      CI_LogEntry("CI_Ceay_TokenObjDelete","Setting PIN failed", 
		  rv ,0);
      TC_free(cryptdb);
      return rv;
    }

  /* set the disabled-flag */
  /* set an empty user pin */
  /* set user pin trial count */
  
  rv = CDB_Close(cryptdb);
  if (rv != CKR_OK)
    {
      CI_LogEntry("CI_Ceay_TokenObjDelete","Closing of database failed.", 
		  rv ,0);
      TC_free(cryptdb);
      return rv;
    }
  
  TC_free(cryptdb);

  return CKR_OK;
}
/* }}} */

/* {{{ CI_Ceay_FinalizeToken */
CK_DEFINE_FUNCTION(CK_RV, CI_Ceay_FinalizeToken)(
  CK_I_SLOT_DATA_PTR slot_data
)
{
  if(CK_I_generic_empty_key_obj != NULL_PTR)
    CI_ObjDestroyObj(CK_I_generic_empty_key_obj);
  if(CK_I_ssl3_pre_master_empty_key_obj != NULL_PTR)
    CI_ObjDestroyObj(CK_I_ssl3_pre_master_empty_key_obj);
  if(CK_I_des_empty_key_obj != NULL_PTR)
    CI_ObjDestroyObj(CK_I_des_empty_key_obj);
  if(CK_I_des3_empty_key_obj != NULL_PTR)
    CI_ObjDestroyObj(CK_I_des3_empty_key_obj);
  if(CK_I_rc2_empty_key_obj != NULL_PTR)
    CI_ObjDestroyObj(CK_I_rc2_empty_key_obj);
  if(CK_I_idea_empty_key_obj != NULL_PTR)
    CI_ObjDestroyObj(CK_I_idea_empty_key_obj);
  if(CK_I_rc4_empty_key_obj != NULL_PTR)
    CI_ObjDestroyObj(CK_I_rc4_empty_key_obj);
  if(CK_I_rsa_empty_public_key_obj != NULL_PTR)
    CI_ObjDestroyObj(CK_I_rsa_empty_public_key_obj);
  if(CK_I_rsa_empty_private_key_obj != NULL_PTR)
    CI_ObjDestroyObj(CK_I_rsa_empty_private_key_obj);

  /* clear the space of the random number generator */
  CI_Ceay_RAND_cleanup();
  
  return CKR_OK;
}
/* }}} */

/* {{{ CI_Ceay_InitPIN */
CK_DEFINE_FUNCTION(CK_RV, CI_Ceay_InitPIN)(
 CK_I_SESSION_DATA_PTR session_data,  
 CK_CHAR_PTR       pPin,      /* the normal user's PIN */
 CK_ULONG          ulPinLen   /* length in bytes of the PIN */
)
{
  CK_RV rv = CKR_OK;
  CK_CHAR_PTR db_file;
  CK_I_CRYPT_DB_PTR cryptdb;

  CI_LogEntry("CI_Ceay_InitPIN","InitPin start.....", rv ,0);

  /* open/create the persistent storage */
  rv = CI_GetConfigString(CEAY_CONFIG_SECTION, "PersistentDataFile",&db_file);
  if(rv != CKR_OK)
    {
      CI_LogEntry("CI_Ceay_InitPIN","Error reading field from config file.",rv,0);      
      return rv;
    }

  cryptdb = CDB_Open(db_file);
  if(cryptdb == NULL_PTR)
    { 
      rv = CKR_GENERAL_ERROR;
      CI_LogEntry("CI_Ceay_InitPIN","Could not open/create the database file", 
		  rv ,0);
      return rv;
    }

  /* save normal user's PIN to cryptdb */
  rv = CDB_NewPin(cryptdb, FALSE, NULL, 0, pPin, ulPinLen);

  if (rv != CKR_OK)
    {
      CI_LogEntry("CI_Ceay_InitPIN","Setting PIN failed", rv ,0);
      TC_free(cryptdb);
      return rv;
    }
  else
    {
      CI_LogEntry("CI_Ceay_InitPIN","InitPin success.....", rv ,0);
    }

  /* set the disabled-flag */
  /* set an empty user pin */
  /* set user pin trial count */
  
  rv = CDB_Close(cryptdb);
  if (rv != CKR_OK)
    {
      CI_LogEntry("CI_Ceay_InitPIN","Closing of database failed.", rv ,0);
      TC_free(cryptdb);
      return rv;
    }
  
  TC_free(cryptdb);
  CI_LogEntry("CI_Ceay_InitPIN","InitPin complete.....", rv ,0);

  return CKR_OK;
}
/* }}} */
/* {{{ CI_Ceay_SetPIN */
CK_DEFINE_FUNCTION(CK_RV, CI_Ceay_SetPIN)(
 CK_I_SESSION_DATA_PTR session_data,  
 CK_CHAR_PTR       pOldPin,   /* the old PIN */
 CK_ULONG          ulOldLen,  /* length of the old PIN */
 CK_CHAR_PTR       pNewPin,   /* the new PIN */
 CK_ULONG          ulNewLen   /* length of the new PIN */
)
{
  CK_RV rv = CKR_OK;
  CK_CHAR_PTR db_file;
  CK_I_CRYPT_DB_PTR cryptdb;

  CI_LogEntry("CI_Ceay_SetPIN","SetPin start.....", rv ,0);

  /* open/create the persistent storage */
  rv = CI_GetConfigString(CEAY_CONFIG_SECTION, "PersistentDataFile",&db_file);
  if(rv != CKR_OK)
    {
      CI_LogEntry("CI_Ceay_SetPIN","Error reading field from config file.",rv,0);      
      return rv;
    }

  cryptdb = CDB_Open(db_file);
  if(cryptdb == NULL_PTR)
    { 
      rv = CKR_GENERAL_ERROR;
      CI_LogEntry("CI_Ceay_SetPIN","Could not open/create the database file", 
		  rv ,0);
      return rv;
    }

  /* modify normal user's PIN and save to cryptdb */
  rv = CDB_NewPin(cryptdb, FALSE,  pOldPin, ulOldLen, pNewPin, ulNewLen);
  
  if (rv != CKR_OK)
    {
      CI_LogEntry("CI_Ceay_SetPIN","Setting PIN failed", rv ,0);
      TC_free(cryptdb);
      return rv;
    }
  else
    {
      CI_LogEntry("CI_Ceay_SetPIN","SetPIN success.....", rv ,0);
    }
  
  /* set the disabled-flag */
  /* set an empty user pin */
  /* set user pin trial count */
  
  rv = CDB_Close(cryptdb);
  if (rv != CKR_OK)
    {
      CI_LogEntry("CI_Ceay_SetPIN","Closing of database failed.", rv ,0);
      TC_free(cryptdb);
      return rv;
    }
  
  TC_free(cryptdb);
  CI_LogEntry("CI_Ceay_SetPIN","SetPIN complete.....", rv ,0);
  
  return CKR_OK;
}
/* }}} */

/* {{{ CI_Ceay_OpenSession */
/* Will be called from the base function. Token must implement this function 
 * if it holds some internal representation of each session 
 */
#define CK_I_CEAY_SESSION_TABLE_SIZE 20

CK_DEFINE_FUNCTION(CK_RV, CI_Ceay_OpenSession)(
  CK_I_SESSION_DATA_PTR   session_data   
)
{
  CK_I_HASH_ITERATOR_PTR pIter;
  CK_ULONG key;
  CK_I_OBJ_PTR val;
  CK_RV rv = CKR_OK;

  CI_LogEntry("CI_Ceay_OpenSession","starting...",rv,2);

  /* init implementation specific part of the session information */
  session_data->implement_data = TC_calloc(1,sizeof(CK_I_CEAY_SESS_IMPL_DATA));
  if(session_data->implement_data == NULL_PTR)
    return CKR_HOST_MEMORY;

  /* *** do token objects *** */
  if(IMPL_DATA(persistent_cache) == NULL_PTR)
    {
      rv = CI_Ceay_ReadPersistent(session_data, &IMPL_DATA(persistent_cache));
      if(rv != CKR_OK)
	{
	  TC_free(session_data->implement_data);
	  return rv;
	}
    }

  /* copy all persistent objects into the session object list */
  for(CI_HashIterateInit(IMPL_DATA(persistent_cache),&pIter);
      CI_HashIterValid(pIter);
      CI_HashIterateInc(pIter))
    {
      rv = CI_HashIterateDeRef(pIter,&key,(CK_VOID_PTR_PTR)&val);
      if(rv != CKR_OK) 
	{
	  CI_LogEntry("CI_Ceay_OpenSession",
		      "failed to deref iter on persistent cache",
		      rv,0);
	  return rv;
	}

      /* if the object isn't referenced in any session (it means
       * if no session is opened), the object doesn't appear in the
       * application object list, so put it there 
       */
      if ( Ceay_token_info.ulSessionCount == 0 ) 
	{
	  /** fill in the Cryptoki structures **/
	  /* put data in hashtable of application */
	  rv = CI_ContainerAddObj(session_data->slot_data->token_data->object_list,key,val);
	  if(rv != CKR_OK) 
	    {
	      CI_LogEntry("CI_Ceay_OpenSession",
			  "failed to insert object into application obj list", 
			  rv ,0);
	      return rv; 
	    }
	  /* tell the object who it belongs to */
	  val->session = session_data;
	} /* end if */
      
      rv = CI_ContainerAddObj(session_data->object_list,key,val);
      if(rv != CKR_OK) 
	{
	  CI_LogEntry("CI_Ceay_OpenSession","failed to add object to persistent storage",rv,0);
	  return rv;
	}
    }
  CI_HashIterateDelete(pIter);

  /* create list of sessions */
  if(IMPL_DATA(session_list) == NULL_PTR)
    {
      rv = CI_InitHashtable(&IMPL_DATA(session_list),CK_I_CEAY_SESSION_TABLE_SIZE);
      if(rv != CKR_OK)
	{
	  CI_LogEntry("CI_Ceay_OpenSession","unable to create Session list in token.",rv,0);
	  return rv;
	}
    }

  /* add session to list (pointer as the key) */
  rv = CI_HashPutEntry(IMPL_DATA(session_list), 
		       (CK_ULONG)session_data, 
		       (CK_VOID_PTR)session_data);

  CI_LogEntry("CI_Ceay_OpenSession","...complete",rv,2);

  return rv;
}
/* }}} */
/* {{{ CI_Ceay_CloseSession */
CK_DEFINE_FUNCTION(CK_RV, CI_Ceay_CloseSession)(
  CK_I_SESSION_DATA_PTR   session_data
)
{
  /* the lenght is increased by one to avoid having a NULL_PTR returned by 
   * malloc for the size being 0. this should not matter since the memory 
   * is freed in full directly afterwards. 
   */

  CK_BYTE_PTR buff = NULL_PTR;
  CK_ULONG len=0;
  CK_RV rv = CKR_OK;

  CI_LogEntry("CI_Ceay_CloseSession","starting...",rv,2);

  if(session_data->digest_state != NULL_PTR) 
    {
      CI_LogEntry("CI_Ceay_CloseSession","clearing digest state",rv,2);

      rv = CI_Ceay_DigestFinal(session_data, NULL_PTR, &len);
      if(rv != CKR_OK) return rv;
      if((buff=CI_ByteStream_new(++len)) == NULL_PTR)
	return CKR_HOST_MEMORY;
      rv = CI_Ceay_DigestFinal(session_data, buff, &len);
      TC_free(buff);
      if(rv != CKR_OK) return rv;
    }
  if(session_data->encrypt_state != NULL_PTR) 
    {
      CI_LogEntry("CI_Ceay_CloseSession","clearing encrypt state",rv,2);

      rv = CI_Ceay_EncryptFinal(session_data, NULL_PTR, &len);
      if((buff=CI_ByteStream_new(++len)) == NULL_PTR)
	return CKR_HOST_MEMORY;
      rv = CI_Ceay_EncryptFinal(session_data, buff, &len);
      TC_free(buff);
      if(rv != CKR_OK) return rv;

      if(session_data->encrypt_state == NULL_PTR)
	CI_LogEntry("CI_Ceay_CloseSession","encrypt state cleared",rv,2);
      else
	CI_LogEntry("CI_Ceay_CloseSession","encrypt state not cleared",rv,2);
      
    }
  if(session_data->decrypt_state != NULL_PTR) 
    {
      CI_LogEntry("CI_Ceay_CloseSession","clearing decrypt state",rv,2);

      rv = CI_Ceay_DecryptFinal(session_data, NULL_PTR, &len);
      if((buff=CI_ByteStream_new(++len)) == NULL_PTR)
	return CKR_HOST_MEMORY;
      rv = CI_Ceay_DecryptFinal(session_data, buff, &len);
      TC_free(buff);
      if(rv != CKR_OK) return rv;
    }
  if(session_data->sign_state != NULL_PTR) 
    {
      CI_LogEntry("CI_Ceay_CloseSession","clearing sign state",rv,2);

      rv = CI_Ceay_SignFinal(session_data, NULL_PTR, &len);
      if((buff=CI_ByteStream_new(++len)) == NULL_PTR)
	return CKR_HOST_MEMORY;
      rv = CI_Ceay_SignFinal(session_data, buff, &len);
      TC_free(buff);
      if(rv != CKR_OK) return rv;
    }
  if(session_data->verify_state != NULL_PTR) 
    {
      CI_LogEntry("CI_Ceay_CloseSession","clearing verify state",rv,2);

      rv = CI_Ceay_VerifyFinal(session_data, NULL_PTR, 0);
      if((rv != CKR_OK) || (rv != CKR_SIGNATURE_INVALID)) return CKR_OK;
    }

  CI_VarLogEntry("CI_Ceay_CloseSession","%d sessions in token session list left",rv,2,IMPL_DATA(session_list)->entries);


  /* clean up the PINs and the session specific implementation data */
  if(session_data->implement_data != NULL_PTR)
    {
      TC_free(session_data->implement_data);
      session_data->implement_data = NULL_PTR;
    }

  /* remove session from list (pointer as the key) */
  rv = CI_HashRemoveEntry(IMPL_DATA(session_list), 
			  (CK_ULONG)session_data);
  if(rv != CKR_OK)
    {
      CI_LogEntry("CI_Ceay_CloseSession","Failure to remove session_data from sessio list",rv,2);
      return rv;
    }

  CI_LogEntry("CI_Ceay_CloseSession","...complete",rv,2);

  return rv;
}
/* }}} */

/* {{{ CI_Ceay_GetOperationState */
 CK_DEFINE_FUNCTION(CK_RV, CI_Ceay_GetOperationState)(
  CK_I_SESSION_DATA_PTR session_data,     
  CK_BYTE_PTR           pOperationState,      /* gets state */
  CK_ULONG_PTR          pulOperationStateLen  /* gets state length */
)
{
  return CKR_FUNCTION_NOT_SUPPORTED;
}
/* }}} */
/* {{{ CI_Ceay_SetOperationState */
CK_DEFINE_FUNCTION(CK_RV, CI_Ceay_SetOperationState)(
  CK_I_SESSION_DATA_PTR session_data,     
  CK_BYTE_PTR           pOperationState,      /* holds state */
  CK_ULONG              ulOperationStateLen,  /* holds state length */
  CK_I_OBJ_PTR          encrypt_key_obj,      /* en/decryption key */
  CK_I_OBJ_PTR          auth_key_obj          /* sign/verify key */
)
{
  return CKR_FUNCTION_NOT_SUPPORTED;
}
/* }}} */
/* {{{ CI_Ceay_Login */
CK_DECLARE_FUNCTION(CK_RV, CI_Ceay_Login)(
 CK_I_SESSION_DATA_PTR session_data,  /* the session's handle */
 CK_USER_TYPE          userType,      /* the user type */
 CK_CHAR_PTR           pPin,          /* the user's PIN */
 CK_ULONG              ulPinLen       /* the length of the PIN */
)
{   
  CK_RV rv = CKR_OK;
  CK_CHAR_PTR db_file;
  CK_I_CRYPT_DB_PTR cryptdb;

  CI_LogEntry("CI_Ceay_Login","starting...", rv ,0);

  // open/create the persistent storage 
  rv = CI_GetConfigString(CEAY_CONFIG_SECTION, "PersistentDataFile",&db_file);
  if(rv != CKR_OK)
    {
      CI_LogEntry("CI_Ceay_Login","Error reading field from config file.",rv,0);      
      return rv;
    }

  cryptdb = CDB_Open(db_file);
  if(cryptdb == NULL_PTR)
    { 
      rv = CKR_GENERAL_ERROR;
      CI_LogEntry("CDB_Ceay_Login","Could not open the database file", rv ,0);
      return rv;
    }

  if(userType == CKU_SO)
    {
      rv = CDB_CheckPin(cryptdb, TRUE, pPin, ulPinLen);
      if (rv != CKR_OK)
	{
	  CDB_Close(cryptdb);
	  TC_free(cryptdb);
	  return rv;
	}
      
      IMPL_DATA(so_pin)= TC_malloc(ulPinLen);
      if(IMPL_DATA(so_pin) == NULL_PTR)
	return CKR_HOST_MEMORY;
      
      memcpy(IMPL_DATA(so_pin),pPin, ulPinLen);
      IMPL_DATA(so_pin_len) = ulPinLen;
    }
  else
    {
      rv = CDB_CheckPin(cryptdb, FALSE, pPin, ulPinLen);
      if (rv != CKR_OK)
	{
	  CDB_Close(cryptdb);
	  TC_free(cryptdb);
	  return rv;
	}

      IMPL_DATA(user_pin)= TC_malloc(ulPinLen);
      if(IMPL_DATA(user_pin) == NULL_PTR)
	return CKR_HOST_MEMORY;
      
      memcpy(IMPL_DATA(user_pin),pPin, ulPinLen);
      IMPL_DATA(user_pin_len) = ulPinLen;
    }

  /* TODO: this might load public objects more than once */
  CI_Ceay_ReadPrivate(session_data, cryptdb);

  rv = CDB_Close(cryptdb);
  if (rv != CKR_OK)
    {
      CI_LogEntry("CI_Ceay_Login","Closing of database failed.", rv ,0);
      TC_free(cryptdb);
      return rv;
    }
  
  TC_free(cryptdb);
  CI_LogEntry("CI_Ceay_Login","complete...", rv ,0);
  
  return rv;
}
/* }}} */
/* {{{ CI_Ceay_Logout */
CK_DECLARE_FUNCTION(CK_RV, CI_Ceay_Logout)(
  CK_I_SESSION_DATA_PTR session_data  /* the session's handle */
)
{
  return CKR_OK;
}
/* }}} */

/* {{{ CI_Ceay_DigestInit */
CK_DEFINE_FUNCTION(CK_RV, CI_Ceay_DigestInit)(
  CK_I_SESSION_DATA_PTR  session_data,
  CK_MECHANISM_PTR  pMechanism  /* the digesting mechanism */
)
{
  CK_RV rv = CKR_OK;

  CI_LogEntry("CI_Ceay_DigestInit", "starting...", rv ,2);

  if (session_data->digest_state != NULL_PTR)
    {
      rv = CKR_OPERATION_ACTIVE;
      CI_LogEntry("CI_Ceay_DigestInit", "testing state", rv ,0);
      return rv;
    }

  switch(pMechanism->mechanism)
    {
    case CKM_MD5:
      session_data->digest_state = CI_MD5_CTX_new();
      if (session_data->digest_state == NULL_PTR)
	{
	  rv = CKR_HOST_MEMORY;
	  CI_LogEntry("CI_Ceay_DigestInit", "alloc'ing state", rv ,0);
	  return rv;
	}

      session_data->digest_mechanism = CKM_MD5;

      MD5_Init((MD5_CTX CK_PTR)session_data->digest_state);
      break;
    case CKM_MD2:
      session_data->digest_state = CI_MD2_CTX_new();
      if (session_data->digest_state == NULL_PTR)
	{
	  rv = CKR_HOST_MEMORY;
	  CI_LogEntry("CI_Ceay_DigestInit", "alloc'ing state", rv ,0);
	  return rv;
	}

      session_data->digest_mechanism = CKM_MD2;

      MD2_Init((MD2_CTX CK_PTR)session_data->digest_state);
      break;
    case CKM_SHA_1:
      session_data->digest_state = CI_SHA_CTX_new();
      if (session_data->digest_state == NULL_PTR)
	{
	  rv = CKR_HOST_MEMORY;
	  CI_LogEntry("CI_Ceay_DigestInit", "alloc'ing memory for SHA-1 state", rv ,0);
	  return rv;
	}

      session_data->digest_mechanism = CKM_SHA_1;

      CI_Ceay_SHA1_Init((SHA_CTX CK_PTR)session_data->digest_state);
      break;

    default:
      rv = CKR_MECHANISM_INVALID;
      CI_LogEntry("CI_Ceay_DigestInit", "switch on mechanism", rv ,0);
      return rv; 
    }

  CI_LogEntry("CI_Ceay_DigestInit", "...complete", rv ,2);

  return rv;
}
/* }}} */
/* {{{ CI_Ceay_Digest */
CK_DEFINE_FUNCTION(CK_RV, CI_Ceay_Digest)(
  CK_I_SESSION_DATA_PTR  session_data,
  CK_BYTE_PTR       pData,        /* data to be digested */
  CK_ULONG          ulDataLen,    /* bytes of data to digest */
  CK_BYTE_PTR       pDigest,      /* gets the message digest */
  CK_ULONG_PTR      pulDigestLen  /* gets digest length */
)
{
  CK_ULONG digestLen;

  switch(session_data->digest_mechanism)
    {
    case CKM_MD5:
      digestLen = MD5_DIGEST_LENGTH;
      break;
    case CKM_MD2:
      digestLen = MD2_DIGEST_LENGTH;
      break;
    case CKM_SHA_1:
      digestLen = SHA_DIGEST_LENGTH;
      break;
    default:
      return CKR_MECHANISM_INVALID;
    }

  /* only testing the length */
  if(pDigest == NULL_PTR)
    {
      *pulDigestLen = digestLen;
      return CKR_OK;
    }  
  
  if(*pulDigestLen < digestLen)
    {
      *pulDigestLen = digestLen;
      return CKR_BUFFER_TOO_SMALL;
    }

  switch(session_data->digest_mechanism)
    {
    case CKM_MD5:
      MD5_Update((MD5_CTX CK_PTR)session_data->digest_state,pData,ulDataLen);
      MD5_Final(pDigest,(MD5_CTX CK_PTR)session_data->digest_state);
      TC_free(session_data->digest_state);
      session_data->digest_state = NULL_PTR;
      break;
    case CKM_MD2:
      MD2_Update((MD2_CTX CK_PTR)session_data->digest_state,pData,ulDataLen);
      MD2_Final(pDigest,(MD2_CTX CK_PTR)session_data->digest_state);
      TC_free(session_data->digest_state);
      session_data->digest_state = NULL_PTR;
      break;
    case CKM_SHA_1:
      CI_Ceay_SHA1_Update((SHA_CTX CK_PTR)session_data->digest_state,pData,ulDataLen);
      CI_Ceay_SHA1_Final(pDigest,(SHA_CTX CK_PTR)session_data->digest_state);
      TC_free(session_data->digest_state);
      session_data->digest_state = NULL_PTR;
      break;
    default:
      return CKR_MECHANISM_INVALID;
    }

  *pulDigestLen = digestLen;

  return CKR_OK;
}
/* }}} */
/* {{{ CI_Ceay_DigestUpdate */
CK_DEFINE_FUNCTION(CK_RV, CI_Ceay_DigestUpdate)(
  CK_I_SESSION_DATA_PTR  session_data,
  CK_C_BYTE_PTR     pPart,     /* data to be digested */
  CK_ULONG          ulPartLen  /* bytes of data to be digested */
)
{
  CK_RV rv = CKR_OK;
  CK_BYTE_PTR tmp_str = NULL_PTR;

  CI_LogEntry("CI_Ceay_DigestUpdate", "starting...", rv ,2);

  CI_VarLogEntry("CI_Ceay_DigestUpdate", 
		 "session_data->digest_state: %p, pPart: %p (%s), ulPartLen: %u", 
		 rv ,2,
		 session_data->digest_state,
		 pPart,
		 tmp_str = CI_PrintableByteStream(pPart,ulPartLen),
		 ulPartLen);
  TC_free(tmp_str);

  switch(session_data->digest_mechanism)
    {
    case CKM_MD5:
    MD5_Update((MD5_CTX CK_PTR)session_data->digest_state,
	       (unsigned char *)pPart,ulPartLen);
      break;
    case CKM_MD2:
    MD2_Update((MD2_CTX CK_PTR)session_data->digest_state,
	       (unsigned char *)pPart,ulPartLen);
      break;
    case CKM_SHA_1:
    CI_Ceay_SHA1_Update((SHA_CTX CK_PTR)session_data->digest_state,
		(unsigned char *)pPart,ulPartLen);
      break;
    default:
      return CKR_MECHANISM_INVALID;
    }

  CI_LogEntry("CI_Ceay_DigestUpdate", "...complete", rv ,2);

  return rv;
}
/* }}} */
/* {{{ CI_Ceay_DigestFinal */
CK_DEFINE_FUNCTION(CK_RV, CI_Ceay_DigestFinal)(
  CK_I_SESSION_DATA_PTR  session_data,
  CK_BYTE_PTR       pDigest,      /* gets the message digest */
  CK_ULONG_PTR      pulDigestLen  /* gets byte count of digest */
)
{
  CK_ULONG digestLen;
  CK_RV rv = CKR_OK;

  CI_LogEntry("CI_Ceay_DigestFinal", "starting...", rv ,2);

  switch(session_data->digest_mechanism)
    {
    case CKM_MD5:
      digestLen = MD5_DIGEST_LENGTH;
      break;
    case CKM_MD2:
      digestLen = MD2_DIGEST_LENGTH;
      break;
    case CKM_SHA_1:
      digestLen = SHA_DIGEST_LENGTH;
      break;
    default:
      rv = CKR_MECHANISM_INVALID;
      CI_LogEntry("CI_Ceay_DigestFinal", "setting digest length", rv ,0);
      return rv;
    }

  /* only testing the length */
  if(pDigest == NULL_PTR)
    {
      *pulDigestLen = digestLen;
      rv = CKR_OK;
      CI_LogEntry("CI_Ceay_DigestFinal", "only getting the length of the digest data", rv ,0);
      return rv;
    }  
  
  if(*pulDigestLen < digestLen)
    {
      *pulDigestLen = digestLen;
      rv = CKR_BUFFER_TOO_SMALL;
      CI_LogEntry("CI_Ceay_DigestFinal", "testing buffer length", rv ,0);
      return rv;
    }

  switch(session_data->digest_mechanism)
    {
    case CKM_MD5:
      MD5_Final(pDigest,(MD5_CTX CK_PTR)session_data->digest_state);
      break;
    case CKM_MD2:
      MD2_Final(pDigest,(MD2_CTX CK_PTR)session_data->digest_state);
      break;
    case CKM_SHA_1:
      CI_Ceay_SHA1_Final(pDigest,(SHA_CTX CK_PTR)session_data->digest_state);
      break;
    default:
      rv = CKR_MECHANISM_INVALID;
      CI_LogEntry("CI_Ceay_DigestFinal", "completing digests", rv ,0);      
      return rv;
    }

  *pulDigestLen = digestLen;

  TC_free(session_data->digest_state);
  session_data->digest_state = NULL_PTR;

  CI_LogEntry("CI_Ceay_DigestFinal", "...complete", rv ,2);

  return rv;
}
/* }}} */
/* {{{ CI_Ceay_DigestKey */
CK_DEFINE_FUNCTION(CK_RV, CI_Ceay_DigestKey)(
  CK_I_SESSION_DATA_PTR  session_data,
  CK_I_OBJ_PTR           key_obj       /* secret key to digest */
)
{
  CK_BYTE_PTR       pPart = NULL_PTR;     /* data to be digested */
  CK_ULONG          ulPartLen; /* bytes of data to be digested */
    

  /* Check what type of key */
  if(CI_ObjLookup(key_obj,CK_IA_KEY_TYPE) == NULL_PTR)
    return CKR_KEY_INDIGESTIBLE;

  switch(*((CK_KEY_TYPE CK_PTR)CI_ObjLookup(key_obj,CK_IA_KEY_TYPE)->pValue))
    {
    case CKO_PUBLIC_KEY:
    case CKO_PRIVATE_KEY:
      pPart= CI_ObjLookup(key_obj,CK_IA_PUBLIC_EXPONENT)->pValue;
      ulPartLen = CI_ObjLookup(key_obj,CK_IA_PUBLIC_EXPONENT)->ulValueLen;
      break;
    case CKO_SECRET_KEY:
      pPart= CI_ObjLookup(key_obj,CK_IA_VALUE)->pValue;
      ulPartLen = CI_ObjLookup(key_obj,CK_IA_VALUE)->ulValueLen;
      break;
    default:
      return CKR_KEY_INDIGESTIBLE;
    }

  
  switch(session_data->digest_mechanism)
    {
    case CKM_MD5:
      MD5_Update((MD5_CTX CK_PTR)session_data->digest_state,pPart,ulPartLen);
      break;
    case CKM_MD2:
      MD2_Update((MD2_CTX CK_PTR)session_data->digest_state,pPart,ulPartLen);
      break;
    case CKM_SHA_1:
      CI_Ceay_SHA1_Update((SHA_CTX CK_PTR)session_data->digest_state,pPart,ulPartLen);
    default:
      return CKR_MECHANISM_INVALID;
    }

  return CKR_OK;
}
/* }}} */

/* {{{ CI_Ceay_SignInit */
/* padding for CKM_SSL3_MD5_MAC */
static CK_CHAR CK_I_ssl3_pad1[48]={
        0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,
        0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,
        0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,
        0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,
        0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,
        0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36 };
 
static CK_CHAR CK_I_ssl3_pad2[48]={
        0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,
        0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,
        0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,
        0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,
        0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,
        0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c };

#define CK_I_ssl3_md5_pad_len 48
#define CK_I_ssl3_sha_pad_len 40

CK_DEFINE_FUNCTION(CK_RV, CI_Ceay_SignInit)(
  CK_I_SESSION_DATA_PTR  session_data,
  CK_MECHANISM_PTR  pMechanism,  /* the signature mechanism */
  CK_I_OBJ_PTR      key_obj      /* handle of signature key */
)
{
  CK_RV rv;

  rv = CKR_OK;

  /* All Checked. Set signing object */
  switch(pMechanism->mechanism)
    {
      /* {{{ CKM_DSA_SHA1 */
    case CKM_DSA_SHA1:
      {
	DSA_PTR internal_key_obj = NULL_PTR;
	
	CI_LogEntry("CI_Ceay_SignInit with CKM_DSA_SHA1", "starting...", rv ,2);
	
	if (session_data->digest_state != NULL_PTR)
	  {
	    rv = CKR_OPERATION_ACTIVE;
	    CI_LogEntry("CI_Ceay_SignInit with CKM_DSA_SHA1", "testing state", rv ,0);
	    return rv;
	  }
	/* check that object is a private key */
	if((CI_ObjLookup(key_obj,CK_IA_CLASS) == NULL_PTR) ||
	   (*((CK_OBJECT_CLASS CK_PTR)CI_ObjLookup(key_obj,CK_IA_CLASS)->pValue) != CKO_PRIVATE_KEY))
	  {
	    rv = CKR_KEY_TYPE_INCONSISTENT;
	    CI_LogEntry("CI_Ceay_SignInit with CKM_DSA_SHA1", 
			"testing that object is a private key", rv ,0);
	    return rv;
	  }
	
	internal_key_obj = CI_Ceay_Obj2DSA(key_obj);
	if(internal_key_obj == NULL_PTR)
	  return CKR_HOST_MEMORY;
	
	session_data->sign_state = (CK_VOID_PTR)internal_key_obj;
	session_data->sign_mechanism = CKM_DSA_SHA1;
	
	/* Allocating data structures */
	session_data->digest_state = CI_SHA_CTX_new();
	if (session_data->digest_state == NULL_PTR)
	  {
	    rv = CKR_HOST_MEMORY;
	    CI_LogEntry("CI_Ceay_SignInit with CKM_DSA_SHA1", 
			"alloc'ing memory for SHA-1 state", rv ,0);
	    return rv;
	  }
	
	session_data->digest_mechanism = CKM_SHA_1;
	
	CI_Ceay_SHA1_Init((SHA_CTX CK_PTR)session_data->digest_state);
	
      }
      break;
      /* }}} */
      /* {{{ CKM_SHA1_RSA_PKCS */
    case CKM_SHA1_RSA_PKCS:
      {
	RSA CK_PTR internal_key_obj = NULL_PTR;
	
	CI_LogEntry("CI_Ceay_SignInit with CKM_SHA1_RSA_PKCS", "starting...", rv ,2);
	
	if (session_data->digest_state != NULL_PTR)
	  {
	    rv = CKR_OPERATION_ACTIVE;
	    CI_LogEntry("CI_Ceay_SignInit with CKM_SHA1_RSA_PKCS", "testing state", rv ,0);
	    return rv;
	  }
	/* check that object is a private key */
	if((CI_ObjLookup(key_obj,CK_IA_CLASS) == NULL_PTR) ||
	   (*((CK_OBJECT_CLASS CK_PTR)CI_ObjLookup(key_obj,CK_IA_CLASS)->pValue) != CKO_PRIVATE_KEY))
	  {
	    rv = CKR_KEY_TYPE_INCONSISTENT;
	    CI_LogEntry("CI_Ceay_SignInit with CKM_SHA1_RSA_PKCS", 
			"testing that object is a private key", rv ,0);
	    return rv;
	  }
	
	internal_key_obj = CI_Ceay_Obj2RSA(key_obj);
	if(internal_key_obj == NULL_PTR)
	  return CKR_HOST_MEMORY;
	
	session_data->sign_state = (CK_VOID_PTR)internal_key_obj;
	session_data->sign_mechanism = CKM_SHA1_RSA_PKCS;
	
	/* Allocating data structures */
	session_data->digest_state = CI_SHA_CTX_new();
	if (session_data->digest_state == NULL_PTR)
	  {
	    rv = CKR_HOST_MEMORY;
	    CI_LogEntry("CI_Ceay_SignInit with CKM_SHA1_RSA_PKCS", 
			"alloc'ing memory for SHA-1 state", rv ,0);
	    return rv;
	  }
	
	session_data->digest_mechanism = CKM_SHA_1;
	
	CI_Ceay_SHA1_Init((SHA_CTX CK_PTR)session_data->digest_state);
	
      }
      break;
      /* }}} */
      /* {{{ CKM_RSA_PKCS */
    case CKM_RSA_PKCS:
      {
	RSA CK_PTR internal_key_obj = NULL_PTR;
	
	/* check that object is a private key */
	if((CI_ObjLookup(key_obj,CK_IA_CLASS) == NULL_PTR) || 
	   (*((CK_OBJECT_CLASS CK_PTR)CI_ObjLookup(key_obj,CK_IA_CLASS)->pValue) != CKO_PRIVATE_KEY))
	  return CKR_KEY_TYPE_INCONSISTENT; 

	internal_key_obj = CI_Ceay_Obj2RSA(key_obj);
	if(internal_key_obj == NULL_PTR)
	  return CKR_HOST_MEMORY;
	
	session_data->sign_state = (CK_VOID_PTR)internal_key_obj;
	session_data->sign_mechanism = CKM_RSA_PKCS;
      }
      break;
      /* }}} */
      /* {{{ CKM_RSA_X_509 */
    case CKM_RSA_X_509:
      {
	RSA CK_PTR internal_key_obj = NULL_PTR;
	
	/* check that object is a private key */
	if((CI_ObjLookup(key_obj,CK_IA_CLASS) == NULL_PTR) || 
	   (*((CK_OBJECT_CLASS CK_PTR)CI_ObjLookup(key_obj,CK_IA_CLASS)->pValue) != CKO_PRIVATE_KEY))
	  return CKR_KEY_TYPE_INCONSISTENT; 

	internal_key_obj = CI_Ceay_Obj2RSA(key_obj);
	if(internal_key_obj == NULL_PTR)
	  return CKR_HOST_MEMORY;
	
	session_data->sign_state = (CK_VOID_PTR)internal_key_obj;
	session_data->sign_mechanism = CKM_RSA_X_509;
      }
      break;
      /* }}} */
      /* {{{ CKM_DSA */
    case CKM_DSA:
      {
	DSA_PTR internal_key_obj = NULL_PTR;
	
	/* check that object is a private key */
	if((CI_ObjLookup(key_obj,CK_IA_CLASS) == NULL_PTR) || 
	   (*((CK_OBJECT_CLASS CK_PTR)CI_ObjLookup(key_obj,CK_IA_CLASS)->pValue) != CKO_PRIVATE_KEY))
	  return CKR_KEY_TYPE_INCONSISTENT; 

	internal_key_obj = CI_Ceay_Obj2DSA(key_obj);
	if(internal_key_obj == NULL_PTR)
	  return CKR_HOST_MEMORY;
	
	session_data->sign_state = (CK_VOID_PTR)internal_key_obj;
	session_data->sign_mechanism = CKM_DSA;
      }
      break;
      /* }}} */
      /* {{{ CKM_SSL3_MD5_MAC */
      /*
       * The MAC is generated as: 
       *
       * hash(MAC_write_secret + pad_2 +
       *      hash (MAC_write_secret + pad_1 + seq_num + length + content));
       *
       * where "+" denotes concatenation. 
       *
       * pad_1    The character 0x36 repeated 48 time for MD5 or 40 times for SHA. 
       * pad_2    The character 0x5c repeated the same number of times. 
       * seq_num  The sequence number for this message. 
       * hash     The hashing algorithm derived from the cipher suite. 
       * content  Data of the transmission
       * 
       * Use in Netscape:
       *     seq_num and length are sent in one, the actual data sent in a
       *     second call to SignUpdate
       * 
       * Assumption for this implementation:
       * - the write secret is given as the key of the sign operation
       * - the seq_num and the length are sent by the application as data
       *
       * both hashes are init'ed in this function to minimize the number of copies
       * of the key that have to lay about in the clear (otherwise we would need 
       * to carry it to the closing functions for the outer hash)
       */
    case CKM_SSL3_MD5_MAC:
      {
	CK_BYTE_PTR key_data = NULL_PTR;
	CK_ULONG key_len;
	CK_I_MD5_MAC_STATE_PTR mac_state = NULL_PTR;

	/* get and check key data */
	if(CI_ObjLookup(key_obj,CK_IA_VALUE) == NULL_PTR)
	  {
	    rv = CKR_KEY_TYPE_INCONSISTENT;
	    CI_LogEntry("CI_Ceay_SignInit","checking key data",rv,0);
	    return rv;
	  }

	key_len = CI_ObjLookup(key_obj,CK_IA_VALUE)->ulValueLen;
	key_data = CI_ObjLookup(key_obj,CK_IA_VALUE)->pValue;
	
	{
	  CK_BYTE_PTR tmp_str = NULL_PTR;
	  
	  CI_VarLogEntry("CI_Ceay_SignInit","using key data: %s",rv,2,
			 tmp_str = CI_PrintableByteStream(key_data,key_len));
	  TC_free(tmp_str);
	}
	
	/* safety check of mechanism parameter */
	if(pMechanism->ulParameterLen != sizeof(CK_MAC_GENERAL_PARAMS))
	  {
	    rv = CKR_MECHANISM_PARAM_INVALID;
	    CI_LogEntry("CI_Ceay_SignInit","checking validity of mechanism",rv,0);
	    return rv;
	  }

	/* Allocating data structures */
	mac_state= CI_MD5_MAC_STATE_new();
	if (mac_state == NULL_PTR)
	  {
	    rv = CKR_HOST_MEMORY;
	    CI_LogEntry("CI_Ceay_SignInit", "alloc'ing state", rv ,0);
	    return rv;
	  }
	session_data->sign_state  = mac_state;
	session_data->sign_mechanism = CKM_SSL3_MD5_MAC;

	mac_state->params = *((CK_MAC_GENERAL_PARAMS_PTR)pMechanism->pParameter);
	CI_VarLogEntry("CI_Ceay_SignInit","MAC Length (mechanism parameter): %i",
		       rv,2,
		       mac_state->params);
	
	/* start hashing of key */
	MD5_Update(mac_state->inner_CTX,key_data,key_len);
	MD5_Update(mac_state->inner_CTX,CK_I_ssl3_pad1,CK_I_ssl3_md5_pad_len);

	/* start hashing of key */
	MD5_Update(mac_state->outer_CTX,key_data,key_len);
	MD5_Update(mac_state->outer_CTX,CK_I_ssl3_pad2,CK_I_ssl3_md5_pad_len);
	
	break;	
      }
    break;
    /* }}} */
      /* {{{ CKM_SSL3_SHA1_MAC */
      /*
       * The MAC is generated as: 
       *
       * hash(MAC_write_secret + pad_2 +
       *      hash (MAC_write_secret + pad_1 + seq_num + length + content));
       *
       * where "+" denotes concatenation. 
       *
       * pad_1    The character 0x36 repeated 48 time for MD5 or 40 times for SHA. 
       * pad_2    The character 0x5c repeated the same number of times. 
       * seq_num  The sequence number for this message. 
       * hash     The hashing algorithm derived from the cipher suite. 
       * content  Data of the transmission
       * 
       * Use in Netscape:
       *     seq_num and length are sent in one, the actual data sent in a
       *     second call to SignUpdate
       * 
       * Assumption for this implementation:
       * - the write secret is given as the key of the sign operation
       * - the seq_num and the length are sent by the application as data
       *
       * both hashes are init'ed in this function to minimize the number of copies
       * of the key that have to lay about in the clear (otherwise we would need 
       * to carry it to the closing functions for the outer hash)
       */
    case CKM_SSL3_SHA1_MAC:
      {
	CK_BYTE_PTR key_data = NULL_PTR;
	CK_ULONG key_len;
	CK_I_SHA_MAC_STATE_PTR mac_state = NULL_PTR;

	/* get and check key data */
	if(CI_ObjLookup(key_obj,CK_IA_VALUE) == NULL_PTR)
	  {
	    rv = CKR_KEY_TYPE_INCONSISTENT;
	    CI_LogEntry("CI_Ceay_SignInit","checking key data",rv,0);
	    return rv;
	  }

	key_len = CI_ObjLookup(key_obj,CK_IA_VALUE)->ulValueLen;
	key_data = CI_ObjLookup(key_obj,CK_IA_VALUE)->pValue;
	
	{
	  CK_BYTE_PTR tmp_str = NULL_PTR;
	  
	  CI_VarLogEntry("CI_Ceay_SignInit","using key data: %s",rv,2,
			 tmp_str = CI_PrintableByteStream(key_data,key_len));
	  TC_free(tmp_str);
	}
	
	/* safety check of mechanism parameter */
	if(pMechanism->ulParameterLen != sizeof(CK_MAC_GENERAL_PARAMS))
	  {
	    rv = CKR_MECHANISM_PARAM_INVALID;
	    CI_LogEntry("CI_Ceay_SignInit","checking validity of mechanism",rv,0);
	    return rv;
	  }

	/* Allocating data structures */
	mac_state= CI_SHA_MAC_STATE_new();
	if (mac_state == NULL_PTR)
	  {
	    rv = CKR_HOST_MEMORY;
	    CI_LogEntry("CI_Ceay_SignInit", "alloc'ing state", rv ,0);
	    return rv;
	  }
	session_data->sign_state  = mac_state;
	session_data->sign_mechanism = CKM_SSL3_SHA1_MAC;

	mac_state->params = *((CK_MAC_GENERAL_PARAMS_PTR)pMechanism->pParameter);
	CI_VarLogEntry("CI_Ceay_SignInit","MAC Length (mechanism parameter): %i",
		       rv,2,mac_state->params);
	
	/* start hashing of key */
	CI_Ceay_SHA1_Update(mac_state->inner_CTX,key_data,key_len);
	CI_Ceay_SHA1_Update(mac_state->inner_CTX,CK_I_ssl3_pad1,CK_I_ssl3_sha_pad_len);

	/* start hashing of key */
	CI_Ceay_SHA1_Update(mac_state->outer_CTX,key_data,key_len);
	CI_Ceay_SHA1_Update(mac_state->outer_CTX,CK_I_ssl3_pad2,CK_I_ssl3_sha_pad_len);
	
	break;	
      }
    break;
    /* }}} */
    default:
      rv = CKR_MECHANISM_INVALID;
      CI_VarLogEntry("CI_Ceay_SignInit", "switching on mechanism (%x)", rv, 0,
		     pMechanism->mechanism);
    }

  return rv;
}
/* }}} */
/* {{{ CI_Ceay_Sign */
CK_DEFINE_FUNCTION(CK_RV, CI_Ceay_Sign)(
  CK_I_SESSION_DATA_PTR  session_data,
  CK_BYTE_PTR       pData,           /* the data to sign */
  CK_ULONG          ulDataLen,       /* count of bytes to sign */
  CK_BYTE_PTR       pSignature,      /* gets the signature */
  CK_ULONG_PTR      pulSignatureLen  /* gets signature length */
)
{
  CK_RV rv;
  CK_ULONG digestLen;
  CK_VOID_PTR mutex = NULL_PTR;

  rv =CI_CreateMutex (&mutex);
  if(rv != CKR_OK)
    {
      CI_LogEntry("CI_Ceay_Sign","setting mutex",rv,0);
      return rv;
    }

  switch(session_data->sign_mechanism)
    {
      /* {{{ CKM_SHA1_RSA_PKCS */
    case CKM_SHA1_RSA_PKCS:
      {
	/* the data is copied in order to strip the space for the padding after the processing */
	/* TODO: check if this correct. */
	CK_BYTE_PTR tmp_buf = NULL_PTR;
	CK_ULONG sign_len;
	long processed; /* number of bytes processed by the crypto routine */
	
	rv = CKR_OK;
	sign_len = CI_Ceay_RSA_size((RSA CK_PTR)session_data->sign_state);
	
	/* check if this is only a call for the length of the output buffer */
	if(pSignature == NULL_PTR)
	  {
	    *pulSignatureLen = sign_len;
	    return CKR_OK;
	  }
	else /* check that buffer is of sufficent size */
	  {
	    if(*pulSignatureLen < sign_len)
	      {
		*pulSignatureLen = sign_len;
		return CKR_BUFFER_TOO_SMALL;
	      }
	  }
	
	tmp_buf = CI_ByteStream_new(sign_len);
	if(tmp_buf == NULL_PTR) { rv = CKR_HOST_MEMORY; goto sha1_rsa_pkcs1_err; }
	
	CI_Ceay_SHA1_Update((SHA_CTX CK_PTR)session_data->digest_state,pData,ulDataLen);
	CI_Ceay_SHA1_Final(pSignature,(SHA_CTX CK_PTR)session_data->digest_state);
	session_data->digest_state = NULL_PTR;
	
	processed = CI_Ceay_RSA_private_encrypt(SHA_DIGEST_LENGTH,pSignature,
					tmp_buf,
					session_data->sign_state,
					RSA_PKCS1_PADDING);
	if(processed == -1)
	  { rv = CKR_GENERAL_ERROR; goto sha1_rsa_pkcs1_err; }
	*pulSignatureLen = processed;
	
	memcpy(pSignature,tmp_buf,sign_len);
	
	TC_free(session_data->digest_state);
	
      sha1_rsa_pkcs1_err:
	if(tmp_buf != NULL_PTR) TC_free(tmp_buf);
	if(session_data->sign_state != NULL_PTR)
	  CI_Ceay_RSA_free(session_data->sign_state);
	session_data->sign_state = NULL_PTR;
      }
      break;
      /* }}} */
      /* {{{ CKM_RSA_PKCS */
    case CKM_RSA_PKCS:
      {
	/* the data is copied in order to strip the space for the padding after the processing */
	/* TODO: check if this correct. */
	CK_BYTE_PTR tmp_buf = NULL_PTR;
	CK_ULONG sign_len;
	long processed; /* number of bytes processed by the crypto routine */

	rv = CKR_OK;
	sign_len = CI_Ceay_RSA_size((RSA CK_PTR)session_data->sign_state);

	/* check if this is only a call for the length of the output buffer */
	if(pSignature == NULL_PTR)
	  {
	    *pulSignatureLen = sign_len;
	    return CKR_OK;
	  }
	else /* check that buffer is of sufficent size */
	  {
	    if(*pulSignatureLen < sign_len)
	      { 
		*pulSignatureLen = sign_len;
		return CKR_BUFFER_TOO_SMALL;
	      }
	  }
	
	/* check for length of input */
	if(ulDataLen > sign_len-CK_I_PKCS1_MIN_PADDING)
	  { rv = CKR_DATA_LEN_RANGE; goto rsa_pkcs1_err; }
	
	tmp_buf = CI_ByteStream_new(sign_len);
	if(tmp_buf == NULL_PTR) { rv = CKR_HOST_MEMORY; goto rsa_pkcs1_err; }
	
	processed = CI_Ceay_RSA_private_encrypt(ulDataLen,pData,
					tmp_buf,
					session_data->sign_state,
					RSA_PKCS1_PADDING);
	if(processed == -1)
	  { rv = CKR_GENERAL_ERROR; goto rsa_pkcs1_err; }
	*pulSignatureLen = processed;
	
	memcpy(pSignature,tmp_buf,sign_len);
	
      rsa_pkcs1_err:
	if(tmp_buf != NULL_PTR) TC_free(tmp_buf);
	if(session_data->sign_state != NULL_PTR)
	  { 
	    CI_Ceay_RSA_free(session_data->sign_state); 
	    session_data->sign_state = NULL_PTR;
	  }
	break;
      }
      /* }}} */
      /* {{{ CKM_RSA_X_509 */
    case CKM_RSA_X_509:
      {
	/* the data is copied in order to strip the space for the padding after the processing */
	/* TODO: check if this correct. */
	CK_BYTE_PTR tmp_buf = NULL_PTR;
	CK_ULONG sign_len;
	long processed; /* number of bytes processed by the crypto routine */

	rv = CKR_OK;
	sign_len = CI_Ceay_RSA_size((RSA CK_PTR)session_data->sign_state);

	/* check if this is only a call for the length of the output buffer */
	if(pSignature == NULL_PTR)
      	  {
	    *pulSignatureLen = sign_len;
	    return CKR_OK;
	  }
	else /* check that buffer is of sufficent size */
	  {
	    if(*pulSignatureLen < sign_len)
	      {
		*pulSignatureLen = sign_len;
		return CKR_BUFFER_TOO_SMALL;
	      }
	  }
	
	/* check for length of input */
	if(ulDataLen != sign_len)
	  { rv = CKR_DATA_LEN_RANGE; goto rsa_x509_err; }
	
	tmp_buf = CI_ByteStream_new(sign_len);
	if(tmp_buf == NULL_PTR) { rv = CKR_HOST_MEMORY; goto rsa_x509_err; }
	
	processed = CI_Ceay_RSA_private_encrypt(ulDataLen,pData,
					tmp_buf,
					session_data->sign_state,
					RSA_NO_PADDING);
	if(processed == -1)
	  { rv = CKR_GENERAL_ERROR; goto rsa_x509_err; }
	*pulSignatureLen = processed;
	
	memcpy(pSignature,tmp_buf,sign_len);
	
      rsa_x509_err:
	if(tmp_buf != NULL_PTR) TC_free(tmp_buf);
	if(session_data->sign_state != NULL_PTR)
	  { 
	    CI_Ceay_RSA_free(session_data->sign_state); 
	    session_data->sign_state = NULL_PTR;
	  }
	break;
      }
      /* }}} */
      /* {{{ CKM_DSA */
    case CKM_DSA:
      {
	unsigned int sig_len;

	rv = CKR_OK;
	
	/* check if this is only a call for the length of the output buffer */
	if(pSignature == NULL_PTR)
      	  {
	    *pulSignatureLen = CK_I_DSA_SIGN_LEN;
	    return CKR_OK;
	  }
	else /* check that buffer is of sufficent size */
	  {
	    if(*pulSignatureLen < CK_I_DSA_SIGN_LEN)
	      {
		*pulSignatureLen = CK_I_DSA_SIGN_LEN;
		return CKR_BUFFER_TOO_SMALL;
	      }
	  }
	
	/* check for length of input */
	if(ulDataLen != CK_I_DSA_DIGEST_LEN)
	  { rv = CKR_DATA_LEN_RANGE; goto dsa_err; }
	
	if(!DSA_sign(0,
		     pData,ulDataLen,
		     pSignature, &sig_len,
		     (DSA_PTR)session_data->sign_state))
	  { rv = CKR_GENERAL_ERROR; goto dsa_err; }

	*pulSignatureLen = sig_len;

      dsa_err:
	if(session_data->sign_state != NULL_PTR)
	  { 
	    DSA_free(session_data->sign_state); 
	    session_data->sign_state = NULL_PTR;
	  }
	break;
      }
      /* }}} */
      /* {{{ CKM_DSA_SHA1 */
    case CKM_DSA_SHA1:
      {
	/* the data is copied in order to strip the space for the padding after the processing */
	/* TODO: check if this correct. */
	CK_BYTE_PTR tmp_buf = NULL_PTR;
	unsigned int processed; /* number of bytes processed by the crypto routine */
	
	rv = CKR_OK;
	
	/* check if this is only a call for the length of the output buffer */
	if(pSignature == NULL_PTR)
	  {
	    *pulSignatureLen = CK_I_DSA_SIGN_LEN;
	    return CKR_OK;
	  }
	else /* check that buffer is of sufficent size */
	  {
	    if(*pulSignatureLen < CK_I_DSA_SIGN_LEN)
	      {
		*pulSignatureLen = CK_I_DSA_SIGN_LEN;
		return CKR_BUFFER_TOO_SMALL;
	      }
	  }
	
	tmp_buf = CI_ByteStream_new(CK_I_DSA_SIGN_LEN);
	if(tmp_buf == NULL_PTR) { rv = CKR_HOST_MEMORY; goto dsa_sha1_err; }
	
	CI_Ceay_SHA1_Update((SHA_CTX CK_PTR)session_data->digest_state,pData,ulDataLen);
	CI_Ceay_SHA1_Final(pSignature,(SHA_CTX CK_PTR)session_data->digest_state);
	session_data->digest_state = NULL_PTR;
	
	if(!DSA_sign(0, pSignature, SHA_DIGEST_LENGTH,
		     tmp_buf, &processed,
		     (DSA_PTR)session_data->sign_state))
	  { rv = CKR_GENERAL_ERROR; goto dsa_sha1_err; }
	
	*pulSignatureLen = processed;
	memcpy(pSignature, tmp_buf, processed);
	
	TC_free(session_data->digest_state);
	
      dsa_sha1_err:
	if(tmp_buf != NULL_PTR) TC_free(tmp_buf);
	if(session_data->sign_state != NULL_PTR)
	  
	  DSA_free(session_data->sign_state);
	session_data->sign_state = NULL_PTR;
      }
      break;
      /* }}} */
      /* {{{ CKM_SSL3_MD5_MAC */
    case CKM_SSL3_MD5_MAC:
      {
	CK_BYTE internal_hash[MD5_DIGEST_LENGTH];
	CK_I_MD5_MAC_STATE_PTR mac_state = NULL_PTR;

	mac_state = (CK_I_MD5_MAC_STATE_PTR)session_data->sign_state;
	digestLen = mac_state->params;
	
	/* only testing the length */
	if(pSignature == NULL_PTR)
	  {
	    rv = CKR_OK;
	    goto ckm_ssl3_md5_end;
	  }  
	
	if(*pulSignatureLen < digestLen)
	  {
	    rv = CKR_BUFFER_TOO_SMALL;
	    goto ckm_ssl3_md5_end;
	  }

	/* add piece of data */
	MD5_Update(mac_state->inner_CTX,pData,ulDataLen);

	/* wrap up the digesting of the data */
	MD5_Final(internal_hash,mac_state->inner_CTX);
	
	/* perform outer hash */
	MD5_Update(mac_state->outer_CTX,internal_hash,MD5_DIGEST_LENGTH);
	MD5_Final(internal_hash,mac_state->outer_CTX);

	memcpy(pSignature,internal_hash,digestLen);

	_LOCK(mutex);
	TC_free(mac_state->inner_CTX);
	TC_free(mac_state->outer_CTX);
	TC_free(mac_state);
	session_data->sign_state = NULL_PTR;
	_UNLOCK(mutex);
	
	
	/* This jump marks ensures that all pathed lead throught the DestroyMutex below */
	/* Otherwise they are not cleaned up by leaving the scope and Win32 balks */
      ckm_ssl3_md5_end:
	*pulSignatureLen = digestLen;
      }
      break;
    /* }}} */
      /* {{{ CKM_SSL3_SHA1_MAC */
    case CKM_SSL3_SHA1_MAC:
      {
	CK_BYTE internal_hash[SHA_DIGEST_LENGTH];
	CK_I_SHA_MAC_STATE_PTR mac_state = NULL_PTR;

	mac_state = (CK_I_SHA_MAC_STATE_PTR)session_data->sign_state;
	digestLen = mac_state->params;
	
	/* only testing the length */
	if(pSignature == NULL_PTR)
	  {
	    rv = CKR_OK;
	    goto ckm_ssl3_sha1_end;
	  }  
	
	if(*pulSignatureLen < digestLen)
	  {
	    rv = CKR_BUFFER_TOO_SMALL;
	    goto ckm_ssl3_sha1_end;
	  }

	/* add piece of data */
	CI_Ceay_SHA1_Update(mac_state->inner_CTX,pData,ulDataLen);

	/* wrap up the digesting of the data */
	CI_Ceay_SHA1_Final(internal_hash,mac_state->inner_CTX);
	
	/* perform outer hash */
	CI_Ceay_SHA1_Update(mac_state->outer_CTX,internal_hash,SHA_DIGEST_LENGTH);
	CI_Ceay_SHA1_Final(internal_hash,mac_state->outer_CTX);

	memcpy(pSignature,internal_hash,digestLen);

	_LOCK(mutex);
	TC_free(mac_state->inner_CTX);
	TC_free(mac_state->outer_CTX);
	TC_free(mac_state);
	session_data->sign_state = NULL_PTR;
	_UNLOCK(mutex);
	
	
	/* This jump marks ensures that all pathed lead throught the DestroyMutex below */
	/* Otherwise they are not cleaned up by leaving the scope and Win32 balks */
      ckm_ssl3_sha1_end:
	*pulSignatureLen = digestLen;
      }
      break;
    /* }}} */
    default:
      rv = CKR_MECHANISM_INVALID;
      CI_VarLogEntry("CI_Ceay_Sign", "switching on mechanism (%x)", rv, 0,
		     session_data->sign_mechanism);
    }

  /* If rv != CKR_OK, we should not replace its value by the result
   *  of CI_DestroyMutex */
  if (rv != CKR_OK)
    CI_DestroyMutex(mutex);
  else {
    rv = CI_DestroyMutex(mutex);
  if(rv != CKR_OK)
    CI_LogEntry("CI_Ceay_Sign","destroying mutex",rv,0);
  }

  return rv;
}
/* }}} */
/* {{{ CI_Ceay_SignUpdate */
CK_DEFINE_FUNCTION(CK_RV, CI_Ceay_SignUpdate)(
  CK_I_SESSION_DATA_PTR  session_data,
  CK_BYTE_PTR       pPart,     /* the data to sign */
  CK_ULONG          ulPartLen  /* count of bytes to sign */
)
{
  CK_RV rv = CKR_OK;

  CI_LogEntry("CI_Ceay_SignUpdate","starting...",rv,2);

  
  switch(session_data->sign_mechanism)
    {
      /* {{{ CKM_DSA_SHA1 + CKM_SHA1_RSA_PKCS */
    case CKM_DSA_SHA1:
    case CKM_SHA1_RSA_PKCS:
      {
	CI_Ceay_SHA1_Update((SHA_CTX CK_PTR)session_data->digest_state,
		    (unsigned char *)pPart,ulPartLen);
	
      }
      break;
      /* }}} */
      /* {{{ CKM_SSL3_MD5_MAC */
    case CKM_SSL3_MD5_MAC:
      {
	if(((CK_I_MD5_MAC_STATE_PTR)session_data->sign_state)->inner_CTX == NULL_PTR)
	  {
	    rv = CKR_GENERAL_ERROR;
	    CI_LogEntry("CI_Ceay_SignUpdate","inner_CTX == NULL_PTR",rv,0);
	    return rv;
	  }
	else
	  {
	    CK_BYTE_PTR tmp_str = NULL_PTR;
	    
	    CI_VarLogEntry("CI_Ceay_SignUpdate",
			   "inner MD5 Context set: %x Part '%s' PartLen: %i",
			   rv,2,
			   ((CK_I_MD5_MAC_STATE_PTR)session_data->sign_state)->inner_CTX,
			   tmp_str = CI_PrintableByteStream(pPart,ulPartLen),ulPartLen);
	    TC_free(tmp_str);
	  }
	
	/* add piece of data */
	MD5_Update(((CK_I_MD5_MAC_STATE_PTR)session_data->sign_state)->inner_CTX,
		   pPart,ulPartLen);
      }
    break;
    /* }}} */
      /* {{{ CKM_SSL3_SHA1_MAC */
    case CKM_SSL3_SHA1_MAC:
      {
	/* add piece of data */
	CI_Ceay_SHA1_Update(((CK_I_SHA_MAC_STATE_PTR)session_data->sign_state)->inner_CTX,pPart,ulPartLen);
      }
    break;
    /* }}} */
    default:
      rv = CKR_MECHANISM_INVALID;
      CI_VarLogEntry("CI_Ceay_SignUpdate", "switching on mechanism (%x)", rv, 0,
		     session_data->sign_mechanism);
      return rv;
    }

  CI_LogEntry("CI_Ceay_SignUpdate","...complete",rv,2);

  return rv;
}
/* }}} */
/* {{{ CI_Ceay_SignFinal */
CK_DEFINE_FUNCTION(CK_RV, CI_Ceay_SignFinal)(
  CK_I_SESSION_DATA_PTR  session_data,
  CK_BYTE_PTR       pSignature,      /* gets the signature */
  CK_ULONG_PTR      pulSignatureLen  /* gets signature length */
)
{
  CK_RV rv = CKR_OK;
  /* CK_VOID_PTR mutex; */

  CI_LogEntry("CI_Ceay_SignFinal","starting...",rv,2);

  CI_VarLogEntry("CI_Ceay_SignFinal","using mechanism %x",rv,2,
		 session_data->sign_mechanism);

  switch(session_data->sign_mechanism)
    {
      /* {{{ CKM_DSA_SHA1 */
    case CKM_DSA_SHA1:
      {
	/* the data is copied in order to strip the space for the padding after the processing */
	/* TODO: check if this correct. */
	CK_BYTE_PTR tmp_buf = NULL_PTR;
	unsigned int processed; /* number of bytes processed by the crypto routine */
	
	rv = CKR_OK;
	
	/* check if this is only a call for the length of the output buffer */
	if(pSignature == NULL_PTR)
	  {
	    *pulSignatureLen = CK_I_DSA_SIGN_LEN;
	    return CKR_OK;
	  }
	else /* check that buffer is of sufficent size */
	  {
	    if(*pulSignatureLen < CK_I_DSA_SIGN_LEN)
	      { 
		*pulSignatureLen = CK_I_DSA_SIGN_LEN;
		return CKR_BUFFER_TOO_SMALL; 
	      }
	  }
	
	tmp_buf = CI_ByteStream_new(CK_I_DSA_SIGN_LEN);
	if(tmp_buf == NULL_PTR) { rv = CKR_HOST_MEMORY; goto dsa_sha1_err; }
	
	CI_Ceay_SHA1_Final(pSignature,(SHA_CTX CK_PTR)session_data->digest_state);
	session_data->digest_state = NULL_PTR;
	
	if(!DSA_sign(0, pSignature, SHA_DIGEST_LENGTH,
		     tmp_buf, &processed,
		     (DSA_PTR)session_data->sign_state))
	  { rv = CKR_GENERAL_ERROR; goto dsa_sha1_err; }
	
	*pulSignatureLen = processed;
	memcpy(pSignature, tmp_buf, processed);
	
	TC_free(session_data->digest_state);
	
      dsa_sha1_err:
	if(tmp_buf != NULL_PTR) TC_free(tmp_buf);
	if(session_data->sign_state != NULL_PTR)
	  CI_Ceay_RSA_free(session_data->sign_state);
	session_data->sign_state = NULL_PTR;
      }
      break;
      /* }}} */
      /* {{{ CKM_SHA1_RSA_PKCS */
    case CKM_SHA1_RSA_PKCS:
      {
	/* the data is copied in order to strip the space for the padding after the processing */
	/* TODO: check if this correct. */
	CK_BYTE_PTR tmp_buf = NULL_PTR;
	CK_ULONG sign_len;
	long processed; /* number of bytes processed by the crypto routine */
	
	rv = CKR_OK;
	sign_len = CI_Ceay_RSA_size((RSA CK_PTR)session_data->sign_state);
	
	/* check if this is only a call for the length of the output buffer */
	if(pSignature == NULL_PTR)
	  {
	    *pulSignatureLen = sign_len;
	    return CKR_OK;
	  }
	else /* check that buffer is of sufficent size */
	  {
	    if(*pulSignatureLen < sign_len)
	      { 
		*pulSignatureLen = sign_len;
		return CKR_BUFFER_TOO_SMALL; 
	      }
	  }
	
	/* check for length of input */
	if(SHA_DIGEST_LENGTH > sign_len-CK_I_PKCS1_MIN_PADDING)
	  { rv = CKR_DATA_LEN_RANGE; goto sha1_rsa_pkcs1_err; }
	
	tmp_buf = CI_ByteStream_new(sign_len);
	if(tmp_buf == NULL_PTR) { rv = CKR_HOST_MEMORY; goto sha1_rsa_pkcs1_err; }
	
	CI_Ceay_SHA1_Final(pSignature,(SHA_CTX CK_PTR)session_data->digest_state);
	session_data->digest_state = NULL_PTR;
	
	processed = CI_Ceay_RSA_private_encrypt(SHA_DIGEST_LENGTH,pSignature,
					tmp_buf,
					session_data->sign_state,
					RSA_PKCS1_PADDING);
	if(processed == -1)
	  { rv = CKR_GENERAL_ERROR; goto sha1_rsa_pkcs1_err; }
	*pulSignatureLen = processed;
	
	memcpy(pSignature,tmp_buf,sign_len);
	
	TC_free(session_data->digest_state);
	
      sha1_rsa_pkcs1_err:
	if(tmp_buf != NULL_PTR) TC_free(tmp_buf);
	if(session_data->sign_state != NULL_PTR)
	  CI_Ceay_RSA_free(session_data->sign_state);
	session_data->sign_state = NULL_PTR;
      }
      break;
      /* }}} */
      /* {{{ CKM_SSL3_MD5_MAC */
    case CKM_SSL3_MD5_MAC:
      {
	CK_ULONG digestLen;
	CK_BYTE internal_hash[MD5_DIGEST_LENGTH];
	CK_I_MD5_MAC_STATE_PTR mac_state = NULL_PTR;

	CI_LogEntry("CI_Ceay_SignFinal","doing CKM_SSL3_MD5_MAC",rv,2);

	mac_state = (CK_I_MD5_MAC_STATE_PTR)session_data->sign_state;
	
	digestLen = mac_state->params;

	CI_VarLogEntry("CI_Ceay_SignFinal","digest len: %i",rv,2,digestLen);
	
	/* only testing the length */
	if(pSignature == NULL_PTR)
	  {
	    *pulSignatureLen = digestLen;
	    rv = CKR_OK;
	    CI_LogEntry("CI_Ceay_SignFinal","only testing lenght of signature",rv,0);
	    return rv;
	  }  
	
	if(*pulSignatureLen < digestLen)
	  {
	    *pulSignatureLen = digestLen;
	    rv = CKR_BUFFER_TOO_SMALL;
	    CI_LogEntry("CI_Ceay_SignFinal","testing signature lenght",rv,0);
	    return rv;
	  }

	/* wrap up the digesting of the data */
	MD5_Final(internal_hash,mac_state->inner_CTX);
	
	/* perform outer hash */
	MD5_Update(mac_state->outer_CTX,internal_hash,MD5_DIGEST_LENGTH);
	MD5_Final(internal_hash,mac_state->outer_CTX);

	memcpy(pSignature,internal_hash,digestLen);
	
	{
	  CK_BYTE_PTR tmp_str = NULL_PTR;
	  
	  CI_VarLogEntry("CI_Ceay_SignFinal","MAC: %s",rv,2,
			 tmp_str = CI_PrintableByteStream(pSignature,digestLen));
	  TC_free(tmp_str);
	}
	
	/* _LOCK(mutex); */
	/* TODO: create delete for mac-state */
	session_data->sign_state = NULL_PTR;
	TC_free(mac_state->inner_CTX);
	TC_free(mac_state->outer_CTX);
	TC_free(mac_state);
	/* _UNLOCK(mutex); */
	
	*pulSignatureLen = digestLen;
      }
    break;
    /* }}} */
      /* {{{ CKM_SSL3_SHA1_MAC */
    case CKM_SSL3_SHA1_MAC:
      {
	CK_ULONG digestLen;
	CK_BYTE internal_hash[SHA_DIGEST_LENGTH];
	CK_I_SHA_MAC_STATE_PTR mac_state = NULL_PTR;

	CI_LogEntry("CI_Ceay_SignFinal","doing CKM_SSL3_SHA1_MAC",rv,2);

	mac_state = (CK_I_SHA_MAC_STATE_PTR)session_data->sign_state;
	
	digestLen = mac_state->params;

	CI_VarLogEntry("CI_Ceay_SignFinal","digest len: %i",rv,2,digestLen);
	
	/* only testing the length */
	if(pSignature == NULL_PTR)
	  {
	    *pulSignatureLen = digestLen;
	    rv = CKR_OK;
	    CI_LogEntry("CI_Ceay_SignFinal","only testing lenght of signature",rv,0);
	    return rv;
	  }  
	
	if(*pulSignatureLen < digestLen)
	  {
	    *pulSignatureLen = digestLen;
	    rv = CKR_BUFFER_TOO_SMALL;
	    CI_LogEntry("CI_Ceay_SignFinal","testing signature lenght",rv,0);
	    return rv;
	  }

	/* wrap up the digesting of the data */
	CI_Ceay_SHA1_Final(internal_hash,mac_state->inner_CTX);
	
	/* perform outer hash */
	CI_Ceay_SHA1_Update(mac_state->outer_CTX,internal_hash,SHA_DIGEST_LENGTH);
	CI_Ceay_SHA1_Final(internal_hash,mac_state->outer_CTX);

	memcpy(pSignature,internal_hash,digestLen);

	  {
	    CK_BYTE_PTR tmp_str = NULL_PTR;
	    
	    CI_VarLogEntry("CI_Ceay_SignFinal","MAC: %s",rv,2,
			   tmp_str = CI_PrintableByteStream(pSignature,digestLen));
	    TC_free(tmp_str);
	  }

	/* _LOCK(mutex); */
	session_data->sign_state = NULL_PTR;
	TC_free(mac_state->inner_CTX);
	TC_free(mac_state->outer_CTX);
	TC_free(mac_state);
	/* _UNLOCK(mutex); */
	
	*pulSignatureLen = digestLen;
      }
    break;
    /* }}} */
    default:
      rv = CKR_MECHANISM_INVALID;
      CI_VarLogEntry("CI_Ceay_SignFinal", "switching on mechanism (%x)", rv, 0,
		     session_data->sign_mechanism);
    }

  CI_LogEntry("CI_Ceay_SignFinal","...complete",rv,2);

  return rv;
}
/* }}} */

/* {{{ CI_Ceay_SignRecoverInit */
CK_DEFINE_FUNCTION(CK_RV, CI_Ceay_SignRecoverInit)(
  CK_I_SESSION_DATA_PTR  session_data,
  CK_MECHANISM_PTR  pMechanism, /* the signature mechanism */
  CK_I_OBJ_PTR      key_obj     /* handle of the signature key */
)
{
  CK_RV rv;

  rv = CKR_OK;

  /* All Checked. Set signing object */
  switch(pMechanism->mechanism)
    {
      /* {{{ CKM_RSA_PKCS */
    case CKM_RSA_PKCS:
      {
	RSA CK_PTR internal_key_obj = NULL_PTR;

	/* check that object is a private key */
	if(*((CK_OBJECT_CLASS CK_PTR)CI_ObjLookup(key_obj,CK_IA_CLASS)->pValue) != CKO_PRIVATE_KEY)
	  return CKR_KEY_TYPE_INCONSISTENT;
	
	internal_key_obj = CI_Ceay_Obj2RSA(key_obj);
	if(internal_key_obj == NULL_PTR)
	  return CKR_HOST_MEMORY;

	
	session_data->sign_state = (CK_VOID_PTR)internal_key_obj;
	session_data->sign_mechanism = CKM_RSA_PKCS;
	
      }
      break;
      /* }}} */
      /* {{{ CKM_RSA_X_509 */
    case CKM_RSA_X_509:
      {
	RSA CK_PTR internal_key_obj = NULL_PTR;

	/* check that object is a private key */
	if(*((CK_OBJECT_CLASS CK_PTR)CI_ObjLookup(key_obj,CK_IA_CLASS)->pValue) != CKO_PRIVATE_KEY)
	  return CKR_KEY_TYPE_INCONSISTENT;
	
	internal_key_obj = CI_Ceay_Obj2RSA(key_obj);
	if(internal_key_obj == NULL_PTR)
	  return CKR_HOST_MEMORY;

	
	session_data->sign_state = (CK_VOID_PTR)internal_key_obj;
	session_data->sign_mechanism = CKM_RSA_X_509;
	
      }
      break;
      /* }}} */
    default:
      rv = CKR_MECHANISM_INVALID;
    }

  return rv;
}
/* }}} */
/* {{{ CI_Ceay_SignRecover */
CK_DEFINE_FUNCTION(CK_RV, CI_Ceay_SignRecover)(
  CK_I_SESSION_DATA_PTR  session_data,
  CK_BYTE_PTR       pData,           /* the data to sign */
  CK_ULONG          ulDataLen,       /* count of bytes to sign */
  CK_BYTE_PTR       pSignature,      /* gets the signature */
  CK_ULONG_PTR      pulSignatureLen  /* gets signature length */
)
{
  CK_RV rv;

  switch(session_data->sign_mechanism)
    {
      /* {{{ CKM_RSA_PKCS */
    case CKM_RSA_PKCS:
      {
	CK_BYTE_PTR tmp_buf = NULL_PTR;
	CK_ULONG sign_len;
	long processed; /* number of bytes processed by the crypto routine */

	rv = CKR_OK;
	sign_len = CI_Ceay_RSA_size((RSA CK_PTR)session_data->sign_state);

	/* check if this is only a call for the length of the output buffer */
	if(pSignature == NULL_PTR)
	  {
	    *pulSignatureLen = sign_len-CK_I_PKCS1_MIN_PADDING;
	    return CKR_OK;
	  }
	else /* check that buffer is of sufficent size */
	  {
	    if(*pulSignatureLen < sign_len-CK_I_PKCS1_MIN_PADDING)
	      { 
		rv = CKR_BUFFER_TOO_SMALL; 
		*pulSignatureLen = sign_len-CK_I_PKCS1_MIN_PADDING;
		return rv;
	      }
	  }
	
	/* check for length of input */
	if(ulDataLen != sign_len)
	  { rv = CKR_DATA_LEN_RANGE; goto rsa_pkcs1_err; }
	
	tmp_buf = CI_ByteStream_new(sign_len);
	if(tmp_buf == NULL_PTR) { rv = CKR_HOST_MEMORY; goto rsa_pkcs1_err; }
	
	processed = CI_Ceay_RSA_private_encrypt(ulDataLen,pData,
					tmp_buf,
					session_data->sign_state,
					RSA_PKCS1_PADDING);
	if(processed == -1)
	  { rv = CKR_GENERAL_ERROR; goto rsa_pkcs1_err; }
	*pulSignatureLen = processed;
	
	memcpy(pSignature,tmp_buf,sign_len);
	
      rsa_pkcs1_err:
	if(tmp_buf != NULL_PTR) TC_free(tmp_buf);
	if(session_data->sign_state != NULL_PTR)
	  { 
	    CI_Ceay_RSA_free(session_data->sign_state); 
	    session_data->sign_state = NULL_PTR;
	  }
      }
      /* }}} */
      /* {{{ CKM_RSA_X_509 */
    case CKM_RSA_X_509:
      {
	CK_BYTE_PTR tmp_buf = NULL_PTR;
	CK_ULONG sign_len;
	long processed; /* number of bytes processed by the crypto routine */

	rv = CKR_OK;
	sign_len = CI_Ceay_RSA_size((RSA CK_PTR)session_data->sign_state);

	/* check if this is only a call for the length of the output buffer */
	if(pData == NULL_PTR)
	  {
	    *pulSignatureLen = sign_len;
	    return CKR_OK;
	  }
	else /* check that buffer is of sufficent size */
	  {
	    if(*pulSignatureLen < sign_len)
	      {
		*pulSignatureLen = sign_len;
		return CKR_BUFFER_TOO_SMALL; 
	      }
	  }
	
	/* check for length of input */
	if(ulDataLen != sign_len)
	  { rv = CKR_DATA_LEN_RANGE; goto rsa_x509_err; }
	
	tmp_buf = CI_ByteStream_new(sign_len);
	if(tmp_buf == NULL_PTR) { rv = CKR_HOST_MEMORY; goto rsa_x509_err; }
	
	processed = CI_Ceay_RSA_private_encrypt(ulDataLen,pData,
					tmp_buf,
					session_data->sign_state,
					RSA_NO_PADDING);
	if(processed == -1)
	  { rv = CKR_GENERAL_ERROR; goto rsa_x509_err; }
	*pulSignatureLen = processed;
	
	memcpy(pSignature,tmp_buf,sign_len);
	
      rsa_x509_err:
	if(tmp_buf != NULL_PTR) TC_free(tmp_buf);
	if(session_data->sign_state != NULL_PTR)
	  { 
	    CI_Ceay_RSA_free(session_data->sign_state); 
	    session_data->sign_state = NULL_PTR;
	  }
      }
      /* }}} */
    default:
      rv = CKR_MECHANISM_INVALID;
    }

  return rv;
}
/* }}} */

/* {{{ CI_Ceay_VerifyInit */
CK_DEFINE_FUNCTION(CK_RV, CI_Ceay_VerifyInit)(
  CK_I_SESSION_DATA_PTR  session_data,
  CK_MECHANISM_PTR  pMechanism,  /* the verification mechanism */
  CK_I_OBJ_PTR      key_obj    /* verification key */ 
)
{
  CK_RV rv = CKR_OK;

  switch(pMechanism->mechanism)
    {
      /* {{{ CKM_RSA_PKCS */
    case CKM_RSA_PKCS:
      {
	RSA CK_PTR internal_key_obj = NULL_PTR;

	/* check that object is a public key */
	if(*((CK_OBJECT_CLASS CK_PTR)CI_ObjLookup(key_obj,CK_IA_CLASS)->pValue) != CKO_PUBLIC_KEY)
	  return CKR_KEY_TYPE_INCONSISTENT; 
	
	internal_key_obj = CI_Ceay_Obj2RSA(key_obj);
	if(internal_key_obj == NULL_PTR)
	  return CKR_HOST_MEMORY;
	
	session_data->verify_state = (CK_VOID_PTR)internal_key_obj;
	session_data->verify_mechanism = CKM_RSA_PKCS;
      }
      break;
      /* }}} */
      /* {{{ CKM_RSA_X_509 */
    case CKM_RSA_X_509:
      {
	RSA CK_PTR internal_key_obj = NULL_PTR;

	/* check that object is a public key */
	if(*((CK_OBJECT_CLASS CK_PTR)CI_ObjLookup(key_obj,CK_IA_CLASS)->pValue) != CKO_PUBLIC_KEY)
	  return CKR_KEY_TYPE_INCONSISTENT; 
	
	internal_key_obj = CI_Ceay_Obj2RSA(key_obj);
	if(internal_key_obj == NULL_PTR)
	  return CKR_HOST_MEMORY;
	
	session_data->verify_state = (CK_VOID_PTR)internal_key_obj;
	session_data->verify_mechanism = CKM_RSA_X_509;
      }
      break;
      /* }}} */
      /* {{{ CKM_SHA1_RSA_PKCS */
    case CKM_SHA1_RSA_PKCS:
      {
	RSA CK_PTR internal_key_obj = NULL_PTR;
	
	CI_LogEntry("CI_Ceay_VerifyInit with CKM_SHA1_RSA_PKCS", "starting...", rv ,2);
	
	if (session_data->digest_state != NULL_PTR)
	  {
	    rv = CKR_OPERATION_ACTIVE;
	    CI_LogEntry("CI_Ceay_VerifyInit with CKM_SHA1_RSA_PKCS", "testing state", rv ,0);
	    return rv;
	  }
	/* check that object is a public key */
	if(*((CK_OBJECT_CLASS CK_PTR)CI_ObjLookup(key_obj,CK_IA_CLASS)->pValue) != CKO_PUBLIC_KEY)
	  {
	    rv = CKR_KEY_TYPE_INCONSISTENT;
	    CI_LogEntry("CI_Ceay_VerifyInit with CKM_SHA1_RSA_PKCS", 
			"testing that object is a private key", rv ,0);
	    return rv;
	  }
	
	internal_key_obj = CI_Ceay_Obj2RSA(key_obj);
	if(internal_key_obj == NULL_PTR)
	  return CKR_HOST_MEMORY;
	
	session_data->verify_state = (CK_VOID_PTR)internal_key_obj;
	session_data->verify_mechanism = CKM_SHA1_RSA_PKCS;
	
	/* Allocating data structures */
	session_data->digest_state = CI_SHA_CTX_new();
	if (session_data->digest_state == NULL_PTR)
	  {
	    rv = CKR_HOST_MEMORY;
	    CI_LogEntry("CI_Ceay_VerifyInit with CKM_SHA1_RSA_PKCS", 
			"alloc'ing memory for SHA-1 state", rv ,0);
	    return rv;
	  }
	
	session_data->digest_mechanism = CKM_SHA_1;
	
	CI_Ceay_SHA1_Init((SHA_CTX CK_PTR)session_data->digest_state);
      }
      break;
      /* }}} */
      /* {{{ CKM_DSA */
    case CKM_DSA:
      {
	DSA CK_PTR internal_key_obj = NULL_PTR;
	
	/* check that object is a public key */
	if((CI_ObjLookup(key_obj,CK_IA_CLASS) == NULL_PTR) || 
	   (*((CK_OBJECT_CLASS CK_PTR)CI_ObjLookup(key_obj,CK_IA_CLASS)->pValue) != CKO_PUBLIC_KEY))
	  return CKR_KEY_TYPE_INCONSISTENT; 

	internal_key_obj = CI_Ceay_Obj2DSA(key_obj);
	if(internal_key_obj == NULL_PTR)
	  return CKR_HOST_MEMORY;
	
	session_data->verify_state = (CK_VOID_PTR)internal_key_obj;
	session_data->verify_mechanism = CKM_DSA;
      }
      break;
      /* }}} */
      /* {{{ CKM_DSA_SHA1 */
    case CKM_DSA_SHA1:
      {
	DSA CK_PTR internal_key_obj = NULL_PTR;
	
	CI_LogEntry("CI_Ceay_VerifyInit with CKM_DSA_SHA1", "starting...", rv ,2);
	
	if (session_data->digest_state != NULL_PTR)
	  {
	    rv = CKR_OPERATION_ACTIVE;
	    CI_LogEntry("CI_Ceay_VerifyInit with CKM_DSA_SHA1", "testing state", rv ,0);
	    return rv;
	  }
	/* check that object is a public key */
	if(*((CK_OBJECT_CLASS CK_PTR)CI_ObjLookup(key_obj,CK_IA_CLASS)->pValue) != CKO_PUBLIC_KEY)
	  {
	    rv = CKR_KEY_TYPE_INCONSISTENT;
	    CI_LogEntry("CI_Ceay_VerifyInit with CKM_DSA_SHA1", 
			"testing that object is a private key", rv ,0);
	    return rv;
	  }
	
	internal_key_obj = CI_Ceay_Obj2DSA(key_obj);
	if(internal_key_obj == NULL_PTR)
	  return CKR_HOST_MEMORY;
	
	session_data->verify_state = (CK_VOID_PTR)internal_key_obj;
	session_data->verify_mechanism = CKM_DSA_SHA1;
	
	/* Allocating data structures */
	session_data->digest_state = CI_SHA_CTX_new();
	if (session_data->digest_state == NULL_PTR)
	  {
	    rv = CKR_HOST_MEMORY;
	    CI_LogEntry("CI_Ceay_VerifyInit with CKM_DSA_SHA1", 
			"alloc'ing memory for SHA-1 state", rv ,0);
	    return rv;
	  }
	
	session_data->digest_mechanism = CKM_SHA_1;
	
	CI_Ceay_SHA1_Init((SHA_CTX CK_PTR)session_data->digest_state);
      }
      break;
      /* }}} */
      /* {{{ CKM_SSL3_MD5_MAC */
    case CKM_SSL3_MD5_MAC:
      {
	CK_BYTE_PTR key_data = NULL_PTR;
	CK_ULONG key_len;
	CK_I_MD5_MAC_STATE_PTR mac_state = NULL_PTR;

	/* get and check key data */
	if(CI_ObjLookup(key_obj,CK_IA_VALUE) == NULL_PTR)
	  {
	    rv = CKR_KEY_TYPE_INCONSISTENT;
	    CI_LogEntry("CI_Ceay_VerifyInit","checking key data",rv,0);
	    return rv;
	  }

	key_len = CI_ObjLookup(key_obj,CK_IA_VALUE)->ulValueLen;
	key_data = CI_ObjLookup(key_obj,CK_IA_VALUE)->pValue;

	/* safety check of mechanism parameter */
	if(pMechanism->ulParameterLen != sizeof(CK_MAC_GENERAL_PARAMS))
	  {
	    rv = CKR_MECHANISM_PARAM_INVALID;
	    CI_LogEntry("CI_Ceay_VerifyInit","checking validity of mechanism",rv,0);
	    return rv;
	  }

	/* Allocating data structures */
	mac_state= CI_MD5_MAC_STATE_new();
	if (mac_state == NULL_PTR)
	  {
	    rv = CKR_HOST_MEMORY;
	    CI_LogEntry("CI_Ceay_VerifyInit", "alloc'ing state", rv ,0);
	    return rv;
	  }
	session_data->sign_state  = mac_state;
	session_data->sign_mechanism = CKM_SSL3_MD5_MAC;

	mac_state->params = *((CK_MAC_GENERAL_PARAMS_PTR)pMechanism->pParameter);
	
	/* start hashing of key */
	MD5_Update(mac_state->inner_CTX,key_data,key_len);
	MD5_Update(mac_state->inner_CTX,CK_I_ssl3_pad1,CK_I_ssl3_md5_pad_len);

	/* start hashing of key */
	MD5_Update(mac_state->outer_CTX,key_data,key_len);
	MD5_Update(mac_state->outer_CTX,CK_I_ssl3_pad2,CK_I_ssl3_md5_pad_len);
	
	break;	
      }
    break;
    /* }}} */
      /* {{{ CKM_SSL3_SHA1_MAC */
    case CKM_SSL3_SHA1_MAC:
      {
	CK_BYTE_PTR key_data = NULL_PTR;
	CK_ULONG key_len;
	CK_I_SHA_MAC_STATE_PTR mac_state = NULL_PTR;

	/* get and check key data */
	if(CI_ObjLookup(key_obj,CK_IA_VALUE) == NULL_PTR)
	  {
	    rv = CKR_KEY_TYPE_INCONSISTENT;
	    CI_LogEntry("CI_Ceay_VerifyInit","checking key data",rv,0);
	    return rv;
	  }

	key_len = CI_ObjLookup(key_obj,CK_IA_VALUE)->ulValueLen;
	key_data = CI_ObjLookup(key_obj,CK_IA_VALUE)->pValue;

	/* safety check of mechanism parameter */
	if(pMechanism->ulParameterLen != sizeof(CK_MAC_GENERAL_PARAMS))
	  {
	    rv = CKR_MECHANISM_PARAM_INVALID;
	    CI_LogEntry("CI_Ceay_VerifyInit","checking validity of mechanism",rv,0);
	    return rv;
	  }

	/* Allocating data structures */
	mac_state= CI_SHA_MAC_STATE_new();
	if (mac_state == NULL_PTR)
	  {
	    rv = CKR_HOST_MEMORY;
	    CI_LogEntry("CI_Ceay_VerifyInit", "alloc'ing state", rv ,0);
	    return rv;
	  }
	session_data->sign_state  = mac_state;
       	session_data->sign_mechanism = CKM_SSL3_SHA1_MAC;

	mac_state->params = *((CK_MAC_GENERAL_PARAMS_PTR)pMechanism->pParameter);
	
	/* start hashing of key */
	CI_Ceay_SHA1_Update(mac_state->inner_CTX,key_data,key_len);
	CI_Ceay_SHA1_Update(mac_state->inner_CTX,CK_I_ssl3_pad1,CK_I_ssl3_sha_pad_len);

	/* start hashing of key */
	CI_Ceay_SHA1_Update(mac_state->outer_CTX,key_data,key_len);
	CI_Ceay_SHA1_Update(mac_state->outer_CTX,CK_I_ssl3_pad2,CK_I_ssl3_sha_pad_len);
	
	break;	
      }
    break;
    /* }}} */
    default:
      rv = CKR_MECHANISM_INVALID;
    }

  return rv;
}
/* }}} */
/* {{{ CI_Ceay_Verify */
CK_DEFINE_FUNCTION(CK_RV, CI_Ceay_Verify)(
  CK_I_SESSION_DATA_PTR  session_data,
  CK_BYTE_PTR       pData,          /* signed data */
  CK_ULONG          ulDataLen,      /* length of signed data */
  CK_BYTE_PTR       pSignature,     /* signature */
  CK_ULONG          ulSignatureLen  /* signature length*/
)
{
  CK_RV rv = CKR_OK;
  CK_ULONG digestLen;

  CI_LogEntry("CI_Ceay_Verify", "starting...", rv, 2);      

  switch(session_data->verify_mechanism)
    {
      /* {{{ CKM_RSA_PKCS */
    case CKM_RSA_PKCS:
      {
	CK_BYTE_PTR tmp_buf = NULL_PTR;
	CK_ULONG sign_len;
	long processed; /* number of bytes processed by the crypto routine */

	sign_len = CI_Ceay_RSA_size((RSA CK_PTR)session_data->verify_state);
	if(sign_len != ulSignatureLen)
	  {
	    rv = CKR_SIGNATURE_LEN_RANGE;
	    goto rsa_pkcs1_err;
	  };
	
	tmp_buf = CI_ByteStream_new(sign_len);
	if(tmp_buf == NULL_PTR) { rv = CKR_HOST_MEMORY; goto rsa_pkcs1_err; }
	
	processed = CI_Ceay_RSA_public_decrypt(ulSignatureLen,pSignature,tmp_buf,
					session_data->verify_state,
					RSA_PKCS1_PADDING);
	if(processed == -1)
	  { rv = CKR_GENERAL_ERROR; goto rsa_pkcs1_err; }

	if(ulDataLen != processed)
	  {
	    rv = CKR_DATA_LEN_RANGE;
	    goto rsa_pkcs1_err;
	  };
	
	if(memcmp(pData,tmp_buf,processed)!= 0)
	    rv = CKR_SIGNATURE_INVALID;
	
      rsa_pkcs1_err:
	if(tmp_buf != NULL_PTR) TC_free(tmp_buf);
	if(session_data->verify_state != NULL_PTR)
	  { 
	    CI_Ceay_RSA_free(session_data->verify_state); 
	    session_data->verify_state = NULL_PTR;
	  }
      }
      break;
      /* }}} */
      /* {{{ CKM_RSA_X_509 */
    case CKM_RSA_X_509:
      {
	CK_BYTE_PTR tmp_buf = NULL_PTR;
	CK_ULONG sign_len;
	long processed; /* number of bytes processed by the crypto routine */

	sign_len = CI_Ceay_RSA_size((RSA CK_PTR)session_data->verify_state);
	if(sign_len != ulSignatureLen)
	  {
	    rv = CKR_SIGNATURE_LEN_RANGE;
	    goto rsa_x509_err;
	  };
	
	tmp_buf = CI_ByteStream_new(sign_len);
	if(tmp_buf == NULL_PTR) { rv = CKR_HOST_MEMORY; goto rsa_x509_err; }
	
	processed = CI_Ceay_RSA_public_decrypt(ulSignatureLen,pSignature,tmp_buf,
					session_data->verify_state,
					RSA_NO_PADDING);
	if(processed == -1)
	  { rv = CKR_GENERAL_ERROR; goto rsa_x509_err; }

	if(ulDataLen != processed)
	  {
	    rv = CKR_DATA_LEN_RANGE;
	    goto rsa_x509_err;
	  };
	
	if(memcmp(pData,tmp_buf,processed)!= 0)
	    rv = CKR_SIGNATURE_INVALID;
	
      rsa_x509_err:
	if(tmp_buf != NULL_PTR) TC_free(tmp_buf);
	if(session_data->verify_state != NULL_PTR)
	  { 
	    CI_Ceay_RSA_free(session_data->verify_state); 
	    session_data->verify_state = NULL_PTR;
	  }
      }
      break;
      /* }}} */
      /* {{{ CKM_SHA1_RSA_PKCS */
    case CKM_SHA1_RSA_PKCS:
      {
	CK_BYTE_PTR tmp_buf = NULL_PTR;
	CK_BYTE_PTR tmp_buf1 = NULL_PTR;
	CK_ULONG sign_len;
	long processed; /* number of bytes processed by the crypto routine */
	
	sign_len = CI_Ceay_RSA_size((RSA CK_PTR)session_data->verify_state);
	if(sign_len != ulSignatureLen)
	  {
	    rv = CKR_SIGNATURE_LEN_RANGE;
	    goto sha1_rsa_pkcs1_err;
	  };
	
	tmp_buf = CI_ByteStream_new(sign_len);
	if(tmp_buf == NULL_PTR) { rv = CKR_HOST_MEMORY; goto sha1_rsa_pkcs1_err; }
	
	CI_Ceay_SHA1_Update((SHA_CTX CK_PTR)session_data->digest_state,pData,ulDataLen);
	CI_Ceay_SHA1_Final(tmp_buf,(SHA_CTX CK_PTR)session_data->digest_state);
	session_data->digest_state = NULL_PTR;
	
	tmp_buf1 = CI_ByteStream_new(sign_len);
	if(tmp_buf1 == NULL_PTR) { rv = CKR_HOST_MEMORY; goto sha1_rsa_pkcs1_err; }
	
	processed = CI_Ceay_RSA_public_decrypt(ulSignatureLen,pSignature,tmp_buf1,
				       session_data->verify_state,
				       RSA_PKCS1_PADDING);
	if(processed == -1)
	  { rv = CKR_GENERAL_ERROR; goto sha1_rsa_pkcs1_err; }
	
	if(SHA_DIGEST_LENGTH  != processed)
	  {
	    rv = CKR_DATA_LEN_RANGE;
	    goto sha1_rsa_pkcs1_err;
	  };
	
	if(memcmp(tmp_buf1,tmp_buf,processed)!= 0)
	  rv = CKR_SIGNATURE_INVALID;
	
      sha1_rsa_pkcs1_err:
	TC_free(session_data->digest_state);
	if(tmp_buf != NULL_PTR) TC_free(tmp_buf);
	if(tmp_buf1 != NULL_PTR) TC_free(tmp_buf1);
	if(session_data->verify_state != NULL_PTR)
	  CI_Ceay_RSA_free(session_data->verify_state);
	session_data->verify_state = NULL_PTR;
      }
      break;
      /* }}} */
      /* {{{ CKM_DSA */
    case CKM_DSA:
      {
	int ret;

	if(ulSignatureLen != CK_I_DSA_SIGN_LEN)
	  {
	    rv = CKR_SIGNATURE_LEN_RANGE;
	    goto dsa_err;
	  };

	if(ulDataLen != CK_I_DSA_DIGEST_LEN)
	  {
	    rv = CKR_DATA_LEN_RANGE;
	    goto dsa_err;
	  };
	
	ret = DSA_verify(0,
			 pData,ulDataLen,
			 pSignature,ulSignatureLen,
			 session_data->verify_state);
	/* actual error */
	if(ret == -1)
	  { rv = CKR_GENERAL_ERROR; goto dsa_err; }
	
	if(ret == 0)
	  rv = CKR_SIGNATURE_INVALID;
      dsa_err:
	if(session_data->verify_state != NULL_PTR)
	  { 
	    DSA_free(session_data->verify_state); 
	    session_data->verify_state = NULL_PTR;
	  }
      }
      break;
      /* }}} */
      /* {{{ CKM_DSA_SHA1 */
    case CKM_DSA_SHA1:
      {
	CK_BYTE_PTR tmp_buf = NULL_PTR;
	long ret;
	
	tmp_buf = CI_ByteStream_new(SHA_DIGEST_LENGTH);
	if(tmp_buf == NULL_PTR) { rv = CKR_HOST_MEMORY; goto dsa_sha1_err; }
	
	CI_Ceay_SHA1_Update((SHA_CTX CK_PTR)session_data->digest_state,pData,ulDataLen);
	CI_Ceay_SHA1_Final(tmp_buf,(SHA_CTX CK_PTR)session_data->digest_state);
	session_data->digest_state = NULL_PTR;
	
	ret = DSA_verify(0, tmp_buf,SHA_DIGEST_LENGTH,
			 pSignature,ulSignatureLen,
			 session_data->verify_state);
	/* actual error */
	if(ret == -1)
	  { rv = CKR_GENERAL_ERROR; goto dsa_sha1_err; }
	
	if(ret == 0)
	  rv = CKR_SIGNATURE_INVALID;
      dsa_sha1_err:
	TC_free(session_data->digest_state);
	if(tmp_buf != NULL_PTR) TC_free(tmp_buf);
	if(session_data->verify_state != NULL_PTR)
	  DSA_free(session_data->verify_state);
	session_data->verify_state = NULL_PTR;
      }
      break;
      /* }}} */
      /* {{{ CKM_SSL3_MD5_MAC */
    case CKM_SSL3_MD5_MAC:
      {
	CK_BYTE internal_hash[MD5_DIGEST_LENGTH];
	CK_I_MD5_MAC_STATE_PTR mac_state = NULL_PTR;


	mac_state = (CK_I_MD5_MAC_STATE_PTR)session_data->sign_state;
	digestLen = mac_state->params;
	
	if(ulSignatureLen != digestLen)
	  {
	    rv = CKR_SIGNATURE_INVALID;
	    CI_LogEntry("CI_Ceay_Verify","checking lenght of signature", rv, 0);
	    goto ssl3_md5_mac_verify_error;
	  }

	/* add piece of data */
	MD5_Update(mac_state->inner_CTX,pData,ulDataLen);

	/* wrap up the digesting of the data */
	MD5_Final(internal_hash,mac_state->inner_CTX);
	
	/* perform outer hash */
	MD5_Update(mac_state->outer_CTX,internal_hash,MD5_DIGEST_LENGTH);
	MD5_Final(internal_hash,mac_state->outer_CTX);

	if(memcmp(pSignature,internal_hash,digestLen) != 0)
	  {
	    rv = CKR_SIGNATURE_INVALID;
	    CI_LogEntry("CI_Ceay_Verify","comparing signature", rv, 0);
	    goto ssl3_md5_mac_verify_error;
	  }

      ssl3_md5_mac_verify_error:
	/* _LOCK(mutex); */
        TC_free(mac_state->inner_CTX);
	TC_free(mac_state->outer_CTX);
	TC_free(mac_state);
	session_data->digest_state = NULL_PTR;
	/* _UNLOCK(mutex); */
	
      }
    /* }}} */
      /* {{{ CKM_SSL3_SHA1_MAC */
    case CKM_SSL3_SHA1_MAC:
      {
	CK_BYTE internal_hash[SHA_DIGEST_LENGTH];
	CK_I_SHA_MAC_STATE_PTR mac_state = NULL_PTR;


	mac_state = (CK_I_SHA_MAC_STATE_PTR)session_data->sign_state;
	digestLen = mac_state->params;
	
	if(ulSignatureLen != digestLen)
	  {
	    rv = CKR_SIGNATURE_INVALID;
	    CI_LogEntry("CI_Ceay_Verify","checking lenght of signature", rv, 0);
	    goto ssl3_sha_mac_verify_error;
	  }

	/* add piece of data */
	CI_Ceay_SHA1_Update(mac_state->inner_CTX,pData,ulDataLen);

	/* wrap up the digesting of the data */
	CI_Ceay_SHA1_Final(internal_hash,mac_state->inner_CTX);
	
	/* perform outer hash */
	CI_Ceay_SHA1_Update(mac_state->outer_CTX,internal_hash,SHA_DIGEST_LENGTH);
	CI_Ceay_SHA1_Final(internal_hash,mac_state->outer_CTX);

	if(memcmp(pSignature,internal_hash,digestLen) != 0)
	  {
	    rv = CKR_SIGNATURE_INVALID;
	    CI_LogEntry("CI_Ceay_Verify","comparing signature", rv, 0);
	    goto ssl3_sha_mac_verify_error;
	  }

      ssl3_sha_mac_verify_error:
	/* _LOCK(mutex); */
        TC_free(mac_state->inner_CTX);
	TC_free(mac_state->outer_CTX);
	TC_free(mac_state);
	session_data->digest_state = NULL_PTR;
	/* _UNLOCK(mutex); */
	
      }
    /* }}} */
    default:
      rv = CKR_MECHANISM_INVALID;
      CI_VarLogEntry("CI_Ceay_Verify", "invalid_mechanism: %lx", rv, 0,
		     session_data->verify_mechanism);      
    }

  if(rv == CKR_OK) CI_LogEntry("CI_Ceay_Verify", "...complete", rv, 2);      

  return rv;
}
/* }}} */
/* {{{ CI_Ceay_VerifyUpdate */
CK_DEFINE_FUNCTION(CK_RV, CI_Ceay_VerifyUpdate)(
  CK_I_SESSION_DATA_PTR  session_data,
  CK_BYTE_PTR       pPart,     /* signed data */
  CK_ULONG          ulPartLen  /* length of signed data */
)
{
  CK_RV rv = CKR_OK;

  CI_LogEntry("CI_Ceay_VerifyUpdate","starting...",rv,2);

  switch(session_data->verify_mechanism)
    {
      /* {{{ CKM_SHA1_RSA_PKCS + CKM_DSA_SHA1 */
     case CKM_SHA1_RSA_PKCS:
     case CKM_DSA_SHA1:
       {
	 CI_Ceay_SHA1_Update((SHA_CTX CK_PTR)session_data->digest_state,
			     (unsigned char *)pPart,ulPartLen);
	 
       }
       break;
       /* }}} */
      /* {{{ CKM_SSL3_MD5_MAC */
    case CKM_SSL3_MD5_MAC:
      {
	/* add piece of data */
	MD5_Update(((CK_I_MD5_MAC_STATE_PTR)session_data->sign_state)->inner_CTX,pPart,ulPartLen);
      }
      break;
      /* }}} */
      /* {{{ CKM_SSL3_SHA1_MAC */
    case CKM_SSL3_SHA1_MAC:
      {
	/* add piece of data */
	CI_Ceay_SHA1_Update(((CK_I_SHA_MAC_STATE_PTR)session_data->sign_state)->inner_CTX,pPart,ulPartLen);
      }
    break;
    /* }}} */
    default:
      rv = CKR_MECHANISM_INVALID;
    }

  CI_LogEntry("CI_Ceay_VerifyUpdate","...complete",rv,2);

  return rv;
}
/* }}} */
/* {{{ CI_Ceay_VerifyFinal */
CK_DEFINE_FUNCTION(CK_RV, CI_Ceay_VerifyFinal)(
  CK_I_SESSION_DATA_PTR  session_data,
  CK_BYTE_PTR       pSignature,     /* signature to verify */
  CK_ULONG          ulSignatureLen  /* signature length */
)
{
  CK_RV rv = CKR_OK;
  CK_ULONG digestLen;
  CK_VOID_PTR mutex = NULL_PTR;
  
  CI_LogEntry("CI_Ceay_VerifyFinal","starting...",rv,2);
  
  rv =CI_CreateMutex(&mutex);
  if(rv != CKR_OK)
    {
      CI_LogEntry("CI_Ceay_VerifyFinal","setting mutex",rv,0);
      return rv;
    }
  
  switch(session_data->verify_mechanism)
    {
      /* {{{ CKM_DSA_SHA1 */
    case CKM_DSA_SHA1:
      {
	CK_BYTE_PTR tmp_buf = NULL_PTR;
	long ret;
	
	tmp_buf = CI_ByteStream_new(SHA_DIGEST_LENGTH);
	if(tmp_buf == NULL_PTR) { rv = CKR_HOST_MEMORY; goto dsa_sha1_err; }
	
	CI_Ceay_SHA1_Final(tmp_buf,(SHA_CTX CK_PTR)session_data->digest_state);
	session_data->digest_state = NULL_PTR;
	
	ret = DSA_verify(0, tmp_buf, SHA_DIGEST_LENGTH,
			 pSignature, ulSignatureLen,
			 session_data->verify_state);
	/* actual error */
	if(ret == -1)
	  { rv = CKR_GENERAL_ERROR; goto dsa_sha1_err; }
	
	if(ret == 0)
	  rv = CKR_SIGNATURE_INVALID;
      dsa_sha1_err:
	TC_free(session_data->digest_state);
	if(tmp_buf != NULL_PTR) TC_free(tmp_buf);
	if(session_data->verify_state != NULL_PTR)
	  DSA_free(session_data->verify_state);
	session_data->verify_state = NULL_PTR;
      }
      break;
      /* }}} */
      /* {{{ CKM_SHA1_RSA_PKCS */
    case CKM_SHA1_RSA_PKCS:
      {
	CK_BYTE_PTR tmp_buf = NULL_PTR;
	CK_BYTE_PTR tmp_buf1 = NULL_PTR;
	CK_ULONG sign_len;
	long processed; /* number of bytes processed by the crypto routine */
	
	sign_len = CI_Ceay_RSA_size((RSA CK_PTR)session_data->verify_state);
	if(sign_len != ulSignatureLen)
	  {
	    rv = CKR_SIGNATURE_LEN_RANGE;
	    goto sha1_rsa_pkcs1_err;
	  };
	
	tmp_buf = CI_ByteStream_new(sign_len);
	if(tmp_buf == NULL_PTR) { rv = CKR_HOST_MEMORY; goto sha1_rsa_pkcs1_err; }
	
	CI_Ceay_SHA1_Final(tmp_buf,(SHA_CTX CK_PTR)session_data->digest_state);
	session_data->digest_state = NULL_PTR;
	
	tmp_buf1 = CI_ByteStream_new(sign_len);
	if(tmp_buf1 == NULL_PTR) { rv = CKR_HOST_MEMORY; goto sha1_rsa_pkcs1_err; }
	
	processed = CI_Ceay_RSA_public_decrypt(ulSignatureLen,pSignature,tmp_buf1,
				       session_data->verify_state,
				       RSA_PKCS1_PADDING);
	if(processed == -1)
	  { rv = CKR_GENERAL_ERROR; goto sha1_rsa_pkcs1_err; }
	
	if(SHA_DIGEST_LENGTH  != processed)
	  {
	    rv = CKR_DATA_LEN_RANGE;
	    goto sha1_rsa_pkcs1_err;
	  };
	
	if(memcmp(tmp_buf1,tmp_buf,processed)!= 0)
	  rv = CKR_SIGNATURE_INVALID;
	
      sha1_rsa_pkcs1_err:
	TC_free(session_data->digest_state);
	if(tmp_buf != NULL_PTR) TC_free(tmp_buf);
	if(tmp_buf1 != NULL_PTR) TC_free(tmp_buf1);
	if(session_data->verify_state != NULL_PTR)
	  CI_Ceay_RSA_free(session_data->verify_state);
	session_data->verify_state = NULL_PTR;
      }
      break;
      /* }}} */
      /* {{{ CKM_SSL3_MD5_MAC */
    case CKM_SSL3_MD5_MAC:
      {
	CK_BYTE internal_hash[MD5_DIGEST_LENGTH];
	CK_I_MD5_MAC_STATE_PTR mac_state = NULL_PTR;


	mac_state = (CK_I_MD5_MAC_STATE_PTR)session_data->sign_state;
	digestLen = mac_state->params;
	
	if(ulSignatureLen != digestLen)
	  {
	    rv = CKR_SIGNATURE_INVALID;
	    CI_LogEntry("CI_Ceay_Verify","checking lenght of signature", rv, 0);
	    goto ssl3_md5_mac_verify_error;
	  }


	/* wrap up the digesting of the data */
	MD5_Final(internal_hash,mac_state->inner_CTX);
	
	/* perform outer hash */
	MD5_Update(mac_state->outer_CTX,internal_hash,MD5_DIGEST_LENGTH);
	MD5_Final(internal_hash,mac_state->outer_CTX);

	if(memcmp(pSignature,internal_hash,digestLen) != 0)
	  {
	    rv = CKR_SIGNATURE_INVALID;
	    CI_LogEntry("CI_Ceay_Verify","comparing signature", rv, 0);
	    goto ssl3_md5_mac_verify_error;
	  }

      ssl3_md5_mac_verify_error:
	_LOCK(mutex);
        TC_free(mac_state->inner_CTX);
	TC_free(mac_state->outer_CTX);
	TC_free(mac_state);
	session_data->digest_state = NULL_PTR;
	_UNLOCK(mutex);
	
      }
    /* }}} */
      /* {{{ CKM_SSL3_SHA1_MAC */
    case CKM_SSL3_SHA1_MAC:
      {
	CK_BYTE internal_hash[SHA_DIGEST_LENGTH];
	CK_I_SHA_MAC_STATE_PTR mac_state = NULL_PTR;


	mac_state = (CK_I_SHA_MAC_STATE_PTR)session_data->sign_state;
	digestLen = mac_state->params;
	
	if(ulSignatureLen != digestLen)
	  {
	    rv = CKR_SIGNATURE_INVALID;
	    CI_LogEntry("CI_Ceay_Verify","checking lenght of signature", rv, 0);
	    goto ssl3_sha_mac_verify_error;
	  }


	/* wrap up the digesting of the data */
	CI_Ceay_SHA1_Final(internal_hash,mac_state->inner_CTX);
	
	/* perform outer hash */
	CI_Ceay_SHA1_Update(mac_state->outer_CTX,internal_hash,SHA_DIGEST_LENGTH);
	CI_Ceay_SHA1_Final(internal_hash,mac_state->outer_CTX);

	if(memcmp(pSignature,internal_hash,digestLen) != 0)
	  {
	    rv = CKR_SIGNATURE_INVALID;
	    CI_LogEntry("CI_Ceay_Verify","comparing signature", rv, 0);
	    goto ssl3_sha_mac_verify_error;
	  }

      ssl3_sha_mac_verify_error:
	_LOCK(mutex);
        TC_free(mac_state->inner_CTX);
	TC_free(mac_state->outer_CTX);
	TC_free(mac_state);
	session_data->digest_state = NULL_PTR;
	_UNLOCK(mutex);
	
      }
    /* }}} */
    default:
      rv = CKR_MECHANISM_INVALID;
    }

  rv =CI_DestroyMutex(mutex);
  if(rv != CKR_OK)
    {
      CI_LogEntry("CI_Ceay_VerifyFinal","destroying mutex",rv,0);
      return rv;
    }


  CI_LogEntry("CI_Ceay_VerifyFinal","...complete",rv,2);
  return rv;
}
/* }}} */

/* {{{ CI_Ceay_VerifyRecoverInit */
CK_DEFINE_FUNCTION(CK_RV, CI_Ceay_VerifyRecoverInit)(
  CK_I_SESSION_DATA_PTR  session_data,
  CK_MECHANISM_PTR  pMechanism,  /* the verification mechanism */
  CK_I_OBJ_PTR      key_obj      /* verification key */
)
{
  CK_RV rv;

  switch(pMechanism->mechanism)
    {
      /* {{{ CKM_RSA_PKCS */
    case CKM_RSA_PKCS:
      {
	RSA CK_PTR internal_key_obj = NULL_PTR;
	
	rv = CKR_OK;
	
	/* check that object is a public key */
	if(*((CK_OBJECT_CLASS CK_PTR)CI_ObjLookup(key_obj,CK_IA_CLASS)->pValue) != CKO_PUBLIC_KEY)
	  return CKR_KEY_TYPE_INCONSISTENT;
	
	internal_key_obj = CI_Ceay_Obj2RSA(key_obj);
	if(internal_key_obj == NULL_PTR)
	  return CKR_HOST_MEMORY;
	
	session_data->verify_state = (CK_VOID_PTR)internal_key_obj;
	session_data->verify_mechanism = CKM_RSA_PKCS;
      }
      break;
      /* }}} */
      /* {{{ CKM_RSA_X_509 */
    case CKM_RSA_X_509:
      {
	RSA CK_PTR internal_key_obj = NULL_PTR;
	
	rv = CKR_OK;
	
	/* check that object is a public key */
	if(*((CK_OBJECT_CLASS CK_PTR)CI_ObjLookup(key_obj,CK_IA_CLASS)->pValue) != CKO_PUBLIC_KEY)
	  return CKR_KEY_TYPE_INCONSISTENT;
	
	internal_key_obj = CI_Ceay_Obj2RSA(key_obj);
	if(internal_key_obj == NULL_PTR)
	  return CKR_HOST_MEMORY;
	
	session_data->verify_state = (CK_VOID_PTR)internal_key_obj;
	session_data->verify_mechanism = CKM_RSA_X_509;
      }
      break;
      /* }}} */
    default:
      rv = CKR_MECHANISM_INVALID;
    }

  return rv;
}
/* }}} */
/* {{{ CI_Ceay_VerifyRecover */
CK_DEFINE_FUNCTION(CK_RV, CI_Ceay_VerifyRecover)(
  CK_I_SESSION_DATA_PTR  session_data,
  CK_BYTE_PTR       pSignature,      /* signature to verify */
  CK_ULONG          ulSignatureLen,  /* signature length */
  CK_BYTE_PTR       pData,           /* gets signed data */
  CK_ULONG_PTR      pulDataLen       /* gets signed data len */
)
{
  CK_RV rv = CKR_OK;

  CI_LogEntry("CI_Ceay_VerifyRecover", "starting...", rv, 2);

  switch(session_data->verify_mechanism)
    {
      /* {{{ CKM_RSA_PKCS */
      /* 
       * TODO: liegt das nur am RSA_PKCS oder ist 
       * hier niemals CKR_SIGNATURE_INVALID zu melden? 
       */
    case CKM_RSA_PKCS:
      {
	CK_ULONG sign_len;
	long processed; /* number of bytes processed by the crypto routine */

	CI_LogEntry("CI_Ceay_VerifyRecover", "doing CKM_RSA_PKCS", rv, 2);

	sign_len = CI_Ceay_RSA_size((RSA CK_PTR)session_data->verify_state);

	CI_LogEntry("CI_Ceay_VerifyRecover", "done computing sign_len", rv, 2);

	/* only test length of return buffer */
	if(pData == NULL_PTR)
	  {
	    *pulDataLen =sign_len;
	    CI_LogEntry("CI_Ceay_VerifyRecover", "only a buffer len test", rv, 2);
	    return CKR_OK; /* keep operation active for another try */
	  }

	CI_LogEntry("CI_Ceay_VerifyRecover", "check for differing signature lens", rv, 2);
	if(sign_len != ulSignatureLen)
	  {
	    rv = CKR_SIGNATURE_LEN_RANGE;
	    goto rsa_pkcs1_err; /* stop operation as Signature has failed */
	  };
	
	if(sign_len > *pulDataLen)
	  {
	    *pulDataLen = sign_len;
	    return CKR_BUFFER_TOO_SMALL; /* keep operation active for another try */
	  }

	processed = CI_Ceay_RSA_public_decrypt(ulSignatureLen,pSignature,pData,
					session_data->verify_state,
					RSA_PKCS1_PADDING);
	if(processed == -1)
	  { rv = CKR_GENERAL_ERROR; goto rsa_pkcs1_err; }

	*pulDataLen = processed;
	
      rsa_pkcs1_err:
	if(session_data->verify_state != NULL_PTR)
	  { 
	    CI_Ceay_RSA_free(session_data->verify_state); 
	    session_data->verify_state = NULL_PTR;
	  }
      }      
      break;
      /* }}} */
      /* {{{ CKM_RSA_X_509 */
      /* 
       * TODO: is it only PSA_X_509 or is there never the case of CKR_SIGNATURE_INVALID to
       * report? 
       */
    case CKM_RSA_X_509:
      {
	CK_ULONG sign_len;
	long processed; /* number of bytes processed by the crypto routine */

	CI_LogEntry("CI_Ceay_VerifyRecover", "doing CKM_RSA_PKCS", rv, 2);

	sign_len = CI_Ceay_RSA_size((RSA CK_PTR)session_data->verify_state);

	CI_LogEntry("CI_Ceay_VerifyRecover", "done computing sign_len", rv, 2);

	/* only test length of return buffer */
	if(pData == NULL_PTR)
	  {
	    *pulDataLen =sign_len;
	    CI_LogEntry("CI_Ceay_VerifyRecover", "only a buffer len test", rv, 2);
	    return CKR_OK; /* keep operation active for another try */
	  }

	CI_LogEntry("CI_Ceay_VerifyRecover", "check for differing signature lens", rv, 2);
	if(sign_len != ulSignatureLen)
	  {
	    rv = CKR_SIGNATURE_LEN_RANGE;
	    goto rsa_x509_err; /* stop operation as Signature has failed */
	  };
	
	if(sign_len > *pulDataLen)
	  {
	    *pulDataLen = sign_len;
	    return CKR_BUFFER_TOO_SMALL; /* keep operation active for another try */
	  }

	processed = CI_Ceay_RSA_public_decrypt(ulSignatureLen,pSignature,pData,
					session_data->verify_state,
					RSA_NO_PADDING);
	if(processed == -1)
	  { rv = CKR_GENERAL_ERROR; goto rsa_x509_err; }

	*pulDataLen = processed;

	
      rsa_x509_err:
	if(session_data->verify_state != NULL_PTR)
	  { 
	    CI_Ceay_RSA_free(session_data->verify_state); 
	    session_data->verify_state = NULL_PTR;
	  }
      }      
      break;
      /* }}} */
    default:
      rv = CKR_MECHANISM_INVALID;
      CI_VarLogEntry("CI_Ceay_VerifyRecover", "invalid_mechanism: %lx", rv, 0,
		     session_data->verify_mechanism);      
    }

  CI_LogEntry("CI_Ceay_VerifyRecover", "...complete", rv, 2);

  return rv;
}
/* }}} */

/* {{{ CI_Ceay_DigestEncryptUpdate */
CK_DEFINE_FUNCTION(CK_RV, CI_Ceay_DigestEncryptUpdate)(
  CK_I_SESSION_DATA_PTR  session_data,
  CK_BYTE_PTR       pPart,               /* the plaintext data */
  CK_ULONG          ulPartLen,           /* plaintext length */
  CK_BYTE_PTR       pEncryptedPart,      /* gets ciphertext */
  CK_ULONG_PTR      pulEncryptedPartLen  /* gets c-text length */
)
{
  /* 
   * no need to check that there are active Digest and Encrypt Mechanism! 
   * Done by the wrapper! 
   */

  CK_RV rv;

  /* 
   * encrypt first so we may keep the plaintext from the digester 
   * if encryption fails. 
   */
  rv = CI_Ceay_EncryptUpdate(session_data, pPart, ulPartLen, pEncryptedPart, pulEncryptedPartLen);  
  if(rv != CKR_OK)
    return rv;

  /* 
   * If the call to was only to check the length of the output buffer, 
   * rv will be CKR_OK, but we still don't want to digest the data.
   */
  if(pEncryptedPart == NULL_PTR)
    return CKR_OK;

  return CI_Ceay_DigestUpdate(session_data, pPart, ulPartLen);

}
/* }}} */
/* {{{ CI_Ceay_DecryptDigestUpdate */
CK_DEFINE_FUNCTION(CK_RV, CI_Ceay_DecryptDigestUpdate)(
  CK_I_SESSION_DATA_PTR  session_data,
  CK_BYTE_PTR       pEncryptedPart,      /* ciphertext */
  CK_ULONG          ulEncryptedPartLen,  /* ciphertext length */
  CK_BYTE_PTR       pPart,               /* gets plaintext */
  CK_ULONG_PTR      pulPartLen           /* gets plaintext len */
)
{
  /* 
   * no need to check that there are active Digest and Decrypt Mechanism! 
   * Done by the wrapper! 
   */

  CK_RV rv;

  /* 
   * decrypt first so we may keep the plaintext from the digester 
   * if encryption fails. 
   */
  rv = CI_Ceay_DecryptUpdate(session_data, pEncryptedPart, ulEncryptedPartLen, pPart, pulPartLen);  
  if(rv != CKR_OK)
    return rv;

  /* 
   * If the call to was only to check the length of the output buffer, 
   * rv will be CKR_OK, but we still don't want to digest the data.
   */
  if(pPart == NULL_PTR)
    return CKR_OK;

  return CI_Ceay_DigestUpdate(session_data, pPart, *pulPartLen);
}
/* }}} */
/* {{{ CI_Ceay_SignEncryptUpdate */
CK_DEFINE_FUNCTION(CK_RV, CI_Ceay_SignEncryptUpdate)(
  CK_I_SESSION_DATA_PTR  session_data,
  CK_BYTE_PTR       pPart,               /* the plaintext data */
  CK_ULONG          ulPartLen,           /* plaintext length */
  CK_BYTE_PTR       pEncryptedPart,      /* gets ciphertext */
  CK_ULONG_PTR      pulEncryptedPartLen  /* gets c-text length */
)
{
  /* 
   * no need to check that there are active Sign and Encrypt Mechanism! 
   * Done by the wrapper! 
   */

  CK_RV rv;

  /* 
   * encrypt first so we may keep the plaintext from the digester 
   * if encryption fails. 
   */
  rv = CI_Ceay_EncryptUpdate(session_data, pPart, ulPartLen, pEncryptedPart, pulEncryptedPartLen);  
  if(rv != CKR_OK)
    return rv;

  /* 
   * If the call to was only to check the length of the output buffer, 
   * rv will be CKR_OK, but we still don't want to sign the data.
   */
  if(pEncryptedPart == NULL_PTR)
    return CKR_OK;

  return CI_Ceay_SignUpdate(session_data, pPart, ulPartLen);
}
/* }}} */
/* {{{ CI_Ceay_DecryptVerifyUpdate */
CK_DEFINE_FUNCTION(CK_RV, CI_Ceay_DecryptVerifyUpdate)(
  CK_I_SESSION_DATA_PTR  session_data,
  CK_BYTE_PTR       pEncryptedPart,      /* ciphertext */
  CK_ULONG          ulEncryptedPartLen,  /* ciphertext length */
  CK_BYTE_PTR       pPart,               /* gets plaintext */
  CK_ULONG_PTR      pulPartLen           /* gets p-text length */
)
{
  /* 
   * no need to check that there are active Verify and Encrypt Mechanism! 
   * Done by the wrapper! 
   */

  CK_RV rv;

  /* 
   * decrypt first so we may keep the plaintext from the verifier
   * if decryption fails. 
   */
  rv = CI_Ceay_DecryptUpdate(session_data, pEncryptedPart, ulEncryptedPartLen, pPart, pulPartLen);  
  if(rv != CKR_OK)
    return rv;

  /* 
   * If the call to was only to check the length of the output buffer, 
   * rv will be CKR_OK, but we still don't want to verify the data.
   */
  if(pPart == NULL_PTR)
    return CKR_OK;

  return CI_Ceay_VerifyUpdate(session_data, pPart, *pulPartLen);
}
/* }}} */

/* {{{ CI_Ceay_GenerateKey */
CK_DEFINE_FUNCTION(CK_RV, CI_Ceay_GenerateKey)(
  CK_I_SESSION_DATA_PTR  session_data,
  CK_MECHANISM_PTR       pMechanism,  /* key generation mech. */
  CK_I_OBJ_PTR           key_obj      /* generated key data is put in here */
)
{
  CK_ULONG key_len, rv = CKR_OK;
  CK_I_OBJ_PTR default_obj = NULL_PTR;
  CK_I_OBJ_PTR CK_PTR current_default_obj = NULL_PTR;
  CK_MECHANISM_INFO mechanism_info;
  CK_ATTRIBUTE_PTR current_template = NULL_PTR;
  CK_ULONG current_template_len;
  CK_BYTE_PTR value = NULL_PTR; 

  CI_LogEntry("CI_Ceay_GenerateKey", "starting...", rv, 2);

  rv = CI_Ceay_GetMechanismInfo(pMechanism->mechanism, &mechanism_info);
  if(rv != CKR_OK)
    {
      CI_LogEntry("CI_Ceay_GenerateKey", "...exit: reading mechanism info", rv, 0);
      return rv;
    }
  
  CI_VarLogEntry("CI_Ceay_GenerateKey", "Key Mechanism Type: %i", rv, 2, pMechanism->mechanism);

  /* {{{ Set key template values */
  switch(pMechanism->mechanism)
    {
    case CKM_SSL3_PRE_MASTER_KEY_GEN:
      current_default_obj = &CK_I_ssl3_pre_master_empty_key_obj;
      current_template = CK_I_ssl3_pre_master_empty_key;
      current_template_len = CK_I_ssl3_pre_master_empty_key_count;
      break;
    case CKM_DES_KEY_GEN:
      current_default_obj = &CK_I_des_empty_key_obj;
      current_template = CK_I_des_empty_key;
      current_template_len = CK_I_des_empty_key_count;
      break;
    case CKM_DES3_KEY_GEN:
      current_default_obj = &CK_I_des3_empty_key_obj;
      current_template = CK_I_des3_empty_key;
      current_template_len = CK_I_des3_empty_key_count;
      break;
    case CKM_IDEA_KEY_GEN:
      current_default_obj = &CK_I_idea_empty_key_obj;
      current_template = CK_I_idea_empty_key;
      current_template_len = CK_I_idea_empty_key_count;
      break;
    case CKM_RC4_KEY_GEN:
      current_default_obj = &CK_I_rc4_empty_key_obj;
      current_template = CK_I_rc4_empty_key;
      current_template_len = CK_I_rc4_empty_key_count;
      break;
    case CKM_RC2_KEY_GEN:
      current_default_obj = &CK_I_rc2_empty_key_obj;
      current_template = CK_I_rc2_empty_key;
      current_template_len = CK_I_rc2_empty_key_count;
      break;
    default: /* unknown key type */
      /*
       * The code should never reach this as the validity of the mechanism
       * is checked above!
       */
      rv = CKR_GENERAL_ERROR; 
      CI_LogEntry("CI_Ceay_GenerateKey", "...exit: unknown key type", rv, 0);
      return rv ;
    }
  /* }}} */

  CI_LogEntry("CI_Ceay_GenerateKey", "set template values", rv, 2);

  /* parse the empty_key */
  rv = CI_ObjTemplateInit(current_default_obj,
		     current_template,
		     current_template_len);
  if(rv != CKR_OK)
    {
      CI_LogEntry("CI_Ceay_GenerateKey", "init object template", rv, 0);
      return rv;
    }
  default_obj = *current_default_obj;
  
  CI_LogEntry("CI_Ceay_GenerateKey", "empty key parsed", rv, 2);
  
  switch(pMechanism->mechanism)
    {
    /* {{{ CKM_SSL3_PRE_MASTER_KEY_GEN */
    case CKM_SSL3_PRE_MASTER_KEY_GEN:
      {
	CK_VERSION_PTR tmp_version = NULL_PTR;

	/* template must not specify an inconsistent key type */
	if( (CI_ObjLookup(key_obj,CK_IA_KEY_TYPE) != NULL_PTR)  && 
	   (*((CK_KEY_TYPE CK_PTR)CI_ObjLookup(key_obj,CK_IA_KEY_TYPE)->pValue) != 
	    CKK_GENERIC_SECRET) )
	  {
	    rv = CKR_TEMPLATE_INCONSISTENT;
	    CI_LogEntry("CI_Ceay_GenerateKey", "key type check", rv, 0);
	    return rv;
	  }

	/* Parameter must supply SSL Version */
	if((pMechanism->pParameter == NULL_PTR) ||
	   (pMechanism->ulParameterLen != sizeof(CK_VERSION)))
	  {
	    rv = CKR_MECHANISM_PARAM_INVALID;
	    CI_LogEntry("CI_Ceay_GenerateKey", 
			"Mechanism Parameter check: no SSL Version supplied", rv, 0);
	    return rv;
	  }
     
	/* Setzen der SSL Version im Schlüssel Obj */
	tmp_version = CI_VERSION_new();
	if(tmp_version == NULL_PTR)
	  {
	    rv = CKR_HOST_MEMORY;
	    CI_LogEntry("CI_Ceay_GenerateKey", "memory alloc", rv, 0);
	    return rv;
	  }
	memcpy(tmp_version, pMechanism->pParameter, sizeof(CK_VERSION));


	rv = CI_ObjSetIntAttributeValue(key_obj, CK_IA_SSL_VERSION, 
					tmp_version, sizeof(CK_VERSION));
	if(rv != CKR_OK)
	  {
	    TC_free(tmp_version);
	    CI_LogEntry("CI_Ceay_GenerateKey", "setting CK_IA_SSL_VERSION", rv, 0);
	    return rv;
	  }
	
	CI_LogEntry("CI_Ceay_GenerateKey", "alloc'ing memory for key", rv, 2);
	
	if((value=TC_calloc(1,CK_I_SSL3_PRE_MASTER_SIZE)) == NULL_PTR)
	  {
	    TC_free(tmp_version);
	    rv = CKR_HOST_MEMORY;
	    CI_LogEntry("CI_Ceay_GenerateKey", 
			"key memory alloc", rv, 0);
	    return rv;
	  }
	
	/* writing the version number into the beginning of the key material */
	value[0] = tmp_version->major;
	value[1] = tmp_version->minor;
	TC_free(tmp_version);

	CI_LogEntry("CI_Ceay_GenerateKey", "start generating random", rv, 2);
	rv = CI_Ceay_GenerateRandom(session_data,&(value[2]), 
				    CK_I_SSL3_PRE_MASTER_SIZE-2);
	if(rv != CKR_OK)
	  {
	    /* key_obj wird in der Außenfunktion zerstört */
	    TC_free(value);
	    CI_LogEntry("CI_Ceay_GenerateKey", "generating random", rv, 0);
	    return rv;
	  }
  	
	  {
	    CK_BYTE_PTR tmp_str = NULL_PTR;
	    
	    CI_VarLogEntry("CI_Ceay_GenerateKey", "SSL3 pre Master Secret: %s", rv, 2, 
			   tmp_str = CI_PrintableByteStream(value,
							    CK_I_SSL3_PRE_MASTER_SIZE));
	    TC_free(tmp_str);
	  }

        rv = CI_ObjSetIntAttributeValue(key_obj,CK_IA_VALUE,value,
					CK_I_SSL3_PRE_MASTER_SIZE);
	if(rv != CKR_OK)
	  {
	    /* key_obj wird in der Außenfunktion zerstört */
	    TC_free(value);
	    CI_LogEntry("CI_Ceay_GenerateKey", "inserting key value", rv, 0);
	    return rv;
	  }
	/* data is copied in CI_ObjSetIntAttributeValue(), so clean up */
	TC_free(value);
	
	CI_LogEntry("CI_Ceay_GenerateKey", "SSL3_PRE_MASTER complete", rv, 2);
      }
    break;
    /* }}} */
    /* {{{ CKM_DES_KEY_GEN */
    case CKM_DES_KEY_GEN:
      {
	CK_BBOOL key_correct= FALSE;

	/* template must not specify an inconsistent key type */
	if( (CI_ObjLookup(key_obj,CK_IA_KEY_TYPE) != NULL_PTR)  && 
	   (*((CK_KEY_TYPE CK_PTR)CI_ObjLookup(key_obj,CK_IA_KEY_TYPE)->pValue) != CKK_DES) )
	  return CKR_TEMPLATE_INCONSISTENT;
              
	
	if((value= CI_ByteStream_new(sizeof(des_cblock))) == NULL_PTR)
	  return CKR_HOST_MEMORY;
	
      /* maximale Qualität der Schlüssel erzwingen */
	while(!key_correct)
	  {
	    /* der random number generator ist ja schon im Wrapper mit Zufall gefüllt worden */
	    /* gleich daten holen */
	    /* TODO: wir wissen eigentlich nicht genau ob dieses Token ge-Seeded wurde. Wir sollten
	     * über die Bibliotheks function gehen. 
	     */
	    CI_Ceay_GenerateRandom(session_data,value,sizeof(des_cblock));

	    /* Erzwingen von odd-parity im Key */
	    des_set_odd_parity((des_cblock*)value);
	    key_correct = !des_is_weak_key((des_cblock*)value);
	  }

	rv = CI_ObjSetIntAttributeValue(key_obj,CK_IA_VALUE,value,sizeof(des_cblock));
	if(rv != CKR_OK)
	  {
	    /* key_obj wird in der Außenfunktion zerstört */
	    TC_free(value);
	    return rv;
	  }

      }
    break;
    /* }}} */
    /* {{{ CKM_DES3_KEY_GEN */
    case CKM_DES3_KEY_GEN:
      {
	CK_BYTE key_correct= 0;
	des_cblock keys[3];

	/* template must not specify an inconsistent key type */
	if( (CI_ObjLookup(key_obj,CK_IA_KEY_TYPE) != NULL_PTR)  && 
	   (*((CK_KEY_TYPE CK_PTR)CI_ObjLookup(key_obj,CK_IA_KEY_TYPE)->pValue) != CKK_DES3) )
	  return CKR_TEMPLATE_INCONSISTENT;

	if((value= CI_ByteStream_new(sizeof(des_cblock)*3)) == NULL_PTR)
	  return CKR_HOST_MEMORY;

	/* maximale Qualität der Schlüssel erzwingen */
	while(key_correct<3)
	  {
	    /* der random number generator ist ja schon im Wrapper mit Zufall gefüllt worden */
	    /* gleich daten holen */
	    /* TODO: wir wissen eigentlich nicht genau ob dieses Token ge-Seeded wurde. Wir sollten
	     * über die Bibliotheks function gehen. 
	     */
	    CI_Ceay_GenerateRandom(session_data, 
				   keys[key_correct], 
				   sizeof(des_cblock));

	    /* Erzwingen von odd-parity im Key */
	    des_set_odd_parity(&(keys[key_correct]));
	    if( !des_is_weak_key(&(keys[key_correct])) )
	       key_correct++;

	  }

	rv = CI_ObjSetIntAttributeValue(key_obj,CK_IA_VALUE,value,sizeof(des_cblock)*3);
	if(rv != CKR_OK)
	  {
	    /* key_obj wird in der Außenfunktion zerstört */
	    TC_free(value);
	    return rv;
	  }

      }
    break;
    /* }}} */
    /* {{{ CKM_IDEA_KEY_GEN */
    case CKM_IDEA_KEY_GEN:
      {
	/* template must not specify an inconsistent key type */
	if( (CI_ObjLookup(key_obj,CK_IA_KEY_TYPE) != NULL_PTR)  && 
	   (*((CK_KEY_TYPE CK_PTR)CI_ObjLookup(key_obj,CK_IA_KEY_TYPE)->pValue) != CKK_IDEA) )
	  return CKR_TEMPLATE_INCONSISTENT;

	if((value=CI_ByteStream_new(IDEA_KEY_LENGTH)) == NULL_PTR)
	  return CKR_HOST_MEMORY;
            
	CI_Ceay_GenerateRandom(session_data, 
			       value, 
			       IDEA_KEY_LENGTH);
	
	
	rv = CI_ObjSetIntAttributeValue(key_obj,CK_IA_VALUE,value,IDEA_KEY_LENGTH);
	if(rv != CKR_OK)
	  {
	    /* key_obj wird in der Außenfunktion zerstört */
	    TC_free(value);
	    return rv;
	  }
	
      }
    break;
    /* }}} */
    /* {{{ CKM_RC4_KEY_GEN */
    case CKM_RC4_KEY_GEN:
      {
	/* template must not specify an inconsistent key type */
	if( (CI_ObjLookup(key_obj,CK_IA_KEY_TYPE) != NULL_PTR)  && 
	   (*((CK_KEY_TYPE CK_PTR)CI_ObjLookup(key_obj,CK_IA_KEY_TYPE)->pValue) != CKK_RC4) )
	  return CKR_TEMPLATE_INCONSISTENT;
	
	/* get key len (in bits) */
	if(CI_ObjLookup(key_obj,CK_IA_VALUE_LEN) == NULL_PTR)
	  {
	    return CKR_TEMPLATE_INCOMPLETE; /* no key len specified. Keine Haende keine Kekse! */
	  }

	key_len = *((CK_ULONG_PTR)CI_ObjLookup(key_obj,CK_IA_VALUE_LEN)->pValue);
	
	/* check that key_len is in range */
	if( (key_len < mechanism_info.ulMinKeySize) ||
	    (key_len > mechanism_info.ulMaxKeySize) )
	  {
	    return CKR_ATTRIBUTE_VALUE_INVALID;
	  }
	
	/* get the actual key - simply get key_len/8 bytes from the internal 
	 * random number generator 
	 */

	if((value=CI_ByteStream_new(key_len/8)) == NULL_PTR)
	  {
	    return CKR_HOST_MEMORY;
	}
	
	CI_Ceay_GenerateRandom(session_data,value,key_len/8);
	
	rv = CI_ObjSetIntAttributeValue(key_obj,CK_IA_VALUE,value,key_len/8);
	if(rv != CKR_OK)
	  {
	    /* key_obj wird in der Außenfunktion zerstört */
	    TC_free(value);
	    return rv;
	  }
      }
    break;
    /* }}} */
    /* {{{ CKM_RC2_KEY_GEN */
    case CKM_RC2_KEY_GEN:
      {
	/* template must not specify an inconsistent key type */
	if( (CI_ObjLookup(key_obj,CK_IA_KEY_TYPE) != NULL_PTR)  && 
	   (*((CK_KEY_TYPE CK_PTR)CI_ObjLookup(key_obj,CK_IA_KEY_TYPE)->pValue) != CKK_RC2) )
	  return CKR_TEMPLATE_INCONSISTENT;
		
	/* get key len (in bits) */
	if(CI_ObjLookup(key_obj,CK_IA_VALUE_LEN) == NULL_PTR)
	  {
	    return CKR_TEMPLATE_INCOMPLETE; /* no key len specified. Keine Haende keine Kekse! */
	  }

	key_len = *((CK_ULONG_PTR)CI_ObjLookup(key_obj,CK_IA_VALUE_LEN)->pValue);
	
	/* check that key_len is in range */
	if( (key_len < mechanism_info.ulMinKeySize) ||
	    (key_len > mechanism_info.ulMaxKeySize) )
	  {
	    return CKR_ATTRIBUTE_VALUE_INVALID;
	  }
	
	/* get the actual key - simply get key_len/8 bytes from the internal 
	 * random number generator 
	 */
	if((value=CI_ByteStream_new(key_len/8)) == NULL_PTR)
	  {
	    return CKR_HOST_MEMORY;
	}

      CI_Ceay_GenerateRandom(session_data,value,key_len/8);
      
	rv = CI_ObjSetIntAttributeValue(key_obj,CK_IA_VALUE,value,key_len/8);
	if(rv != CKR_OK)
	  {
	    /* key_obj wird in der Außenfunktion zerstört */
	    TC_free(value);
	    return rv;
	  }
      }
    break;
    /* }}} */
    default: /* unknown key type */
      /*
       * The code should never reach this as the validity of the mechanism
       * is checked above!
       */
      return CKR_GENERAL_ERROR; 
    }


  CI_LogEntry("CI_Ceay_GenerateKey", "key generated", rv, 2);

  rv = CI_ObjMergeObj(key_obj, default_obj, FALSE);
  if(rv != CKR_OK)
    {
      CI_LogEntry("CI_Ceay_GenerateKey", "object merge failed", rv, 2);
      return rv; /* Zerstört wird in der Außenfunktion */
    }

  rv= CI_ObjVerifyObj(default_obj);
  if(rv != CKR_OK)
    {
      CI_LogEntry("CI_Ceay_GenerateKey", "object verify failed", rv, 2);
      return rv; /* Zerstört wird in der Außenfunktion */
    }

  CI_LogEntry("CI_Ceay_GenerateKey", "...complete", rv, 2);

  return rv;
  }
/* }}} */
/* {{{ CI_Ceay_GenerateKeyPair */
CK_DEFINE_FUNCTION(CK_RV, CI_Ceay_GenerateKeyPair)(
  CK_I_SESSION_DATA_PTR   session_data,
  CK_MECHANISM_PTR        pMechanism,      /* key-gen mech. */
  CK_I_OBJ_PTR    public_key_obj,          /* generated public key
			                    * is put in here */
  CK_I_OBJ_PTR    private_key_obj          /* generated private key
                                            * is put in here */
)
{
  CK_RV rv = CKR_OK;
  CK_I_OBJ_PTR default_private_obj = NULL_PTR;
  CK_I_OBJ_PTR default_public_obj = NULL_PTR;
  CK_ULONG key_len;
  CK_MECHANISM_INFO mechanism_info;

  CI_LogEntry("CI_Ceay_GenerateKeyPair", "starting...", rv, 2);

  CI_Ceay_GetMechanismInfo(pMechanism->mechanism,&mechanism_info);
  switch(pMechanism->mechanism)
    {
      /* {{{ CKM_RSA_PKCS_KEY_PAIR_GEN */
    case CKM_RSA_PKCS_KEY_PAIR_GEN:
      {
	BIGNUM CK_PTR pub_exp = NULL_PTR;
	RSA CK_PTR common_key = NULL_PTR;

	/* template must not specify an inconsistent key type */
	/* The type of the key MUST be specified. */
	if((CI_ObjLookup(public_key_obj, CK_IA_KEY_TYPE) == NULL_PTR))
	  {
	    CK_KEY_TYPE val = CKK_RSA;

	    CI_LogEntry("CI_Ceay_GenerateKeyPair", 
			"warning: public key type not defined", 
			CKR_TEMPLATE_INCONSISTENT, 0);
	    /* I would not allow this behavior, but netscape does not set a key type, so 
	       I have to live with it */
	    CI_ObjSetIntAttributeValue(public_key_obj,CK_IA_KEY_TYPE,
				       &val,sizeof(CK_KEY_TYPE));
	  }
	if((*((CK_KEY_TYPE CK_PTR) CI_ObjLookup(public_key_obj, CK_IA_KEY_TYPE)->pValue) 
	    != CKK_RSA))
	  {
	    rv = CKR_TEMPLATE_INCONSISTENT;
	    CI_VarLogEntry("CI_Ceay_GenerateKeyPair", 
			   "public key template inconsistent: %lu", rv, 0,
			   *((CK_KEY_TYPE CK_PTR) 
			     CI_ObjLookup(public_key_obj, CK_IA_KEY_TYPE)->pValue));
	    return rv;
	  }
	
	if((CI_ObjLookup(private_key_obj, CK_IA_KEY_TYPE) == NULL_PTR))
	  {
	    CK_KEY_TYPE val = CKK_RSA;

	    CI_LogEntry("CI_Ceay_GenerateKeyPair", 
			"warning: private key type not defined", 
			CKR_TEMPLATE_INCONSISTENT, 0);
	    /* I would not allow this behavior, but netscape does not set a key type, so 
	       I have to live with it */
	    CI_ObjSetIntAttributeValue(private_key_obj,CK_IA_KEY_TYPE,
				       &val,sizeof(CK_KEY_TYPE));
	  }
	if((*((CK_KEY_TYPE CK_PTR)
	      CI_ObjLookup(private_key_obj, CK_IA_KEY_TYPE)->pValue) 
	    != CKK_RSA))
	  {
	    rv = CKR_TEMPLATE_INCONSISTENT;
	    CI_VarLogEntry("CI_Ceay_GenerateKeyPair", 
			   "private key template inconsistent: %lu", rv, 0,
			   *((CK_KEY_TYPE CK_PTR) 
			     CI_ObjLookup(public_key_obj, CK_IA_KEY_TYPE)->pValue));
	    return rv;
	  }

	/* parse the public empty_key */
	rv = CI_ObjTemplateInit(&CK_I_rsa_empty_public_key_obj,
				CK_I_rsa_empty_public_key,
				CK_I_rsa_empty_public_key_count);
	if(rv != CKR_OK)
	  {
	    CI_LogEntry("CI_Ceay_GenerateKeyPair", 
			"creating public key template", rv, 0);
	    return rv;
	  }
	default_public_obj = CK_I_rsa_empty_public_key_obj;

	/* parse the private empty_key */
	rv = CI_ObjTemplateInit(&CK_I_rsa_empty_private_key_obj,
				CK_I_rsa_empty_private_key,
				CK_I_rsa_empty_private_key_count);
	if(rv != CKR_OK)
	  {
	    CI_LogEntry("CI_Ceay_GenerateKeyPair", 
			"creating private key template", rv, 0);
	    return rv;
	  }
	default_private_obj = CK_I_rsa_empty_private_key_obj;
		
	/* get modulus len (in bits) */
	if(CI_ObjLookup(public_key_obj,CK_IA_MODULUS_BITS) == NULL_PTR)
	  {
	    rv = CKR_TEMPLATE_INCOMPLETE;
	    CI_LogEntry("CI_Ceay_GenerateKeyPair", "no key len specified", rv, 0);
	    return rv; /* no key len specified. Keine Hände - keine Kekse! */
	  }
	key_len = *((CK_ULONG_PTR)CI_ObjLookup(public_key_obj,
					       CK_IA_MODULUS_BITS)->pValue);
		
	/* check that key_len is in range */
	if( (key_len < mechanism_info.ulMinKeySize) ||
	    (key_len > mechanism_info.ulMaxKeySize) )
	  {
	    rv = CKR_ATTRIBUTE_VALUE_INVALID;
	    CI_VarLogEntry("CI_Ceay_GenerateKeyPair", "check key len of %ld", 
			   rv, 0,key_len);	    
	    return rv;
	  }

      
	/* get the public exponent */
	if(CI_ObjLookup(public_key_obj,CK_IA_PUBLIC_EXPONENT) == NULL_PTR)
	  /* no public exponent specified. Keine Hände - keine Kekse! */
	  {
	    rv = CKR_TEMPLATE_INCOMPLETE; 
	    CI_LogEntry("CI_Ceay_GenerateKeyPair", 
			"no public exponent supplied", rv, 0);
	    return rv;
	  }	

	pub_exp = CI_Ceay_BN_bin2bn(CI_ObjLookup(public_key_obj,CK_IA_PUBLIC_EXPONENT)->pValue,
			    CI_ObjLookup(public_key_obj,CK_IA_PUBLIC_EXPONENT)->ulValueLen, 
			    NULL_PTR); /* don't forget to free pub_exp at the end! */
	if(pub_exp == NULL_PTR)
	  {
	    rv = CKR_HOST_MEMORY;
	    CI_LogEntry("CI_Ceay_GenerateKeyPair", "unable to create the public exp BN", rv, 0);
	    return rv;
	  }
	
	/* have the crypto lib generate a key */
	/* SSLeay-0.8.xy format */
#if (OPENSSL_VERSION_NUMBER < 0x0900)
#error this Version  is not supported anymore
#endif
        /* SSLeay-0.9.xy format */
	/* the pointer to session data should come clean as we always 
	   use far pointer */
	/* TODO: check that this always true */
	CI_VarLogEntry("CI_Ceay_GeneratePair","session_data is %p",
		       rv ,2,session_data);
#ifdef ALLOW_STRONG_PRIMES
	common_key=TCC_GenKey_generate_rsa_key(key_len,BN_get_word(pub_exp),
					       0, /* no flags */
					       &CI_Ceay_RSA_Callback, 
					       (CK_CHAR_PTR)session_data);
#else /* no strong primes (use the standard function) */
        common_key=CI_Ceay_RSA_generate_key(key_len,BN_get_word(pub_exp),
				    &CI_Ceay_RSA_Callback, 
				    (CK_CHAR_PTR)session_data);
#endif

	/* did the allocation succeed */
	if(common_key== NULL_PTR)
	  {
	    TC_free(pub_exp);
	    rv = CKR_HOST_MEMORY;
	    CI_LogEntry("CI_Ceay_GenerateKeyPair", "unable to create combined key struct", rv, 0);
	    return rv;
	  }
	
	/* copy the elements into the relevant templates */
	/* bits len and public exponent are already there */
	
	/* modulus */
	if((rv = CI_Ceay_BN2ObjEntry(CKA_MODULUS,common_key->n,
				private_key_obj, public_key_obj)) 
	   != CKR_OK) 
	  {
	    CI_LogEntry("CI_Ceay_GenerateKeyPair", "failure to retrieve Modulus BN", rv, 0);
	  return rv;
	  }

	/* public exponent */
	if((rv = CI_Ceay_BN2ObjEntry(CKA_PUBLIC_EXPONENT,common_key->e,
				private_key_obj, NULL_PTR)) 
	   != CKR_OK)
	  {
	    CI_LogEntry("CI_Ceay_GenerateKeyPair", "failure to retrieve public Exponent BN", rv, 0);
	  return rv;
	  }
	
	/* private exponent */
	if((rv = CI_Ceay_BN2ObjEntry(CKA_PRIVATE_EXPONENT,common_key->d,
				private_key_obj, NULL_PTR)) 
	   != CKR_OK)
	  {
	    CI_LogEntry("CI_Ceay_GenerateKeyPair", "failure to retrieve private Exponent BN", rv, 0);
	  return rv;
	  }
	
	/* PRIME 1 */
	if((rv = CI_Ceay_BN2ObjEntry(CKA_PRIME_1,common_key->p,
				private_key_obj, NULL_PTR)) 
	   != CKR_OK) 
	  {
	    CI_LogEntry("CI_Ceay_GenerateKeyPair", "failure to retrieve Prime 1 BN", rv, 0);
	  return rv;
	  }

	
	/* PRIME 2 */
	if((rv = CI_Ceay_BN2ObjEntry(CKA_PRIME_2,common_key->q,
				private_key_obj, NULL_PTR)) 
	   != CKR_OK) 
	  {
	    CI_LogEntry("CI_Ceay_GenerateKeyPair", "failure to retrieve Prime 2 BN", rv, 0);
	  return rv;
	  }
	
	/* EXPONENT 1 */
	if((rv = CI_Ceay_BN2ObjEntry(CKA_EXPONENT_1,common_key->dmp1,
				private_key_obj, NULL_PTR)) 
	   != CKR_OK) 
	  {
	    CI_LogEntry("CI_Ceay_GenerateKeyPair", "failure to retrieve Exponent 1 BN", rv, 0);
	  return rv;
	  }
	
	/* EXPONENT 2 */
	if((rv = CI_Ceay_BN2ObjEntry(CKA_EXPONENT_2,common_key->dmq1,
				private_key_obj, NULL_PTR)) 
	   != CKR_OK) 
	  {
	    CI_LogEntry("CI_Ceay_GenerateKeyPair", "failure to retrieve Exponent 2 BN", rv, 0);
	  return rv;
	  }
	
	/* COEFFICIENT */
	if((rv = CI_Ceay_BN2ObjEntry(CKA_COEFFICIENT,common_key->iqmp,
				private_key_obj, NULL_PTR)) 
	   != CKR_OK) 
	  {
	    CI_LogEntry("CI_Ceay_GenerateKeyPair", "failure to retrieve Coefficient BN", rv, 0);
	    return rv;
	  }
	      
	/* free rsa specific data */
	CI_Ceay_RSA_free(common_key);
      }
      break;
      /* }}} */
      /* {{{ CKM_DSA_KEY_PAIR_GEN */
    case CKM_DSA_KEY_PAIR_GEN:
      {
	DSA_PTR common_key = DSA_new();

	/* template must not specify an inconsistent key type */
	/* The type of the key MUST be specified.
	 */
	if((CI_ObjLookup(public_key_obj, CK_IA_KEY_TYPE) == NULL_PTR) || 
	   (*((CK_KEY_TYPE CK_PTR)
	      CI_ObjLookup(public_key_obj, CK_IA_KEY_TYPE)->pValue) 
	    != CKK_DSA) ||
	   (CI_ObjLookup(private_key_obj, CK_IA_KEY_TYPE) == NULL_PTR) || 
	   (*((CK_KEY_TYPE CK_PTR)
	      CI_ObjLookup(private_key_obj, CK_IA_KEY_TYPE)->pValue) 
	    != CKK_DSA))
	  return CKR_TEMPLATE_INCONSISTENT;
	
	/* parse the public empty_key */
	rv = CI_ObjTemplateInit(&CK_I_dsa_empty_public_key_obj,
				    CK_I_dsa_empty_public_key,
				    CK_I_dsa_empty_public_key_count);
	if(rv != CKR_OK)
	  {
	    CI_LogEntry("CI_Ceay_GenerateKeyPair", 
			"creating public dsa key template", rv, 0);
	    return rv;
	  }
	default_public_obj = CK_I_dsa_empty_public_key_obj;

	/* parse the private empty_key */
	rv = CI_ObjTemplateInit(&CK_I_dsa_empty_private_key_obj,
				CK_I_dsa_empty_private_key,
				CK_I_dsa_empty_private_key_count);
	if(rv != CKR_OK)
	  {
	    CI_LogEntry("CI_Ceay_GenerateKeyPair", 
			"creating private dsa key template", rv, 0);
	    return rv;
	  }
	default_private_obj = CK_I_dsa_empty_private_key_obj;
	
	/* kopieren der template Einträge in das interne object */
	
	rv = CI_Ceay_ObjEntry2BN(CI_ObjLookup(public_key_obj,CK_IA_PRIME),&(common_key->p));
	if(rv != CKR_OK) return rv;
	rv = CI_Ceay_ObjEntry2BN(CI_ObjLookup(public_key_obj,CK_IA_SUBPRIME),&(common_key->q));
	if(rv != CKR_OK) return rv;
	rv = CI_Ceay_ObjEntry2BN(CI_ObjLookup(public_key_obj,CK_IA_BASE),&(common_key->g));
	if(rv != CKR_OK) return rv;
	
	/* die eigentliche Schlüsselerzeugung */
	rv = DSA_generate_key(common_key);
	if(rv == 0) return CKR_GENERAL_ERROR;

	/* kopieren des schlüssels in die objecte */
 	/* y (public key) */
	if((rv = CI_Ceay_BN2ObjEntry(CKA_VALUE,common_key->pub_key,
				     NULL_PTR, public_key_obj)) 
	   != CKR_OK) 
	  return rv;
 	/* x (private key) */
	if((rv = CI_Ceay_BN2ObjEntry(CKA_VALUE,common_key->priv_key,
				     private_key_obj, NULL_PTR)) 
	   != CKR_OK) 
	  return rv;
	
	/* copy the prime, subprime and base into the private key */
	/* they might already be set, but the spec calls for setting them
	 * in the private key */
	rv = CI_ObjSetAttribute(private_key_obj, CI_ObjLookup(public_key_obj, CK_IA_PRIME));
	if(rv != CKR_OK) return rv;
	rv = CI_ObjSetAttribute(private_key_obj, CI_ObjLookup(public_key_obj, CK_IA_SUBPRIME));
	if(rv != CKR_OK) return rv;
	rv = CI_ObjSetAttribute(private_key_obj, CI_ObjLookup(public_key_obj, CK_IA_BASE));
	if(rv != CKR_OK) return rv;

	/* free dsa specific data */
	DSA_free(common_key);
      }
      break;
      /* }}} */
    default: /* unknown key type */
      /*
       * The code should never reach this as the validity of the mechanism
       * is checked above!
       */
      return CKR_GENERAL_ERROR; 
    }

  CI_ObjMergeObj(public_key_obj, default_public_obj, FALSE);
  CI_ObjMergeObj(private_key_obj, default_private_obj, FALSE);

  CI_LogEntry("CI_Ceay_GenerateKeyPair", "...complete", rv, 0);
  return CKR_OK;
}
/* }}} */
/* {{{ CI_Ceay_WrapKey */
CK_DEFINE_FUNCTION(CK_RV, CI_Ceay_WrapKey)(
  CK_I_SESSION_DATA_PTR  session_data,
  CK_MECHANISM_PTR  pMechanism,      /* the wrapping mechanism */
  CK_I_OBJ_PTR      wrap_key_obj,    /* wrapping key */
  CK_I_OBJ_PTR      key_obj,         /* key to be wrapped */
  CK_BYTE_PTR       pWrappedKey,     /* gets wrapped key */
  CK_ULONG_PTR      pulWrappedKeyLen /* gets wrapped key size */
)
{
  CK_BYTE_PTR       pData = NULL_PTR;     
  CK_ULONG          ulDataLen; 
  CK_BBOOL          data_allocated = FALSE;
  CK_RV             rv =CKR_OK;

  CI_LogEntry("CI_Ceay_WrapKey", "starting...", rv, 2);

  /* ensure that key type is defined */
  if(CI_ObjLookup(key_obj,CK_IA_CLASS) == NULL_PTR)
    {
      rv = CKR_KEY_TYPE_INCONSISTENT;
      CI_LogEntry("CI_Ceay_WrapKey", "checking that key type is defined", rv, 0);
      return rv;
    }

  /* TODO: redo the whole wrapping code */
  
  /* act depending on object class and on key type */
  switch(*((CK_OBJECT_CLASS CK_PTR)CI_ObjLookup(key_obj,CK_IA_CLASS)->pValue))
    {
    case CKO_PRIVATE_KEY:
      switch (*((CK_KEY_TYPE CK_PTR)CI_ObjLookup(key_obj,CK_IA_KEY_TYPE)->pValue))
	{
	case CKK_RSA:
	  {
	    PKCS8_PRIV_KEY_INFO *p8;
	    RSA *rsa= NULL;
	    EVP_PKEY *pkey = NULL;	
	    unsigned char *in, *p;
	    int inlen;
	    
	    /* code provided by Felix Baessler <Felix.Baessler@swisscom.com> */
	    
	    /* TODO: check that the wripping mechanism is a valid one */
	    CI_LogEntry("CI_Ceay_WrapKey", "p8 encoding for private key...", rv, 2);
	    rsa= CI_Ceay_Obj2RSA(key_obj);
	    pkey= EVP_PKEY_new();
	    EVP_PKEY_assign_RSA (pkey, rsa);
	    p8= EVP_PKEY2PKCS8(pkey);
	    EVP_PKEY_free(pkey);
	    
	    ulDataLen = i2d_PKCS8_PRIV_KEY_INFO (p8, NULL);
	    pData = TC_malloc (ulDataLen);
	    if(pData == NULL_PTR)
	      {
		rv = CKR_HOST_MEMORY;
		CI_LogEntry("CI_Ceay_WrapKey", "alloc'ing space for output data", rv, 0);
		return rv;
	      }
	    else
	      data_allocated = TRUE;
	    
	    p = pData;
	    i2d_PKCS8_PRIV_KEY_INFO (p8, &p);
	    
	  }
	  break;
	default:
	  /* we don't cater for that set of objects and key types */
	  return CKR_FUNCTION_NOT_SUPPORTED;
	}
    case CKO_PUBLIC_KEY:
      /* DER-encode the Stream */
      
      /* get size*/
      CI_Ceay_MakeKeyString(key_obj, NULL_PTR, &ulDataLen);
      
      pData = CI_ByteStream_new(ulDataLen);
      if(pData == NULL_PTR)
	{
	  rv = CKR_HOST_MEMORY;
	  CI_LogEntry("CI_Ceay_WrapKey", "alloc'ing space for output data", rv, 0);
	  return rv;
	}
      else
	data_allocated = TRUE;

      /* get data */
      CI_Ceay_MakeKeyString(key_obj, pData, &ulDataLen);

      break;
    case CKO_SECRET_KEY:
      pData= CI_ObjLookup(key_obj,CK_IA_VALUE)->pValue;
      ulDataLen = CI_ObjLookup(key_obj,CK_IA_VALUE)->ulValueLen;
      break;
    default:
      {
	rv = CKR_KEY_NOT_WRAPPABLE;
	CI_LogEntry("CI_Ceay_WrapKey", "testing object type: %x", rv, 0);
	return rv;
      }
    }

  rv = CI_Ceay_EncryptInit(session_data,pMechanism,wrap_key_obj);
  if(rv != CKR_OK)
    {
      CI_LogEntry("CI_Ceay_WrapKey", "init encryption", rv, 0);
      return rv;
    }

  rv = CI_Ceay_Encrypt(session_data, pData,ulDataLen, pWrappedKey, pulWrappedKeyLen);
  /* dont test rv. free the pData in either case */

  if(data_allocated)
    {
      if(pData != NULL_PTR)
	TC_free(pData);
    }

  CI_LogEntry("CI_Ceay_WrapKey", "...complete", rv, 2);

  return rv;
}
/* }}} */
/* {{{ CI_Ceay_UnwrapKey */
CK_DEFINE_FUNCTION(CK_RV, CI_Ceay_UnwrapKey)(
  CK_I_SESSION_DATA_PTR  session_data,
  CK_MECHANISM_PTR       pMechanism,        /* unwrapping mech. */
  CK_I_OBJ_PTR           unwrap_key_obj,    /* unwrapping key */
  CK_BYTE_PTR            pWrappedKey,       /* the wrapped key */
  CK_ULONG               ulWrappedKeyLen,   /* wrapped key len */
  CK_I_OBJ_PTR           key_obj            /* key to be unwrapped */
)
{
  CK_BYTE_PTR       pData = NULL_PTR;     /* data to be digested */
  CK_ULONG          ulDataLen; /* bytes of data to be digested */
  CK_RV rv;
  CK_ATTRIBUTE att_value;

  rv = CI_Ceay_DecryptInit(session_data,pMechanism,unwrap_key_obj);
  if(rv != CKR_OK)
    return rv;

  /* get the length of the buffer needed */
  rv = CI_Ceay_Decrypt(session_data, pWrappedKey, ulWrappedKeyLen, NULL_PTR, &ulDataLen);
  if(rv != CKR_OK)
    return rv;

  pData = CI_ByteStream_new(ulDataLen);
  if(pData == NULL_PTR)
     return CKR_HOST_MEMORY;

  rv = CI_Ceay_Decrypt(session_data, pWrappedKey, ulWrappedKeyLen, pData, &ulDataLen);
  
  if(CI_ObjLookup(key_obj,CK_IA_CLASS) == NULL)
    {
      return CKR_WRAPPED_KEY_INVALID;
    }

  if(*((CK_KEY_TYPE CK_PTR)CI_ObjLookup(key_obj,CK_IA_CLASS)->pValue) == CKO_SECRET_KEY) 
    {
      /* create attribute entry */
      att_value.pValue = pData;
      att_value.ulValueLen = ulDataLen;
      att_value.type = CKA_VALUE;
      
      /* write data into template */
      return CI_ObjSetAttribute(key_obj, &att_value);      
    }

  /* Check what type of key */
  if(*((CK_KEY_TYPE CK_PTR)CI_ObjLookup(key_obj,CK_IA_CLASS)->pValue) == CKO_PUBLIC_KEY)
    {
      if(CI_ObjLookup(key_obj,CK_IA_KEY_TYPE) == NULL_PTR)
	return CKR_TEMPLATE_INCOMPLETE;

      switch(*((CK_KEY_TYPE CK_PTR)CI_ObjLookup(key_obj,CK_IA_KEY_TYPE)->pValue))
	{
	case CKK_RSA:
	  {
	    /* code provided by Felix Baessler <Felix.Baessler@swisscom.com> */
	    
	    PKCS8_PRIV_KEY_INFO *p8;
	    X509_ALGOR *a;
	    RSA CK_PTR rsa= NULL;
	    EVP_PKEY *pkey = NULL;	
	    unsigned char *p;
	    int pkeylen;
	    
	    p8 = d2i_PKCS8_PRIV_KEY_INFO(NULL, &pData, ulDataLen);
	    if(!p8) return CKR_WRAPPED_KEY_INVALID;
	    
	    if(p8->pkey->type == V_ASN1_OCTET_STRING)
	      {
		p8->broken = PKCS8_OK;
		p = p8->pkey->value.octet_string->data;
		pkeylen = p8->pkey->value.octet_string->length;
	      }
	    else
	      {
		p8->broken = PKCS8_NO_OCTET;
		p = p8->pkey->value.sequence->data;
		pkeylen = p8->pkey->value.sequence->length;
	      }
	    if (!(pkey = EVP_PKEY_new()))
	      {
		return CKR_HOST_MEMORY;
	      }
	    a = p8->pkeyalg;
	    if(OBJ_obj2nid(a->algorithm) != NID_rsaEncryption)
	      return CKR_WRAPPED_KEY_INVALID;
	    
	    if (!(rsa = d2i_RSAPublicKey (NULL, &p, pkeylen)))
	      {
		return CKR_WRAPPED_KEY_INVALID;
	      }
	    EVP_PKEY_assign_RSA (pkey, rsa);
	    
	    /* structure felder in template kopieren */
	    return CI_Ceay_RSA2Obj(rsa,key_obj);
	  }
	  break;
	default:
	  return CKR_TEMPLATE_INCONSISTENT;
	}
    }

  if(*((CK_KEY_TYPE CK_PTR)CI_ObjLookup(key_obj,CK_IA_CLASS)->pValue) == CKO_PRIVATE_KEY)
    {
      if(CI_ObjLookup(key_obj,CK_IA_KEY_TYPE) == NULL_PTR)
	return CKR_TEMPLATE_INCOMPLETE;

      switch(*((CK_KEY_TYPE CK_PTR)CI_ObjLookup(key_obj,CK_IA_KEY_TYPE)->pValue))
	{
	case CKK_RSA:
	  {
	    PKCS8_PRIV_KEY_INFO *p8;
	    X509_ALGOR *a;
	    RSA *rsa= NULL;
	    EVP_PKEY *pkey = NULL;	
	    unsigned char *p;
	    int pkeylen;

	    p8 = d2i_PKCS8_PRIV_KEY_INFO(NULL, &pData, ulDataLen);
	    if(!p8) return CKR_WRAPPED_KEY_INVALID;
	    
	    if(p8->pkey->type == V_ASN1_OCTET_STRING)
	      {
		p8->broken = PKCS8_OK;
		p = p8->pkey->value.octet_string->data;
		pkeylen = p8->pkey->value.octet_string->length;
	      }
	    else
	      {
		p8->broken = PKCS8_NO_OCTET;
		p = p8->pkey->value.sequence->data;
		pkeylen = p8->pkey->value.sequence->length;
	      }
	    if (!(pkey = EVP_PKEY_new()))
	      {
		/* EVPerr(EVP_F_EVP_PKCS82PKEY,ERR_R_MALLOC_FAILURE); */
		return CKR_WRAPPED_KEY_INVALID;
	      }
	    a = p8->pkeyalg;
	    if(OBJ_obj2nid(a->algorithm) != NID_rsaEncryption)
	      return CKR_WRAPPED_KEY_INVALID;
	    
	    if (!(rsa = d2i_RSAPrivateKey (NULL, &p, pkeylen)))
	      {
		/* EVPerr(EVP_F_EVP_PKCS82PKEY, EVP_R_DECODE_ERROR); */
		return CKR_WRAPPED_KEY_INVALID;
	      }
	    EVP_PKEY_assign_RSA (pkey, rsa);
	    
	    /* structure felder in template kopieren */
	    return CI_Ceay_RSA2Obj(rsa,key_obj);
	  }
	  break;
	default:
	  return CKR_TEMPLATE_INCONSISTENT;
	}
      
    }
  
  return CKR_WRAPPED_KEY_INVALID;
}
/* }}} */
/* {{{ CI_Ceay_DeriveKey */
static CK_ULONG CK_I_SSL_WRITE_KEY_LEN = 16;
static CK_ULONG CK_I_SSL_EXPORT_KEY_LEN = 5;

#undef CI_ERR
#define CI_ERR(expression) rv = expression ; 	\
   if( rv != CKR_OK ) goto ssl3_mat_derive_error 

CK_DEFINE_FUNCTION(CK_RV, CI_Ceay_DeriveKey)(
  CK_I_SESSION_DATA_PTR  session_data,
  CK_MECHANISM_PTR       pMechanism,        /* key deriv. mech. */
  CK_I_OBJ_PTR           base_key,          /* base key */
  CK_I_OBJ_PTR           key_obj         /* template for derived key */
)
{
  CK_RV rv = CKR_OK;
  static CK_MECHANISM sha1_mech = {CKM_SHA_1, NULL_PTR, 0 };
  static CK_MECHANISM md5_mech = {CKM_MD5, NULL_PTR, 0 };
  CK_BYTE_PTR tmp_str = NULL_PTR;

  CI_LogEntry("CI_Ceay_DeriveKey", "starting...", rv, 2);

  switch(pMechanism->mechanism)
    {
      /* {{{ CKM_SSL3_MASTER_KEY_DERIVE */
      /*
       * Der Master key ist nach folgendem Verfahren erstellt:
       *
       * master_secret = 
       * MD5(pre_master_secret + SHA1('A' + pre_master_secret 
       *       + ClientHello.random + ServerHello.random)) +
       * MD5(pre_master_secret + SHA1('BB' + pre_master_secret 
       *       + ClientHello.random + ServerHello.random)) +
       * MD5(pre_master_secret + SHA1('CCC' + pre_master_secret 
       *       + ClientHello.random + ServerHello.random));
       */
    case CKM_SSL3_MASTER_KEY_DERIVE:
      {
	CK_SSL3_MASTER_KEY_DERIVE_PARAMS_PTR param = NULL_PTR;
	CK_MECHANISM_INFO mech_info;
	CK_ULONG len, key_len, buf_len, rest_out_len, n;
        CK_BYTE CK_PTR buf = NULL_PTR;
	CK_BYTE  CK_PTR out = NULL_PTR;    /* space in which the key is generated */
	CK_BYTE CK_PTR curr_out = NULL_PTR; /* moving pointer for current piece of buffer */
	CK_BYTE CK_PTR p = NULL_PTR;   /* master Secret */
        int i=0;

	/* Wenn sich die Länge des Schlüssels ändert brauchen wir mehr Salz */
	
	CI_LogEntry("CI_Ceay_DeriveKey", "CKM_SSL3_MASTER_KEY_DERIVE starting...", rv, 2);

	/* make sure that the parameters are correct */
	if( (pMechanism->pParameter == NULL_PTR) ||
	    (pMechanism->ulParameterLen != sizeof(CK_SSL3_MASTER_KEY_DERIVE_PARAMS)) )
	  {
	    rv = CKR_MECHANISM_PARAM_INVALID;
	    CI_LogEntry("CI_Ceay_DeriveKey", "checking Mechanism Parameters" ,rv ,0);
	    return rv;
	  }
	   
	param = (CK_SSL3_MASTER_KEY_DERIVE_PARAMS_PTR) pMechanism->pParameter;

	p = CI_ObjLookup(base_key,CK_IA_VALUE)->pValue;

	rv = CI_Ceay_GetMechanismInfo(pMechanism->mechanism, &mech_info);
	if(rv != CKR_OK) goto ssl3_mkd_error;

	key_len = mech_info.ulMinKeySize;
	len = key_len; /* Allways use the default len */
	if( len != key_len )
	  {
	    rv = CKR_TEMPLATE_INCONSISTENT;
	    CI_VarLogEntry("CI_Ceay_DeriveKey", 
			   "check key length (len != key_len) len: %i key_len: %i",
			   rv, 0, len, key_len);
	    /* return rv; */
	  }

	/* allocate space for the whole key to be returned */
	if((out = CI_ByteStream_new(key_len)) == NULL_PTR) 
	  {
	    rv = CKR_HOST_MEMORY;
	    CI_LogEntry("CI_Ceay_DeriveKey", "alloc'ing memory for output key", rv ,0);
	    return rv;
	  }
	
	CI_VarLogEntry("CI_Ceay_DeriveKey", "Client Random: %s", rv ,2, 
		       tmp_str = CI_PrintableByteStream(param->RandomInfo.pClientRandom,
							param->RandomInfo.ulClientRandomLen));
	TC_free(tmp_str);
	CI_VarLogEntry("CI_Ceay_DeriveKey", "Server Random: %s", rv ,2, 
		       tmp_str = CI_PrintableByteStream(param->RandomInfo.pServerRandom,
							param->RandomInfo.ulServerRandomLen));
	TC_free(tmp_str);
	
	/* 
	 * Achtung: dieser Code geht schief ( erzeugt einen Fehler im MD5
	 * FinalDigest ) wenn die Länge des Schlüssels nicht ein vielfaches
	 * der MD5 Digestgröße (128 Bit) ist.
	 */
	rest_out_len = len;
	curr_out = out;
	for(i=0; rest_out_len > 0; i++)
	{
	    rv = CI_Ceay_DigestInit(session_data, &sha1_mech); 
	    if(rv != CKR_OK) 
	      {
		CI_LogEntry("CI_Ceay_DeriveKey", "digest init", rv ,0);
		goto ssl3_mkd_error;
	      }
	    rv = CI_Ceay_DigestUpdate(session_data, (CK_BYTE_PTR)salt[i],
				      strlen((CK_BYTE_PTR)salt[i]));
	    if(rv != CKR_OK) 
	      {
		CI_VarLogEntry("CI_Ceay_DeriveKey", "salt[%i] digest update", rv ,0,i);
		goto ssl3_mkd_error;
	      }
	    rv = CI_Ceay_DigestUpdate(session_data, p,len);
	    if(rv != CKR_OK) 
	      {
		CI_VarLogEntry("CI_Ceay_DeriveKey", "p digest update: len: %i", rv ,0,len);
		goto ssl3_mkd_error;
	      }	    
	    
	    rv = CI_Ceay_DigestUpdate(session_data, param->RandomInfo.pClientRandom,
				      param->RandomInfo.ulClientRandomLen);
	    if(rv != CKR_OK) 
	      {
		CI_LogEntry("CI_Ceay_DeriveKey", "Client Random info disgest update", rv ,0);
		goto ssl3_mkd_error;
	      }

	    rv = CI_Ceay_DigestUpdate(session_data, param->RandomInfo.pServerRandom,
				      param->RandomInfo.ulServerRandomLen);
	    if(rv != CKR_OK) 
	      {
		CI_LogEntry("CI_Ceay_DeriveKey", "Server RandomInfo digest update", rv ,0);
		goto ssl3_mkd_error;
	      }
	    
	    /* get needed size for SHA-1 result*/
	    rv = CI_Ceay_DigestFinal(session_data, NULL_PTR, &buf_len);
	    if(rv != CKR_OK) 
	      {
		CI_LogEntry("CI_Ceay_DeriveKey", "getting digest len", rv ,0);
		goto ssl3_mkd_error;
	      }

	    TC_free(buf);
	    if((buf = CI_ByteStream_new(buf_len)) == NULL_PTR)
	      { 
		rv = CKR_HOST_MEMORY; 
		CI_LogEntry("CI_Ceay_DeriveKey", "malloc buff space", rv ,0);
		goto ssl3_mkd_error; 
	      }

	    rv = CI_Ceay_DigestFinal(session_data, buf, &buf_len);
	    /* TODO: dies ist nur debug und sollte raus */
	    if(session_data->digest_state != NULL_PTR)
	      {
		rv = CKR_GENERAL_ERROR;
		CI_LogEntry("CI_Ceay_DeriveKey", "digest final: state not reset", rv ,0);
		goto ssl3_mkd_error;
	      }

	    if(rv != CKR_OK) 
	      {
		CI_LogEntry("CI_Ceay_DeriveKey", "digest final", rv ,0);
		goto ssl3_mkd_error;
	      }
	    rv = CI_Ceay_DigestInit(session_data, &md5_mech);
	    if(rv != CKR_OK) 
	      {
		CI_LogEntry("CI_Ceay_DeriveKey", "md5 digest init", rv ,0);
		goto ssl3_mkd_error;
	      }
	    rv = CI_Ceay_DigestUpdate(session_data, p,len);
	    if(rv != CKR_OK) 
	      {
		CI_LogEntry("CI_Ceay_DeriveKey", "md5 p digest update", rv ,0);
		goto ssl3_mkd_error;
	      }
	    rv = CI_Ceay_DigestUpdate(session_data, buf,buf_len);
	    if(rv != CKR_OK) 
	      {
		CI_LogEntry("CI_Ceay_DeriveKey", "md5 buf digest update", rv ,0);
		goto ssl3_mkd_error;
	      }

	    /* read one chunk */
	    n = rest_out_len;
	    rv = CI_Ceay_DigestFinal(session_data, curr_out, &n);
	    /* TODO: dies ist nur debug und sollte raus */
	    if(session_data->digest_state != NULL_PTR)
	      {
		rv = CKR_GENERAL_ERROR;
		CI_LogEntry("CI_Ceay_DeriveKey", "digest final: state not reset", rv ,0);
		goto ssl3_mkd_error;
	      }

	    if(rv != CKR_OK) 
	      {
		CI_LogEntry("CI_Ceay_DeriveKey", "md5 digest final", rv ,0);
		goto ssl3_mkd_error;
	      }

	    curr_out+=n;
	    rest_out_len-=n;
	  }
	CI_LogEntry("CI_Ceay_DeriveKey", "got here3", rv ,2);
	
	/* Elemente in Schlüssel eintragen */
	CI_VarLogEntry("CI_Ceay_DeriveKey", "Master Key: %s (key len: %i)",
		       rv,2,
		       tmp_str = CI_PrintableByteStream(out,key_len),
		       key_len);
	TC_free(tmp_str);
	
	rv=CI_ObjSetAttributeValue(key_obj,CKA_VALUE,out,key_len);
	if(rv != CKR_OK)
	  {
	    CI_LogEntry("CI_Ceay_DeriveKey", "setting VALUE in Key", rv ,0);
	    goto ssl3_mkd_error;
	  }
	
	rv=CI_ObjSetAttributeValue(key_obj,CKA_VALUE_LEN,&key_len,sizeof(key_len));
	if(rv != CKR_OK)
	  {
	    CI_LogEntry("CI_Ceay_DeriveKey", "setting VALUE_LEN in Key", rv ,0);
	    goto ssl3_mkd_error;
	  }

	/* ist der Schlüssel mit dieser PKCS11 erstellt worden? */
	if(CI_ObjLookup(base_key,CK_IA_SSL_VERSION) == NULL_PTR)
	  {
	    rv = CKR_TEMPLATE_INCOMPLETE;
	    goto ssl3_mkd_error;
	  }
	/*  Setze SSL Versionsnummer aus dem template des original Keys */
	if(param->pVersion == NULL_PTR)
	  {
	    param->pVersion = CI_VERSION_new();
	    if(param->pVersion == NULL_PTR)
	      {
		rv = CKR_HOST_MEMORY;
		goto ssl3_mkd_error;
	      }
	  }
	CI_LogEntry("CI_Ceay_DeriveKey", "got here5", rv ,2);

	memcpy(param->pVersion, 
	       CI_ObjLookup(base_key,CK_IA_SSL_VERSION)->pValue, 
	       sizeof(CK_VERSION));

	/* Erzeugen der drei abgeleiteten Objekte */
	CI_LogEntry("CI_Ceay_DeriveKey", "got here6", rv ,2);

      ssl3_mkd_error:
	if(out != NULL_PTR) TC_free(out); 
	if(buf != NULL_PTR) TC_free(buf); 

	CI_LogEntry("CI_Ceay_DeriveKey", "got here7", rv ,2);

	CI_LogEntry("CI_Ceay_DeriveKey", "CKM_SSL3_MASTER_KEY_DERIVE ...complete", rv, 2);
      }
      break;
      /* }}} */
      /* {{{ CKM_SSL3_KEY_AND_MAC_DERIVE */
      /* Der key_block ist nach folgendem Verfahren erstellt:
       *
       * key_block = 
       * MD5(pre_master_secret + SHA1('A' + master_secret 
       *       + ServerHello.random + ClientHello.random)) +
       * MD5(pre_master_secret + SHA1('BB' + master_secret 
       *       + ServerHello.random + ClientHello.random)) +
       * MD5(pre_master_secret + SHA1('CCC' + master_secret 
       *       + ServerHello.random + ClientHello.random));
       */
    case CKM_SSL3_KEY_AND_MAC_DERIVE:
      {
	CK_SSL3_KEY_MAT_PARAMS_PTR param = NULL_PTR;
	CK_I_OBJ_PTR clientMac = NULL_PTR;
	CK_I_OBJ_PTR serverMac = NULL_PTR;
	CK_I_OBJ_PTR clientKey = NULL_PTR;
	CK_I_OBJ_PTR serverKey = NULL_PTR;
	CK_BYTE_PTR value = NULL_PTR, key_block = NULL_PTR;
	CK_ULONG ulValueLen, element_start, buf_len;
	CK_BYTE hash_flag = 0;
	CK_BYTE_PTR buf = NULL_PTR;

	CI_LogEntry("CI_Ceay_DeriveKey", "CKM_SSL3_KEY_AND_MAC_DERIVE starting...", rv, 2);

	/* ensure validity of the parameter structure */
	if(pMechanism->pParameter == NULL_PTR)
	  {
	    rv = CKR_MECHANISM_PARAM_INVALID;
	    CI_LogEntry("CI_Ceay_DeriveKey", "checking Mechanism Parameter", rv ,0);
	    return rv;
	  }

	param = (CK_SSL3_KEY_MAT_PARAMS_PTR)pMechanism->pParameter;
	if(param->pReturnedKeyMaterial == NULL_PTR)
	  { 
	    rv = CKR_MECHANISM_PARAM_INVALID;
	    CI_LogEntry("CI_Ceay_DeriveKey", "checking key material", rv ,0);
	    return rv;
	  }

	/* parse the empty_key */
	rv = CI_ObjTemplateInit(&CK_I_generic_empty_key_obj,
				CK_I_generic_empty_key,
				CK_I_generic_empty_key_count);
	if(rv != CKR_OK)
	  {
	    CI_LogEntry("CI_Ceay_DeriveKey", 
			"creating generic secret key template", rv ,0);
	    return rv;
	  }

	/* TODO: ensure (*(CKA_VALUE_LEN->pValue) == 48) && (CKA_VALUE->ulValueLen = 48)  */
	value = CI_ObjLookup(base_key,CK_IA_VALUE)->pValue;

	/**** create new objects ****/
	CI_ERR(CI_ObjCreateObj(&clientMac)); 
	CI_ERR(CI_ObjMergeObj(clientMac,CK_I_generic_empty_key_obj, FALSE));

	CI_ERR(CI_ObjCreateObj(&serverMac)); 
	CI_ERR(CI_ObjMergeObj(serverMac,CK_I_generic_empty_key_obj, FALSE)); 

	CI_ERR(CI_ObjCreateObj(&clientKey)); 
	CI_ERR(CI_ObjMergeObj(clientKey,CK_I_generic_empty_key_obj, FALSE));

	CI_ERR(CI_ObjCreateObj(&serverKey)); 
	CI_ERR(CI_ObjMergeObj(serverKey,CK_I_generic_empty_key_obj, FALSE)); 

	key_block = CI_ByteStream_new(CK_I_SSL3_PRE_MASTER_SIZE);
	if(key_block == NULL_PTR) { rv = CKR_HOST_MEMORY; goto ssl3_mat_derive_error; }
	
	CI_Ceay_DigestTransform(session_data,
				value, CK_I_SSL3_PRE_MASTER_SIZE,
				param->RandomInfo.pServerRandom,  
				param->RandomInfo.ulServerRandomLen,
				param->RandomInfo.pClientRandom,  
				param->RandomInfo.ulClientRandomLen,
				key_block);
	
	/* TODO: this code assumes that all key-lens are multiple of 8 Bits */
	element_start = 0;
	ulValueLen = param->ulMacSizeInBits/8;
	CI_ERR(CI_ObjSetIntAttributeValue(clientMac, CK_IA_VALUE, 
					  &(key_block[element_start]), ulValueLen));
	CI_ERR(CI_ObjSetIntAttributeValue(clientMac, CK_IA_VALUE_LEN, 
					  (CK_BYTE_PTR)&ulValueLen, sizeof(CK_ULONG)));
	CI_VarLogEntry("CI_Ceay_DeriveKey","clientMAC: %s",rv,2,
		       tmp_str = CI_PrintableByteStream(&(key_block[element_start]),
							ulValueLen));
	TC_free(tmp_str);
	element_start += ulValueLen;
	
	CI_ERR(CI_ObjSetIntAttributeValue(serverMac,CK_IA_VALUE, 
					  &(key_block[element_start]), ulValueLen));
	CI_ERR(CI_ObjSetIntAttributeValue(serverMac, CK_IA_VALUE_LEN, 
					  (CK_BYTE_PTR)&ulValueLen, 
					  sizeof(CK_ULONG)));
	CI_VarLogEntry("CI_Ceay_DeriveKey","serverMAC: %s",rv,2,
		       tmp_str = CI_PrintableByteStream(&(key_block[element_start]),
							ulValueLen));
	TC_free(tmp_str);
	element_start += ulValueLen;


	/* Value for the initial key 
	 * 5 if it is an exportable cipher 
	 * 16 otherwise
	 */
	ulValueLen = param->ulKeySizeInBits/8;
	
	CI_ERR(CI_ObjSetIntAttributeValue(clientKey, CK_IA_VALUE, 
					  &(key_block[element_start]), ulValueLen));
	CI_ERR(CI_ObjSetIntAttributeValue(clientKey, CK_IA_VALUE_LEN, 
					  (CK_BYTE_PTR)&ulValueLen, 
					    sizeof(CK_ULONG)));
	CI_VarLogEntry("CI_Ceay_DeriveKey","clientKey: %s",rv,2,
		       tmp_str = CI_PrintableByteStream(&(key_block[element_start]),
							ulValueLen));
	TC_free(tmp_str);
	element_start += ulValueLen;
	
	CI_ERR(CI_ObjSetIntAttributeValue(serverKey,CK_IA_VALUE, 
					  &(key_block[element_start]), ulValueLen));
	CI_ERR(CI_ObjSetIntAttributeValue(serverKey, CK_IA_VALUE_LEN, 
					  (CK_BYTE_PTR)&ulValueLen, 
					  sizeof(CK_ULONG)));
	CI_VarLogEntry("CI_Ceay_DeriveKey","serverKey: %s",rv,2,
		       tmp_str = CI_PrintableByteStream(&(key_block[element_start]),
							ulValueLen));
	TC_free(tmp_str);
	element_start += ulValueLen;
	
	/* create IVs only if requested (param->ulIVSizeInBits != 0) */ 
	if(param->ulIVSizeInBits != 0)
	  {
	    
	    CI_LogEntry("CI_Ceay_DeriveKey","computing IVs",rv,2);
	    
	    if(param->bIsExport == FALSE)
	      {
		ulValueLen = param->ulIVSizeInBits;
		memcpy(param->pReturnedKeyMaterial->pIVClient, &(key_block[element_start]), ulValueLen);
		element_start += ulValueLen;
		memcpy(param->pReturnedKeyMaterial->pIVServer, &(key_block[element_start]), ulValueLen);
	      }
	    else
	      {
		
		/* Client IV */
		rv = CI_Ceay_DigestInit(session_data, &md5_mech);	    
		CI_ERR(CI_Ceay_DigestUpdate(session_data, param->RandomInfo.pClientRandom, 
					    param->RandomInfo.ulClientRandomLen));
		CI_ERR(CI_Ceay_DigestUpdate(session_data, param->RandomInfo.pServerRandom, 
					    param->RandomInfo.ulServerRandomLen));
		
		/* nur für buf_len */
		CI_ERR(CI_Ceay_DigestFinal(session_data, NULL_PTR, &buf_len)); 
		CI_ERR(CI_Ceay_DigestFinal(session_data, 
					   param->pReturnedKeyMaterial->pIVClient, 
					   &buf_len));
		
		/* Server IV */
		CI_ERR(CI_Ceay_DigestInit(session_data, &md5_mech));
		CI_ERR(CI_Ceay_DigestUpdate(session_data, 
					    param->RandomInfo.pClientRandom,
					    param->RandomInfo.ulClientRandomLen));
		CI_ERR(CI_Ceay_DigestUpdate(session_data,
					    param->RandomInfo.pServerRandom,
					    param->RandomInfo.ulServerRandomLen));
		CI_ERR(CI_Ceay_DigestFinal(session_data, NULL_PTR, &buf_len)); /* nur für buf_len */
		CI_ERR(CI_Ceay_DigestFinal(session_data, 
					   param->pReturnedKeyMaterial->pIVServer, 
					   &buf_len));
	      }
	    
	    tmp_str = CI_PrintableByteStream(param->pReturnedKeyMaterial->pIVServer,
					     buf_len);
	    CI_VarLogEntry("CI_Ceay_DeriveKey","final client IV: %s",rv,2,tmp_str);
	    TC_free(tmp_str);
	  }
	
	
	/* müssen wir die Daten noch für export Verbindungen nachbearbeiten? */
	if( param->bIsExport == TRUE )
	  {
	    CI_LogEntry("CI_Ceay_DeriveKey","doing exportable Encryption",rv,2);
	    
	    /* final_client_write_key = MD5(client_write_key +
	     *                              ClientHello.random + ServerHello.random); 
	     */
	    value = CI_ObjLookup(clientKey, CK_IA_VALUE)->pValue;
	    CI_ERR(CI_Ceay_DigestInit(session_data, &md5_mech));	    
	    CI_ERR(CI_Ceay_DigestUpdate(session_data, value, 
							CK_I_SSL_EXPORT_KEY_LEN)); 
	    CI_VarLogEntry("CI_Ceay_DeriveKey","using %i bits of key len and '%s' as key",rv,1,
			   CK_I_SSL_EXPORT_KEY_LEN,
			   tmp_str = CI_PrintableByteStream(value,
							    CK_I_SSL_EXPORT_KEY_LEN));
	    TC_free(tmp_str);
	    
	    CI_ERR(CI_Ceay_DigestUpdate(session_data, 
					param->RandomInfo.pClientRandom,
					param->RandomInfo.ulClientRandomLen));
	    
	    CI_ERR(CI_Ceay_DigestUpdate(session_data, 
					param->RandomInfo.pServerRandom,
					param->RandomInfo.ulServerRandomLen));
	    
	    CI_ERR(CI_Ceay_DigestFinal(session_data, NULL_PTR, &buf_len));
	    
	    if((buf = CI_ByteStream_new(buf_len)) == NULL_PTR)
	      { rv = CKR_HOST_MEMORY; goto ssl3_mat_derive_error; }
	    CI_ERR(CI_Ceay_DigestFinal(session_data, buf, &buf_len));
	    
	    CI_ERR(CI_ObjSetIntAttributeValue(clientKey,CK_IA_VALUE, buf, buf_len));
	    
	    CI_ERR(CI_ObjSetIntAttributeValue(clientKey, CK_IA_VALUE_LEN, 
					      (CK_BYTE_PTR)&CK_I_SSL_WRITE_KEY_LEN, 
					      sizeof(CK_I_SSL_WRITE_KEY_LEN)));
	    
	    CI_VarLogEntry("CI_Ceay_DeriveKey","final client Key: %s",rv,2,
			   tmp_str = CI_PrintableByteStream(buf,buf_len));
	    /* gleich wieder aufräumen! */
	    TC_free(buf); buf = NULL_PTR;
	    TC_free(tmp_str);
	    
	    /* final_server_write_key = MD5(server_write_key +
	     *                              ServerHello.random + ClientHello.random); 
	     */
	    value = CI_ObjLookup(serverKey, CK_IA_VALUE)->pValue;
	    rv = CI_Ceay_DigestInit(session_data, &md5_mech);	    
	    if(rv != CKR_OK) goto ssl3_mat_derive_error;
	    
	    rv = CI_Ceay_DigestUpdate(session_data, value, 
				      CK_I_SSL_EXPORT_KEY_LEN); 
	    if(rv != CKR_OK) goto ssl3_mat_derive_error;
	    
	    rv = CI_Ceay_DigestUpdate(session_data, 
				      param->RandomInfo.pServerRandom,
				      param->RandomInfo.ulServerRandomLen);
	    if(rv != CKR_OK) goto ssl3_mat_derive_error;
	    
	    rv = CI_Ceay_DigestUpdate(session_data, 
				      param->RandomInfo.pClientRandom,
				      param->RandomInfo.ulClientRandomLen);
	    if(rv != CKR_OK) goto ssl3_mat_derive_error;	    
	    rv = CI_Ceay_DigestFinal(session_data, NULL_PTR, &buf_len);
	    
	    if((buf = CI_ByteStream_new(buf_len)) == NULL_PTR)
	      { rv = CKR_HOST_MEMORY; goto ssl3_mat_derive_error; }
	    rv = CI_Ceay_DigestFinal(session_data, buf, &buf_len);
	    if(rv != CKR_OK) goto ssl3_mat_derive_error;
	    
	    rv = CI_ObjSetIntAttributeValue(serverKey,CK_IA_VALUE, buf, buf_len);
	    if(rv != CKR_OK) goto ssl3_mat_derive_error;
	    
	    rv = CI_ObjSetIntAttributeValue(serverKey, CK_IA_VALUE_LEN, 
					    (CK_BYTE_PTR)&CK_I_SSL_WRITE_KEY_LEN, 
					    sizeof(CK_I_SSL_WRITE_KEY_LEN));
	    if(rv != CKR_OK) goto ssl3_mat_derive_error;
	    
	    CI_VarLogEntry("CI_Ceay_DeriveKey","final server Key: %s",rv,2,
			   tmp_str = CI_PrintableByteStream(buf,buf_len));
	    /* gleich wieder aufräumen! */
	    TC_free(buf); buf = NULL_PTR;
	    TC_free(tmp_str);
	  }
	
	/* Ok alles gutgegangen jetzt die Object in die Hashtabelle */
	rv = CI_InternalCreateObject(session_data,clientMac, 
				     &(param->pReturnedKeyMaterial->hClientMacSecret));
	if( rv != CKR_OK ) goto ssl3_mat_derive_error; else hash_flag|=1;
	rv = CI_InternalCreateObject(session_data, serverMac, 
				     &(param->pReturnedKeyMaterial->hServerMacSecret));
	if( rv != CKR_OK ) goto ssl3_mat_derive_error;  else hash_flag|=2;
	rv = CI_InternalCreateObject(session_data,clientKey, 
				     &(param->pReturnedKeyMaterial->hClientKey));
	if( rv != CKR_OK ) goto ssl3_mat_derive_error;  else hash_flag|=4;
	rv = CI_InternalCreateObject(session_data, serverKey, 
				     &(param->pReturnedKeyMaterial->hServerKey));
	if( rv != CKR_OK ) goto ssl3_mat_derive_error;  else hash_flag|=8;
	
      ssl3_mat_derive_error:	
	if(key_block != NULL_PTR)
	  {
	    memset(key_block,0,CK_I_SSL3_PRE_MASTER_SIZE);
	    TC_free(key_block);
	  }
	if(buf != NULL_PTR) TC_free(buf);
	
	if(rv != CKR_OK)
	  {
	    if(hash_flag & 1)
	      CI_InternalDestroyObject(session_data, 
				       param->pReturnedKeyMaterial->hClientMacSecret,
				       TRUE);
	    else
	      if(clientMac != NULL_PTR) CI_ObjDestroyObj(clientMac);
	    
	    if(hash_flag & 2)
	      CI_InternalDestroyObject(session_data, 
				       param->pReturnedKeyMaterial->hServerMacSecret, 
				       TRUE);
	    else
	      if(serverMac != NULL_PTR) CI_ObjDestroyObj(serverMac);
	    
	    if(hash_flag & 4)
	      CI_InternalDestroyObject(session_data, 
				       param->pReturnedKeyMaterial->hClientKey,
				       TRUE);
	    else
	      if(clientKey != NULL_PTR) CI_ObjDestroyObj(clientKey);
	    
	    if(hash_flag & 8)
	      CI_InternalDestroyObject(session_data, 
				       param->pReturnedKeyMaterial->hServerKey, 
				       TRUE);
	    else
	      if(serverKey != NULL_PTR) CI_ObjDestroyObj(serverKey);
	  }
      }
      break;
      /* }}} */
    default:
      rv = CKR_MECHANISM_INVALID;
    }

  CI_LogEntry("CI_Ceay_DeriveKey", "...complete", rv, 2);

  return rv;
}
/* }}} */

/* {{{ CI_Ceay_SeedRandom */
CK_DEFINE_FUNCTION(CK_RV, CI_Ceay_SeedRandom)(
  CK_I_SESSION_DATA_PTR  session_data,
  CK_BYTE_PTR       pSeed,     /* the seed material */
  CK_ULONG          ulSeedLen  /* length of seed material */
)
{
  CI_Ceay_RAND_seed(pSeed,ulSeedLen);
  return CKR_OK;
}
/* }}} */
/* {{{ CI_Ceay_GenerateRandom */
CK_DEFINE_FUNCTION(CK_RV, CI_Ceay_GenerateRandom)(
  CK_I_SESSION_DATA_PTR  session_data,
  CK_BYTE_PTR       pRandomData,  /* receives the random data */
  CK_ULONG          ulRandomLen  /* # of bytes to generate */
)
{
#if !defined(NO_REAL_RANDOM)
  CI_Ceay_RAND_bytes(pRandomData,ulRandomLen);
#else
  CK_ULONG i;
  for(i=0; i<ulRandomLen ; i++)
    /*    pRandomData[i]=i%256; */
        pRandomData[i]=15;
#endif

  return CKR_OK;
}
/* }}} */

/* {{{ CI_Ceay_GetFunctionStatus */
CK_DEFINE_FUNCTION(CK_RV, CI_Ceay_GetFunctionStatus)(
  CK_I_SESSION_DATA_PTR  session_data
)
{
  return CKR_FUNCTION_NOT_SUPPORTED;
}
/* }}} */

/* {{{ CI_Ceay_CancelFunction */
CK_DEFINE_FUNCTION(CK_RV, CI_Ceay_CancelFunction)(
  CK_I_SESSION_DATA_PTR  session_data
)
{
  return CKR_FUNCTION_NOT_SUPPORTED;
}
/* }}} */

/* {{{ CI_Ceay_WaitForSlotEvent */
CK_DEFINE_FUNCTION(CK_RV, CI_Ceay_WaitForSlotEvent)(
  CK_FLAGS flags,        /* blocking/nonblocking flag */
  CK_SLOT_ID_PTR pSlot,  /* location that receives the slot ID */
  CK_VOID_PTR pRserved   /* reserved.  Should be NULL_PTR */
)
{
  return CKR_FUNCTION_NOT_SUPPORTED;
}
/* }}} */

/* ### Persistent Storage ### */

#define CK_I_FILE_READ 0
#define CK_I_FILE_WRITE 1

#define CK_I_FILE_PUBLIC 0
#define CK_I_FILE_PRIVATE 2
#define CK_I_FILE_CONF 4

#define CK_I_PERSISTENT_CACHE_SIZE 20

/* {{{ CI_Ceay_GetPersistentFile */
CK_DEFINE_FUNCTION(CK_RV, CI_Ceay_GetPersistentFile)(
  FILE CK_PTR CK_PTR ppFile,
  CK_ULONG flags
)
{
  CK_CHAR field_name[30];
  CK_CHAR_PTR file_name;
  CK_CHAR_PTR file_type;
  CK_SLOT_ID slotID;
  CK_RV rv = CKR_OK;

  CI_LogEntry("CI_Ceay_GetPersistentFile","starting...",rv,2);

  if(flags & CK_I_FILE_CONF) file_type = "Config";
  else if(flags & CK_I_FILE_PRIVATE) file_type = "Private";
  else file_type = "Public";

  slotID = Ceay_token_data.slot;
  sprintf(field_name,"Persistent%sFile%lu", file_type, (CK_ULONG)slotID);

  file_name = NULL_PTR;
  rv = CI_GetConfigString(CEAY_CONFIG_SECTION, field_name, &file_name);

  if(rv != CKR_OK)
    {
      return rv;
    }

  *ppFile = NULL_PTR;
  if(flags & CK_I_FILE_WRITE)
    *ppFile = fopen(file_name, "wb");
  else /* CK_I_FILE_READ */
    *ppFile = fopen(file_name, "rb");

  if(*ppFile == NULL_PTR)
    {
      CI_VarLogEntry("CI_Ceay_GetPersistentFile","could not open storage file '%s': %s",rv,0,
		     file_name,strerror(errno));
      /* TODO: check for other than 'file not found' errors and assign proper error code */
      rv = CKR_FILE_NOT_FOUND;
    }
  
  free(file_name);

  CI_LogEntry("CI_Ceay_GetPersistentFile","...complete",rv,2);

  return rv;
}
/* }}} */
/* {{{ CI_Ceay_ReadPersistent */
CK_DEFINE_FUNCTION(CK_RV, CI_Ceay_ReadPersistent)(
  CK_I_SESSION_DATA_PTR session_data,
  CK_I_HASHTABLE_PTR CK_PTR ppCache
)
{
  CK_RV rv = CKR_OK;
  CK_OBJECT_HANDLE handle;
  CK_I_OBJ_PTR curr_obj = NULL_PTR;
  CK_CHAR_PTR db_file;
  CK_ULONG obj_count =1; 

  CK_I_CRYPT_DB_PTR cryptdb;
  
  CI_LogEntry("CI_Ceay_ReadPersistentFile","starting...",rv,2);

  /* alloc new hashtable */
  rv = CI_InitHashtable(ppCache,CK_I_PERSISTENT_CACHE_SIZE);
  if(rv != CKR_OK) 
    return rv;

  /* open the database */
  rv = CI_GetConfigString(CEAY_CONFIG_SECTION, "PersistentDataFile",&db_file);
  if(rv != CKR_OK)
    {
      CI_LogEntry("CI_Ceay_PersistentRead","Error reading field from config file.",rv,0);      
      return rv;
    }

  cryptdb = CDB_Open(db_file);
  if(cryptdb == NULL_PTR) 
    {
      rv = CKR_GENERAL_ERROR;
      CI_VarLogEntry("CI_Ceay_ReadPersistentFile","failed to open database '%s': %s",
		     rv,0,db_file,strerror(errno));
      return rv;
    }

  /* get the pin */
  /* TODO: enable this for multiple application support */
  if(session_data->user_type == CKU_SO)
    CDB_SetPin(cryptdb, TRUE, 
	       IMPL_DATA(so_pin), 
	       IMPL_DATA(so_pin_len));
  else
    CDB_SetPin(cryptdb, FALSE, 
	       IMPL_DATA(user_pin), 
	       IMPL_DATA(user_pin_len));
  
  rv = CDB_GetObjectInit(cryptdb);
  if(rv != CKR_OK)
    {
      CI_LogEntry("CI_Ceay_ReadPersistentFile","Initializing cryptdb failed",
		  rv,0);
      CDB_Close(cryptdb);
      return rv;
    }    

  while(((rv = CDB_GetObjectUpdate( cryptdb, &curr_obj)) == CKR_OK) && 
	(curr_obj != NULL_PTR))
    {
      CI_NewHandle(&handle); /* Wir ignorieren hier mal den Fehler */
      CI_VarLogEntry("CI_Ceay_ReadPersistentFile","Adding Object no %d (handle: %lu)",
		     rv,0,obj_count++,handle);
      rv = CI_ContainerAddObj(*ppCache,handle,curr_obj);
      if(rv != CKR_OK)
	{
	  CI_ObjDestroyObj(curr_obj);
	  CI_LogEntry("CI_Ceay_ReadPersistentFile","Writing object to container failed",
		      rv,0);
	  CDB_Close(cryptdb);
	  return rv;
	}    
    }
  if(rv != CKR_OK)
    {
      CI_LogEntry("CI_Ceay_ReadPersistentFile","error when reading from database",
		  rv,0);
      CDB_Close(cryptdb);
      return rv;
    }    

  rv = CDB_GetObjectFinal(cryptdb);
  if(rv != CKR_OK)
    {
      CI_LogEntry("CI_Ceay_ReadPersistentFile","error when ending reading of objects",
		  rv,0);
      CDB_Close(cryptdb);
      return rv;
    }    

  /* Close the library */
  rv = CDB_Close(cryptdb);
  if(rv != CKR_OK)
    {
      CI_LogEntry("CI_Ceay_ReadPersistentFile","error when closing database",
		  rv,0);
      return rv;
    }    

  CI_LogEntry("CI_Ceay_ReadPersistentFile","...complete",rv,2);

  return CKR_OK;
}
/* }}} */
/* {{{ CI_Ceay_ReadPrivate */
/* Piling, 1999/12/18
 * The function is used to retrieve private data from the db token,
 * since public objects are loaded into memory as system inititalized
 * therefore the private objects are only be loaded after user login
 * (pin required to decode des data)
 */

CK_DEFINE_FUNCTION(CK_RV, CI_Ceay_ReadPrivate)(
 CK_I_SESSION_DATA_PTR session_data,
 CK_I_CRYPT_DB_PTR cryptdb 
)
{
  CK_I_HASH_ITERATOR_PTR pIter;
  CK_ULONG key;
  CK_I_OBJ_PTR val;
  CK_RV rv = CKR_OK;
  CK_I_OBJ_PTR curr_obj = NULL_PTR;
  CK_ULONG obj_count =1;
  CK_OBJECT_HANDLE phObject;

  CI_LogEntry("CI_Ceay_TokenObjLoad","starting...",rv,2);

  rv = CDB_GetObjectInit(cryptdb);
  if(rv != CKR_OK)
    {
      CI_LogEntry("CI_Ceay_TokenObjLoad","Init cryptdb failed", rv,0);
      return rv;
    } 

  while(((rv = CDB_GetPrivObject( cryptdb, &curr_obj)) == CKR_OK) && (curr_obj != NULL_PTR))
    {
      CI_NewHandle(&phObject); /* Wir ignorieren hier mal den Fehler */
      CI_VarLogEntry("CI_Ceay_TokenObjLoad","Adding Object no %d (phObject: %lu)",
		     rv,0,obj_count++,phObject);
      rv = CI_ContainerAddObj(IMPL_DATA(persistent_cache),phObject,curr_obj);
      if(rv != CKR_OK)
	{
	  CI_ObjDestroyObj(curr_obj);
	  CI_LogEntry("CI_Ceay_TokenObjLoad","Writing object to container failed",
		      rv,0);
	  return rv;
	}    
    } 

  /* copy all persistent objects into the session object list */
  for(CI_HashIterateInit(IMPL_DATA(persistent_cache),&pIter);
      CI_HashIterValid(pIter);
      CI_HashIterateInc(pIter))
    {
      rv = CI_HashIterateDeRef(pIter,&key,(CK_VOID_PTR_PTR)&val);
      if(rv != CKR_OK) 
	{
	  CI_LogEntry("CI_Ceay_TokenObjLoad",
		      "failed to deref iter on persistent cache",rv,0);
	  return rv;
	}

      rv = CI_ContainerAddObj(session_data->slot_data->token_data->object_list,key,val);
      if(rv != CKR_OK) 
	{
	  CI_LogEntry("CI_Ceay_TokenObjLoad", 
		      "failed to insert object into application obj list", rv ,0);
	  return rv; 
	}
      /* tell the object who it belongs to */
      val->session = session_data;
      
      rv = CI_ContainerAddObj(session_data->object_list,key,val);
      if(rv != CKR_OK) 
	{
	  CI_LogEntry("CI_Ceay_TokenObjLoad",
		      "failed to add object to persistent storage",rv,0);
	  return rv;
	}
    }
  CI_HashIterateDelete(pIter);

  rv = CDB_GetObjectFinal(cryptdb);
  if(rv != CKR_OK)
    {
      CI_LogEntry("CI_Ceay_TokenObjLoad",
		  "error when ending reading of objects", rv,0);
      return rv;
    }  
  CI_LogEntry("CI_Ceay_TokenObjLoad","...complete",rv,2);

  return CKR_OK;
}
/* }}} */
/* {{{ CI_Ceay_TokenObjAdd */
CK_DEFINE_FUNCTION(CK_RV, CI_Ceay_TokenObjAdd)(
  CK_I_SESSION_DATA_PTR session_data,
  CK_OBJECT_HANDLE phObject, 
  CK_I_OBJ_PTR pNewObject
)
{
  CK_RV rv = CKR_OK;
  CK_I_HASH_ITERATOR_PTR pIter;
  CK_I_SESSION_DATA_PTR val;
  CK_I_CRYPT_DB_PTR cryptdb;
  CK_CHAR_PTR db_file;

  CI_LogEntry("CI_Ceay_TokenObjAdd","starting...", rv ,2);

  /* init the cache */
  if(IMPL_DATA(persistent_cache) == NULL_PTR)
    {
      rv = CI_Ceay_ReadPersistent(session_data,&IMPL_DATA(persistent_cache));
      /* if there is no file it does not matter, the hash was initialized */
      if((rv != CKR_OK) && (rv != CKR_FILE_NOT_FOUND))
	{
	  CI_LogEntry("CI_Ceay_TokenObjAdd","init of persistent_cache failed", rv ,0);
	  return rv;
	}
      rv = CKR_OK; /* reset in case the function returned CKR_FILE_NOT_FOUND */
    }
  else
    {
      CI_VarLogEntry("CI_Ceay_TokenObjAdd","cache already loaded (IMPL_DATA(persistent_cache): %p", 
		  rv ,3, IMPL_DATA(persistent_cache));
    }

  /* add the object to the table */
  rv = CI_ContainerAddObj(IMPL_DATA(persistent_cache),phObject,pNewObject);
  if(rv != CKR_OK)
    {
      CI_LogEntry("CI_Ceay_TokenObjAdd","could not insert object into persistent cache", 
		  rv ,0);
    }

  /* propagate new object to all sessions of this token */
  for(CI_HashIterateInit(IMPL_DATA(session_list),&pIter);
      CI_HashIterValid(pIter);
      CI_HashIterateInc(pIter))
    {
      rv = CI_HashIterateDeRef(pIter, NULL_PTR, (CK_VOID_PTR CK_PTR)&val);
      if(rv != CKR_OK)
	{
	  CI_LogEntry("CI_Ceay_TokenObjAdd","failure to de-ref the object iter", rv ,0);
	  return rv;
	}

      /* TODO: check that the object is in a Private-RW state */
      rv = CI_ContainerAddObj(val->object_list, phObject, pNewObject);
      if(rv != CKR_OK)
	{
	  CI_LogEntry("CI_Ceay_TokenObjAdd","could not insert object into persistent cache", 
		      rv ,0);
	}
    }

  /* open the database */
  rv = CI_GetConfigString(CEAY_CONFIG_SECTION, "PersistentDataFile",&db_file);
  if(rv != CKR_OK)
    {
      CI_LogEntry("CI_Ceay_TokenObjAdd","Error reading field from config file.",rv,0);      
      return rv;
    }

  cryptdb = CDB_Open(db_file);
  if(cryptdb == NULL_PTR) 
    {
      rv = CKR_GENERAL_ERROR;
      CI_VarLogEntry("CI_Ceay_TokenObjAdd","failed to open database '%s'", 
		     rv ,0, db_file);
      return rv;
    }

  /* get the pin */
  /* TODO: enable this for multiple application support */
  if(session_data->user_type == CKU_SO)
    CDB_SetPin(cryptdb, TRUE, 
	       IMPL_DATA(so_pin), 
	       IMPL_DATA(so_pin_len));
  else
    CDB_SetPin(cryptdb, FALSE, 
	       IMPL_DATA(user_pin), 
	       IMPL_DATA(user_pin_len));
  
  /* write the data to the persistent storage */ 
  rv = CDB_PutObject(cryptdb,pNewObject);
  if(rv != CKR_OK)
    {
      CI_LogEntry("CI_Ceay_TokenObjAdd","failed to write objects on persistent storage", rv ,0);
      return rv;
    }

  rv = CDB_Close(cryptdb);
  if(rv != CKR_OK)
    {
      CI_LogEntry("CI_Ceay_TokenObjAdd","failed to close persistent storage database", rv ,0);
      return rv;
    }

  CI_LogEntry("CI_Ceay_TokenObjAdd","...complete", rv ,2);

 return rv;  
}
/* }}} */
/* {{{ CI_Ceay_TokenObjCommit */
/** save the data after changing an object */
CK_DEFINE_FUNCTION(CK_RV, CI_Ceay_TokenObjCommit)(
  CK_I_SESSION_DATA_PTR session_data,
  /* need handle to retrieve object */
  CK_OBJECT_HANDLE hObject,
  CK_I_OBJ_PTR pObject
)
{
  CK_RV rv = CKR_OK;
  CK_CHAR_PTR db_file;
  CK_I_CRYPT_DB_PTR cryptdb;

  /* If the data was not loaded, we shall not overwrite the change by reading 
   * it now 
   */
  if(IMPL_DATA(persistent_cache) == NULL_PTR)
    return CKR_GENERAL_ERROR; 

  /* open the database */
  rv = CI_GetConfigString(CEAY_CONFIG_SECTION, "PersistentDataFile",&db_file);
  if(rv != CKR_OK)
    {
      CI_LogEntry("CI_Ceay_TokenObjCommit","Error reading field from config file.",rv,0);      
      return rv;
    }

  cryptdb = CDB_Open(db_file);
  if(cryptdb == NULL_PTR) return CKR_GENERAL_ERROR;

  /* get the pin */
  /* TODO: enable this for multiple application support */
  if(session_data->user_type == CKU_SO)
    CDB_SetPin(cryptdb, TRUE, 
	       IMPL_DATA(so_pin), 
	       IMPL_DATA(so_pin_len));
  else
    CDB_SetPin(cryptdb, FALSE, 
	       IMPL_DATA(user_pin), 
	       IMPL_DATA(user_pin_len));
  
  rv = CDB_UpdateObject(cryptdb,pObject);
  if(rv != CKR_OK)
    return rv;

  rv = CDB_Close(cryptdb);
  
 return rv;  
}
/* }}} */
/* {{{ CI_Ceay_TokenObjDelete */
CK_DEFINE_FUNCTION(CK_RV, CI_Ceay_TokenObjDelete)(
  CK_I_SESSION_DATA_PTR session_data,
  CK_OBJECT_HANDLE hObject
)
{
  CK_RV rv = CKR_OK;
  CK_I_HASH_ITERATOR_PTR pIter;
  CK_I_CRYPT_DB_PTR cryptdb;
  CK_I_OBJ_PTR obj;
  CK_CHAR_PTR db_file;

  /* TODO: check that the object is in a Private-RW state */

  /* If the data was not loaded, we shall not overwrite the change by reading 
   * it now 
   */
  if(IMPL_DATA(persistent_cache) == NULL_PTR)
    {
      rv = CKR_GENERAL_ERROR; 
      CI_LogEntry("CI_Ceay_TokenObjDelete","persistent cache has not been initialized", 
		  rv ,0);
      return rv;
    }

  /* remove object from persistent storage */
  /* open the database */
  rv = CI_GetConfigString(CEAY_CONFIG_SECTION, "PersistentDataFile",&db_file);
  if(rv != CKR_OK)
    {
      CI_LogEntry("CI_Ceay_TokenObjDelete","Error reading field from config file.",rv,0);      
      return rv;
    }

  cryptdb = CDB_Open(db_file);
  if(cryptdb == NULL_PTR) return CKR_GENERAL_ERROR;

  /* get the pin */
  /* TODO: enable this for multiple application support */
  if(session_data->user_type == CKU_SO)
    CDB_SetPin(cryptdb, TRUE, 
	       IMPL_DATA(so_pin), 
	       IMPL_DATA(so_pin_len));
  else
    CDB_SetPin(cryptdb, FALSE, 
	       IMPL_DATA(user_pin), 
	       IMPL_DATA(user_pin_len));
  
  /* delete object */
  rv = CI_ReturnObj(session_data, hObject, &obj);
  if (rv != CKR_OK)
    {
      CI_LogEntry("CI_Ceay_TokenObjDelete","could not retrieve object", 
		  rv ,0);
      return rv;
    }
  rv = CDB_DeleteObject(cryptdb, obj);
  if (rv != CKR_OK)
    {
      CI_LogEntry("CI_Ceay_TokenObjDelete","could not delete object from database", 
		  rv ,0);
      return rv;
    }
  
  /* close database */
  rv = CDB_Close(cryptdb);
  if (rv != CKR_OK)
    {
      CI_LogEntry("CI_Ceay_TokenObjDelete","Closing of database failed.", 
		  rv ,0);
      return rv;
    }

  /* remove from all temporary storages */
  rv = CI_ContainerDelObj(IMPL_DATA(persistent_cache),hObject);
  if(rv != CKR_OK)
    {
       CI_LogEntry("CI_Ceay_TokenObjDelete","could not delete object from persistent cache", 
		  rv ,0);
    }

  /* remove object from all sessions */
  for(CI_HashIterateInit(IMPL_DATA(session_list),&pIter);
      CI_HashIterValid(pIter);
      CI_HashIterateInc(pIter))
    {
      rv = CI_HashIterateDeRef(pIter, NULL_PTR, (CK_VOID_PTR CK_PTR)&session_data);
      if(rv != CKR_OK)
	return rv;
      
      rv = CI_ContainerDelObj(session_data->object_list, hObject);
      if(rv != CKR_OK)
	{
	  CI_LogEntry("CI_Ceay_TokenObjDelete",
		      "could not delete object from session object list", 
		      rv ,0);
	}
    }
  
  
 return rv;  
}
/* }}} */

/* {{{ Ceay_token_methods */
CK_I_TOKEN_METHODS Ceay_token_methods = {
  CI_Ceay_GetTokenInfo,
  CI_Ceay_GetMechanismList,
  CI_Ceay_GetMechanismInfo,
  CI_Ceay_InitToken,
  CI_Ceay_FinalizeToken,
  CI_Ceay_InitPIN,
  CI_Ceay_SetPIN,
  CI_Ceay_OpenSession,
  CI_Ceay_CloseSession,
  CI_Ceay_GetOperationState,
  CI_Ceay_SetOperationState,
  CI_Ceay_Login,
  CI_Ceay_Logout,
  CI_Ceay_EncryptInit,
  CI_Ceay_Encrypt,
  CI_Ceay_EncryptUpdate,
  CI_Ceay_EncryptFinal,
  CI_Ceay_DecryptInit,
  CI_Ceay_Decrypt,
  CI_Ceay_DecryptUpdate,
  CI_Ceay_DecryptFinal,
  CI_Ceay_DigestInit,
  CI_Ceay_Digest,
  CI_Ceay_DigestUpdate,
  CI_Ceay_DigestKey,
  CI_Ceay_DigestFinal,
  CI_Ceay_SignInit,
  CI_Ceay_Sign,
  CI_Ceay_SignUpdate,
  CI_Ceay_SignFinal,
  CI_Ceay_SignRecoverInit,
  CI_Ceay_SignRecover,
  CI_Ceay_VerifyInit,
  CI_Ceay_Verify,
  CI_Ceay_VerifyUpdate,
  CI_Ceay_VerifyFinal,
  CI_Ceay_VerifyRecoverInit,
  CI_Ceay_VerifyRecover,
  CI_Ceay_DigestEncryptUpdate,
  CI_Ceay_DecryptDigestUpdate,
  CI_Ceay_SignEncryptUpdate,
  CI_Ceay_DecryptVerifyUpdate,
  CI_Ceay_GenerateKey,
  CI_Ceay_GenerateKeyPair,
  CI_Ceay_WrapKey,
  CI_Ceay_UnwrapKey,
  CI_Ceay_DeriveKey,
  CI_Ceay_SeedRandom,
  CI_Ceay_GenerateRandom,
  CI_Ceay_GetFunctionStatus,
  CI_Ceay_CancelFunction,
  CI_Ceay_WaitForSlotEvent,

  CI_Ceay_TokenObjAdd,
  CI_Ceay_TokenObjCommit,
  CI_Ceay_TokenObjDelete
};
/* }}} */

/* TODO: code to handle for Flags: 
 * CKF_WRITE_PROTECTED, 
 * CKF_LOGIN_REQUIRED, 
 * CKF_RESTORE_KEY_NOT_NEEDED, 
 * 
 * no CKF_CLOCK_ON_TOKEN: the clock is the same for the rest of the 
 *                        application, hence no _seperate H/W Clock_
 * no CKF_PROTECTED_AUTHENTICATION_PATH: All input is via the application
 */
#define CK_I_MAX_SESSION_COUNT   100
#define CK_I_MAX_RW_SESSION_COUNT   100
#define CK_I_MIN_PIN_LEN 8
#define CK_I_MAX_PIN_LEN 255

/* {{{ CK_TOKEN_INFO Ceay_token_info */
CK_TOKEN_INFO Ceay_token_info = {
"OpenSSL Wrap Token              ", /* label (32 Characters) */
"TC TrustCenter GmbH, Hamburg    ", /* manufacturerID (32 Characters) */
"OpenSSLWrap     ",                /* model (16 chars) */
"1               ",                /* serial number (16 chars) 
				    * TODO: sollten wir hier der Software S/N's per build geben? 
				    * datum? epoch? 
				    */
CKF_RNG|CKF_USER_PIN_INITIALIZED|CKF_DUAL_CRYPTO_OPERATIONS, /* flags */
CK_I_MAX_SESSION_COUNT,            /* ulMaxSessionCount */
0,                                 /* ulSessionCount */
CK_I_MAX_RW_SESSION_COUNT,         /* ulMaxRwSessionCount */
0,                                 /* ulRwSessionCount */
CK_I_MAX_PIN_LEN,                  /* ulMaxPinLen in bytes */
CK_I_MIN_PIN_LEN,                  /* ulMinPinLen in bytes*/
CK_EFFECTIVELY_INFINITE,           /* ulTotalPublicMemory in bytes */
CK_EFFECTIVELY_INFINITE,           /* ulFreePublicMemory in bytes */
CK_EFFECTIVELY_INFINITE,           /* ulTotalPrivateMemory in bytes */
CK_EFFECTIVELY_INFINITE,           /* ulFreePrivateMemory in bytes */
{0,0},                             /* hardwareVersion */
{0,94},                            /* firmwareVersion (Version of used OpenSSL Lib) */
"                "                 /* time (16 characters) */
};
/* }}} */


CK_I_CEAY_IMPL_DATA Ceay_impl_data = {
  NULL_PTR,
  NULL_PTR,
  0
};

CK_I_TOKEN_DATA Ceay_token_data = {
  &Ceay_token_info,
  0,  /* dummy. will be set by the init functions with the slot of the token */
  NULL_PTR, /* will be filled with the object_list */
  &Ceay_impl_data
};

/* dynamically fill table of slots in init.c and slot.c
 * (using gpkcs11.rc and following data structures) 
 */
CK_SLOT_INFO Ceay_slot_info={
  "GNU PKCS #11 Wrapper for SSLeay                        ",
  "TrustCenter GmbH, Hamburg     ",
  CKF_TOKEN_PRESENT, /* this token is allways present */
  {0,0},
  {0,1}
};

static CK_I_SLOT_DATA Ceay_slot_data={
  0, 
  NULL_PTR, 
  &Ceay_slot_info, 
  &Ceay_token_data,
  &Ceay_token_methods
 };

/* {{{ ceayToken_init */
CK_DEFINE_FUNCTION(CK_RV, ceayToken_init)(
 CK_CHAR_PTR token_name,
 CK_I_SLOT_DATA_PTR CK_PTR ppSlotData
)
{
  CK_RV rv = CKR_OK;

  CI_LogEntry("ceayToken_init", "starting...", rv, 2);

  *ppSlotData = &Ceay_slot_data;
  Ceay_slot_data.flags = 0;
  Ceay_slot_data.slot_info = &Ceay_slot_info;
  Ceay_slot_data.token_data = &Ceay_token_data;

  CI_LogEntry("ceayToken_init", "...complete", rv, 2);
  return rv;
}
/* }}} */

/***************************************************************
 *     internal functions, not defined in internal.h           *
 ***************************************************************/

/* {{{ CI_Ceay_Obj2RSA */
/** Erzeugen einer internen struktur aus einem Template.
 * @return ceay interne RSA Schlüssel Struktur; NULL_PTR bei auftreten 
 *         eines Fehlers
 * @param  key_obj Schlüssel der in die Struktur gewandelt werden soll.
 */
CK_DEFINE_FUNCTION(RSA_PTR, CI_Ceay_Obj2RSA)(
 CK_I_OBJ_PTR key_obj
)
{
  BN_CTX *ctx=NULL_PTR;
  BIGNUM CK_PTR r1=NULL_PTR, CK_PTR r2=NULL_PTR;
  CK_RV rv = CKR_OK;
  
  RSA_PTR internal_key_obj = CI_Ceay_RSA_new();
  if(internal_key_obj == NULL_PTR)
    return NULL_PTR;
  
  rv = CI_Ceay_ObjEntry2BN(CI_ObjLookup(key_obj,CK_IA_MODULUS),&(internal_key_obj->n));
  if(rv != CKR_OK) return NULL_PTR;
  rv = CI_Ceay_ObjEntry2BN(CI_ObjLookup(key_obj,CK_IA_PUBLIC_EXPONENT),&(internal_key_obj->e));
  if(rv != CKR_OK) return NULL_PTR;
  
  /* check that object is a public key */
  if(*((CK_OBJECT_CLASS CK_PTR)CI_ObjLookup(key_obj,CK_IA_CLASS)->pValue) == CKO_PUBLIC_KEY)
    return internal_key_obj;
  
  if(*((CK_OBJECT_CLASS CK_PTR)CI_ObjLookup(key_obj,CK_IA_CLASS)->pValue) == CKO_PRIVATE_KEY)
    {
      ctx=BN_CTX_new();
      if (ctx == NULL) { internal_key_obj=NULL_PTR; goto rsa_err; }
      r1=&(ctx->bn[0]);
      r2=&(ctx->bn[1]);
      ctx->tos+=2;
      
      /* copy entries into internal key object (compute if missing) */
      rv = CI_Ceay_ObjEntry2BN(CI_ObjLookup(key_obj,CK_IA_PRIVATE_EXPONENT),&(internal_key_obj->d));
      if(rv != CKR_OK) { internal_key_obj = NULL_PTR; goto rsa_err; }

      /* TODO: paranoia check if PRIME_1 and PRIME_2 are avaliable */
      rv = CI_Ceay_ObjEntry2BN(CI_ObjLookup(key_obj,CK_IA_PRIME_1),&(internal_key_obj->p));
      if(rv != CKR_OK) { internal_key_obj = NULL_PTR; goto rsa_err; }
      rv = CI_Ceay_ObjEntry2BN(CI_ObjLookup(key_obj,CK_IA_PRIME_2),&(internal_key_obj->q));
      if(rv != CKR_OK) { internal_key_obj = NULL_PTR; goto rsa_err; }

      /* compute the following if missing */
      if(CI_ObjLookup(key_obj,CK_IA_EXPONENT_1) != NULL_PTR)
	{
	  rv = CI_Ceay_ObjEntry2BN(CI_ObjLookup(key_obj,CK_IA_EXPONENT_1),&(internal_key_obj->dmp1));
	  if(rv != CKR_OK) { internal_key_obj = NULL_PTR; goto rsa_err; }
	}
      else /* compute the value */
	{
	  /* calculate d mod (p-1) */
	  if (!BN_sub(r1,internal_key_obj->p,BN_value_one()))        /* p-1 */
	    { internal_key_obj = NULL_PTR; goto rsa_err; }
	  internal_key_obj->dmp1=BN_new();
	  if (internal_key_obj->dmp1 == NULL) { internal_key_obj = NULL_PTR; goto rsa_err; }
	  if (!BN_mod(internal_key_obj->dmp1,internal_key_obj->d,r1,ctx)) 
	    { internal_key_obj = NULL_PTR; goto rsa_err; }
	}
      
      if(CI_ObjLookup(key_obj,CK_IA_EXPONENT_2) != NULL_PTR)
	{
	  rv = CI_Ceay_ObjEntry2BN(CI_ObjLookup(key_obj,CK_IA_EXPONENT_2),&(internal_key_obj->dmq1));
	  if(rv != CKR_OK) { internal_key_obj = NULL_PTR; goto rsa_err; }
	}
      else /* compute the value */
	{
	  /* calculate d mod (q-1) */
	  if (!BN_sub(r2,internal_key_obj->q,BN_value_one()))   /* q-1 */
	    { internal_key_obj = NULL_PTR; goto rsa_err; }
	  internal_key_obj->dmq1=BN_new();
	  if (internal_key_obj->dmq1 == NULL) { internal_key_obj = NULL_PTR; goto rsa_err; }
	  if (!BN_mod(internal_key_obj->dmq1,internal_key_obj->d,r2,ctx)) 
	    { internal_key_obj = NULL_PTR; goto rsa_err; }
	}
      
      if(CI_ObjLookup(key_obj, CK_IA_COEFFICIENT) != NULL_PTR)
	{
	  rv = CI_Ceay_ObjEntry2BN(CI_ObjLookup(key_obj,CK_IA_COEFFICIENT),&(internal_key_obj->iqmp));
	  if(rv != CKR_OK) { internal_key_obj = NULL_PTR; goto rsa_err; }
	}
      else /* compute the value */
	{
	  /* calculate inverse of q mod p */
	  internal_key_obj->iqmp=BN_mod_inverse(NULL, internal_key_obj->q,internal_key_obj->p,ctx);
	  if (internal_key_obj->iqmp == NULL) 
	    { internal_key_obj = NULL_PTR; goto rsa_err;}
	}
  
    rsa_err:
	if(ctx != NULL_PTR ) BN_CTX_free(ctx);
	
	return internal_key_obj;
    }
  
  /* weder private noch public key, irgendetwas muss falsch sein */
  return NULL_PTR;
}
/* }}} */
/* {{{ CI_Ceay_RSA2Obj */
/** Füllt Teile eines Templates aus einer internen Struktur.
 * Dir Funktion ruft CI_SetAttributeValue() auf um die Werte zu setzen. Um
 * ein mehrmaliges Umkopieren der Attributestabelle zu vermeiden, sollten 
 * die Einträge im Objekt schon vorher zur Verfügung stehen. Welche das im
 * einzelnen sind hängt davon ab welche Werte in der RSA Struktur enthalten
 * sind und ob es sich um einen private- oder public-key handelt.
 *
 * @param rsa_struct interne Struktur welch die Werte des Schlüssels enthält
 * @param pKeyObj Template in die die Werte der RSA Struktur geschrieben werden.
 */
CK_DEFINE_FUNCTION(CK_RV, CI_Ceay_RSA2Obj)(
 RSA CK_PTR rsa_struct,
 CK_I_OBJ_PTR pKeyObj
)
{
  BN_CTX *ctx=NULL_PTR;
  BIGNUM CK_PTR r1=NULL_PTR, CK_PTR r2=NULL_PTR;
  CK_RV rv = CKR_OK;
  
  /* check that object is a public or private key */
  if((*((CK_OBJECT_CLASS CK_PTR)CI_ObjLookup(pKeyObj,CK_IA_CLASS)->pValue) == CKO_PUBLIC_KEY)
     ||(*((CK_OBJECT_CLASS CK_PTR)CI_ObjLookup(pKeyObj,CK_IA_CLASS)->pValue) == CKO_PRIVATE_KEY))
    {
      /* copy entries into internal key object (compute if missing) */
      if((rv = CI_Ceay_BN2ObjEntry(CKA_MODULUS,rsa_struct->n,
			      pKeyObj, NULL_PTR)) 
	 != CKR_OK) 
	return rv;

      if((rv = CI_Ceay_BN2ObjEntry(CKA_PUBLIC_EXPONENT,rsa_struct->e,
			      pKeyObj, NULL_PTR)) 
	 != CKR_OK) 
	return rv;

      /* thats it for a public key */
      if(*((CK_OBJECT_CLASS CK_PTR)CI_ObjLookup(pKeyObj,CK_IA_CLASS)->pValue) != CKO_PRIVATE_KEY)
	return CKR_OK;

      ctx=BN_CTX_new();
      if (ctx == NULL) { return CKR_HOST_MEMORY; }
      r1=&(ctx->bn[0]);
      r2=&(ctx->bn[1]);
      ctx->tos+=2;
      
      if((rv = CI_Ceay_BN2ObjEntry(CKA_PRIVATE_EXPONENT,rsa_struct->d,
			      pKeyObj, NULL_PTR)) 
	 != CKR_OK) 
	return rv;
      if((rv = CI_Ceay_BN2ObjEntry(CKA_PRIME_1,rsa_struct->p,
			      pKeyObj, NULL_PTR)) 
	 != CKR_OK) 
	return rv;
      if((rv = CI_Ceay_BN2ObjEntry(CKA_PRIME_2,rsa_struct->q,
			      pKeyObj, NULL_PTR)) 
	 != CKR_OK) 
	return rv;

      if(rsa_struct->dmp1 == NULL_PTR) /* compute the value */
	{
	  /* calculate d mod (p-1) */
	  if (!BN_sub(r1,rsa_struct->p,BN_value_one()))        /* p-1 */
	    { return CKR_HOST_MEMORY; }
	  rsa_struct->dmp1=BN_new();
	  if (rsa_struct->dmp1 == NULL) { return CKR_HOST_MEMORY; }
	  if (!BN_mod(rsa_struct->dmp1,rsa_struct->d,r1,ctx)) 
	    { return CKR_HOST_MEMORY; }
	}
      if((rv = CI_Ceay_BN2ObjEntry(CKA_EXPONENT_1,rsa_struct->dmp1,
			      pKeyObj, NULL_PTR)) 
	 != CKR_OK) 
	return rv;

      if(rsa_struct->dmq1 == NULL_PTR) /* compute the value */
	{
	  /* calculate d mod (q-1) */
	  if (!BN_sub(r2,rsa_struct->q,BN_value_one()))   /* q-1 */
	    { return CKR_HOST_MEMORY; }
	  rsa_struct->dmq1=BN_new();
	  if (rsa_struct->dmq1 == NULL) { return CKR_HOST_MEMORY; }
	  if (!BN_mod(rsa_struct->dmq1,rsa_struct->d,r2,ctx)) 
	    { return CKR_HOST_MEMORY; }
	}
      if((rv = CI_Ceay_BN2ObjEntry(CKA_EXPONENT_2,rsa_struct->dmq1,
			      pKeyObj, NULL_PTR)) 
	 != CKR_OK) 
	return rv;

      if(rsa_struct->iqmp == NULL_PTR) /* compute the value */
	{
	  /* calculate inverse of q mod p */
	  rsa_struct->iqmp=BN_mod_inverse(NULL, rsa_struct->q,rsa_struct->p,ctx);
	  if (rsa_struct->iqmp == NULL) 
	    { return CKR_HOST_MEMORY; }
	}
      if((rv = CI_Ceay_BN2ObjEntry(CKA_COEFFICIENT,rsa_struct->iqmp,
			      pKeyObj, NULL_PTR)) 
	 != CKR_OK) 
	return rv;

      return CKR_OK;
    }

  return CKR_TEMPLATE_INCONSISTENT;
}
/* }}} */

/* {{{ CI_Ceay_Obj2DSA */
CK_DEFINE_FUNCTION(DSA_PTR, CI_Ceay_Obj2DSA)(
 CK_I_OBJ_PTR key_obj
)
{
  CK_RV rv = CKR_OK;

  DSA_PTR internal_key_obj = DSA_new();
  if(internal_key_obj == NULL_PTR)
    return NULL_PTR;
  
  rv = CI_Ceay_ObjEntry2BN(CI_ObjLookup(key_obj,CK_IA_PRIME),&(internal_key_obj->p));
  if(rv != CKR_OK) return NULL_PTR;
  rv = CI_Ceay_ObjEntry2BN(CI_ObjLookup(key_obj,CK_IA_SUBPRIME),&(internal_key_obj->q));
  if(rv != CKR_OK) return NULL_PTR;
  rv = CI_Ceay_ObjEntry2BN(CI_ObjLookup(key_obj,CK_IA_BASE),&(internal_key_obj->g));
  if(rv != CKR_OK) return NULL_PTR;
  
  /* check that object is a public key */
  if(*((CK_OBJECT_CLASS CK_PTR)CI_ObjLookup(key_obj,CK_IA_CLASS)->pValue) == CKO_PUBLIC_KEY)
    {
      rv = CI_Ceay_ObjEntry2BN(CI_ObjLookup(key_obj,CK_IA_VALUE),&(internal_key_obj->pub_key));
      if(rv != CKR_OK) return NULL_PTR;
      
      return internal_key_obj;
    }
  
  if(*((CK_OBJECT_CLASS CK_PTR)CI_ObjLookup(key_obj,CK_IA_CLASS)->pValue) == CKO_PRIVATE_KEY)
    {
      rv = CI_Ceay_ObjEntry2BN(CI_ObjLookup(key_obj,CK_IA_VALUE),&(internal_key_obj->priv_key));
      if(rv != CKR_OK) return NULL_PTR;

      return internal_key_obj;
    }
  
  /* weder private noch public key, irgendetwas muss falsch sein */
  return NULL_PTR;
}
/* }}} */

/* {{{ CI_Ceay_MakeKeyString */
/** Erzeugen eines DER-Strings aus einem Public- oder Private Key.
 * Die Funktion nutzt die Puffer- und Returncode-Konventionen wie in 
 * PKCS#11 V2.01 Section&nbsp;10.1 und Section&nbsp;10.2 beschrieben.
 * @param key_obj      Schlüssel der in einen DER-String gewandelt werden 
 *                     soll
 * @param pBuffer      Platz für den zurückgegeben String
 * @param pulBufferLen Länge des zur Verfügung gestellten / benötigten 
 *                     Puffers.
 * @return CKR_OK, CKR_HOST_MEMORY, CKR_KEY_TYPE_INVALID
 * @see PKCS11 S10.1 S10.2
 */
CK_DEFINE_FUNCTION(CK_RV, CI_Ceay_MakeKeyString)(
 CK_I_OBJ_PTR key_obj,
 CK_CHAR_PTR pBuffer,
 CK_ULONG_PTR pulBufferLen
)
{
  CK_ULONG string_len;
  CK_RV rv = CKR_OK;
    
  switch(*((CK_KEY_TYPE CK_PTR)CI_ObjLookup(key_obj,CK_IA_KEY_TYPE)->pValue))
    {
    case CKK_RSA:
      {
	RSA CK_PTR internal_key = CI_Ceay_Obj2RSA(key_obj);
	CK_BYTE_PTR internal_buf = pBuffer;

	/* private of public key? */
	if(*((CK_OBJECT_CLASS CK_PTR)CI_ObjLookup(key_obj,CK_IA_CLASS)->pValue) == CKO_PUBLIC_KEY)
	  string_len = i2d_RSAPublicKey(internal_key,NULL_PTR);
	
	else if(*((CK_OBJECT_CLASS CK_PTR)CI_ObjLookup(key_obj,CK_IA_CLASS)->pValue) == CKO_PRIVATE_KEY)
	  string_len = i2d_RSAPrivateKey(internal_key,NULL_PTR);
	else 
	  {
	    rv = CKR_KEY_TYPE_INCONSISTENT;
	    goto rsa_err;
	  }

	/* TODO: this is only correct if the block len is 8 */
	if ((string_len % 8) != 0) string_len += 8 - (string_len % 8);

	/* ist dies nur ein Test? */
	if(pBuffer == NULL_PTR)
	  {
	    *pulBufferLen = string_len;
	    rv= CKR_OK;
	    goto rsa_err;
	  }
	
	if(string_len > *pulBufferLen)
	  {
	    *pulBufferLen = string_len;
	    rv = CKR_BUFFER_TOO_SMALL;
	    goto rsa_err;
	  }

	/* private of public key? */
	/* 
	 * Writes the data into the space pointed to by pBuffer, but changes internal_buff
	 * to the new position
	 */
	if(*((CK_OBJECT_CLASS CK_PTR)CI_ObjLookup(key_obj,CK_IA_CLASS)->pValue) == CKO_PUBLIC_KEY)
	  i2d_RSAPublicKey(internal_key,&internal_buf);
	else 
	  i2d_RSAPrivateKey(internal_key,&internal_buf);
	
      rsa_err:
	if(internal_key != NULL_PTR)
	  CI_Ceay_RSA_free(internal_key);
	  
	}
    break;
    default:
      rv = CKR_MECHANISM_INVALID;
    }

  return rv;
}
/* }}} */
/* {{{ CI_Ceay_DigestTransform */
CK_DEFINE_FUNCTION(CK_RV, CI_Ceay_DigestTransform)(
  CK_I_SESSION_DATA_PTR  session_data,
  CK_BYTE_PTR pSecret,
  CK_ULONG ulSecretLen,
  CK_BYTE_PTR pRandom1,
  CK_ULONG ulRandom1Len,
  CK_BYTE_PTR pRandom2,
  CK_ULONG ulRandom2Len,
  CK_BYTE_PTR pDigest  /* stuff will be written in here */
  )
{
  CK_RV rv = CKR_OK;
  int i;
  static CK_MECHANISM sha1_mech = {CKM_SHA_1, NULL_PTR, 0 };
  static CK_MECHANISM md5_mech = {CKM_MD5, NULL_PTR, 0 };

  CK_ULONG buf_len, rest_out_len, n;
  CK_BYTE CK_PTR buf = NULL_PTR;
  CK_BYTE CK_PTR curr_out = NULL_PTR; /* moving pointer for current piece of buffer */
  
  /* Wenn sich die Länge des Schlüssels ändert brauchen wir mehr Salz */

  CI_LogEntry("CI_Ceay_DigestTransform", "starting...", rv, 2);

  /* 
   * Achtung: dieser Code geht schief ( erzeugt einen Fehler im MD5
   * FinalDigest ) wenn die Länge des Schlüssels nicht ein vielfaches
   * der MD5 Digestgröße (128 Bit) ist.
   */
  rest_out_len = CK_I_SSL3_KEY_BLOCK_SIZE; 
  curr_out = pDigest;
  for(i=0; rest_out_len > 0; i++)
    {
      rv = CI_Ceay_DigestInit(session_data, &sha1_mech); 
      if(rv != CKR_OK) 
	{
	  CI_LogEntry("CI_Ceay_DigestTransform", "digest init", rv ,0);
	  goto ssl3_mkd_error;
	}
      
      rv = CI_Ceay_DigestUpdate(session_data, salt[i],strlen(salt[i]));
      if(rv != CKR_OK) 
	{
	  CI_VarLogEntry("CI_Ceay_DigestTransform", "salt[%i] digest update", rv ,0,i);
	  goto ssl3_mkd_error;
	}
      rv = CI_Ceay_DigestUpdate(session_data, pSecret,ulSecretLen);
      if(rv != CKR_OK) 
	{
	  CI_VarLogEntry("CI_Ceay_DigestTransform", "Secret digest update: len: %i", rv ,0,
			 ulSecretLen);
	  goto ssl3_mkd_error;
	}	    
      
      rv = CI_Ceay_DigestUpdate(session_data, pRandom1,
				ulRandom1Len);
      if(rv != CKR_OK) 
	{
	  CI_LogEntry("CI_Ceay_DigestTransform", "Client Random info disgest update", rv ,0);
	  goto ssl3_mkd_error;
	}
      
      rv = CI_Ceay_DigestUpdate(session_data, pRandom2,
				ulRandom2Len);
      if(rv != CKR_OK) 
	{
	  CI_LogEntry("CI_Ceay_DigestTransform", "Server RandomInfo digest update", rv ,0);
	  goto ssl3_mkd_error;
	}
      
      /* get needed size for SHA-1 result*/
      rv = CI_Ceay_DigestFinal(session_data, NULL_PTR, &buf_len);
      if(rv != CKR_OK) 
	{
	  CI_LogEntry("CI_Ceay_DigestTransform", "getting digest len", rv ,0);
	  goto ssl3_mkd_error;
	}
      
      TC_free(buf);
      if((buf = CI_ByteStream_new(buf_len)) == NULL_PTR)
	{ 
	  rv = CKR_HOST_MEMORY; 
	  CI_LogEntry("CI_Ceay_DigestTransform", "malloc buff space", rv ,0);
	  goto ssl3_mkd_error; 
	}
      
      rv = CI_Ceay_DigestFinal(session_data, buf, &buf_len);
      /* TODO: dies ist nur debug und sollte raus */
      if(session_data->digest_state != NULL_PTR)
	{
	  rv = CKR_GENERAL_ERROR;
	  CI_LogEntry("CI_Ceay_DigestTransform", "digest final: state not reset", rv ,0);
	  goto ssl3_mkd_error;
	}
      
      if(rv != CKR_OK) 
	{
	  CI_LogEntry("CI_Ceay_DigestTransform", "digest final", rv ,0);
	  goto ssl3_mkd_error;
	}
      rv = CI_Ceay_DigestInit(session_data, &md5_mech);
      if(rv != CKR_OK) 
	{
	  CI_LogEntry("CI_Ceay_DigestTransform", "md5 digest init", rv ,0);
	  goto ssl3_mkd_error;
	}
      rv = CI_Ceay_DigestUpdate(session_data, pSecret,ulSecretLen);
      if(rv != CKR_OK) 
	{
	  CI_LogEntry("CI_Ceay_DigestTransform", "md5 secret digest update", rv ,0);
	  goto ssl3_mkd_error;
	}
      rv = CI_Ceay_DigestUpdate(session_data, buf,buf_len);
      if(rv != CKR_OK) 
	{
	  CI_LogEntry("CI_Ceay_DigestTransform", "md5 buf digest update", rv ,0);
	  goto ssl3_mkd_error;
	}
      
      /* read one chunk */
      n = rest_out_len;
      rv = CI_Ceay_DigestFinal(session_data, curr_out, &n);
      if(rv != CKR_OK) 
	{
	  CI_LogEntry("CI_Ceay_DigestTransform", "md5 digest final", rv ,0);
	  goto ssl3_mkd_error;
	}
      
      CI_VarLogEntry("CI_Ceay_DigestTransform", "md5 digest length: %i", rv ,2,n);

      curr_out+=n;
      rest_out_len-=n;
    }
  
ssl3_mkd_error:
  if(buf != NULL_PTR) TC_free(buf); 
  
  CI_LogEntry("CI_Ceay_DigestTransform", "got here7", rv ,2);
  
  CI_LogEntry("CI_Ceay_DigestTransform", "...complete", rv, 2);
  
  return rv;
}
/* }}} */
/* {{{ CI_Ceay_BN2ObjEntry */
/* either key may be NULL_PTR if not applicable */
CK_DEFINE_FUNCTION(CK_RV, CI_Ceay_BN2ObjEntry)(
  CK_ATTRIBUTE_TYPE Attrib,
  BIGNUM*  number,
  CK_I_OBJ_PTR pPrivateObj,
  CK_I_OBJ_PTR pPublicObj
)
{
  CK_ATTRIBUTE temp_attrib;
  
  temp_attrib.type = Attrib;
  temp_attrib.ulValueLen = BN_num_bytes(number);
  temp_attrib.pValue = CI_ByteStream_new(temp_attrib.ulValueLen);
  if(temp_attrib.pValue == NULL_PTR)
    return CKR_HOST_MEMORY;
  CI_Ceay_BN_bn2bin(number,temp_attrib.pValue);
  if(pPublicObj) CI_ObjSetAttribute(pPublicObj, &temp_attrib);
  if(pPrivateObj) CI_ObjSetAttribute(pPrivateObj, &temp_attrib);
  TC_free(temp_attrib.pValue); /* has been copied by the CI_Obj* fkt */

  return CKR_OK;
}
/* }}} */
/* {{{ CI_Ceay_ObjEntry2BN */
CK_DEFINE_FUNCTION(CK_RV, CI_Ceay_ObjEntry2BN)(
  CK_ATTRIBUTE_PTR Attrib,
  BIGNUM** number
)
{
  if(Attrib == NULL_PTR)
    return CKR_ARGUMENTS_BAD;

  if(*number == NULL_PTR)
    {
      *number = BN_new();
      if(*number == NULL_PTR) return CKR_HOST_MEMORY;
    }

  CI_Ceay_BN_bin2bn(Attrib->pValue,Attrib->ulValueLen,*number);

  return CKR_OK;
}
/* }}} */

/* {{{ CI_Ceay_RSA_Callback */
/* TODO: put a setjmp(), longjmp() handling in place to 
 * interrupt running functions. This whole function is
 * not very thread clean. I'd better fix that.
 */

CK_DEFINE_FUNCTION(void, CI_Ceay_RSA_Callback)(
  int type,  /* type of callback */
  int count,  /* value of prime (?) */
  void* session_ptr /* pointer to the session_data. */
)
{
  /* als variable um ein ändern beim debug zu ermöglichen */
  static int CK_I_CEAY_min_callback_level =0;

  static CK_CHAR_PTR type_txts[] = { "prime suspected",
				     "prime found",
				     "prime rejected",
				     "prime selected" };

  CK_I_SESSION_DATA_PTR curr_sess = (CK_I_SESSION_DATA_PTR) session_ptr;
  CK_RV rv = CKR_OK;

  if(curr_sess == NULL_PTR) 
  return;

  /* suppress some of the callbacks ( or we would never get done ) */
  if(type <= CK_I_CEAY_min_callback_level)
    return;

  CI_VarLogEntry("CI_Ceay_RSA_Callback","callback for %s: %d",rv ,2,type_txts[type-1],count);

  /* call ya */
  if(curr_sess->Notify != NULL_PTR)
    rv = (curr_sess->Notify)(curr_sess->session_handle, CKN_SURRENDER, curr_sess->pApplication);
  
  /* check wether to stop this thing */
  if(rv == CKR_CANCEL)
    {
      CI_LogEntry("CI_Ceay_RSA_Callback","*abort requested*",rv ,2);
      
      return;  /* tough luck. */
    /* TODO: there is nothing we can do (for now. should be longjmp)*/
    }
  return;
}
/* }}} */

/*
 * Local variables:
 * folded-file: t
 * end:
 */

