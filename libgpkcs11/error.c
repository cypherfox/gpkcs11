/* -*- c -*- */
/*
 * This file is part of GPKCS11. 
 * (c) 1999,2000 TC TrustCenter for Security in DataNetworks GmbH 
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
 * along with GPKCS11; see the file COPYING.  If not, write to the Free
 * Software Foundation, 59 Temple Place - Suite 330, Boston, MA 02111, USA.  
 */
/*
 * RCSID:       $Id$
 * Source:      $Source$
 * Last Delta:  $Date$ $Revision$ $Author$
 * State:       $State$ $Locker$
 * NAME:        error.c
 * SYNOPSIS:    -
 * DESCRIPTION: -
 * FILES:       -
 * SEE/ALSO:    -
 * AUTHOR:      lbe
 * BUGS: *      -
 * HISTORY:     $Log$
 * HISTORY:     Revision 1.1.1.1  2000/10/15 16:48:03  cypherfox
 * HISTORY:     import of gpkcs11-0.7.2, first version for SourceForge
 * HISTORY:
 * HISTORY:     Revision 1.11  2000/06/05 11:43:43  lbe
 * HISTORY:     tcsc token breakup, return pSlotCount in SlotList, code for event handling deactivated
 * HISTORY:
 * HISTORY:     Revision 1.10  2000/03/15 19:21:59  lbe
 * HISTORY:     first try for tc-pkcs11 0.6.1: now works multi-app clean with tc_scard and can handle private decrypt in tcsc_token
 * HISTORY:
 * HISTORY:     Revision 1.9  2000/01/31 18:09:02  lbe
 * HISTORY:     lockdown prior to win_gdbm change
 * HISTORY:
 * HISTORY:     Revision 1.8  2000/01/07 10:24:44  lbe
 * HISTORY:     introduce changes for release
 * HISTORY:
 * HISTORY:     Revision 1.7  1999/12/03 09:35:44  jzu
 * HISTORY:     logging-bug fixed
 * HISTORY:
 * HISTORY:     Revision 1.6  1999/12/02 16:41:50  lbe
 * HISTORY:     small changes, cosmetics
 * HISTORY:
 * HISTORY:     Revision 1.5  1999/12/02 14:16:27  lbe
 * HISTORY:     tons of small bug fixes and bullet proofing of libgpkcs11 and cryptsh
 * HISTORY:
 * HISTORY:     Revision 1.4  1999/12/02 13:52:37  jzu
 * HISTORY:     personal log-files
 * HISTORY:
 * HISTORY:     Revision 1.3  1999/11/02 13:47:18  lbe
 * HISTORY:     change of structures and bug fix in slot.c, add more files for tcsc_token: emptyfuncs and general_data
 * HISTORY:
 * HISTORY:     Revision 1.2  1999/10/06 07:57:22  lbe
 * HISTORY:     solved netscape symbol clash problem
 * HISTORY:
 * HISTORY:     Revision 1.1  1999/06/16 09:46:07  lbe
 * HISTORY:     reorder files
 * HISTORY:
 * HISTORY:     Revision 1.13  1999/06/04 14:58:35  lbe
 * HISTORY:     change to libtool/automake complete (except for __umoddi prob)
 * HISTORY:
 * HISTORY:     Revision 1.12  1999/03/01 14:36:44  lbe
 * HISTORY:     merged changes from the weekend
 * HISTORY:
 * HISTORY:     Revision 1.11  1999/01/19 12:19:39  lbe
 * HISTORY:     first release lockdown
 * HISTORY:
 * HISTORY:     Revision 1.10  1998/12/07 13:19:59  lbe
 * HISTORY:     TC_free von parametern für Zeile und Datei befreit.
 * HISTORY:
 * HISTORY:     Revision 1.9  1998/11/26 10:14:12  lbe
 * HISTORY:     added persistent storage
 * HISTORY:
 * HISTORY:     Revision 1.8  1998/11/13 10:10:19  lbe
 * HISTORY:     added persistent storage.
 * HISTORY:
 * HISTORY:     Revision 1.7  1998/11/10 09:43:24  lbe
 * HISTORY:     hash iter geaendert: hashtabelle braucht nicht mehr an fkts uebergeben werden.
 * HISTORY:
 * HISTORY:     Revision 1.6  1998/11/04 17:12:35  lbe
 * HISTORY:     debug-lockdown
 * HISTORY:
 * HISTORY:     Revision 1.5  1998/11/03 15:59:38  lbe
 * HISTORY:     auto-lockdown
 * HISTORY:
 * HISTORY:     Revision 1.4  1998/10/12 10:00:13  lbe
 * HISTORY:     clampdown
 * HISTORY:
 * HISTORY:     Revision 1.3  1998/07/30 15:31:42  lbe
 * HISTORY:     Win32 Port
 * HISTORY:
 * HISTORY:     Revision 1.2  1998/07/23 15:18:07  lbe
 * HISTORY:     working
 * HISTORY:
 * HISTORY:     Revision 1.1  1998/07/02 17:13:25  lbe
 * HISTORY:     Initial revision
 * HISTORY:
 */
 
static char RCSID[]="$Id$";
const char* Version_error_c(){return RCSID;}

/* Needed for Win32-isms in cryptoki.h */
#ifndef CK_I_library_build
#define CK_I_library_build
#endif

#include "internal.h"
#include "error.h"

#if defined(CK_Win32)
#include "windows.h"
#include "winuser.h"
#include "malloc.h"
#endif

#ifdef HAVE_PURIFY
#include <purify.h>
#else
/* cannot be just a macro with empty body, due to the varible params list */
int purify_printf( char* format, ...);
int purify_printf( char* format, ...)
{
  return 0;
}
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <assert.h>

typedef struct desc_code{
CK_ULONG code;
CK_C_CHAR_PTR desc;
} desc_code;

/* {{{ ck_errors[] */
static desc_code ck_errors[] = {
  {CKR_OK,                              "OK"},
  {CKR_CANCEL,                          "CANCEL"},
  {CKR_HOST_MEMORY,                     "HOST MEMORY"},
  {CKR_SLOT_ID_INVALID,                 "SLOT ID INVALID"},
  {CKR_GENERAL_ERROR,                   "GENERAL ERROR"},
  {CKR_FUNCTION_FAILED,                 "FUNCTION FAILED"},
  {CKR_ARGUMENTS_BAD,                   "ARGUMENTS BAD"},
  {CKR_NO_EVENT,                        "NO EVENT"},
  {CKR_NEED_TO_CREATE_THREADS,          "NEED TO CREATE THREADS"},
  {CKR_CANT_LOCK,                       "CANT LOCK"},
  {CKR_ATTRIBUTE_READ_ONLY,             "ATTRIBUTE READ_ONLY"},
  {CKR_ATTRIBUTE_SENSITIVE,             "ATTRIBUTE SENSITIVE"},
  {CKR_ATTRIBUTE_TYPE_INVALID,          "ATTRIBUTE TYPE INVALID"},
  {CKR_ATTRIBUTE_VALUE_INVALID,         "ATTRIBUTE VALUE INVALID"},
  {CKR_DATA_INVALID,                    "DATA INVALID"},
  {CKR_DATA_LEN_RANGE,                  "DATA LEN RANGE"},
  {CKR_DEVICE_ERROR,                    "DEVICE ERROR"},
  {CKR_DEVICE_MEMORY,                   "DEVICE MEMORY"},
  {CKR_DEVICE_REMOVED,                  "DEVICE REMOVED"},
  {CKR_ENCRYPTED_DATA_INVALID,          "ENCRYPTED DATA INVALID"},
  {CKR_ENCRYPTED_DATA_LEN_RANGE,        "ENCRYPTED DATA LEN RANGE"},
  {CKR_FUNCTION_CANCELED,               "FUNCTION CANCELED"},
  {CKR_FUNCTION_NOT_PARALLEL,           "FUNCTION NOT PARALLEL"},
  {CKR_FUNCTION_NOT_SUPPORTED,          "FUNCTION NOT SUPPORTED"},
  {CKR_KEY_HANDLE_INVALID,              "KEY HANDLE INVALID"},
  {CKR_KEY_SIZE_RANGE,                  "KEY SIZE RANGE"},
  {CKR_KEY_TYPE_INCONSISTENT,           "KEY TYPE INCONSISTENT"},
  {CKR_KEY_NOT_NEEDED,                  "KEY NOT NEEDED"},
  {CKR_KEY_CHANGED,                     "KEY CHANGED"},
  {CKR_KEY_NEEDED,                      "KEY NEEDED"},
  {CKR_KEY_INDIGESTIBLE,                "KEY INDIGESTIBLE"},
  {CKR_KEY_FUNCTION_NOT_PERMITTED,      "KEY FUNCTION NOT PERMITTED"},
  {CKR_KEY_NOT_WRAPPABLE,               "KEY NOT WRAPPABLE"},
  {CKR_KEY_UNEXTRACTABLE,               "KEY UNEXTRACTABLE"},
  {CKR_MECHANISM_INVALID,               "MECHANISM INVALID"},
  {CKR_MECHANISM_PARAM_INVALID,         "MECHANISM PARAM INVALID"},
  {CKR_OBJECT_HANDLE_INVALID,           "OBJECT HANDLE INVALID"},
  {CKR_OPERATION_ACTIVE,                "OPERATION ACTIVE"},
  {CKR_OPERATION_NOT_INITIALIZED,       "OPERATION NOT INITIALIZED"},
  {CKR_PIN_INCORRECT,                   "PIN INCORRECT"},
  {CKR_PIN_INVALID,                     "PIN INVALID"},
  {CKR_PIN_LEN_RANGE,                   "PIN LEN_RANGE"},
  {CKR_PIN_EXPIRED,                     "PIN EXPIRED"},
  {CKR_PIN_LOCKED,                      "PIN LOCKED"},
  {CKR_SESSION_CLOSED,                  "SESSION CLOSED"},
  {CKR_SESSION_COUNT,                   "SESSION COUNT"},
  {CKR_SESSION_HANDLE_INVALID,          "SESSION HANDLE INVALID"},
  {CKR_SESSION_PARALLEL_NOT_SUPPORTED,  "SESSION PARALLEL NOT SUPPORTED"},
  {CKR_SESSION_READ_ONLY,               "SESSION READ ONLY"},
  {CKR_SESSION_EXISTS,                  "SESSION EXISTS"},
  {CKR_SESSION_READ_ONLY_EXISTS,        "SESSION READ ONLY EXISTS"},
  {CKR_SESSION_READ_WRITE_SO_EXISTS,    "SESSION READ WRITE SO EXISTS"},
  {CKR_SIGNATURE_INVALID,               "SIGNATURE INVALID"},
  {CKR_SIGNATURE_LEN_RANGE,             "SIGNATURE LEN RANGE"},
  {CKR_TEMPLATE_INCOMPLETE,             "TEMPLATE INCOMPLETE"},
  {CKR_TEMPLATE_INCONSISTENT,           "TEMPLATE INCONSISTENT"},
  {CKR_TOKEN_NOT_PRESENT,               "TOKEN NOT PRESENT"},
  {CKR_TOKEN_NOT_RECOGNIZED,            "TOKEN NOT RECOGNIZED"},
  {CKR_TOKEN_WRITE_PROTECTED,           "TOKEN WRITE PROTECTED"},
  {CKR_UNWRAPPING_KEY_HANDLE_INVALID,   "UNWRAPPING KEY HANDLE INVALID"},
  {CKR_UNWRAPPING_KEY_SIZE_RANGE,       "UNWRAPPING KEY SIZE RANGE"},
  {CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT,"UNWRAPPING KEY TYPE INCONSISTENT"},
  {CKR_USER_ALREADY_LOGGED_IN,          "USER ALREADY LOGGED IN"},
  {CKR_USER_NOT_LOGGED_IN,              "USER NOT LOGGED IN"},
  {CKR_USER_PIN_NOT_INITIALIZED,        "USER PIN NOT INITIALIZED"},
  {CKR_USER_TYPE_INVALID,               "USER TYPE INVALID"},
  {CKR_USER_ANOTHER_ALREADY_LOGGED_IN,  "USER ANOTHER ALREADY LOGGED IN"},
  {CKR_USER_TOO_MANY_TYPES,             "USER TOO MANY TYPES"},
  {CKR_WRAPPED_KEY_INVALID,             "WRAPPED KEY INVALID"},
  {CKR_WRAPPED_KEY_LEN_RANGE,           "WRAPPED KEY LEN RANGE"},
  {CKR_WRAPPING_KEY_HANDLE_INVALID,     "WRAPPING KEY HANDLE INVALID"},
  {CKR_WRAPPING_KEY_SIZE_RANGE,         "WRAPPING KEY SIZE RANGE"},
  {CKR_WRAPPING_KEY_TYPE_INCONSISTENT,  "WRAPPING KEY TYPE INCONSISTENT"},
  {CKR_RANDOM_SEED_NOT_SUPPORTED,       "RANDOM SEED NOT SUPPORTED"},
  {CKR_RANDOM_NO_RNG,                   "RANDOM NO RNG"},
  {CKR_BUFFER_TOO_SMALL,                "BUFFER TOO SMALL"},
  {CKR_SAVED_STATE_INVALID,             "SAVED STATE INVALID"},
  {CKR_INFORMATION_SENSITIVE,           "INFORMATION SENSITIVE"},
  {CKR_STATE_UNSAVEABLE,                "STATE UNSAVEABLE"},
  {CKR_CRYPTOKI_NOT_INITIALIZED,        "CRYPTOKI NOT INITIALIZED"},
  {CKR_CRYPTOKI_ALREADY_INITIALIZED,    "CRYPTOKI ALREADY INITIALIZED"},
  {CKR_MUTEX_BAD,                       "MUTEX BAD"},
  {CKR_MUTEX_NOT_LOCKED,                "MUTEX NOT LOCKED"},
  {CKR_VENDOR_DEFINED,                  "VENDOR DEFINED"},
  {0xffffffff,                           (NULL_PTR)}
};
/* }}} */
/* {{{ ck_mechansims[] */
static desc_code ck_mechanisms[] = {
  {CKM_RSA_PKCS_KEY_PAIR_GEN,      "RSA_PKCS_KEY_PAIR_GEN"},
  {CKM_RSA_PKCS,                   "RSA_PKCS"},
  {CKM_RSA_9796,                   "RSA_9796"},
  {CKM_RSA_X_509,                  "RSA_X_509"},
  {CKM_MD2_RSA_PKCS,               "MD2_RSA_PKCS"},
  {CKM_MD5_RSA_PKCS,               "MD5_RSA_PKCS"},
  {CKM_SHA1_RSA_PKCS,              "SHA1_RSA_PKCS"},
  {CKM_DSA_KEY_PAIR_GEN,           "DSA_KEY_PAIR_GEN"},
  {CKM_DSA,                        "DSA"},
  {CKM_DSA_SHA1,                   "DSA_SHA1"},
  {CKM_DH_PKCS_KEY_PAIR_GEN,       "DH_PKCS_KEY_PAIR_GEN"},
  {CKM_DH_PKCS_DERIVE,             "DH_PKCS_DERIVE"},
  {CKM_RC2_KEY_GEN,                "RC2_KEY_GEN"},
  {CKM_RC2_ECB,                    "RC2_ECB"},
  {CKM_RC2_CBC,                    "RC2_CBC"},
  {CKM_RC2_MAC,                    "RC2_MAC"},
  {CKM_RC2_MAC_GENERAL,            "RC2_MAC_GENERAL"},
  {CKM_RC2_CBC_PAD,                "RC2_CBC_PAD"},
  {CKM_RC4_KEY_GEN,                "RC4_KEY_GEN"},
  {CKM_RC4,                        "RC4"},
  {CKM_DES_KEY_GEN,                "DES_KEY_GEN"},
  {CKM_DES_ECB,                    "DES_ECB"},
  {CKM_DES_CBC,                    "DES_CBC"},
  {CKM_DES_MAC,                    "DES_MAC"},
  {CKM_DES_MAC_GENERAL,            "DES_MAC_GENERAL"},
  {CKM_DES_CBC_PAD,                "DES_CBC_PAD"},
  {CKM_DES2_KEY_GEN,               "DES2_KEY_GEN"},
  {CKM_DES3_KEY_GEN,               "DES3_KEY_GEN"},
  {CKM_DES3_ECB,                   "DES3_ECB"},
  {CKM_DES3_CBC,                   "DES3_CBC"},
  {CKM_DES3_MAC,                   "DES3_MAC"},
  {CKM_DES3_MAC_GENERAL,           "DES3_MAC_GENERAL"},
  {CKM_DES3_CBC_PAD,               "DES3_CBC_PAD"},
  {CKM_CDMF_KEY_GEN,               "CDMF_KEY_GEN"},
  {CKM_CDMF_ECB,                   "CDMF_ECB"},
  {CKM_CDMF_CBC,                   "CDMF_CBC"},
  {CKM_CDMF_MAC,                   "CDMF_MAC"},
  {CKM_CDMF_MAC_GENERAL,           "CDMF_MAC_GENERAL"},
  {CKM_CDMF_CBC_PAD,               "CDMF_CBC_PAD"},
  {CKM_MD2,                        "MD2"},
  {CKM_MD2_HMAC,                   "MD2_HMAC"},
  {CKM_MD2_HMAC_GENERAL,           "MD2_HMAC_GENERAL"},
  {CKM_MD5,                        "MD5"},
  {CKM_MD5_HMAC,                   "MD5_HMAC"},
  {CKM_MD5_HMAC_GENERAL,           "MD5_HMAC_GENERAL"},
  {CKM_SHA_1,                      "SHA1"},
  {CKM_SHA_1_HMAC,                 "SHA1_HMAC"},
  {CKM_SHA_1_HMAC_GENERAL,         "SHA1_HMAC_GENERAL"},
  {CKM_CAST_KEY_GEN,               "CAST_KEY_GEN"},
  {CKM_CAST_ECB,                   "CAST_ECB"},
  {CKM_CAST_CBC,                   "CAST_CBC"},
  {CKM_CAST_MAC,                   "CAST_MAC"},
  {CKM_CAST_MAC_GENERAL,           "CAST_MAC_GENERAL"},
  {CKM_CAST_CBC_PAD,               "CAST_CBC_PAD"},
  {CKM_CAST3_KEY_GEN,              "CAST3_KEY_GEN"},
  {CKM_CAST3_ECB,                  "CAST3_ECB"},
  {CKM_CAST3_CBC,                  "CAST3_CBC"},
  {CKM_CAST3_MAC,                  "CAST3_MAC"},
  {CKM_CAST3_MAC_GENERAL,          "CAST3_MAC_GENERAL"},
  {CKM_CAST3_CBC_PAD,              "CAST3_CBC_PAD"},
  {CKM_CAST5_KEY_GEN,              "CAST5_KEY_GEN"},
  {CKM_CAST128_KEY_GEN,            "CAST128_KEY_GEN"},
  {CKM_CAST5_ECB,                  "CAST5_ECB"},
  {CKM_CAST128_ECB,                "CAST128_ECB"},
  {CKM_CAST5_CBC,                  "CAST5_CBC"},
  {CKM_CAST128_CBC,                "CAST128_CBC"},
  {CKM_CAST5_MAC,                  "CAST5_MAC"},
  {CKM_CAST128_MAC,                "CAST128_MAC"},
  {CKM_CAST5_MAC_GENERAL,          "CAST5_MAC_GENERAL"},
  {CKM_CAST128_MAC_GENERAL,        "CAST128_MAC_GENERAL"},
  {CKM_CAST5_CBC_PAD,              "CAST5_CBC_PAD"},
  {CKM_CAST128_CBC_PAD,            "CAST128_CBC_PAD"},
  {CKM_RC5_KEY_GEN,                "RC5_KEY_GEN"},
  {CKM_RC5_ECB,                    "RC5_ECB"},
  {CKM_RC5_CBC,                    "RC5_CBC"},
  {CKM_RC5_MAC,                    "RC5_MAC"},
  {CKM_RC5_MAC_GENERAL,            "RC5_MAC_GENERAL"},
  {CKM_RC5_CBC_PAD,                "RC5_CBC_PAD"},
  {CKM_IDEA_KEY_GEN,               "IDEA_KEY_GEN"},
  {CKM_IDEA_ECB,                   "IDEA_ECB"},
  {CKM_IDEA_CBC,                   "IDEA_CBC"},
  {CKM_IDEA_MAC,                   "IDEA_MAC"},
  {CKM_IDEA_MAC_GENERAL,           "IDEA_MAC_GENERAL"},
  {CKM_IDEA_CBC_PAD,               "IDEA_CBC_PAD"},
  {CKM_GENERIC_SECRET_KEY_GEN,     "GENERIC_SECRET_KEY_GEN"},
  {CKM_CONCATENATE_BASE_AND_KEY,   "CONCATENATE_BASE_AND_KEY"},
  {CKM_CONCATENATE_BASE_AND_DATA,  "CONCATENATE_BASE_AND_DATA"},
  {CKM_CONCATENATE_DATA_AND_BASE,  "CONCATENATE_DATA_AND_BASE"},
  {CKM_XOR_BASE_AND_DATA,          "XOR_BASE_AND_DATA"},
  {CKM_EXTRACT_KEY_FROM_KEY,       "EXTRACT_KEY_FROM_KEY"},
  {CKM_SSL3_PRE_MASTER_KEY_GEN,    "SSL3_PRE_MASTER_KEY_GEN"},
  {CKM_SSL3_MASTER_KEY_DERIVE,     "SSL3_MASTER_KEY_DERIVE"},
  {CKM_SSL3_KEY_AND_MAC_DERIVE,    "SSL3_KEY_AND_MAC_DERIVE"},
  {CKM_SSL3_MD5_MAC,               "SSL3_MD5_MAC"},
  {CKM_SSL3_SHA1_MAC,              "SSL3_SHA1_MAC"},
  {CKM_MD5_KEY_DERIVATION,         "MD5_KEY_DERIVATION"},
  {CKM_MD2_KEY_DERIVATION,         "MD2_KEY_DERIVATION"},
  {CKM_SHA1_KEY_DERIVATION,        "SHA1_KEY_DERIVATION"},
  {CKM_PBE_MD2_DES_CBC,            "PBE_MD2_DES_CBC"},
  {CKM_PBE_MD5_DES_CBC,            "PBE_MD5_DES_CBC"},
  {CKM_PBE_MD5_CAST_CBC,           "PBE_MD5_CAST_CBC"},
  {CKM_PBE_MD5_CAST3_CBC,          "PBE_MD5_CAST3_CBC"},
  {CKM_PBE_MD5_CAST5_CBC,          "PBE_MD5_CAST5_CBC"},
  {CKM_PBE_MD5_CAST128_CBC,        "PBE_MD5_CAST128_CBC"},
  {CKM_PBE_SHA1_CAST5_CBC,         "PBE_SHA1_CAST5_CBC"},
  {CKM_PBE_SHA1_CAST128_CBC,       "PBE_SHA1_CAST128_CBC"},
  {CKM_PBE_SHA1_RC4_128,           "PBE_SHA1_RC4_128"},
  {CKM_PBE_SHA1_RC4_40,            "PBE_SHA1_RC4_40"},
  {CKM_PBE_SHA1_DES3_EDE_CBC,      "PBE_SHA1_DES3_EDE_CBC"},
  {CKM_PBE_SHA1_DES2_EDE_CBC,      "PBE_SHA1_DES2_EDE_CBC"},
  {CKM_PBE_SHA1_RC2_128_CBC,       "PBE_SHA1_RC2_128_CBC"},
  {CKM_PBE_SHA1_RC2_40_CBC,        "PBE_SHA1_RC2_40_CBC"},
  {CKM_PBA_SHA1_WITH_SHA1_HMAC,    "PBA_SHA1_WITH_SHA1_HMAC"},
  {CKM_KEY_WRAP_LYNKS,             "KEY_WRAP_LYNKS"},
  {CKM_KEY_WRAP_SET_OAEP,          "KEY_WRAP_SET_OAEP"},
  {CKM_SKIPJACK_KEY_GEN,           "SKIPJACK_KEY_GEN"},
  {CKM_SKIPJACK_ECB64,             "SKIPJACK_ECB64"},
  {CKM_SKIPJACK_CBC64,             "SKIPJACK_CBC64"},
  {CKM_SKIPJACK_OFB64,             "SKIPJACK_OFB64"},
  {CKM_SKIPJACK_CFB64,             "SKIPJACK_CFB64"},
  {CKM_SKIPJACK_CFB32,             "SKIPJACK_CFB32"},
  {CKM_SKIPJACK_CFB16,             "SKIPJACK_CFB16"},
  {CKM_SKIPJACK_CFB8,              "SKIPJACK_CFB8"},
  {CKM_SKIPJACK_WRAP,              "SKIPJACK_WRAP"},
  {CKM_SKIPJACK_PRIVATE_WRAP,      "SKIPJACK_PRIVATE_WRAP"},
  {CKM_SKIPJACK_RELAYX,            "SKIPJACK_RELAYX"},
  {CKM_KEA_KEY_PAIR_GEN,           "KEA_KEY_PAIR_GEN"},
  {CKM_KEA_KEY_DERIVE,             "KEA_KEY_DERIVE"},
  {CKM_FORTEZZA_TIMESTAMP,         "FORTEZZA_TIMESTAMP"},
  {CKM_BATON_KEY_GEN,              "BATON_KEY_GEN"},
  {CKM_BATON_ECB128,               "BATON_ECB128"},
  {CKM_BATON_ECB96,                "BATON_ECB96"},
  {CKM_BATON_CBC128,               "BATON_CBC128"},
  {CKM_BATON_COUNTER,              "BATON_COUNTER"},
  {CKM_BATON_SHUFFLE,              "BATON_SHUFFLE"},
  {CKM_BATON_WRAP,                 "BATON_WRAP"},
  {CKM_ECDSA_KEY_PAIR_GEN,         "ECDSA_KEY_PAIR_GEN"},
  {CKM_ECDSA,                      "ECDSA"},
  {CKM_ECDSA_SHA1,                 "ECDSA_SHA1"},
  {CKM_JUNIPER_KEY_GEN,            "JUNIPER_KEY_GEN"},
  {CKM_JUNIPER_ECB128,             "JUNIPER_ECB128"},
  {CKM_JUNIPER_CBC128,             "JUNIPER_CBC128"},
  {CKM_JUNIPER_COUNTER,            "JUNIPER_COUNTER"},
  {CKM_JUNIPER_SHUFFLE,            "JUNIPER_SHUFFLE"},
  {CKM_JUNIPER_WRAP,               "JUNIPER_WRAP"},
  {CKM_FASTHASH,                   "FASTHASH"},
  {CKM_VENDOR_DEFINED,             "VENDOR_DEFINED"},
  {0,                               NULL_PTR}
};
/* }}} */
/* {{{ ck_attribute[] */
static desc_code ck_attribute[] = {
  {CKA_CLASS              ,"CLASS"},
  {CKA_TOKEN              ,"TOKEN"},
  {CKA_PRIVATE            ,"PRIVATE"},
  {CKA_LABEL              ,"LABEL"},
  {CKA_APPLICATION        ,"APPLICATION"},
  {CKA_VALUE              ,"VALUE"},
  {CKA_CERTIFICATE_TYPE   ,"CERTIFICATE_TYPE"},
  {CKA_ISSUER             ,"ISSUER"},
  {CKA_SERIAL_NUMBER      ,"SERIAL_NUMBER"},
  {CKA_KEY_TYPE           ,"KEY_TYPE"},
  {CKA_SUBJECT            ,"SUBJECT"},
  {CKA_ID                 ,"ID"},
  {CKA_SENSITIVE          ,"SENSITIVE"},
  {CKA_ENCRYPT            ,"ENCRYPT"},
  {CKA_DECRYPT            ,"DECRYPT"},
  {CKA_WRAP               ,"WRAP"},
  {CKA_UNWRAP             ,"UNWRAP"},
  {CKA_SIGN               ,"SIGN"},
  {CKA_SIGN_RECOVER       ,"SIGN_RECOVER"},
  {CKA_VERIFY             ,"VERIFY"},
  {CKA_VERIFY_RECOVER     ,"VERIFY_RECOVER"},
  {CKA_DERIVE             ,"DERIVE"},
  {CKA_START_DATE         ,"START_DATE"},
  {CKA_END_DATE           ,"END_DATE"},
  {CKA_MODULUS            ,"MODULUS"},
  {CKA_MODULUS_BITS       ,"MODULUS_BITS"},
  {CKA_PUBLIC_EXPONENT    ,"PUBLIC_EXPONENT"},
  {CKA_PRIVATE_EXPONENT   ,"PRIVATE_EXPONENT"},
  {CKA_PRIME_1            ,"PRIME_1"},
  {CKA_PRIME_2            ,"PRIME_2"},
  {CKA_EXPONENT_1         ,"EXPONENT_1"},
  {CKA_EXPONENT_2         ,"EXPONENT_2"},
  {CKA_COEFFICIENT        ,"COEFFICIENT"},
  {CKA_PRIME              ,"PRIME"},
  {CKA_SUBPRIME           ,"SUBPRIME"},
  {CKA_BASE               ,"BASE"},
  {CKA_VALUE_BITS         ,"VALUE_BITS"},
  {CKA_VALUE_LEN          ,"VALUE_LEN"},
  {CKA_EXTRACTABLE        ,"EXTRACTABLE"},
  {CKA_LOCAL              ,"LOCAL"},
  {CKA_NEVER_EXTRACTABLE  ,"NEVER_EXTRACTABLE"},
  {CKA_ALWAYS_SENSITIVE   ,"ALWAYS_SENSITIVE"},
  {CKA_MODIFIABLE         ,"MODIFIABLE"},
  {CKA_ECDSA_PARAMS       ,"ECDSA_PARAMS"},
  {CKA_EC_POINT           ,"EC_POINT"},
  {CKA_VENDOR_DEFINED     ,"VENDOR_DEFINED"},
  {0,NULL_PTR}
};
/* }}} */

static CK_C_CHAR_PTR default_error = "unknown error";
static CK_C_CHAR_PTR default_mechanism = "unknown mechanism";
static CK_C_CHAR_PTR default_attribute = "unknown attribute";
static CK_ULONG CK_I_global_loging_level = 1000;
static CK_CHAR_PTR CK_I_global_logging_file = NULL_PTR;  
static CK_CHAR_PTR CK_I_global_mem_logging_file = NULL_PTR; 

/* {{{ CI_ErrorStr */
CK_DEFINE_FUNCTION(CK_C_CHAR_PTR, CI_ErrorStr)(
 CK_RV rv
)
{
  CK_ULONG i;

  for(i=0;( ck_errors[i].code != rv ) && (ck_errors[i].desc != NULL_PTR); i++);
  if(ck_errors[i].desc == NULL_PTR) return default_error;
  else return ck_errors[i].desc;
}
/* }}} */
/* {{{ CI_MechanismStr(CK_MECHANISM_TYPE) */
CK_DEFINE_FUNCTION(CK_C_CHAR_PTR, CI_MechanismStr)(
  CK_MECHANISM_TYPE mech  /* number of the mechanism */
  )
{
  CK_ULONG i;

  for(i=0;( ck_mechanisms[i].code != mech ) && (ck_mechanisms[i].desc != NULL_PTR); i++);
  if(ck_mechanisms[i].desc == NULL_PTR) return default_mechanism;
  else return ck_mechanisms[i].desc;
}
/* }}} */
/* {{{ CI_AttributeNum(attr_name) */
CK_DECLARE_FUNCTION(CK_ULONG,CI_AttributeNum)(
  CK_CHAR_PTR pAttribName
)
{
  int i;

  for(i=0;(ck_attribute[i].desc != NULL_PTR) && (strcmp(ck_attribute[i].desc,pAttribName) != 0); i++);
  if(ck_attribute[i].desc == NULL_PTR) return 0xffffffff;
  else return ck_attribute[i].code;

}
/* }}} */
/* {{{ CI_AttributeStr(CK_ATTRIBUTE_TYPE); */
CK_DECLARE_FUNCTION(CK_C_CHAR_PTR,CI_AttributeStr)(
  CK_ATTRIBUTE_TYPE attrib
)
{
  CK_ULONG i;

  for(i=0;( ck_attribute[i].code != attrib ) && (ck_attribute[i].desc != NULL_PTR); i++);
  if(ck_attribute[i].desc == NULL_PTR) return default_attribute;
  else return ck_attribute[i].desc;
}
/* }}} */
/* {{{ CI_PrintableByteStream(CK_BYTE_PTR,CK_ULONG) */
CK_DEFINE_FUNCTION(CK_CHAR_PTR, CI_PrintableByteStream)(
   CK_C_BYTE_PTR stream,
   CK_ULONG len
)
{
  CK_BYTE_PTR retval = NULL_PTR;
  CK_BYTE_PTR buf = NULL_PTR;
  CK_ULONG i;

  if(len == 0) 
    {
      retval = TC_malloc(strlen("null")+1);
      if(retval == NULL_PTR) return retval;
      strcpy(retval,"null");
      return retval;
    }

  retval = TC_malloc((len*3)+1);
  if(retval == NULL_PTR)
    return retval;
  buf = retval;

  for (i=0; i<(len-1); i++)
    {
      sprintf(&(buf[i*3]),"%02x:",stream[i]);
    }
  sprintf(&(buf[i*3]),"%02x",stream[i]);

  retval[(len*3)] = '\0';
  return retval;      
}
/* }}} */
/* {{{ CI_ScanableByteStream(CK_BYTE_PTR,CK_ULONG) */
CK_DEFINE_FUNCTION(CK_CHAR_PTR, CI_ScanableByteStream)(
   CK_C_BYTE_PTR stream,
   CK_ULONG len
)
{
  CK_BYTE_PTR retval = NULL_PTR;
  CK_BYTE_PTR buf = NULL_PTR;
  CK_ULONG i;

  if(len == 0)
    {
      retval = TC_malloc(1);
      if(retval== NULL_PTR) return retval;
      
      retval[0] = '\0';
      return retval;
    }

  retval = TC_malloc((len*3)+1);
  if(retval == NULL_PTR)
    return retval;
  buf = retval;

  for (i=0; i<len; i++,buf+=3)
    {
      sprintf(buf,"%02x:",stream[i]);
    }
  *buf = '\0'; 
  

  return retval;      
}
/* }}} */
/* {{{ CI_ScanableMechanism */
CK_DECLARE_FUNCTION(CK_CHAR_PTR, CI_ScanableMechanism)(
  CK_MECHANISM_PTR pMechanism						       
)
{
  CK_CHAR_PTR buffer = NULL_PTR;
  CK_CHAR_PTR mech_str = NULL_PTR;
  CK_BYTE_PTR tmp = NULL_PTR;
  CK_ULONG len;

  if(pMechanism->pParameter == NULL_PTR)
    mech_str = tmp = CI_ScanableByteStream(pMechanism->pParameter,
					   pMechanism->ulParameterLen);
  else
    mech_str = "NULL_PTR";
  
  len = (strlen("{CKM_, , 0x12345678}") + 
	 strlen(CI_MechanismStr(pMechanism->mechanism)) + 
	 strlen(mech_str) + 
	 1);
  
  buffer = TC_malloc(len*sizeof(CK_BYTE));
  if(buffer == NULL_PTR)
    return buffer;
  
  sprintf(buffer, "{CKM_%s, %s, 0x%08lx}", 
	  CI_MechanismStr(pMechanism->mechanism), 
	  mech_str,
	  pMechanism->ulParameterLen);
  
  if(tmp!=NULL_PTR)
    TC_free(tmp);
  
  return buffer;
}
/* }}} */
/* {{{ CI_PrintTemplate( CK_ATTRIBUTE_PTR, CK_ULONG ); */
/** Generates a human readable form of a template given to a function.
  ( ( ATTRIBUTE_NAME <ATTRIBUTE VALUE> LEN)
  ...)

  if the attribute type is known to the function it is printed in proper form 
  otherwise as byte stream.
 */
CK_DEFINE_FUNCTION(CK_CHAR_PTR, CI_PrintTemplate)(
  CK_ATTRIBUTE_PTR pTemplate,
  CK_ULONG         ulCount
)
{
  CK_ULONG len = 0, pos = 0;
  CK_ULONG i;
  CK_CHAR_PTR retval = NULL_PTR;
  CK_CHAR_PTR tmp = NULL_PTR;

  /* calculate needed len */
  len = 3; /* openening, closing bracket, '\0' */

  /* special case if there are no entries at all */
  if(ulCount == 0)
    {
      retval = strdup("()");
      return retval;
    }

  for(i=0;i<ulCount;i++)
    {
      tmp=CI_ScanableByteStream(pTemplate[i].pValue,pTemplate[i].ulValueLen);

      len += strlen("(  #x12345678)\n ");
      len += strlen(CI_AttributeStr(pTemplate[i].type));
      /* len += CI_AttribOutFormat(pTemplate[i].type); später! */
      len += strlen(tmp); 
      TC_free(tmp);
    }
  
  retval = TC_malloc(len);
  if(retval == NULL_PTR) return retval;
  
  retval[0]='(';
  pos += 1;
  
  /* TODO: remember pos to speed strcat up */
  for(i=0;i<ulCount;i++)
    {      
      pos+= sprintf(&(retval[pos]),"(%s %s #x%08lx)\n ",
		    CI_AttributeStr(pTemplate[i].type),
		    tmp=CI_ScanableByteStream(pTemplate[i].pValue,pTemplate[i].ulValueLen),
		    pTemplate[i].ulValueLen);
      TC_free(tmp);
    }
  
  strcat(retval,")");

  return retval;
}
  /* }}} */

#ifndef NO_LOGGING
/* {{{ CI_SetLogingLevel */
CK_DEFINE_FUNCTION(void, CI_SetLogingLevel)(
  CK_ULONG level
)
{
  CK_I_global_loging_level = level;
}
/* }}} */
/* {{{ CI_SetLoggingFile */
CK_DEFINE_FUNCTION(void, CI_SetLoggingFile)(
  CK_CHAR_PTR logFileName
)
{
  if (logFileName == NULL_PTR)
    return;

  if( CK_I_global_logging_file != NULL_PTR )
    free(CK_I_global_logging_file);

  CK_I_global_logging_file = malloc(sizeof(CK_CHAR) * ( strlen(logFileName) +1));
  if(CK_I_global_logging_file == NULL_PTR) return;

  strcpy(CK_I_global_logging_file, logFileName);

  return;
}
/* }}} */
/* {{{ CI_LogEntry */
CK_DEFINE_FUNCTION(void, CI_LogEntry)(
  CK_C_CHAR_PTR FunctionName, /* Name of the current function */
  CK_C_CHAR_PTR ProcessDesc,  /* Description of the current process */
  CK_RV rv,                 /* return value in case of imediate abort of function */
  CK_ULONG level            /* level above which information would be written */
)
{
  FILE CK_PTR log = NULL_PTR;

  if(level> CK_I_global_loging_level)
    return;

  /* Log-FileName bestimmen, falls Angabe noch NULL */

  if ( CK_I_global_logging_file == NULL_PTR ) 
    CI_EvalLogFileName();
  
  /* wir testen nicht ob das öffnen des logs fehlgeschlagen ist. 
   * Wem sollten wir das mitteilen? */
  log = fopen(CK_I_global_logging_file,"a");

#if defined(DEBUG) && defined(CK_Win32)
  if(log == NULL_PTR)
    {
      MessageBox(NULL, "CI_VarLogEntry: could not open Log-file", 
		 "PKCS#11 Notice", MB_OK|MB_ICONWARNING);
      return;
    }
#else
  if(log == NULL_PTR)
    return;
#endif  
 
  FunctionName = (FunctionName == NULL_PTR)? (CK_C_CHAR_PTR)"(NULL)" : FunctionName;
  ProcessDesc = (ProcessDesc == NULL_PTR)? (CK_C_CHAR_PTR)"(NULL)" : ProcessDesc;

  fprintf(log,"/* %s()", FunctionName);
  fprintf(log,": %s ", ProcessDesc);
  fprintf(log,"(%s) */\n", CI_ErrorStr(rv));
  
  fclose(log);

  return;

}
/* }}} */
/* {{{ CI_EvalLogFileName*/
CK_DEFINE_FUNCTION(void, CI_EvalLogFileName)(
 void
)
{
#if defined(CK_GENERIC)
#define CK_I_LOG_FILE "/tmp/pkcs11.log"
#elif defined(CK_Win32)
#define CK_I_LOG_FILE "c:\\pkcs11.log"
#endif


  CK_CHAR_PTR tmp_name = NULL_PTR;

  if((tmp_name = getenv("GPKCS11_LOG")) != NULL_PTR)
    {
      CK_I_global_logging_file = malloc(sizeof(CK_CHAR) * ( strlen(tmp_name) + 1 ));
      strcpy(CK_I_global_logging_file, tmp_name);
      return;
    }
  else
    {
      CK_I_global_logging_file = malloc(sizeof(CK_CHAR) * ( strlen(CK_I_LOG_FILE) + 1 ));
      strcpy(CK_I_global_logging_file, CK_I_LOG_FILE);
    }
  return;
  
}
/* }}} */
/* {{{ CI_VarLogEntry */
CK_DEFINE_FUNCTION(void, CI_VarLogEntry)(
  CK_C_CHAR_PTR FunctionName,  /* Name of the current function */
  CK_C_CHAR_PTR ProcessDesc,   /* Description of the current process */
  CK_RV rv,                  /* return value in case of abort of function */
  CK_ULONG level,            /* level above which information would be written */
  ...
)
{
  FILE CK_PTR log = NULL_PTR;
  va_list params;

  va_start (params, level);

  if(level> CK_I_global_loging_level)
    return;
  
  /* Log-FileName bestimmen, falls Angabe noch NULL */

  if ( CK_I_global_logging_file == NULL_PTR ) 
    CI_EvalLogFileName();

  /* wir testen nicht ob das öffnen des logs fehlgeschlagen ist. 
   * Wem sollten wir das mitteilen? */
  log = fopen(CK_I_global_logging_file,"a");
  if(log == NULL)
#if defined(CK_GENERIC) 
    return;
#elif defined(CK_Win32)
    {
      MessageBox(NULL, "CI_VarLogEntry: could not open Log-file", 
		 "PKCS#11 Notice", MB_OK|MB_ICONWARNING);
      return;
    }
#endif  

  FunctionName = (FunctionName == NULL_PTR)? (CK_C_CHAR_PTR)"(NULL)" : FunctionName;
  ProcessDesc = (ProcessDesc == NULL_PTR)? (CK_C_CHAR_PTR)"(NULL)" : ProcessDesc;

  fprintf(log,"/* %s(): ", FunctionName);

  vfprintf(log, ProcessDesc, params);
  va_end(params);

  fprintf(log,"(%s) */\n",  CI_ErrorStr(rv));

  fclose(log);

  return;
}
/* }}} */
/* {{{ CI_CodeFktEntry */
CK_DECLARE_FUNCTION(void, CI_CodeFktEntry)(
  CK_C_CHAR_PTR FunctionName,     /* Name of the current function */
  CK_C_CHAR_PTR ProcessDesc,      /* Description of the current process */
  ...
)
{
  FILE CK_PTR log = NULL_PTR;
  va_list params;
  int len;

  if(CK_I_global_loging_level < 2 )
    return;

  if ( CK_I_global_logging_file == NULL_PTR ) 
    CI_EvalLogFileName();
  
  /* wir testen nicht ob das öffnen des logs fehlgeschlagen ist. 
   * Wem sollten wir das mitteilen? */
  log = fopen(CK_I_global_logging_file,"a");
  if(log == NULL)
#if defined(CK_GENERIC) 
    return;
#elif defined(CK_Win32)
    {
      MessageBox(NULL, "CI_VarLogEntry: could not open Log-file", 
		 "PKCS#11 Notice", MB_OK|MB_ICONWARNING);
      return;
    }
#endif  


  FunctionName = (FunctionName == NULL_PTR)? (CK_C_CHAR_PTR)"(NULL)" : FunctionName;
  ProcessDesc = (ProcessDesc == NULL_PTR)? (CK_C_CHAR_PTR)"" : ProcessDesc;

  fprintf(log,"DO_FKT(%s, (", FunctionName);

  va_start (params, ProcessDesc);
  len= vfprintf(log, ProcessDesc, params);
  va_end(params);

#if defined(CK_GENERIC)
    purify_printf("doing CI_CodeFktEntry with %d bytes",len);
#endif

  fprintf(log,"));\n");

  fclose(log);

  return;
}
/* }}} */

#else
/* {{{ CI_VarLogEntry */
CK_DEFINE_FUNCTION(void, CI_VarLogEntry)(
  const CK_CHAR_PTR FunctionName, /* Name of the current function */
  const CK_CHAR_PTR ProcessDesc,  /* Description of the current process */
  const CK_RV rv,                 /* return value in case of abort of function */
  const CK_ULONG level,           /* level above which information would be written */
  ...
)
{
 return;
}
/* }}} */
/* {{{ CI_CodeFktEntry */
CK_DECLARE_FUNCTION(void, CI_CodeFktEntry)(
  CK_CHAR_PTR FunctionName,     /* Name of the current function */
  CK_CHAR_PTR ProcessDesc,      /* Description of the current process */
  ...
)
{
 return;
}
/* }}} */

#endif /* !NO_LOGGING */

#ifndef NO_MEM_LOGGING
/* {{{ TC_SetMemLoggingFile */
CK_DEFINE_FUNCTION(void, TC_SetMemLoggingFile)(
  CK_C_CHAR_PTR memLogFileName
)
{
  if (memLogFileName == NULL_PTR)
    return;

  if( CK_I_global_mem_logging_file != NULL_PTR )
    free(CK_I_global_mem_logging_file);

  CK_I_global_mem_logging_file = malloc(sizeof(CK_CHAR) * ( strlen(memLogFileName) +1));
  strcpy(CK_I_global_mem_logging_file, memLogFileName);
  return;
}
/* }}} */
/* {{{ TC_EvalMemLogFileName*/
CK_DEFINE_FUNCTION(void, TC_EvalMemLogFileName)(
 void
)
{
#if defined(CK_GENERIC)
#define CK_I_MEM_LOG_FILE "/tmp/pkcs11.mem.log"
#elif defined(CK_Win32)
#define CK_I_MEM_LOG_FILE "c:\\pkcs11.mem.log"
#endif

  CK_CHAR_PTR tmp_name = NULL_PTR;

  if((tmp_name = getenv("GPKCS11_MEMLOG")) != NULL_PTR)
    {
      CK_I_global_mem_logging_file = malloc(sizeof(CK_CHAR) * ( strlen(tmp_name) + 1 ));
      strcpy(CK_I_global_mem_logging_file, tmp_name);
      return;
    }
  else
    {
      CK_I_global_mem_logging_file = malloc(sizeof(CK_CHAR) * ( strlen(CK_I_MEM_LOG_FILE) + 1 ));
      strcpy(CK_I_global_mem_logging_file, CK_I_MEM_LOG_FILE);
    }
  return;
}
/* }}} */
/* {{{ TC_free */
CK_DECLARE_FUNCTION(void,__TC_free)(
  void *ptr,
  unsigned int line,
  const char *file
)
{
  FILE* log = NULL_PTR;
  CK_CHAR_PTR heap_string = "good";

  /* Log-FileName bestimmen, falls Angabe noch NULL */

  if ( CK_I_global_mem_logging_file == NULL_PTR ) 
    TC_EvalMemLogFileName();
  
  /* wir testen nicht ob das öffnen des logs fehlgeschlagen ist. 
   * Wem sollten wir das mitteilen? */
#if defined(CK_GENERIC) 
  log = fopen(CK_I_global_mem_logging_file,"a");
#elif defined(CK_Win32)
  log = fopen(CK_I_global_mem_logging_file,"a");
  if(log == NULL_PTR)
    {
      MessageBox(NULL, "CI_VarLogEntry: could not open Log-file", 
		 "PKCS#11 Notice", MB_OK|MB_ICONWARNING);
      return;
    }

#else
#error no filename defined
#endif  

#if defined(CK_Win32)
  /* lets do some heap checking while where at it */
  /* Check heap status */
  switch( _heapchk())
    {
    case _HEAPOK:
      heap_string="good";
      break;
    case _HEAPEMPTY:
      heap_string="empty";
      break;
    case _HEAPBADBEGIN:
      heap_string="bad start";
      break;
    case _HEAPBADNODE:
      heap_string="bad node";
      break;
    }
#endif  

  fprintf(log,"%s:%u:free:%p:heap %s\n",file,line,ptr,heap_string);
  fclose(log);

  free(ptr);

  return;
}
/* }}} */
/* {{{ TC_calloc */
CK_DECLARE_FUNCTION(void*,__TC_calloc)(
  size_t nelem, 
  size_t elsize,
  unsigned int line,
  const char *file
)
{
  FILE* log = NULL_PTR;
  void* retval;
  CK_CHAR_PTR heap_string = "good";
  
  /* Log-FileName bestimmen, falls Angabe noch NULL */

  if ( CK_I_global_mem_logging_file == NULL_PTR ) 
    TC_EvalMemLogFileName();
  
  /* wir testen nicht ob das öffnen des logs fehlgeschlagen ist. 
   * Wem sollten wir das mitteilen? */
#if defined(CK_GENERIC) 
  log = fopen(CK_I_global_mem_logging_file,"a");
#elif defined(CK_Win32)
  log = fopen(CK_I_global_mem_logging_file,"a");
  if(log == NULL_PTR)
    {
      MessageBox(NULL, "CI_VarLogEntry: could not open Log-file", 
		 "PKCS#11 Notice", MB_OK|MB_ICONWARNING);
      return NULL_PTR;
    }
#else
#error no filename defined
#endif  
  retval = calloc(nelem,elsize);

#if defined(CK_Win32)
  /* lets do some heap checking while where at it */
  /* Check heap status */
  switch( _heapchk())
    {
    case _HEAPOK:
      heap_string="good";
      break;
    case _HEAPEMPTY:
      heap_string="empty";
      break;
    case _HEAPBADBEGIN:
      heap_string="bad start";
      break;
    case _HEAPBADNODE:
      heap_string="bad node";
      break;
    }
#endif  

  fprintf(log,"%s:%u:calloc:%p:heap %s:%lu bytes\n",
	  file,line,retval,heap_string,nelem*elsize);
  fclose(log);

  return retval;
}
/* }}} */
/* {{{ TC_malloc */
CK_DECLARE_FUNCTION(void*,__TC_malloc)(
  size_t size,
  unsigned int line,
  const char *file
)
{
  FILE* log = NULL_PTR;
  void* retval;
  CK_CHAR_PTR heap_string = "good";
  
  /* Log-FileName bestimmen, falls Angabe noch NULL */

  if ( CK_I_global_mem_logging_file == NULL_PTR ) 
    TC_EvalMemLogFileName();
  
  /* wir testen nicht ob das öffnen des logs fehlgeschlagen ist. 
   * Wem sollten wir das mitteilen? */
#if defined(CK_GENERIC) 
  log = fopen(CK_I_global_mem_logging_file,"a");
#elif defined(CK_Win32)
  log = fopen(CK_I_global_mem_logging_file,"a");
  if(log == NULL_PTR)
    {
      MessageBox(NULL, "CI_VarLogEntry: could not open Log-file", 
		 "PKCS#11 Notice", MB_OK|MB_ICONWARNING);
      return NULL_PTR;
    }
#else
#error no filename defined
#endif  

  retval = malloc(size);

#if defined(CK_Win32)
  /* lets do some heap checking while where at it */
  /* Check heap status */
  switch( _heapchk())
    {
    case _HEAPOK:
      heap_string="good";
      break;
    case _HEAPEMPTY:
      heap_string="empty";
      break;
    case _HEAPBADBEGIN:
      heap_string="bad start";
      break;
    case _HEAPBADNODE:
      heap_string="bad node";
      break;
    }
#endif  

  fprintf(log,"%s:%u:malloc:%p:heap %s:%lu bytes\n",file,line,retval,heap_string,size);
  fclose(log);

  return retval;
}
/* }}} */

#endif /* !NO_LOGGING */

/*
 *
 * Local variables:
 * folded-file: t
 * end:
 */
