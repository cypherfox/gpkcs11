/* -*- c -*- */
/*
 * This file is part of GPKCS11. 
 * (c) 1999-2001 TC TrustCenter for Security in DataNetworks GmbH 
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
 * NAME:        dual.c
 * SYNOPSIS:    -
 * DESCRIPTION: -
 * FILES:       -
 * SEE/ALSO:    -
 * AUTHOR:      lbe
 * BUGS:        -
 */
 
static char RCSID[]="$Id$";
const char* Version_dual_c(){return RCSID;}

#ifndef CK_I_library_build
#define CK_I_library_build
#endif

#include "internal.h"
#include "error.h"
#include "objects.h"

#include <errno.h>
#include <stdlib.h>

/* {{{ C_DigestEncryptUpdate */
/* C_DigestEncryptUpdate continues a multiple-part digesting
 * and encryption operation. */
CK_DEFINE_FUNCTION(CK_RV, C_DigestEncryptUpdate)

(
  CK_SESSION_HANDLE hSession,            /* session's handle */
  CK_BYTE_PTR       pPart,               /* the plaintext data */
  CK_ULONG          ulPartLen,           /* plaintext length */
  CK_BYTE_PTR       pEncryptedPart,      /* gets ciphertext */
  CK_ULONG_PTR      pulEncryptedPartLen  /* gets c-text length */
)
{
  CK_RV rv = CKR_OK;
  CK_I_SESSION_DATA_PTR session_data = NULL_PTR;
  CK_BYTE_PTR tmp1 = NULL_PTR;

  CI_LogEntry("C_DigestEncryptUpdate", "starting...", rv, 1);
  CI_CodeFktEntry("C_DigestEncryptUpdate", "%i,%s,%i,%p,%p", 
		  hSession,
		  tmp1 = CI_ScanableByteStream(pPart, ulPartLen),
		  ulPartLen,
		  pEncryptedPart,
		  pulEncryptedPartLen);
  TC_free(tmp1);
  CI_VarLogEntry("C_DigestEncryptUpdate", "*pulEncryptedPartLen: %i", rv, 1, *pulEncryptedPartLen);


  /* make sure we are initialized */
  if (!(CK_I_global_flags & CK_IGF_INITIALIZED)) 
    return CKR_CRYPTOKI_NOT_INITIALIZED;

  /* get session info and make sure that this session exists */
  rv = CI_ReturnSession(hSession, &session_data);
  if(rv != CKR_OK)
    {
      CI_VarLogEntry("C_DigestEncryptUpdate", "retrieve session data (hSession: %lu)", rv, 1,
                     hSession);
      return rv;
    }
 
  /* Is there an active digest at all? */
  if(session_data->digest_state == NULL_PTR)
    return CKR_OPERATION_NOT_INITIALIZED;
  /* Is there an active encrypt at all? */
  if(session_data->encrypt_state == NULL_PTR)
    return CKR_OPERATION_NOT_INITIALIZED;

  CK_I_CALL_TOKEN_METHOD(rv, DigestEncryptUpdate, (session_data, pPart, ulPartLen, pEncryptedPart, pulEncryptedPartLen));

  CI_LogEntry("C_DigestEncryptUpdate", "...complete", rv, 1);

  return rv;
}
/* }}} */
/* {{{ C_DecryptDigestUpdate */
/* C_DecryptDigestUpdate continues a multiple-part decryption and
 * digesting operation. */
CK_DEFINE_FUNCTION(CK_RV, C_DecryptDigestUpdate)

(
  CK_SESSION_HANDLE hSession,            /* session's handle */
  CK_BYTE_PTR       pEncryptedPart,      /* ciphertext */
  CK_ULONG          ulEncryptedPartLen,  /* ciphertext length */
  CK_BYTE_PTR       pPart,               /* gets plaintext */
  CK_ULONG_PTR      pulPartLen           /* gets plaintext len */
)
{
  CK_RV rv = CKR_OK;
  CK_I_SESSION_DATA_PTR session_data = NULL_PTR;
  CK_BYTE_PTR tmp1 = NULL_PTR;

  CI_LogEntry("C_DecryptDigestUpdate", "starting...", rv, 1);
  CI_CodeFktEntry("C_DecryptDigestUpdate", "%i,%s,%i,%p,%p", 
		  hSession,
		  tmp1 = CI_ScanableByteStream(pEncryptedPart, ulEncryptedPartLen),
		  ulEncryptedPartLen,
		  pPart,
		  pulPartLen);
  TC_free(tmp1);
  CI_VarLogEntry("C_DecryptDigestUpdate", "*pulPartLen: %i", rv, 1, *pulPartLen);

  /* make sure we are initialized */
  if (!(CK_I_global_flags & CK_IGF_INITIALIZED)) 
    return CKR_CRYPTOKI_NOT_INITIALIZED;

  /* get session info and make sure that this session exists */
  rv = CI_ReturnSession(hSession, &session_data);
  if(rv != CKR_OK)
    {
      CI_VarLogEntry("C_DecryptDigestUpdate", "retrieve session data (hSession: %lu)", rv, 1,
                     hSession);
      return rv;
    }

  /* Is there an active digest at all? */
  if(session_data->digest_state == NULL_PTR)
    return CKR_OPERATION_NOT_INITIALIZED;
  /* Is there an active decrypt at all? */
  if(session_data->decrypt_state == NULL_PTR)
    return CKR_OPERATION_NOT_INITIALIZED;

  CK_I_CALL_TOKEN_METHOD(rv, DecryptDigestUpdate, (session_data, pEncryptedPart, ulEncryptedPartLen, pPart, pulPartLen));

  CI_LogEntry("C_DecryptDigestUpdate", "...complete", rv, 1);

  return rv;
}
/* }}} */
/* {{{ C_SignEncryptUpdate */
/* C_SignEncryptUpdate continues a multiple-part signing and
 * encryption operation. */
CK_DEFINE_FUNCTION(CK_RV, C_SignEncryptUpdate)

(
  CK_SESSION_HANDLE hSession,            /* session's handle */
  CK_BYTE_PTR       pPart,               /* the plaintext data */
  CK_ULONG          ulPartLen,           /* plaintext length */
  CK_BYTE_PTR       pEncryptedPart,      /* gets ciphertext */
  CK_ULONG_PTR      pulEncryptedPartLen  /* gets c-text length */
)
{
  CK_RV rv = CKR_OK;
  CK_I_SESSION_DATA_PTR session_data = NULL_PTR;
  CK_BYTE_PTR tmp1 = NULL_PTR;

  CI_LogEntry("C_SignEncryptUpdate", "starting...", rv, 1);
  CI_CodeFktEntry("C_SignEncryptUpdate", "%i,%s,%i,%p,%p", 
		  hSession,
		  tmp1 = CI_ScanableByteStream(pPart, ulPartLen),
		  ulPartLen,
		  pEncryptedPart,
		  pulEncryptedPartLen);
  TC_free(tmp1);
  CI_VarLogEntry("C_SignEncryptUpdate", "*pulEncryptedPartLen: %i", rv, 1, *pulEncryptedPartLen);

  /* make sure we are initialized */
  if (!(CK_I_global_flags & CK_IGF_INITIALIZED)) 
    return CKR_CRYPTOKI_NOT_INITIALIZED;

  /* get session info and make sure that this session exists */
  rv = CI_ReturnSession(hSession, &session_data);
  if(rv != CKR_OK)
    {
      CI_VarLogEntry("C_SignEncryptUpdate", "retrieve session data (hSession: %lu)", rv, 1,
                     hSession);
      return rv;
    }

  /* Is there an active digest at all? */
  if(session_data->sign_state == NULL_PTR)
    return CKR_OPERATION_NOT_INITIALIZED;
  /* Is there an active encrypt at all? */
  if(session_data->encrypt_state == NULL_PTR)
    return CKR_OPERATION_NOT_INITIALIZED;

  CK_I_CALL_TOKEN_METHOD(rv, SignEncryptUpdate, (session_data, pPart, ulPartLen, pEncryptedPart, pulEncryptedPartLen));

  CI_LogEntry("C_SignEncryptUpdate", "...complete", rv, 1);

  return rv;
}
 /* }}} */
/* {{{ C_DecryptVerifyUpdate */
 /* C_DecryptVerifyUpdate continues a multiple-part decryption and
 * verify operation. */
CK_DEFINE_FUNCTION(CK_RV, C_DecryptVerifyUpdate)
(
  CK_SESSION_HANDLE hSession,            /* session's handle */
  CK_BYTE_PTR       pEncryptedPart,      /* ciphertext */
  CK_ULONG          ulEncryptedPartLen,  /* ciphertext length */
  CK_BYTE_PTR       pPart,               /* gets plaintext */
  CK_ULONG_PTR      pulPartLen           /* gets p-text length */
)
{
  CK_RV rv = CKR_OK;
  CK_I_SESSION_DATA_PTR session_data = NULL_PTR;
  CK_BYTE_PTR tmp1 = NULL_PTR;

  CI_LogEntry("C_DecryptVerifyUpdate", "starting...", rv, 1);
  CI_CodeFktEntry("C_DecryptVerifyUpdate", "%i,%s,%i,%p,%p", 
		  hSession,
		  tmp1 = CI_ScanableByteStream(pEncryptedPart, ulEncryptedPartLen),
		  ulEncryptedPartLen,
		  pPart,
		  pulPartLen);
  TC_free(tmp1);
  CI_VarLogEntry("C_DecryptVerifyUpdate", "*pulPartLen: %i", rv, 1, *pulPartLen);

  /* make sure we are initialized */
  if (!(CK_I_global_flags & CK_IGF_INITIALIZED)) 
    return CKR_CRYPTOKI_NOT_INITIALIZED;

  /* get session info and make sure that this session exists */
  rv = CI_ReturnSession(hSession, &session_data);
  if(rv != CKR_OK)
    {
      CI_VarLogEntry("C_DecryptVerifyUpdate", "retrieve session data (hSession: %lu)", rv, 1,
                     hSession);
      return rv;
    }

  /* Is there an active digest at all? */
  if(session_data->verify_state == NULL_PTR)
    return CKR_OPERATION_NOT_INITIALIZED;
  /* Is there an active encrypt at all? */
  if(session_data->decrypt_state == NULL_PTR)
    return CKR_OPERATION_NOT_INITIALIZED;

  CK_I_CALL_TOKEN_METHOD(rv, DecryptVerifyUpdate, (session_data, pEncryptedPart, ulEncryptedPartLen, pPart, pulPartLen));

  CI_LogEntry("C_DecryptVerifyUpdate", "...complete", rv, 1);

  return rv;
}
/* }}} */
/*
 * Local variables:
 * folded-file: t
 * end:
 */




