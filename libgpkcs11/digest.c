/* -*- c -*- */
/*
 * This file is part of GPKCS11. 
 * (c) 1999-2001 TC TrustCenter GmbH 
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
 * NAME:        digest.c
 * SYNOPSIS:    -
 * DESCRIPTION: -
 * FILES:       -
 * SEE/ALSO:    -
 * AUTHOR:      lbe
 * BUGS:        -
 */
 
static char RCSID[]="$Id$";
const char* Version_digest_c(){return RCSID;}

#ifndef CK_I_library_build
#define CK_I_library_build
#endif

#include "internal.h"
#include "pkcs11_error.h"
#include "objects.h"

#include <stdlib.h>

/* {{{ C_DigestInit */
CK_DEFINE_FUNCTION(CK_RV, C_DigestInit)(
      CK_SESSION_HANDLE hSession,
      CK_MECHANISM_PTR pMechanism
      )
{
  CK_RV rv = CKR_OK;
  CK_I_SESSION_DATA_PTR session_data = NULL_PTR;

  CI_VarLogEntry("C_DigestInit", "starting...Session:%i", rv, 1,hSession);
  CI_CodeFktEntry("C_DigestInit", "%i,%s", 
		  hSession,
		  CI_ScanableMechanism(pMechanism));

  /* make sure we are initialized */
  if (!(CK_I_global_flags & CK_IGF_INITIALIZED)) 
    {
      rv = CKR_CRYPTOKI_NOT_INITIALIZED;
      CI_LogEntry("C_DigestInit", "library status", rv, 0);
      return rv;
    }

  /* get session info and make sure that this session exists */
  rv = CI_ReturnSession(hSession, &session_data);
  if(rv != CKR_OK)
    {
      CI_VarLogEntry("C_DigestInit", "retrieve session data (hSession: %lu)", rv, 1,
                     hSession);
      return rv;
    }

  /* Make sure that there is not a digest allready in progress */
  if(session_data->digest_state != NULL_PTR)
    {
      rv =CKR_OPERATION_ACTIVE;
      CI_LogEntry("C_DigestInit", "starting...", rv, 1);
      return rv;
    }

  CK_I_CALL_TOKEN_METHOD(rv, DigestInit, (session_data, pMechanism));

  CI_LogEntry("C_DigestInit", "...complete", rv, 1);

  return rv;
}
/* }}} */
/* {{{ C_Digest */
CK_DEFINE_FUNCTION(CK_RV, C_Digest)(
        CK_SESSION_HANDLE hSession,
        CK_BYTE_PTR pData,
        CK_ULONG ulDataLen,
        CK_BYTE_PTR pDigest,
        CK_ULONG_PTR pulDigestLen
      )
{
  CK_RV rv = CKR_OK;
  CK_I_SESSION_DATA_PTR session_data = NULL_PTR;
  
  CI_LogEntry("C_Digest", "starting...", rv, 1);
  CI_CodeFktEntry("C_Digest", "%i,%s,%i,%p,%p", 
		  hSession,
		  CI_ScanableByteStream(pData,ulDataLen),
		  ulDataLen,
		  pDigest,
		  pulDigestLen);
  CI_VarLogEntry("C_Digest", "*pulDigestLen: %i", rv, 1,*pulDigestLen);

  /* make sure we are initialized */
  if (!(CK_I_global_flags & CK_IGF_INITIALIZED)) 
    return CKR_CRYPTOKI_NOT_INITIALIZED;

  /* get session info and make sure that this session exists */
  rv = CI_ReturnSession(hSession, &session_data);
  if(rv != CKR_OK)
    {
      CI_VarLogEntry("C_Digest", "retrieve session data (hSession: %lu)", rv, 1,
                     hSession);
      return rv;
    }

  /* Make sure that there is a digest in progress */
  if(session_data->digest_state == NULL_PTR)
    {
      rv = CKR_OPERATION_NOT_INITIALIZED;
      CI_LogEntry("C_Digest", "check operation status", rv, 1);
      return rv;
    }

  CK_I_CALL_TOKEN_METHOD(rv, Digest, (session_data, pData, ulDataLen, pDigest, pulDigestLen));

  if(pDigest == NULL_PTR)
    CI_LogEntry("C_Digest", "computing needed size for digest data", rv, 1);
  else
    CI_LogEntry("C_Digest", "...complete", rv, 1);

  return rv;
}
/* }}} */
/* {{{ C_DigestUpdate */
CK_DEFINE_FUNCTION(CK_RV, C_DigestUpdate)(
        CK_SESSION_HANDLE hSession,
        CK_BYTE_PTR pPart,
        CK_ULONG ulPartLen
      )
{
  CK_RV rv = CKR_OK;
  CK_I_SESSION_DATA_PTR session_data = NULL_PTR;

  CI_LogEntry("C_DigestUpdate", "starting...", rv, 1);
  CI_CodeFktEntry("C_DigestUpdate", "%i,%s,%i", 
		  hSession,
		  CI_ScanableByteStream(pPart,ulPartLen),
		  ulPartLen);

  /* make sure we are initialized */
  if (!(CK_I_global_flags & CK_IGF_INITIALIZED)) 
    return CKR_CRYPTOKI_NOT_INITIALIZED;

  /* get session info and make sure that this session exists */
  rv = CI_ReturnSession(hSession, &session_data);
  if(rv != CKR_OK)
    {
      CI_VarLogEntry("C_DigestUpdate", "retrieve session data (hSession: %lu)", rv, 1,
                     hSession);
      return rv;
    }

  /* Make sure that there is a digest in progress */
  if(session_data->digest_state == NULL_PTR)
    {
      rv = CKR_OPERATION_NOT_INITIALIZED;
      CI_LogEntry("C_DigestUpdate", "check operation status", rv, 1);
      return rv;
    }

  CK_I_CALL_TOKEN_METHOD(rv, DigestUpdate, (session_data, pPart, ulPartLen));

  CI_LogEntry("C_DigestUpdate", "...complete", rv, 1);

  return rv;
}
/* }}} */
/* {{{ C_DigestKey */
/* C_DigestKey continues a multi-part message-digesting
 * operation, by digesting the value of a secret key as part of
 * the data already digested. */
CK_DEFINE_FUNCTION(CK_RV, C_DigestKey)
(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_OBJECT_HANDLE  hKey       /* secret key to digest */
)
{
  CK_RV rv = CKR_OK;
  CK_I_OBJ_PTR key_obj = NULL_PTR;
  CK_I_SESSION_DATA_PTR session_data = NULL_PTR;

  CI_LogEntry("C_DigestKey", "starting...", rv, 1);
  CI_CodeFktEntry("C_DigestKey", "%i,%i", 
		  hSession,
		  hKey);

  /* make sure we are initialized */
  if (!(CK_I_global_flags & CK_IGF_INITIALIZED)) 
    return CKR_CRYPTOKI_NOT_INITIALIZED;

  /* get session info and make sure that this session exists */
  rv = CI_ReturnSession(hSession, &session_data);
  if(rv != CKR_OK)
    {
      CI_VarLogEntry("C_DigestKey", "retrieve session data (hSession: %lu)", rv, 1,
                     hSession);
      return rv;
    }

  /* Make sure that there is a digest in progress */
  if(session_data->digest_state == NULL_PTR)
    {
      rv = CKR_OPERATION_NOT_INITIALIZED;
      CI_LogEntry("C_DigestKey", "ckeck operation status", rv, 0);
      return rv;
    }

  rv = CI_ReturnObj(session_data,hKey, &key_obj);
  if(rv != CKR_OK)
    {
      CI_VarLogEntry("C_DigestKey", "retrieve key object(hSession: %lu, hKey: %lu)", 
		     rv, 1,
                     hSession, hKey);
      return rv;
    }


  CK_I_CALL_TOKEN_METHOD(rv, DigestKey, (session_data, key_obj));

  CI_LogEntry("C_DigestKey", "...complete", rv, 1);

  return rv;
}
/* }}} */
/* {{{ C_DigestFinal */
CK_DEFINE_FUNCTION(CK_RV, C_DigestFinal)(
        CK_SESSION_HANDLE hSession,
        CK_BYTE_PTR pDigest,
        CK_ULONG_PTR pulDigestLen
      )
{
  CK_RV rv = CKR_OK;
  CK_I_SESSION_DATA_PTR session_data = NULL_PTR;

  CI_LogEntry("C_DigestFinal", "starting...", rv, 1);
  CI_CodeFktEntry("C_DigestFinal", "%i,%p,%p", 
		  hSession,
		  pDigest,
		  pulDigestLen);
  CI_VarLogEntry("C_DigestFinal", "*pulDigestLen: %i", rv, 1,*pulDigestLen);

  /* make sure we are initialized */
  if (!(CK_I_global_flags & CK_IGF_INITIALIZED)) 
    return CKR_CRYPTOKI_NOT_INITIALIZED;

  /* get session info and make sure that this session exists */
  rv = CI_ReturnSession(hSession, &session_data);
  if(rv != CKR_OK)
    {
      CI_VarLogEntry("C_DigestFinal", "retrieve session data (hSession: %lu)", rv, 1,
                     hSession);
      return rv;
    }

  /* Make sure that there is a digest in progress */
  if(session_data->digest_state == NULL_PTR)
    {
    rv = CKR_OPERATION_NOT_INITIALIZED;
    CI_LogEntry("C_DigestFinal", "checking operation status", rv, 0);
    return rv;
    }

  CK_I_CALL_TOKEN_METHOD(rv, DigestFinal, (session_data, pDigest, pulDigestLen));

  CI_LogEntry("C_DigestFinal", "...complete", rv, 1);

  return rv;
}
/* }}} */

/*
 * Local variables:
 * folded-file: t
 * end:
 */

