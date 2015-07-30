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
 * NAME:        verify.c
 * SYNOPSIS:    -
 * DESCRIPTION: -
 * FILES:       -
 * SEE/ALSO:    -
 * AUTHOR:      lbe
 * BUGS: *      -
 * HISTORY:     $Log$
 * HISTORY:     Revision 1.4  2000/01/31 18:09:03  lbe
 * HISTORY:     lockdown prior to win_gdbm change
 * HISTORY:
 * HISTORY:     Revision 1.3  1999/11/02 13:47:19  lbe
 * HISTORY:     change of structures and bug fix in slot.c, add more files for tcsc_token: emptyfuncs and general_data
 * HISTORY:
 * HISTORY:     Revision 1.2  1999/10/06 07:57:23  lbe
 * HISTORY:     solved netscape symbol clash problem
 * HISTORY:
 * HISTORY:     Revision 1.1  1999/06/16 09:46:12  lbe
 * HISTORY:     reorder files
 * HISTORY:
 * HISTORY:     Revision 1.8  1999/01/19 12:19:48  lbe
 * HISTORY:     first release lockdown
 * HISTORY:
 * HISTORY:     Revision 1.7  1998/12/07 13:20:30  lbe
 * HISTORY:     TC_free von parametern für Zeile und Datei befreit.
 * HISTORY:
 * HISTORY:     Revision 1.6  1998/11/13 10:10:03  lbe
 * HISTORY:     added persistent storage.
 * HISTORY:
 * HISTORY:     Revision 1.5  1998/10/12 10:00:13  lbe
 * HISTORY:     clampdown
 * HISTORY:
 * HISTORY:     Revision 1.4  1998/08/05 09:00:29  lbe
 * HISTORY:     *** empty log message ***
 * HISTORY:
 * HISTORY:     Revision 1.3  1998/07/30 15:25:48  lbe
 * HISTORY:     Win32 Port
 * HISTORY:
 * HISTORY:     Revision 1.2  1998/07/23 15:19:06  lbe
 * HISTORY:     working
 * HISTORY:
 * HISTORY:     Revision 1.1  1998/07/02 17:26:05  lbe
 * HISTORY:     Initial revision
 * HISTORY:
 */
 
static char RCSID[]="$Id$";
const char* Version_verify_c(){return RCSID;}

#ifndef CK_I_library_build
#define CK_I_library_build
#endif

#include "internal.h"
#include "error.h"
#include "objects.h"

#include <stdlib.h>

/* {{{ C_VerifyInit */
CK_DEFINE_FUNCTION(CK_RV, C_VerifyInit)(
        CK_SESSION_HANDLE hSession,
        CK_MECHANISM_PTR pMechanism,
        CK_OBJECT_HANDLE hKey
      )
{
  CK_RV rv = CKR_OK;
  CK_I_OBJ_PTR key_obj = NULL_PTR;  /* key to be used */
  CK_I_SESSION_DATA_PTR session_data = NULL_PTR;

  CI_VarLogEntry("C_VerifyInit", "starting... Session: %i, Key: %i", 
		 rv, 1, hSession,hKey);

#ifndef NO_LOGGING
  {
    CK_CHAR_PTR tmp = NULL;
    CI_CodeFktEntry("C_VerifyInit", "%i,%s,%i", 
		  hSession,
		  tmp = CI_ScanableMechanism(pMechanism),
		  hKey);
    TC_free(tmp);
  }
#endif // NO_LOGGING
  
  /* make sure we are initialized */
  if (!(CK_I_global_flags & CK_IGF_INITIALIZED)) 
    {
      rv =CKR_CRYPTOKI_NOT_INITIALIZED;
      CI_LogEntry("C_VerifyInit", "initialization check", rv, 1);
      return rv;
    }
  
  /* get session info and make sure that this session exists */
  rv = CI_ReturnSession(hSession, &session_data);
  if(rv != CKR_OK)
    {
      CI_VarLogEntry("C_VerifyInit", "retrieve session data (hSession: %lu)", rv, 1,
                     hSession);
      return rv;
    }
  
  /* Is there an active verifying? */
  if(session_data->verify_state != NULL_PTR)
    {
      rv =CKR_OPERATION_ACTIVE;
      CI_LogEntry("C_VerifyInit", "check operation status", rv, 0);
      return rv;
    }

  rv = CI_ReturnObj(session_data,hKey, &key_obj);
  if(rv != CKR_OK)
    {
      CI_VarLogEntry("C_VerifyInit", "retrieve object list (hSession: %lu, hKey: %lu)", rv, 1,
                     hSession, hKey);
      return rv;
    }
  
  
  /* Does the key allow verifying? */
  /*
   * no need to check if mechanism allows verifying. 
   * Only those that allow verifying are implemented below 
   */
  if((CI_ObjLookup(key_obj, CK_IA_VERIFY) != NULL_PTR) &&
     (*((CK_BBOOL CK_PTR)CI_ObjLookup(key_obj, CK_IA_VERIFY)->pValue) != TRUE))
    {
      rv = CKR_KEY_TYPE_INCONSISTENT;
      CI_LogEntry("C_VerifyInit", "verify allowed by key?", rv, 0);
      return rv;
    }
  
  CK_I_CALL_TOKEN_METHOD(rv, VerifyInit, (session_data, pMechanism, key_obj));
  
  CI_LogEntry("C_VerifyInit", "...complete", rv, 1);
  
  return rv;
}
/* }}} */
/* {{{ C_Verify */
CK_DEFINE_FUNCTION(CK_RV, C_Verify)(
        CK_SESSION_HANDLE hSession,            /* session's handle */
        CK_BYTE_PTR       pData,               /* gets plaintext */
        CK_ULONG          ulDataLen,           /* gets p-text size */
        CK_BYTE_PTR       pSignature,          /* the Signature */
        CK_ULONG          ulSignatureLen      /* bytes of Signature */
      )
{
  CK_RV rv = CKR_OK;
  CK_I_SESSION_DATA_PTR session_data = NULL_PTR;

  CI_VarLogEntry("C_Verify", "starting... Session: %i", rv, 1, hSession);

#ifndef NO_LOGGING
  {
    CK_CHAR_PTR tmp = NULL;
    CK_CHAR_PTR tmp2 = NULL;
    CI_CodeFktEntry("C_Verify", "%i,%s,%i,%s,%i", 
		  hSession,
		  tmp = CI_ScanableByteStream(pData,ulDataLen),
		  ulDataLen,
		  tmp2 = CI_ScanableByteStream(pSignature,ulSignatureLen),
		  ulSignatureLen);
    TC_free(tmp);
    TC_free(tmp2);
  }
#endif // NO_LOGGING

  /* make sure we are initialized */
  if (!(CK_I_global_flags & CK_IGF_INITIALIZED)) 
    return CKR_CRYPTOKI_NOT_INITIALIZED;

  rv = CI_ReturnSession(hSession, &session_data);
  if(rv != CKR_OK)
    {
      CI_VarLogEntry("C_Verify", "retrieve session data (hSession: %lu)", rv, 1,
                     hSession);
      return rv;
    }

  /* Is there an active verifying at all? */
  if(session_data->verify_state == NULL_PTR)
    {
      rv = CKR_OPERATION_NOT_INITIALIZED;
      CI_LogEntry("C_Verify", "ckeck operation status", rv, 0);
      return rv;
    }

  CK_I_CALL_TOKEN_METHOD(rv, Verify, (session_data, pData, ulDataLen, pSignature, ulSignatureLen));

  CI_LogEntry("C_Verify", "...complete", rv, 1);

  return rv;
}
/* }}} */
/* {{{ C_VerifyUpdate */
CK_DEFINE_FUNCTION(CK_RV, C_VerifyUpdate)(
        CK_SESSION_HANDLE hSession,  /* the session's handle */
        CK_BYTE_PTR pPart,           /* the data to verify */
        CK_ULONG ulPartLen           /* count of bytes to verify */
      )
{
  CK_RV rv = CKR_OK;
  CK_I_SESSION_DATA_PTR session_data = NULL_PTR;

  CI_VarLogEntry("C_VerifyUpdate", "starting... Session: %i", rv, 1, hSession);
  
#ifndef NO_LOGGING
  {
    CK_CHAR_PTR tmp = NULL;
    CI_CodeFktEntry("C_VerifyUpdate", "%i,%s,%i,", 
		  hSession,
		  tmp = CI_PrintableByteStream(pPart,ulPartLen),
		  ulPartLen);
    TC_free(tmp);
  }
#endif // NO_LOGGING
  

  /* make sure we are initialized */
  if (!(CK_I_global_flags & CK_IGF_INITIALIZED)) 
    return CKR_CRYPTOKI_NOT_INITIALIZED;

  rv = CI_ReturnSession(hSession, &session_data);
  if(rv != CKR_OK)
    {
      CI_VarLogEntry("C_VerifyUpdate", "retrieve session data (hSession: %lu)", rv, 1,
                     hSession);
      return rv;
    }

  /* Is there an active verifying at all? */
  if(session_data->verify_state == NULL_PTR)
    {
      rv = CKR_OPERATION_NOT_INITIALIZED;
      CI_LogEntry("C_VerifyUpdate", "checking operation status", rv, 0);
    return rv;
    }

  CK_I_CALL_TOKEN_METHOD(rv, VerifyUpdate, (session_data, pPart, ulPartLen));

  CI_LogEntry("C_VerifyUpdate", "...complete", rv, 1);

  return rv;
}
/* }}} */
/* {{{ C_VerifyFinal */
CK_DEFINE_FUNCTION(CK_RV, C_VerifyFinal)(
        CK_SESSION_HANDLE hSession,
        CK_BYTE_PTR       pSignature,
        CK_ULONG          ulSignatureLen
      )
{
  CK_RV rv = CKR_OK;
  CK_I_SESSION_DATA_PTR session_data = NULL_PTR;

  CI_VarLogEntry("C_VerifyFinal", "starting... Session: %i", rv, 1, hSession);
  
#ifndef NO_LOGGING
  {
    CK_CHAR_PTR tmp = NULL;
    CI_CodeFktEntry("C_VerifyFinal", "%i,%s,%i,", 
		  hSession,
		  tmp = CI_PrintableByteStream(pSignature,ulSignatureLen),
		  ulSignatureLen);
    TC_free(tmp);
  }
#endif // NO_LOGGING

  /* make sure we are initialized */
  if (!(CK_I_global_flags & CK_IGF_INITIALIZED)) 
    return CKR_CRYPTOKI_NOT_INITIALIZED;

  /* get session info and make sure that this session exists */
  rv = CI_ReturnSession(hSession, &session_data);
  if(rv != CKR_OK)
    {
      CI_VarLogEntry("C_CreateObject", "retrieve session data (hSession: %lu)", rv, 1,
                     hSession);
      return rv;
    }

  /* Is there an active verifying at all? */
  if(session_data->verify_state == NULL_PTR)
    {
      rv = CKR_OPERATION_NOT_INITIALIZED;
      CI_LogEntry("C_VerifyFinal", "checking operation status", rv, 0);
      return rv;
    }
  
  CK_I_CALL_TOKEN_METHOD(rv, VerifyFinal, (session_data, pSignature, ulSignatureLen));

  CI_LogEntry("C_VerifyFinal", "...complete", rv, 1);

  return rv;
}
/* }}} */
/* {{{ C_VerifyRecoverInit */
/* C_VerifyRecoverInit initializes a signature verification
 * operation, where the data is recovered from the signature. */
CK_DEFINE_FUNCTION(CK_RV, C_VerifyRecoverInit)
(
  CK_SESSION_HANDLE hSession,    /* the session's handle */
  CK_MECHANISM_PTR  pMechanism,  /* the verification mechanism */
  CK_OBJECT_HANDLE  hKey         /* verification key */
)
{
  CK_RV rv = CKR_OK;
  CK_I_OBJ_PTR key_obj = NULL_PTR;  /* key to be used */
  CK_I_SESSION_DATA_PTR session_data = NULL_PTR;

  CI_VarLogEntry("C_VerifyRecoverInit", "starting... Session: %i", rv, 1, hSession);
  
#ifndef NO_LOGGING
  {
    CK_CHAR_PTR tmp = NULL;
    CI_CodeFktEntry("C_VerifyRecoverInit", "%i,%s,%i", 
		  hSession,
		  tmp = CI_ScanableMechanism(pMechanism),
		  hKey);
    TC_free(tmp);
  }
#endif // NO_LOGGING

  /* make sure we are initialized */
  if (!(CK_I_global_flags & CK_IGF_INITIALIZED)) 
    {
      rv = CKR_CRYPTOKI_NOT_INITIALIZED;
      CI_LogEntry("C_VerifyRecoverInit", "checking initialization", rv, 0);
      return rv;
    }

  CI_LogEntry("C_VerifyRecoverInit", "get session info", rv, 1);

  /* get session info and make sure that this session exists */
  rv = CI_ReturnSession(hSession, &session_data);
  if(rv != CKR_OK)
    {
      CI_VarLogEntry("C_CreateObject", "retrieve session data (hSession: %lu)", rv, 1,
                     hSession);
      return rv;
    }

  CI_LogEntry("C_VerifyRecoverInit", "check session for active verify", rv, 1);

  /* Is there an active verify-recover? */
  if(session_data->verify_state != NULL_PTR)
    {
      rv = CKR_OPERATION_ACTIVE;
      CI_LogEntry("C_VerifyRecoverInit", "check operation status", rv, 0);
      return rv;
    }

  rv = CI_ReturnObj(session_data,hKey, &key_obj);
  if(rv != CKR_OK)
    {
      CI_VarLogEntry("C_VerifyRecoverInit", 
		     "retrieve object list (hSession: %lu, hKey: %lu)", rv, 1,
                     hSession, hKey);
      return rv;
    }
 

  /* Does the key allow verifying? */
  /*
   * no need to check if mechanism allows verifying. 
   * Only those that allow verifying are implemented below 
   */
  if((CI_ObjLookup(key_obj, CK_IA_VERIFY_RECOVER) != NULL_PTR) && 
     (*((CK_BBOOL CK_PTR)(CI_ObjLookup(key_obj, CK_IA_VERIFY_RECOVER)->pValue)) != TRUE))
    {
      rv = CKR_KEY_TYPE_INCONSISTENT;
      CI_LogEntry("C_VerifyRecoverInit", "ckecking whether key allows verify", rv, 1);
      return rv;
  }
  
  CI_LogEntry("C_VerifyRecoverInit", "calling token methods", rv, 1);

  CK_I_CALL_TOKEN_METHOD(rv, VerifyRecoverInit, (session_data, pMechanism, key_obj));
  
  CI_LogEntry("C_VerifyRecoverInit", "...complete", rv, 1);

  return rv;
}
/* }}} */
/* {{{ C_VerifyRecover */
/* C_VerifyRecover verifies a signature in a single-part
 * operation, where the data is recovered from the signature. */
CK_DEFINE_FUNCTION(CK_RV, C_VerifyRecover)
(
  CK_SESSION_HANDLE hSession,        /* the session's handle */
  CK_BYTE_PTR       pSignature,      /* signature to verify */
  CK_ULONG          ulSignatureLen,  /* signature length */
  CK_BYTE_PTR       pData,           /* gets signed data */
  CK_ULONG_PTR      pulDataLen       /* gets signed data len */
)
{
  CK_RV rv = CKR_OK;
  CK_I_SESSION_DATA_PTR session_data = NULL_PTR;

  CI_LogEntry("C_VerifyRecover", "starting...", rv, 1);
  
#ifndef NO_LOGGING
  {
    CK_CHAR_PTR tmp = NULL;
    CI_CodeFktEntry("C_VerifyRecover", "%i,%s,%i,%p,%p", 
		  hSession,
		  tmp = CI_ScanableByteStream(pSignature,ulSignatureLen),
		  ulSignatureLen,
		  pData,
		  pulDataLen);
    TC_free(tmp);
  }
#endif // NO_LOGGING
  
  CI_VarLogEntry("C_VerifyRecover", "*pulDataLen: %lu", rv, 1, *pulDataLen);

  /* make sure we are initialized */
  if (!(CK_I_global_flags & CK_IGF_INITIALIZED)) 
    return CKR_CRYPTOKI_NOT_INITIALIZED;

  /* get session info and make sure that this session exists */
  rv = CI_ReturnSession(hSession, &session_data);
  if(rv != CKR_OK)
    {
      CI_VarLogEntry("C_CreateObject", "retrieve session data (hSession: %lu)", rv, 1,
                     hSession);
      return rv;
    }

  /* Is there an active verifying at all? */
  if(session_data->verify_state == NULL_PTR)
    {
      rv = CKR_OPERATION_NOT_INITIALIZED;
      CI_LogEntry("C_VerifyRecover", "check operation status", rv, 1);
      return rv;
    }

  CI_LogEntry("C_VerifyRecover", "calling token method", rv, 1);

  CK_I_CALL_TOKEN_METHOD(rv, VerifyRecover, (session_data, pSignature, ulSignatureLen, pData, pulDataLen));

  CI_LogEntry("C_VerifyRecover", "...complete", rv, 1);

  return rv;
}
/* }}} */

/*
 * Local variables:
 * folded-file: t
 * end:
 */
