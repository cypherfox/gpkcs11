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
 * NAME:        sign.c
 * SYNOPSIS:    -
 * DESCRIPTION: -
 * FILES:       -
 * SEE/ALSO:    -
 * AUTHOR:      lbe
 * BUGS: *      -
 * HISTORY:     $Log$
 * HISTORY:     Revision 1.5  2000/09/19 09:14:55  lbe
 * HISTORY:     write flag for pin change onto SC, support Auth Pin path
 * HISTORY:
 * HISTORY:     Revision 1.4  2000/01/31 18:09:03  lbe
 * HISTORY:     lockdown prior to win_gdbm change
 * HISTORY:
 * HISTORY:     Revision 1.3  1999/11/02 13:47:19  lbe
 * HISTORY:     change of structures and bug fix in slot.c, add more files for tcsc_token: emptyfuncs and general_data
 * HISTORY:
 * HISTORY:     Revision 1.2  1999/10/06 07:57:23  lbe
 * HISTORY:     solved netscape symbol clash problem
 * HISTORY:
 * HISTORY:     Revision 1.1  1999/06/16 09:46:11  lbe
 * HISTORY:     reorder files
 * HISTORY:
 * HISTORY:     Revision 1.7  1999/01/19 12:19:46  lbe
 * HISTORY:     first release lockdown
 * HISTORY:
 * HISTORY:     Revision 1.6  1998/12/07 13:20:28  lbe
 * HISTORY:     TC_free von parametern für Zeile und Datei befreit.
 * HISTORY:
 * HISTORY:     Revision 1.5  1998/11/13 10:10:09  lbe
 * HISTORY:     added persistent storage.
 * HISTORY:
 * HISTORY:     Revision 1.4  1998/10/12 10:00:12  lbe
 * HISTORY:     clampdown
 * HISTORY:
 * HISTORY:     Revision 1.3  1998/08/05 09:00:24  lbe
 * HISTORY:     *** empty log message ***
 * HISTORY:
 * HISTORY:     Revision 1.2  1998/07/23 15:18:18  lbe
 * HISTORY:     working
 * HISTORY:
 * HISTORY:     Revision 1.1  1998/07/02 17:25:25  lbe
 * HISTORY:     Initial revision
 * HISTORY:
 */
 
static char RCSID[]="$Id$";
const char* Version_sign_c(){return RCSID;}

#ifndef CK_I_library_build
#define CK_I_library_build
#endif

#include "internal.h"
#include "error.h"
#include "objects.h"

#include <stdlib.h>

/* {{{ C_SignInit */
CK_DEFINE_FUNCTION(CK_RV, C_SignInit)(
        CK_SESSION_HANDLE hSession,
        CK_MECHANISM_PTR pMechanism,
        CK_OBJECT_HANDLE hKey
      )
{
  CK_RV rv = CKR_OK;
  CK_I_OBJ_PTR key_obj = NULL_PTR;  /* key to be used */
  CK_I_SESSION_DATA_PTR session_data = NULL_PTR;
  CK_BYTE_PTR tmp = NULL_PTR;
  
  CI_LogEntry("C_SignInit", "starting...",rv,1);
  CI_CodeFktEntry("C_SignInit", "%i,%s,%i", 
		  hSession,
		  tmp = CI_ScanableMechanism(pMechanism),
		  hKey);
  TC_free(tmp);

  /* make sure we are initialized */
  if (!(CK_I_global_flags & CK_IGF_INITIALIZED)) 
    {
      rv = CKR_CRYPTOKI_NOT_INITIALIZED;
      CI_LogEntry("C_SignInit", "library status", rv, 1);
      return rv;
    }

  /* get session info and make sure that this session exists */
   rv = CI_ReturnSession(hSession, &session_data);
  if(rv != CKR_OK)
    {
      CI_VarLogEntry("C_SignInit", "retrieve session data (hSession: %lu)", rv, 1,
                     hSession);
      return rv;
    }
 
  /* Is there an active signing? */
  if(session_data->sign_state != NULL_PTR)
    {
      rv = CKR_OPERATION_ACTIVE;
      CI_LogEntry("C_SignInit", "check for active session", rv, 1);
      return rv;
    }

  rv = CI_ReturnObj(session_data,hKey, &key_obj);
  if(rv != CKR_OK)
    {
      CI_VarLogEntry("C_SignInit", "retrieve object list (hSession: %lu, hKey: %lu)", rv, 1,
                     hSession, hKey);
      return rv;
    }
 
  /* Does the key allow signing? */
  /*
   * no need to check if mechanism allows signing. 
   * Only those that allow signing are implemented below 
   * TODO: check wether the default is sign or no sign
   */
  if((CI_ObjLookup(key_obj,CK_IA_SIGN) != NULL_PTR) && 
     (*((CK_BBOOL CK_PTR)CI_ObjLookup(key_obj,CK_IA_SIGN)->pValue) != TRUE))
    {
      rv = CKR_KEY_TYPE_INCONSISTENT;
      CI_LogEntry("C_SignInit", "checking sign flag", rv, 1);
      return rv;
    }
  
  CK_I_CALL_TOKEN_METHOD(rv, SignInit, (session_data, pMechanism, key_obj));
  
  CI_LogEntry("C_SignInit", "...complete", rv, 1);

  return rv;
}
/* }}} */
/* {{{ C_Sign */
CK_DEFINE_FUNCTION(CK_RV, C_Sign)(
        CK_SESSION_HANDLE hSession,            /* session's handle */
        CK_BYTE_PTR       pData,               /* gets plaintext */
        CK_ULONG          ulDataLen,           /* gets p-text size */
        CK_BYTE_PTR       pSignature,          /* the Signature */
        CK_ULONG_PTR      pulSignatureLen      /* bytes of Signature */
      )
{
  CK_RV rv = CKR_OK;
  CK_I_SESSION_DATA_PTR session_data = NULL_PTR;
  CK_BYTE_PTR tmp = NULL_PTR;
  
  CI_VarLogEntry("C_Sign", "starting... Session: %i", rv, 1,hSession);
  CI_CodeFktEntry("C_Sign", "%i,%s,%i,%p,%p", 
		  hSession,
		  tmp = CI_ScanableByteStream(pData, ulDataLen),
		  ulDataLen,
		  pSignature,
		  pulSignatureLen);
  TC_free(tmp);
  if(pSignature != NULL_PTR)
    CI_VarLogEntry("C_Sign", "*pulSignatureLen: %i", rv, 1, *pulSignatureLen);

  /* make sure we are initialized */
  if (!(CK_I_global_flags & CK_IGF_INITIALIZED)) 
    return CKR_CRYPTOKI_NOT_INITIALIZED;

  /* get session info and make sure that this session exists */
  rv = CI_ReturnSession(hSession, &session_data);
  if(rv != CKR_OK)
    {
      CI_VarLogEntry("C_Sign", "retrieve session data (hSession: %lu)", rv, 1,
                     hSession);
      return rv;
    }

  /* Is there an active signing at all? */
  if(session_data->sign_state == NULL_PTR)
    {
      rv = CKR_OPERATION_NOT_INITIALIZED;
      CI_LogEntry("C_Sign", "checking operation status", rv, 0);
      return rv;
    }
  
  CK_I_CALL_TOKEN_METHOD(rv, Sign, (session_data, pData, ulDataLen, pSignature, pulSignatureLen));

  CI_LogEntry("C_Sign", "...complete", rv, 1);

  return rv;
}
/* }}} */
/* {{{ C_SignUpdate */
CK_DEFINE_FUNCTION(CK_RV, C_SignUpdate)(
        CK_SESSION_HANDLE hSession,  /* the session's handle */
        CK_BYTE_PTR pPart,           /* the data to sign */
        CK_ULONG ulPartLen           /* count of bytes to sign */
      )
{
  CK_RV rv = CKR_OK;
  CK_I_SESSION_DATA_PTR session_data = NULL_PTR;
  CK_BYTE_PTR tmp = NULL_PTR;

  CI_LogEntry("C_SignUpdate", "starting...", rv, 1);
  CI_CodeFktEntry("C_SignUpdate", "%i,%s,%i", 
		  hSession,
		  tmp = CI_ScanableByteStream(pPart, ulPartLen),
		  ulPartLen);
  TC_free(tmp);

  /* make sure we are initialized */
  if (!(CK_I_global_flags & CK_IGF_INITIALIZED)) 
    return CKR_CRYPTOKI_NOT_INITIALIZED;

  /* get session info and make sure that this session exists */
  rv = CI_ReturnSession(hSession, &session_data);
  if(rv != CKR_OK)
    {
      CI_VarLogEntry("C_SignUpdate", "retrieve session data (hSession: %lu)", rv, 1,
                     hSession);
      return rv;
    }

  /* Is there an active signing at all? */
  if(session_data->sign_state == NULL_PTR)
    {
      rv = CKR_OPERATION_NOT_INITIALIZED;
      CI_LogEntry("C_SignUpdate", "checking operation status", rv, 0); 
      return rv;
    }

  CK_I_CALL_TOKEN_METHOD(rv, SignUpdate, (session_data, pPart, ulPartLen));

  CI_LogEntry("C_SignUpdate", "...complete", rv, 1);

  return rv;
}
/* }}} */
/* {{{ C_SignFinal */
CK_DEFINE_FUNCTION(CK_RV, C_SignFinal)(
        CK_SESSION_HANDLE hSession,
        CK_BYTE_PTR pSignature,
        CK_ULONG_PTR pulSignatureLen
      )
{
  CK_RV rv = CKR_OK;
  CK_I_SESSION_DATA_PTR session_data = NULL_PTR;

  CI_LogEntry("C_SignFinal", "starting...", rv, 1);
  CI_CodeFktEntry("C_SignFinal", "%i,%p,%p", 
		  hSession,
		  pSignature,
		  pulSignatureLen);
  CI_VarLogEntry("C_SignFinal", "*pulSignatureLen: %i", rv, 1, *pulSignatureLen);

  /* make sure we are initialized */
  if (!(CK_I_global_flags & CK_IGF_INITIALIZED)) 
    return CKR_CRYPTOKI_NOT_INITIALIZED;

  /* get session info and make sure that this session exists */
  rv = CI_ReturnSession(hSession, &session_data);
  if(rv != CKR_OK)
    {
      CI_VarLogEntry("C_SignFinal", "retrieve session data (hSession: %lu)", rv, 1,
                     hSession);
      return rv;
    }
 
  CI_VarLogEntry("C_SignFinal", "using object with mem-handle %x", rv, 1,
		 session_data);

  /* Is there an active signing at all? */
  if(session_data->sign_state == NULL_PTR)
    {
      rv = CKR_OPERATION_NOT_INITIALIZED;
      CI_LogEntry("C_SignFinal", "check operation status", rv, 1);
      return rv;
    }

  CK_I_CALL_TOKEN_METHOD(rv, SignFinal, (session_data, pSignature, pulSignatureLen));

  if(session_data->sign_state != NULL_PTR)
    CI_LogEntry("C_SignFinal", "sign state not cleared!", rv, 1);

  CI_LogEntry("C_SignFinal", "...complete", rv, 1);

  return rv;
}
/* }}} */
/* {{{ C_SignRecoverInit */
/* C_SignRecoverInit initializes a signature operation, where
 * the data can be recovered from the signature. */
CK_DEFINE_FUNCTION(CK_RV, C_SignRecoverInit)

(
  CK_SESSION_HANDLE hSession,   /* the session's handle */
  CK_MECHANISM_PTR  pMechanism, /* the signature mechanism */
  CK_OBJECT_HANDLE  hKey        /* handle of the signature key */
)
{
  CK_RV rv = CKR_OK;
  CK_I_OBJ_PTR key_obj = NULL_PTR;  /* key to be used */
  CK_I_SESSION_DATA_PTR session_data = NULL_PTR;
  CK_BYTE_PTR tmp = NULL_PTR;

  CI_LogEntry("C_SignRecoverInit", "starting", rv, 1);
  CI_CodeFktEntry("C_SignRecoverInit", "%i,%s,%i", 
		  hSession,
		  tmp = CI_ScanableMechanism(pMechanism),
		  hKey);
  TC_free(tmp);

  /* make sure we are initialized */
  if (!(CK_I_global_flags & CK_IGF_INITIALIZED)) 
    return CKR_CRYPTOKI_NOT_INITIALIZED;

  /* get session info and make sure that this session exists */
  rv = CI_ReturnSession(hSession, &session_data);
  if(rv != CKR_OK)
    {
      CI_VarLogEntry("C_SignRecoverInit", "retrieve session data (hSession: %lu)", rv, 1,
                     hSession);
      return rv;
    }
 
  /* Is there an active signing? */
  if(session_data->sign_state != NULL_PTR)
    {
      rv = CKR_OPERATION_ACTIVE;
      CI_LogEntry("C_SignRecoverInit", "checking operation status", rv, 0);
      return rv;
    }

  rv = CI_ReturnObj(session_data,hKey, &key_obj);
  if(rv != CKR_OK)
    {
      CI_VarLogEntry("C_SignRecoverInit", "retrieve object list (hSession: %lu, hKey: %lu)", rv, 1,
                     hSession, hKey);
      return rv;
    }
  
 
  /* Does the key allow sign-recovery? */
  /*
   * no need to check if mechanism allows signing. 
   * Only those that allow signing are implemented below 
   * TODO: check the default for flag
   */
  if((CI_ObjLookup(key_obj,CK_IA_SIGN_RECOVER) != NULL_PTR) &&
     (*((CK_BBOOL CK_PTR)CI_ObjLookup(key_obj,CK_IA_SIGN_RECOVER)->pValue) != TRUE))
    {
      rv = CKR_KEY_TYPE_INCONSISTENT;
      CI_LogEntry("C_SignRecoverInit", "checking sign-recover flag", rv, 1);
      return rv;
    }
  
  CK_I_CALL_TOKEN_METHOD(rv, SignRecoverInit, (session_data, pMechanism, key_obj));
  
  CI_LogEntry("C_SignRecoverInit", "...complete", rv, 1); 

  return rv;
}
/* }}} */
/* {{{ C_SignRecover */
/* C_SignRecover signs data in a single operation, where the
 * data can be recovered from the signature. */
CK_DEFINE_FUNCTION(CK_RV, C_SignRecover)

(
  CK_SESSION_HANDLE hSession,        /* the session's handle */
  CK_BYTE_PTR       pData,           /* the data to sign */
  CK_ULONG          ulDataLen,       /* count of bytes to sign */
  CK_BYTE_PTR       pSignature,      /* gets the signature */
  CK_ULONG_PTR      pulSignatureLen  /* gets signature length */
)
{
  CK_RV rv = CKR_OK;
  CK_I_SESSION_DATA_PTR session_data = NULL_PTR;
  CK_BYTE_PTR tmp = NULL_PTR;

  CI_LogEntry("C_SignRecover", "starting...", rv, 1);
  CI_CodeFktEntry("C_SignRecover", "%i,%s,%i,%p,%p", 
		  hSession,
		  tmp = CI_ScanableByteStream(pData, ulDataLen),
		  ulDataLen,
		  pSignature,
		  pulSignatureLen);
  CI_VarLogEntry("C_SignRecover", "*pulSignatureLen: %i", rv, 1, *pulSignatureLen);
  TC_free(tmp);
  
  /* make sure we are initialized */
  if (!(CK_I_global_flags & CK_IGF_INITIALIZED)) 
    return CKR_CRYPTOKI_NOT_INITIALIZED;

  /* get session info and make sure that this session exists */
  rv = CI_ReturnSession(hSession, &session_data);
  if(rv != CKR_OK)
    {
      CI_VarLogEntry("C_SignRecover", "retrieve session data (hSession: %lu)", rv, 1,
                     hSession);
      return rv;
    }
 
  /* Is there an active signing at all? */
  if(session_data->sign_state == NULL_PTR)
    {
      rv = CKR_OPERATION_NOT_INITIALIZED;
      CI_LogEntry("C_SignRecover", "checking operation status", rv, 1);
      return rv;
    }

  CK_I_CALL_TOKEN_METHOD(rv, SignRecover, (session_data, pData, ulDataLen, pSignature, pulSignatureLen));

  CI_LogEntry("C_SignRecover", "complete", rv, 1);

  return rv;
}
/* }}} */

/*
 * Local variables:
 * folded-file: t
 * end:
 */
