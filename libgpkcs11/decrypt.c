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
 * NAME:        decrypt.c
 * SYNOPSIS:    -
 * DESCRIPTION: -
 * FILES:       -
 * SEE/ALSO:    -
 * AUTHOR:      lbe
 * BUGS: *      -
 * HISTORY:     $Log$
 * HISTORY:     Revision 1.5  2000/03/08 09:59:07  lbe
 * HISTORY:     fix SIGBUS in cryptdb, improve readeability for C_FindObject log output
 * HISTORY:
 * HISTORY:     Revision 1.4  2000/01/31 18:09:02  lbe
 * HISTORY:     lockdown prior to win_gdbm change
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
 * HISTORY:     Revision 1.7  1999/01/19 12:19:38  lbe
 * HISTORY:     first release lockdown
 * HISTORY:
 * HISTORY:     Revision 1.6  1998/11/13 10:10:24  lbe
 * HISTORY:     added persistent storage.
 * HISTORY:
 * HISTORY:     Revision 1.5  1998/10/12 10:00:12  lbe
 * HISTORY:     clampdown
 * HISTORY:
 * HISTORY:     Revision 1.4  1998/08/05 08:55:02  lbe
 * HISTORY:     *** empty log message ***
 * HISTORY:
 * HISTORY:     Revision 1.3  1998/07/30 15:29:35  lbe
 * HISTORY:     Win32 Port
 * HISTORY:
 * HISTORY:     Revision 1.2  1998/07/23 15:18:03  lbe
 * HISTORY:     working
 * HISTORY:
 * HISTORY:     Revision 1.1  1998/07/02 17:08:42  lbe
 * HISTORY:     Initial revision
 * HISTORY:
 */
 
static char RCSID[]="$Id$";
const char* Version_decrypt_c(){return RCSID;}

#ifndef CK_I_library_build
#define CK_I_library_build
#endif

#include "internal.h"
#include "error.h"
#include "objects.h"

#include <stdlib.h>

/* {{{ C_DecryptInit */
CK_DEFINE_FUNCTION(CK_RV, C_DecryptInit)(
        CK_SESSION_HANDLE hSession,
        CK_MECHANISM_PTR pMechanism,
        CK_OBJECT_HANDLE hKey
      )
{
  CK_RV rv = CKR_OK;
  CK_I_OBJ_PTR key_obj = NULL_PTR;  /* key to be used */
  CK_I_SESSION_DATA_PTR session_data = NULL_PTR;

  CI_VarLogEntry("C_DecryptInit", "starting...Session: %i", rv, 0, hSession);	  
  CI_CodeFktEntry("C_DecryptInit", "%i,%s,%i", 
		  hSession,
		  CI_ScanableMechanism(pMechanism),
		  hKey);

  /* make sure we are initialized */
  if (!(CK_I_global_flags & CK_IGF_INITIALIZED)) 
    return CKR_CRYPTOKI_NOT_INITIALIZED;

  /* get session info and make sure that this session exists */
  rv = CI_ReturnSession(hSession, &session_data);
  if(rv != CKR_OK)
    {
      CI_VarLogEntry("C_DecryptInit", "retrieve session data (hSession: %lu)", rv, 1,
                     hSession);
      return rv;
    }

  CI_LogEntry("C_DecryptInit", "get here 1", rv, 0);	  
 
  /* Is there an active decryption? */
  if(session_data->decrypt_state != NULL_PTR)
    {
      rv = CKR_OPERATION_ACTIVE;
      CI_LogEntry("C_DecryptInit", "check operation status", rv , 0);	  
      return rv;
    }

  CI_LogEntry("C_DecryptInit", "get here 2", rv, 0);	  

  rv = CI_ReturnObj(session_data,hKey, &key_obj);
  if(rv != CKR_OK)
    {
      CI_VarLogEntry("C_DecryptInit", "retrieve object (hSession: %lu, hKey: %lu)", rv, 1,
                     hSession, hKey);
      return rv;
    }

  CI_LogEntry("C_DecryptInit", "get here 3", rv, 0);	  

  /* Does the key allow decryption? */
  /*
   * no need to check if mechanism allows decryption. 
   * Only those that allow decryption are implemented below 
   */
  if((CI_ObjLookup(key_obj,CK_IA_DECRYPT) == NULL_PTR)||
     (*((CK_BBOOL CK_PTR)CI_ObjLookup(key_obj,CK_IA_DECRYPT)->pValue) != TRUE))
    {
      rv = CKR_KEY_TYPE_INCONSISTENT;
      CI_LogEntry("C_DecryptInit", "ensure that key supports decrypt", rv , 0);	        
      return rv;
    }

  CI_LogEntry("C_DecryptInit", "get here 4", rv, 0);	  


  /* TODO: check read-only constraints */

  /* All Checked. Set decryption object */

  CK_I_CALL_TOKEN_METHOD(rv, DecryptInit, (session_data, pMechanism, key_obj));

  CI_LogEntry("C_DecryptInit", "...complete", rv , 1);	  

  return rv;
}
/* }}} */
/* {{{ C_Decrypt */
CK_DEFINE_FUNCTION(CK_RV, C_Decrypt)(
        CK_SESSION_HANDLE hSession,            /* session's handle */
        CK_BYTE_PTR       pEncryptedData,      /* gets ciphertext */
        CK_ULONG          ulEncryptedDataLen,  /* gets c-text size */
        CK_BYTE_PTR       pData,               /* the plaintext data */
        CK_ULONG_PTR      pulDataLen           /* bytes of plaintext */
      )
{
  CK_RV rv = CKR_OK;
  CK_I_SESSION_DATA_PTR session_data = NULL_PTR;

  CI_VarLogEntry("C_Decrypt", "starting... Session: %i", rv , 0, hSession);  
  CI_CodeFktEntry("C_Decrypt", "%i,%s,%i,%p,%p", 
		  hSession,
		  pEncryptedData,
		  ulEncryptedDataLen,
		  pData,
		  pulDataLen);
  CI_VarLogEntry("C_Decrypt", "*pulDataLen: %i", rv , 0, *pulDataLen);  

  /* make sure we are initialized */
  if (!(CK_I_global_flags & CK_IGF_INITIALIZED)) 
    return CKR_CRYPTOKI_NOT_INITIALIZED;

  /* get session info and make sure that this session exists */
  rv = CI_ReturnSession(hSession, &session_data);
  if(rv != CKR_OK)
    {
      CI_VarLogEntry("C_Decrypt", "retrieve session data (hSession: %lu)", rv, 1,
                     hSession);
      return rv;
    }
 
  /* Is there an active decryption at all? */
  if(session_data->decrypt_state == NULL_PTR)
    {
      rv = CKR_OPERATION_NOT_INITIALIZED;
      CI_LogEntry("C_Decrypt", "check operation status", rv , 0);	  
      return rv;
    }

  CK_I_CALL_TOKEN_METHOD(rv, Decrypt, (session_data, pEncryptedData, ulEncryptedDataLen, pData, pulDataLen));

  CI_LogEntry("C_Decrypt", "...complete", rv , 0);	  

  return rv;
}
/* }}} */
/* {{{ C_DecryptUpdate */
CK_DEFINE_FUNCTION(CK_RV, C_DecryptUpdate)(
        CK_SESSION_HANDLE hSession,
        CK_BYTE_PTR pEncryptedPart,
        CK_ULONG ulEncryptedPartLen,
        CK_BYTE_PTR pPart,
        CK_ULONG_PTR pulPartLen
      )
{
  CK_RV rv = CKR_OK;
  CK_I_SESSION_DATA_PTR session_data = NULL_PTR;

  CI_VarLogEntry("C_DecryptUpdate", "starting... Session: %i", rv , 0, hSession);
  CI_CodeFktEntry("C_DecryptUpdate", "%i,%s,%i,%p,%p", 
		  hSession,
		  pEncryptedPart,
		  ulEncryptedPartLen,
		  pPart,
		  pulPartLen);
  CI_VarLogEntry("C_DecryptUpdate", "*pulPartLen: %i", rv , 0, *pulPartLen);

  /* make sure we are initialized */
  if (!(CK_I_global_flags & CK_IGF_INITIALIZED)) 
    return CKR_CRYPTOKI_NOT_INITIALIZED;

  /* get session info and make sure that this session exists */
  rv = CI_ReturnSession(hSession, &session_data);
  if(rv != CKR_OK)
    {
      CI_VarLogEntry("C_DecryptUpdate", "retrieve session data (hSession: %lu)", rv, 1,
                     hSession);
      return rv;
    }

  /* Is there an active decryption at all? */
  if(session_data->decrypt_state == NULL_PTR)
    {
      rv = CKR_OPERATION_NOT_INITIALIZED;
      CI_LogEntry("C_DecryptUpdate", "check operation status", rv , 0);	  
      return rv;
    }

  CK_I_CALL_TOKEN_METHOD(rv, DecryptUpdate, (session_data, pEncryptedPart, ulEncryptedPartLen, pPart, pulPartLen));

  CI_LogEntry("C_DecryptUpdate", "...complete", rv , 0);	  

  return rv;
}
/* }}} */
/* {{{ C_DecryptFinal */
CK_DEFINE_FUNCTION(CK_RV, C_DecryptFinal)(
        CK_SESSION_HANDLE hSession,
        CK_BYTE_PTR pLastPart,
        CK_ULONG_PTR pulLastPartLen
      )
{
  CK_RV rv = CKR_OK;
  CK_I_SESSION_DATA_PTR session_data = NULL_PTR;

  CI_VarLogEntry("C_DecryptFinal", "starting... Session: %i", rv , 0, hSession);
  CI_CodeFktEntry("C_DecryptFinal", "%i,%p,%p", 
		  hSession,
		  pLastPart,
		  pulLastPartLen);
  CI_VarLogEntry("C_DecryptFinal", "*pulLastPartLen: %i", rv , 0, *pulLastPartLen);

  /* make sure we are initialized */
  if (!(CK_I_global_flags & CK_IGF_INITIALIZED)) 
    return CKR_CRYPTOKI_NOT_INITIALIZED;

  /* get session info and make sure that this session exists */
  rv = CI_ReturnSession(hSession, &session_data);
  if(rv != CKR_OK)
    {
      CI_VarLogEntry("C_DecryptFinal", "retrieve session data (hSession: %lu)", rv, 1,
                     hSession);
      return rv;
    }
 
  /* Is there an active decryption at all? */
  if(session_data->decrypt_state == NULL_PTR)
    {
      rv = CKR_OPERATION_NOT_INITIALIZED;
      CI_LogEntry("C_DecryptFinal", "check operation status", rv , 0);	  
      return rv;
    }

  CK_I_CALL_TOKEN_METHOD(rv, DecryptFinal, (session_data, pLastPart, pulLastPartLen));

  CI_LogEntry("C_DecryptFinal", "...complete", rv , 0);	  

  return rv;
}
/* }}} */
/*
 * Local variables:
 * folded-file: t
 * end:
 */
