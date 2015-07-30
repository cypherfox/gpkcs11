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
 * NAME:        encrypt.c
 * SYNOPSIS:    -
 * DESCRIPTION: -
 * FILES:       -
 * SEE/ALSO:    -
 * AUTHOR:      lbe
 * BUGS: *      -
 * HISTORY:     $Log$
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
 * HISTORY:     Revision 1.7  1999/01/19 12:19:39  lbe
 * HISTORY:     first release lockdown
 * HISTORY:
 * HISTORY:     Revision 1.6  1998/12/07 13:19:57  lbe
 * HISTORY:     TC_free von parametern für Zeile und Datei befreit.
 * HISTORY:
 * HISTORY:     Revision 1.5  1998/11/13 10:10:21  lbe
 * HISTORY:     added persistent storage.
 * HISTORY:
 * HISTORY:     Revision 1.4  1998/10/12 10:00:11  lbe
 * HISTORY:     clampdown
 * HISTORY:
 * HISTORY:     Revision 1.3  1998/08/05 08:57:18  lbe
 * HISTORY:     *** empty log message ***
 * HISTORY:
 * HISTORY:     Revision 1.2  1998/07/23 15:18:06  lbe
 * HISTORY:     working
 * HISTORY:
 * HISTORY:     Revision 1.1  1998/07/02 17:13:03  lbe
 * HISTORY:     Initial revision
 * HISTORY:
 */
 
static char RCSID[]="$Id$";
const char* Version_encrypt_c(){return RCSID;}

#ifndef CK_I_library_build
#define CK_I_library_build
#endif

#include "internal.h"
#include "error.h"
#include "objects.h"

/* {{{ C_EncryptInit */
CK_DEFINE_FUNCTION(CK_RV, C_EncryptInit)(
        CK_SESSION_HANDLE hSession,
        CK_MECHANISM_PTR pMechanism,
        CK_OBJECT_HANDLE hKey
      )
{
  CK_RV rv = CKR_OK;
  CK_I_OBJ_PTR key_obj = NULL_PTR;  /* key to be used */
  CK_I_SESSION_DATA_PTR session_data = NULL_PTR;

  CI_VarLogEntry("C_EncryptInit", "starting... Session: %i, Key: %i", rv, 1, 
		 hSession,hKey);
  
#ifndef NO_LOGGING
  {
    CK_CHAR_PTR tmp = NULL;
    CI_CodeFktEntry("C_EncryptInit", "%i,%s,%i", 
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
      CI_LogEntry("C_EncryptInit", "library initialization", rv, 1);
      return rv;
    }

  /* get session info and make sure that this session exists */
  rv = CI_ReturnSession(hSession, &session_data);
  if(rv != CKR_OK)
    {
      CI_VarLogEntry("C_EncryptInit", "retrieve session data (hSession: %lu)", rv, 1,
                     hSession);
      return rv;
    }
 
  /* Is there an active encryption? */
  if(session_data->encrypt_state != NULL_PTR)
    {
      rv = CKR_OPERATION_ACTIVE;
      CI_LogEntry("C_EncryptInit", "check for active encryption", rv, 1);
      return rv;
    }


  rv = CI_ReturnObj(session_data,hKey, &key_obj);
  if(rv != CKR_OK)
    {
      CI_VarLogEntry("C_EncryptInit", "retrieve object (hSession: %lu, hKey: %lu)", rv, 1,
		     hSession, hKey);
      return rv;
    }

  /* Does the key allow encryption? */
  /*
   * no need to check if mechanism allows encryption. 
   * Only those that allow encryption are implemented below 
   */
  if((CI_ObjLookup(key_obj,CK_IA_ENCRYPT) == NULL_PTR) ||
     (*((CK_BBOOL CK_PTR)CI_ObjLookup(key_obj,CK_IA_ENCRYPT)->pValue) != TRUE))
    {
      rv = CKR_KEY_TYPE_INCONSISTENT;
      CI_LogEntry("C_EncryptInit", "test key encrypt attribute", rv, 1);
      return rv;
    }

  /* TODO: check read-only constraints */

  /* All Checked. Set encryption object */
  CK_I_CALL_TOKEN_METHOD(rv, EncryptInit, (session_data, pMechanism, key_obj));
  
  CI_LogEntry("C_EncryptInit", "...complete", rv, 1);

  return rv;
}
/* }}} */
/* {{{ C_Encrypt */
CK_DEFINE_FUNCTION(CK_RV, C_Encrypt)(
        CK_SESSION_HANDLE hSession,            /* session's handle */
        CK_BYTE_PTR       pData,               /* the plaintext data */
        CK_ULONG          ulDataLen,           /* bytes of plaintext */
        CK_BYTE_PTR       pEncryptedData,      /* gets ciphertext */
        CK_ULONG_PTR      pulEncryptedDataLen  /* gets c-text size */
      )
{
  CK_RV rv = CKR_OK;
  CK_I_SESSION_DATA_PTR session_data = NULL_PTR;

  CI_VarLogEntry("C_Encrypt", "starting... Session: %i", rv, 1, hSession);


#ifndef NO_LOGGING
  {
    CK_CHAR_PTR tmp = NULL;
    CI_CodeFktEntry("C_Encrypt", "%i,%s,%i,%p,%p", 
		  hSession,
		  tmp = CI_ScanableByteStream(pData, ulDataLen),
		  ulDataLen,
		  pEncryptedData,
		  pulEncryptedDataLen);
    TC_free(tmp);
  }
#endif // NO_LOGGING

  CI_VarLogEntry("C_Encrypt", "*pulEncryptedDataLen: %i", rv, 1, *pulEncryptedDataLen);


  /* make sure we are initialized */
  if (!(CK_I_global_flags & CK_IGF_INITIALIZED)) 
    return CKR_CRYPTOKI_NOT_INITIALIZED;

  /* get session info and make sure that this session exists */
  rv = CI_ReturnSession(hSession, &session_data);
  if(rv != CKR_OK)
    {
      CI_VarLogEntry("C_Encrypt", "retrieve session data (hSession: %lu)", rv, 1,
                     hSession);
      return rv;
    }
 
  /* Is there an active encryption at all? */
  if(session_data->encrypt_state == NULL_PTR)
    {
      rv = CKR_OPERATION_NOT_INITIALIZED;
      CI_LogEntry("C_Encrypt", "check operation status", rv, 1);
      return rv;
    }

  CK_I_CALL_TOKEN_METHOD(rv, Encrypt, (session_data, pData, ulDataLen, pEncryptedData, pulEncryptedDataLen));

  CI_LogEntry("C_Encrypt", "...complete", rv, 1);

  return rv;
}
/* }}} */
/* {{{ C_EncryptUpdate */
CK_DEFINE_FUNCTION(CK_RV, C_EncryptUpdate)(
        CK_SESSION_HANDLE hSession,
        CK_BYTE_PTR pPart,
        CK_ULONG ulPartLen,
        CK_BYTE_PTR pEncryptedPart,
        CK_ULONG_PTR pulEncryptedPartLen
      )
{
  CK_RV rv = CKR_OK;
  CK_I_SESSION_DATA_PTR session_data = NULL_PTR;

  CI_VarLogEntry("C_EncryptUpdate", "starting... Session: %i", rv, 1, hSession);

#ifndef NO_LOGGING
  {
    CK_CHAR_PTR tmp = NULL;
    CI_CodeFktEntry("C_EncryptUpdate", "%i,%s,%i,%p,%p", 
		  hSession,
		  tmp = CI_ScanableByteStream(pPart, ulPartLen),
		  ulPartLen,
		  pEncryptedPart,
		  pulEncryptedPartLen);
    TC_free(tmp);
  }
#endif // NO_LOGGING

  CI_VarLogEntry("C_EncryptUpdate", "*pulEncryptedPartLen: %i", rv, 1,
		 *pulEncryptedPartLen);

  /* make sure we are initialized */
  if (!(CK_I_global_flags & CK_IGF_INITIALIZED)) 
    return CKR_CRYPTOKI_NOT_INITIALIZED;

  /* get session info and make sure that this session exists */
  rv = CI_ReturnSession(hSession, &session_data);
  if(rv != CKR_OK)
    {
      CI_VarLogEntry("C_EncryptUpdate", "retrieve session data (hSession: %lu)", rv, 1,
                     hSession);
      return rv;
    }

  /* Is there an active encryption at all? */
  if(session_data->encrypt_state == NULL_PTR)
    {
      rv = CKR_OPERATION_NOT_INITIALIZED;
      CI_LogEntry("C_EncryptUpdate", "check operation status", rv, 1);
      return rv;
    }

  CK_I_CALL_TOKEN_METHOD(rv, EncryptUpdate, (session_data, pPart, ulPartLen, pEncryptedPart, pulEncryptedPartLen));

  CI_LogEntry("C_EncryptUpdate", "...complete", rv, 1);

  return rv;
}
/* }}} */
/* {{{ C_EncryptFinal */
CK_DEFINE_FUNCTION(CK_RV, C_EncryptFinal)(
        CK_SESSION_HANDLE hSession,
        CK_BYTE_PTR pLastEncryptedPart,
        CK_ULONG_PTR pulLastEncryptedPartLen
      )
{
  CK_RV rv =CKR_OK;
  CK_I_SESSION_DATA_PTR session_data = NULL_PTR;

  CI_VarLogEntry("C_EncryptFinal", "starting... Session: %i", rv, 1, hSession);
  CI_CodeFktEntry("C_EncryptUpdate", "%i,%p,%p", 
		  hSession,
		  pLastEncryptedPart,
		  pulLastEncryptedPartLen);
  
  CI_VarLogEntry("C_EncryptFinal", "*pulLastEncryptedPartLen: %i", rv, 1,
		 *pulLastEncryptedPartLen);

  /* make sure we are initialized */
  if (!(CK_I_global_flags & CK_IGF_INITIALIZED)) 
    return CKR_CRYPTOKI_NOT_INITIALIZED;

  /* get session info and make sure that this session exists */
  rv = CI_ReturnSession(hSession, &session_data);
  if(rv != CKR_OK)
    {
      CI_VarLogEntry("C_EncryptFinal", "retrieve session data (hSession: %lu)", rv, 1,
                     hSession);
      return rv;
    }

  /* Is there an active encryption at all? */
  if(session_data->encrypt_state == NULL_PTR)
    {
      rv = CKR_OPERATION_NOT_INITIALIZED;
      CI_LogEntry("C_EncryptFinal", "check operation status", rv, 1);
      return rv;
    }

  CK_I_CALL_TOKEN_METHOD(rv, EncryptFinal, (session_data, pLastEncryptedPart, pulLastEncryptedPartLen));

  CI_LogEntry("C_EncryptFinal", "...complete", rv, 1);

  return rv;
}
/* }}} */
/*
 * Local variables:
 * folded-file: t
 * end:
 */

