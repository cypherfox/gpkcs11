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
 * NAME:        pkcs11_logger.c
 * SYNOPSIS:    -
 * DESCRIPTION: Send the information for each call to the loging system
 * FILES:       -
 * SEE/ALSO:    -
 * AUTHOR:      lbe
 * BUGS: *      -
 * HISTORY:     $Log$
 * HISTORY:     Revision 1.6  2000/03/08 09:59:08  lbe
 * HISTORY:     fix SIGBUS in cryptdb, improve readeability for C_FindObject log output
 * HISTORY:
 * HISTORY:     Revision 1.5  2000/01/31 18:09:03  lbe
 * HISTORY:     lockdown prior to win_gdbm change
 * HISTORY:
 * HISTORY:     Revision 1.4  1999/11/25 16:46:51  lbe
 * HISTORY:     moved all lib version defines into the conf.h
 * HISTORY:
 * HISTORY:     Revision 1.3  1999/11/02 13:47:19  lbe
 * HISTORY:     change of structures and bug fix in slot.c, add more files for tcsc_token: emptyfuncs and general_data
 * HISTORY:
 * HISTORY:     Revision 1.2  1999/10/06 07:57:22  lbe
 * HISTORY:     solved netscape symbol clash problem
 * HISTORY:
 * HISTORY:     Revision 1.1  1999/06/16 09:46:10  lbe
 * HISTORY:     reorder files
 * HISTORY:
 * HISTORY:     Revision 1.5  1999/06/04 14:58:35  lbe
 * HISTORY:     change to libtool/automake complete (except for __umoddi prob)
 * HISTORY:
 * HISTORY:     Revision 1.4  1999/03/01 14:36:44  lbe
 * HISTORY:     merged changes from the weekend
 * HISTORY:
 * HISTORY:     Revision 1.3  1999/01/19 12:19:44  lbe
 * HISTORY:     first release lockdown
 * HISTORY:
 * HISTORY:     Revision 1.2  1998/12/07 13:20:20  lbe
 * HISTORY:     TC_free von parametern für Zeile und Datei befreit.
 * HISTORY:
 * HISTORY:     Revision 1.1  1998/11/04 17:28:02  lbe
 * HISTORY:     debug-lockdown
 * HISTORY:
 */
 
static char RCSID[]="$Id$";
const char* Version_pkcs11_logger_c(){return RCSID;}

#ifndef CK_I_library_build
#define CK_I_library_build
#endif

#include <stdio.h>

#include "pkcs11_logger.h"
#include "internal.h"
#include "error.h"

#ifdef CK_Win32
# include <windows.h>
# include <winuser.h>
#elif CK_GENERIC
# include <dlfcn.h>
# include <unistd.h>
#endif /* !CK_Win32 */


#ifdef HAVE_PURIFY
#include <purify.h>
#endif

#if defined(CK_Win32)
# define DLL_NAME "C:\\Programme\\Netscape\\Communicator\\Program\\ISCsign.dll"
#else
# if defined(CK_GENERIC)
#  define DLL_NAME "/lhome/lbe/netscape_install/pkcs11/"
# else
#  error no DLL name defined for this architecure
# endif
#endif

CK_I_EXT_FUNCTION_LIST CK_I_ext_functions;

CK_FUNCTION_LIST_PTR pkcs11_fkt_list = NULL_PTR;

#define DO_FKT( _name , _params )           \
 do                                         \
  {                                         \
  if( (rv = pkcs11_fkt_list->_name  _params ) != CKR_OK)      \
    {                                       \
      CI_LogEntry(#_name, "call to true function failed", rv, 0);    \
      exit(1);                               \
    } }while(0)
 

/* {{{ PlC_GetFunctionList */
CK_FUNCTION_LIST ck_function_list;
 
CK_DEFINE_FUNCTION(CK_RV, C_GetFunctionList)(
 CK_FUNCTION_LIST_PTR_PTR ppFunctionList
 )
{
#ifdef CK_Win32
  MessageBox(NULL, "logger called", "TC PKCS#11",MB_OK|MB_ICONWARNING);
#endif /* CK_Win32 */

  return PlC_GetFunctionList(ppFunctionList);
}

void set_function_list(CK_FUNCTION_LIST_PTR ck_function_list);

/* {{{ void set_function_list(CK_FUNCTION_LIST_PTR ck_function_list) */
void set_function_list(CK_FUNCTION_LIST_PTR ck_function_list)
{
  ck_function_list->version.major=         0;
  ck_function_list->version.minor=         1;
  ck_function_list->C_Initialize=          &PlC_Initialize;
  ck_function_list->C_Finalize=            &PlC_Finalize;
  ck_function_list->C_GetInfo=             &PlC_GetInfo;
  ck_function_list->C_GetFunctionList=     &PlC_GetFunctionList;
  ck_function_list->C_GetSlotList=         &PlC_GetSlotList;
  ck_function_list->C_GetSlotInfo=         &PlC_GetSlotInfo;
  ck_function_list->C_GetTokenInfo=        &PlC_GetTokenInfo;
  ck_function_list->C_GetMechanismList=    &PlC_GetMechanismList;
  ck_function_list->C_GetMechanismInfo=    &PlC_GetMechanismInfo;
  ck_function_list->C_InitToken=           &PlC_InitToken;
  ck_function_list->C_InitPIN=             &PlC_InitPIN;
  ck_function_list->C_SetPIN=              &PlC_SetPIN;
  ck_function_list->C_OpenSession=         &PlC_OpenSession;
  ck_function_list->C_CloseSession=        &PlC_CloseSession;
  ck_function_list->C_CloseAllSessions=    &PlC_CloseAllSessions;
  ck_function_list->C_GetSessionInfo=      &PlC_GetSessionInfo;
  ck_function_list->C_GetOperationState=   &PlC_GetOperationState;
  ck_function_list->C_SetOperationState=   &PlC_SetOperationState;
  ck_function_list->C_Login=               &PlC_Login;
  ck_function_list->C_Logout=              &PlC_Logout;
  ck_function_list->C_CreateObject=        &PlC_CreateObject;
  ck_function_list->C_CopyObject=          &PlC_CopyObject;
  ck_function_list->C_DestroyObject=       &PlC_DestroyObject;
  ck_function_list->C_GetObjectSize=       &PlC_GetObjectSize;
  ck_function_list->C_GetAttributeValue=   &PlC_GetAttributeValue;
  ck_function_list->C_SetAttributeValue=   &PlC_SetAttributeValue;
  ck_function_list->C_FindObjectsInit=     &PlC_FindObjectsInit;
  ck_function_list->C_FindObjects=         &PlC_FindObjects;
  ck_function_list->C_FindObjectsFinal=    &PlC_FindObjectsFinal;
  ck_function_list->C_EncryptInit=         &PlC_EncryptInit;
  ck_function_list->C_Encrypt=             &PlC_Encrypt;
  ck_function_list->C_EncryptUpdate=       &PlC_EncryptUpdate;
  ck_function_list->C_EncryptFinal=        &PlC_EncryptFinal;
  ck_function_list->C_DecryptInit=         &PlC_DecryptInit;
  ck_function_list->C_Decrypt=             &PlC_Decrypt;
  ck_function_list->C_DecryptUpdate=       &PlC_DecryptUpdate;
  ck_function_list->C_DecryptFinal=        &PlC_DecryptFinal;
  ck_function_list->C_DigestInit=          &PlC_DigestInit;
  ck_function_list->C_Digest=              &PlC_Digest;
  ck_function_list->C_DigestUpdate=        &PlC_DigestUpdate;
  ck_function_list->C_DigestKey=           &PlC_DigestKey;
  ck_function_list->C_DigestFinal=         &PlC_DigestFinal;
  ck_function_list->C_SignInit=            &PlC_SignInit;
  ck_function_list->C_Sign=                &PlC_Sign;
  ck_function_list->C_SignUpdate=          &PlC_SignUpdate;
  ck_function_list->C_SignFinal=           &PlC_SignFinal;
  ck_function_list->C_SignRecoverInit=     &PlC_SignRecoverInit;
  ck_function_list->C_SignRecover=         &PlC_SignRecover;
  ck_function_list->C_VerifyInit=          &PlC_VerifyInit;
  ck_function_list->C_Verify=              &PlC_Verify;
  ck_function_list->C_VerifyUpdate=        &PlC_VerifyUpdate;
  ck_function_list->C_VerifyFinal=         &PlC_VerifyFinal;
  ck_function_list->C_VerifyRecoverInit=   &PlC_VerifyRecoverInit;
  ck_function_list->C_VerifyRecover=       &PlC_VerifyRecover;
  ck_function_list->C_DigestEncryptUpdate= &PlC_DigestEncryptUpdate;
  ck_function_list->C_DecryptDigestUpdate= &PlC_DecryptDigestUpdate;
  ck_function_list->C_SignEncryptUpdate=   &PlC_SignEncryptUpdate;
  ck_function_list->C_DecryptVerifyUpdate= &PlC_DecryptVerifyUpdate;
  ck_function_list->C_GenerateKey=         &PlC_GenerateKey;
  ck_function_list->C_GenerateKeyPair=     &PlC_GenerateKeyPair;
  ck_function_list->C_WrapKey=             &PlC_WrapKey;
  ck_function_list->C_UnwrapKey=           &PlC_UnwrapKey;
  ck_function_list->C_DeriveKey=           &PlC_DeriveKey;
  ck_function_list->C_SeedRandom=          &PlC_SeedRandom;
  ck_function_list->C_GenerateRandom=      &PlC_GenerateRandom;
  ck_function_list->C_GetFunctionStatus=   &PlC_GetFunctionStatus;
  ck_function_list->C_CancelFunction=      &PlC_CancelFunction;
  ck_function_list->C_WaitForSlotEvent=    &PlC_WaitForSlotEvent;
}
/* }}} */

CK_DEFINE_FUNCTION(CK_RV, PlC_GetFunctionList)(
 CK_FUNCTION_LIST_PTR_PTR ppFunctionList
 )
{
  char *reason = NULL_PTR;
  void* dll_handle = NULL_PTR;
  CK_C_GetFunctionList gfl_handle = NULL_PTR;
  CK_RV rv = CKR_OK;
  static CK_FUNCTION_LIST log_fkt_list;

  CI_LogEntry("C_GetFunctionList", "starting...", rv, 1); 
  CI_CodeFktEntry("C_GetFunctionList", "%p", 
                  ppFunctionList);

 
# if defined(CK_GENERIC)
  /* open library */
  if((dll_handle = dlopen(DLL_NAME, RTLD_LAZY|RTLD_GLOBAL))== NULL_PTR)
    {
      reason = dlerror();
      
      CI_VarLogEntry("PlC_GetFunctionList", "Opening Dynamic Library '%s' failed: %s\n", 
		     rv, 0, DLL_NAME, reason);
      return rv;      
    }
 
  /* get fkt-pointer table */
  gfl_handle= ( CK_C_GetFunctionList )(dlsym(dll_handle, "C_GetFunctionList"));
  if(gfl_handle == NULL_PTR)
    exit(1);
# endif
 
# if defined(CK_Win32)
 
      if((dll_handle = LoadLibrary(DLL_NAME)) == NULL_PTR)
        {
          char buff[1024];
          rv = CKR_GENERAL_ERROR;
 
          FormatMessage( FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
                         NULL, GetLastError(),
                         MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // Default language
                         (LPTSTR) &reason,
                         0, NULL);

          sprintf(buff, "Opening Dynamic Library '%s' failed: %s (PATH: %s)", 
		  DLL_NAME,reason,getenv("PATH"));
	  
	  MessageBox(NULL, buff, "TC PKCS#11",MB_OK|MB_ICONWARNING);

          LocalFree(reason);
        }
  
  /* get fkt-pointer table */
  gfl_handle= ( CK_C_GetFunctionList )(GetProcAddress(dll_handle, "C_GetFunctionList"));
  if(gfl_handle == NULL_PTR)
    exit(1);
 
# endif /* CK_Win32 */
 
  gfl_handle(&pkcs11_fkt_list);

  /* prepare to return the list for these functions to the caller */
  *ppFunctionList = &log_fkt_list;
  set_function_list(&log_fkt_list);

  CI_LogEntry("C_GetFunctionList", "...complete", rv, 1); 

  return rv;
}
/* }}} */

/* {{{ PlC_Initialize */
CK_DEFINE_FUNCTION(CK_RV, PlC_Initialize)(
 CK_VOID_PTR pInitArgs
)
{
  CK_RV rv = CKR_OK;

  CI_LogEntry("C_Initialize", "starting...", rv, 1);
  CI_CodeFktEntry("C_Initialize", "%p", 
		  pInitArgs);

  DO_FKT( C_Initialize, (pInitArgs));

  CI_LogEntry("C_Initialize", "...complete", rv, 1);
  return rv;
}
/* }}} */
/* {{{ PlC_Finalize */
/* PlC_Finalize indicates that an application is done with the
 * Cryptoki library. */
CK_DEFINE_FUNCTION(CK_RV, PlC_Finalize)(
        CK_VOID_PTR pReserved
)
{
  CK_RV rv = CKR_OK;

  CI_LogEntry("C_Finalize", "starting...", rv, 1);

  DO_FKT( C_Finalize, (pReserved));

  CI_LogEntry("C_Finalize", "...complete", rv, 1);
  return rv;
}
/* }}} */
/* {{{ PlC_InitToken */
CK_DEFINE_FUNCTION(CK_RV, PlC_InitToken)
(
  CK_SLOT_ID     slotID,    /* ID of the token's slot */
  CK_CHAR_PTR    pPin,      /* the SO's initial PIN */
  CK_ULONG       ulPinLen,  /* length in bytes of the PIN */
  CK_CHAR_PTR    pLabel     /* 32-byte token label (blank padded) */
)
{
  CK_RV rv = CKR_OK;

  CI_LogEntry("C_InitToken", "starting...", rv, 1);

  DO_FKT( C_InitToken, (slotID, pPin, ulPinLen, pLabel));

  CI_LogEntry("C_InitToken", "...complete", rv, 1);
  
  return rv;
}

/* }}} */
/* {{{ PlC_DecryptInit */
CK_DEFINE_FUNCTION(CK_RV, PlC_DecryptInit)(
        CK_SESSION_HANDLE hSession,
        CK_MECHANISM_PTR pMechanism,
        CK_OBJECT_HANDLE hKey
      )
{
  CK_RV rv = CKR_OK;

  CI_VarLogEntry("C_DecryptInit", "starting...Session: %i", rv, 0, hSession);	  
  CI_CodeFktEntry("C_DecryptInit", "%i,%s,%i", 
		  hSession,
		  CI_ScanableMechanism(pMechanism),
		  hKey);

  DO_FKT( C_DecryptInit, (hSession, pMechanism, hKey));

  CI_LogEntry("C_DecryptInit", "...complete", rv , 1);	  

  return rv;
}
/* }}} */
/* {{{ PlC_Decrypt */
CK_DEFINE_FUNCTION(CK_RV, PlC_Decrypt)(
        CK_SESSION_HANDLE hSession,            /* session's handle */
        CK_BYTE_PTR       pEncryptedData,      /* gets ciphertext */
        CK_ULONG          ulEncryptedDataLen,  /* gets c-text size */
        CK_BYTE_PTR       pData,               /* the plaintext data */
        CK_ULONG_PTR      pulDataLen           /* bytes of plaintext */
      )
{
  CK_RV rv = CKR_OK;

  CI_VarLogEntry("C_Decrypt", "starting... Session: %i", rv , 0, hSession);  
  CI_CodeFktEntry("C_Decrypt", "%i,%s,%i,%p,%p", 
		  hSession,
		  pEncryptedData,
		  ulEncryptedDataLen,
		  pData,
		  pulDataLen);
  CI_VarLogEntry("C_Decrypt", "*pulDataLen: %i", rv , 0, *pulDataLen);  

  DO_FKT( C_Decrypt, (hSession, pEncryptedData, ulEncryptedDataLen, pData, pulDataLen));

  CI_LogEntry("C_Decrypt", "...complete", rv , 0);	  

  return rv;
}
/* }}} */
/* {{{ PlC_DecryptUpdate */
CK_DEFINE_FUNCTION(CK_RV, PlC_DecryptUpdate)(
        CK_SESSION_HANDLE hSession,
        CK_BYTE_PTR pEncryptedPart,
        CK_ULONG ulEncryptedPartLen,
        CK_BYTE_PTR pPart,
        CK_ULONG_PTR pulPartLen
      )
{
  CK_RV rv = CKR_OK;

  CI_VarLogEntry("C_DecryptUpdate", "starting... Session: %i", rv , 0, hSession);
  CI_CodeFktEntry("C_DecryptUpdate", "%i,%s,%i,%p,%p", 
		  hSession,
		  pEncryptedPart,
		  ulEncryptedPartLen,
		  pPart,
		  pulPartLen);
  CI_VarLogEntry("C_DecryptUpdate", "*pulPartLen: %i", rv , 0, *pulPartLen);

  DO_FKT( C_DecryptUpdate, (hSession, pEncryptedPart, ulEncryptedPartLen, pPart, pulPartLen));

  CI_LogEntry("C_DecryptUpdate", "...complete", rv , 0);	  

  return rv;
}
/* }}} */
/* {{{ PlC_DecryptFinal */
CK_DEFINE_FUNCTION(CK_RV, PlC_DecryptFinal)(
        CK_SESSION_HANDLE hSession,
        CK_BYTE_PTR pLastPart,
        CK_ULONG_PTR pulLastPartLen
      )
{
  CK_RV rv = CKR_OK;

  CI_VarLogEntry("C_DecryptFinal", "starting... Session: %i", rv , 0, hSession);
  CI_CodeFktEntry("C_DecryptFinal", "%i,%p,%p", 
		  hSession,
		  pLastPart,
		  pulLastPartLen);
  CI_VarLogEntry("C_DecryptFinal", "*pulLastPartLen: %i", rv , 0, *pulLastPartLen);

  DO_FKT( C_DecryptFinal, (hSession, pLastPart, pulLastPartLen));

  CI_LogEntry("C_DecryptFinal", "...complete", rv , 0);	  

  return rv;
}
/* }}} */
/* {{{ PlC_DigestInit */
CK_DEFINE_FUNCTION(CK_RV, PlC_DigestInit)(
      CK_SESSION_HANDLE hSession,
      CK_MECHANISM_PTR pMechanism
      )
{
  CK_RV rv = CKR_OK;

  CI_VarLogEntry("C_DigestInit", "starting...Session:%i", rv, 1,hSession);
  CI_CodeFktEntry("C_DigestInit", "%i,%s", 
		  hSession,
		  CI_ScanableMechanism(pMechanism));

  DO_FKT( C_DigestInit, (hSession, pMechanism));
  
  CI_LogEntry("C_DigestInit", "...complete", rv, 1);

  return rv;
}
/* }}} */
/* {{{ PlC_Digest */
CK_DEFINE_FUNCTION(CK_RV, PlC_Digest)(
        CK_SESSION_HANDLE hSession,
        CK_BYTE_PTR pData,
        CK_ULONG ulDataLen,
        CK_BYTE_PTR pDigest,
        CK_ULONG_PTR pulDigestLen
      )
{
  CK_RV rv = CKR_OK;
  
  CI_LogEntry("C_Digest", "starting...", rv, 1);
  CI_CodeFktEntry("C_Digest", "%i,%s,%i,%p,%p", 
		  hSession,
		  CI_ScanableByteStream(pData,ulDataLen),
		  ulDataLen,
		  pDigest,
		  pulDigestLen);
  CI_VarLogEntry("C_Digest", "*pulDigestLen: %i", rv, 1,*pulDigestLen);

  DO_FKT( C_Digest, (hSession, pData, ulDataLen, pDigest, pulDigestLen));

  CI_LogEntry("C_Digest", "...complete", rv, 1);

  return rv;
}
/* }}} */
/* {{{ PlC_DigestUpdate */
CK_DEFINE_FUNCTION(CK_RV, PlC_DigestUpdate)(
        CK_SESSION_HANDLE hSession,
        CK_BYTE_PTR pPart,
        CK_ULONG ulPartLen
      )
{
  CK_RV rv = CKR_OK;

  CI_LogEntry("C_DigestUpdate", "starting...", rv, 1);
  CI_CodeFktEntry("C_DigestUpdate", "%i,%s,%i", 
		  hSession,
		  CI_ScanableByteStream(pPart,ulPartLen),
		  ulPartLen);

  DO_FKT( C_DigestUpdate, (hSession, pPart, ulPartLen));

  CI_LogEntry("C_DigestUpdate", "...complete", rv, 1);

  return rv;
}
/* }}} */
/* {{{ PlC_DigestKey */
/* PlC_DigestKey continues a multi-part message-digesting
 * operation, by digesting the value of a secret key as part of
 * the data already digested. */
CK_DEFINE_FUNCTION(CK_RV, PlC_DigestKey)
(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_OBJECT_HANDLE  hKey       /* secret key to digest */
)
{
  CK_RV rv = CKR_OK;

  CI_LogEntry("C_DigestKey", "starting...", rv, 1);
  CI_CodeFktEntry("C_DigestKey", "%i,%i", 
		  hSession,
		  hKey);

  DO_FKT( C_DigestKey, (hSession, hKey));

  CI_LogEntry("C_DigestKey", "...complete", rv, 1);

  return rv;
}
/* }}} */
/* {{{ PlC_DigestFinal */
CK_DEFINE_FUNCTION(CK_RV, PlC_DigestFinal)(
        CK_SESSION_HANDLE hSession,
        CK_BYTE_PTR pDigest,
        CK_ULONG_PTR pulDigestLen
      )
{
  CK_RV rv = CKR_OK;

  CI_LogEntry("C_DigestFinal", "starting...", rv, 1);
  CI_CodeFktEntry("C_DigestFinal", "%i,%p,%p", 
		  hSession,
		  pDigest,
		  pulDigestLen);
  CI_VarLogEntry("C_DigestFinal", "*pulDigestLen: %i", rv, 1,*pulDigestLen);

  DO_FKT( C_DigestFinal, (hSession, pDigest, pulDigestLen));

  CI_LogEntry("C_DigestFinal", "...complete", rv, 1);

  return rv;
}
/* }}} */
/* {{{ PlC_DigestEncryptUpdate */
/* PlC_DigestEncryptUpdate continues a multiple-part digesting
 * and encryption operation. */
CK_DEFINE_FUNCTION(CK_RV, PlC_DigestEncryptUpdate)
(
  CK_SESSION_HANDLE hSession,            /* session's handle */
  CK_BYTE_PTR       pPart,               /* the plaintext data */
  CK_ULONG          ulPartLen,           /* plaintext length */
  CK_BYTE_PTR       pEncryptedPart,      /* gets ciphertext */
  CK_ULONG_PTR      pulEncryptedPartLen  /* gets c-text length */
)
{
  CK_RV rv;
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

  DO_FKT( C_DigestEncryptUpdate, (hSession, pPart, ulPartLen, pEncryptedPart, pulEncryptedPartLen));

  CI_LogEntry("C_DigestEncryptUpdate", "...complete", rv, 1);

  return rv;
}
/* }}} */
/* {{{ PlC_DecryptDigestUpdate */
/* PlC_DecryptDigestUpdate continues a multiple-part decryption and
 * digesting operation. */
CK_DEFINE_FUNCTION(CK_RV, PlC_DecryptDigestUpdate)

(
  CK_SESSION_HANDLE hSession,            /* session's handle */
  CK_BYTE_PTR       pEncryptedPart,      /* ciphertext */
  CK_ULONG          ulEncryptedPartLen,  /* ciphertext length */
  CK_BYTE_PTR       pPart,               /* gets plaintext */
  CK_ULONG_PTR      pulPartLen           /* gets plaintext len */
)
{
  CK_RV rv;
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

  DO_FKT( C_DecryptDigestUpdate, (hSession, pEncryptedPart, ulEncryptedPartLen, pPart, pulPartLen));

  CI_LogEntry("C_DecryptDigestUpdate", "...complete", rv, 1);

  return rv;
}
/* }}} */
/* {{{ PlC_SignEncryptUpdate */
/* PlC_SignEncryptUpdate continues a multiple-part signing and
 * encryption operation. */
CK_DEFINE_FUNCTION(CK_RV, PlC_SignEncryptUpdate)

(
  CK_SESSION_HANDLE hSession,            /* session's handle */
  CK_BYTE_PTR       pPart,               /* the plaintext data */
  CK_ULONG          ulPartLen,           /* plaintext length */
  CK_BYTE_PTR       pEncryptedPart,      /* gets ciphertext */
  CK_ULONG_PTR      pulEncryptedPartLen  /* gets c-text length */
)
{
  CK_RV rv;
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

  DO_FKT( C_SignEncryptUpdate, (hSession, pPart, ulPartLen, pEncryptedPart, pulEncryptedPartLen));

  CI_LogEntry("C_SignEncryptUpdate", "...complete", rv, 1);

  return rv;
}
 /* }}} */
/* {{{ PlC_DecryptVerifyUpdate */
 /* PlC_DecryptVerifyUpdate continues a multiple-part decryption and
 * verify operation. */
CK_DEFINE_FUNCTION(CK_RV, PlC_DecryptVerifyUpdate)
(
  CK_SESSION_HANDLE hSession,            /* session's handle */
  CK_BYTE_PTR       pEncryptedPart,      /* ciphertext */
  CK_ULONG          ulEncryptedPartLen,  /* ciphertext length */
  CK_BYTE_PTR       pPart,               /* gets plaintext */
  CK_ULONG_PTR      pulPartLen           /* gets p-text length */
)
{
  CK_RV rv;
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

  DO_FKT( C_DecryptVerifyUpdate, (hSession, pEncryptedPart, ulEncryptedPartLen, pPart, pulPartLen));

  CI_LogEntry("C_DecryptVerifyUpdate", "...complete", rv, 1);

  return rv;
}
/* }}} */
/* {{{ PlC_EncryptInit */
CK_DEFINE_FUNCTION(CK_RV, PlC_EncryptInit)(
        CK_SESSION_HANDLE hSession,
        CK_MECHANISM_PTR pMechanism,
        CK_OBJECT_HANDLE hKey
      )
{
  CK_RV rv = CKR_OK;
  CK_BYTE_PTR tmp = NULL_PTR;

  CI_VarLogEntry("C_EncryptInit", "starting... Session: %i, Key: %i", rv, 1, 
		 hSession,hKey);
  CI_CodeFktEntry("C_EncryptInit", "%i,%s,%i", 
		  hSession,
		  tmp = CI_ScanableMechanism(pMechanism),
		  hKey);
  TC_free(tmp);

  DO_FKT( C_EncryptInit, (hSession, pMechanism, hKey));
  
  CI_LogEntry("C_EncryptInit", "...complete", rv, 1);

  return rv;
}
/* }}} */
/* {{{ PlC_Encrypt */
CK_DEFINE_FUNCTION(CK_RV, PlC_Encrypt)(
        CK_SESSION_HANDLE hSession,            /* session's handle */
        CK_BYTE_PTR       pData,               /* the plaintext data */
        CK_ULONG          ulDataLen,           /* bytes of plaintext */
        CK_BYTE_PTR       pEncryptedData,      /* gets ciphertext */
        CK_ULONG_PTR      pulEncryptedDataLen  /* gets c-text size */
      )
{
  CK_RV rv = CKR_OK;
  CK_BYTE_PTR tmp = NULL_PTR;

  CI_VarLogEntry("C_Encrypt", "starting... Session: %i", rv, 1, hSession);
  CI_CodeFktEntry("C_Encrypt", "%i,%s,%i,%p,%p", 
		  hSession,
		  tmp = CI_ScanableByteStream(pData, ulDataLen),
		  ulDataLen,
		  pEncryptedData,
		  pulEncryptedDataLen);
  CI_VarLogEntry("C_Encrypt", "*pulEncryptedDataLen: %i", rv, 1, *pulEncryptedDataLen);
  TC_free(tmp);

  DO_FKT( C_Encrypt, (hSession, pData, ulDataLen, pEncryptedData, pulEncryptedDataLen));

  CI_LogEntry("C_Encrypt", "...complete", rv, 1);

  return rv;
}
/* }}} */
/* {{{ PlC_EncryptUpdate */
CK_DEFINE_FUNCTION(CK_RV, PlC_EncryptUpdate)(
        CK_SESSION_HANDLE hSession,
        CK_BYTE_PTR pPart,
        CK_ULONG ulPartLen,
        CK_BYTE_PTR pEncryptedPart,
        CK_ULONG_PTR pulEncryptedPartLen
      )
{
  CK_RV rv = CKR_OK;
  CK_BYTE_PTR tmp = NULL_PTR;

  CI_VarLogEntry("C_EncryptUpdate", "starting... Session: %i", rv, 1, hSession);
  CI_CodeFktEntry("C_EncryptUpdate", "%i,%s,%i,%p,%p", 
		  hSession,
		  tmp = CI_ScanableByteStream(pPart, ulPartLen),
		  ulPartLen,
		  pEncryptedPart,
		  pulEncryptedPartLen);
  CI_VarLogEntry("C_EncryptUpdate", "*pulEncryptedPartLen: %i", rv, 1,
		 *pulEncryptedPartLen);
  TC_free(tmp);

  DO_FKT( C_EncryptUpdate, (hSession, pPart, ulPartLen, pEncryptedPart, pulEncryptedPartLen));

  CI_LogEntry("C_EncryptUpdate", "...complete", rv, 1);

  return rv;
}
/* }}} */
/* {{{ PlC_EncryptFinal */
CK_DEFINE_FUNCTION(CK_RV, PlC_EncryptFinal)(
        CK_SESSION_HANDLE hSession,
        CK_BYTE_PTR pLastEncryptedPart,
        CK_ULONG_PTR pulLastEncryptedPartLen
      )
{
  CK_RV rv =CKR_OK;

  CI_VarLogEntry("C_EncryptFinal", "starting... Session: %i", rv, 1, hSession);
  CI_CodeFktEntry("C_EncryptUpdate", "%i,%p,%p", 
		  hSession,
		  pLastEncryptedPart,
		  pulLastEncryptedPartLen);
  CI_VarLogEntry("C_EncryptFinal", "*pulLastEncryptedPartLen: %i", rv, 1,
		 *pulLastEncryptedPartLen);

  DO_FKT( C_EncryptFinal, (hSession, pLastEncryptedPart, pulLastEncryptedPartLen));

  CI_LogEntry("C_EncryptFinal", "...complete", rv, 1);

  return rv;
}
/* }}} */
/* {{{ PlC_GetInfo */
CK_DEFINE_FUNCTION(CK_RV, PlC_GetInfo)(
 CK_INFO_PTR pInfo
)
{
  CK_RV rv = CKR_OK;

  CI_LogEntry("C_GetInfo", "starting...", rv, 1);
  CI_CodeFktEntry("C_GetInfo", "%p", 
                  pInfo);

  DO_FKT( C_GetInfo, (pInfo));

  CI_LogEntry("C_GetInfo", "...complete", rv, 1);

  return rv;
}
/* }}} */
/* {{{ PlC_GenerateKey */
CK_DEFINE_FUNCTION(CK_RV, PlC_GenerateKey)(
        CK_SESSION_HANDLE hSession,
        CK_MECHANISM_PTR pMechanism,
        CK_ATTRIBUTE_PTR pTemplate,
        CK_ULONG ulCount,
        CK_OBJECT_HANDLE_PTR phKey
      )
{
  CK_RV rv = CKR_OK;
  CK_BYTE_PTR tmp1 = NULL_PTR,tmp2 = NULL_PTR;

  CI_LogEntry("C_GenerateKey", "starting...", rv, 1);
  CI_CodeFktEntry("C_GenerateKey", "%i,%s,%s,%i,%p", 
                  hSession,
                  tmp1 = CI_ScanableMechanism(pMechanism),
		  tmp2 = CI_PrintTemplate(pTemplate,ulCount),
		  ulCount,
		  phKey);

  TC_free(tmp1);
  TC_free(tmp2);
  
  DO_FKT( C_GenerateKey, (hSession, pMechanism, pTemplate, ulCount, phKey));

  CI_VarLogEntry("C_GenerateKey", "new key object: %i", rv, 1,*phKey);
  CI_LogEntry("C_GenerateKey", "...complete", rv, 1);

  return rv;
}
/* }}} */
/* {{{ PlC_GenerateKeyPair */
CK_DEFINE_FUNCTION(CK_RV, PlC_GenerateKeyPair)(
        CK_SESSION_HANDLE hSession,
        CK_MECHANISM_PTR pMechanism,
        CK_ATTRIBUTE_PTR pPublicKeyTemplate,
        CK_ULONG ulPublicKeyAttributeCount,
        CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
        CK_ULONG ulPrivateKeyAttributeCount,
        CK_OBJECT_HANDLE_PTR phPublicKey,
        CK_OBJECT_HANDLE_PTR phPrivateKey
	)
{
  CK_RV rv = CKR_OK;
  CK_CHAR_PTR tmp1, tmp2, tmp3;
  
  CI_LogEntry("C_GenerateKeyPair", "starting...", rv, 1);
  CI_CodeFktEntry("C_GenerateKeyPair", "%i,%s,%s,%i,%s,%i,%p,%p", 
                  hSession,
                  tmp1 = CI_ScanableMechanism(pMechanism),
		  tmp2 = CI_PrintTemplate(pPublicKeyTemplate,ulPublicKeyAttributeCount),
		  ulPublicKeyAttributeCount,
		  tmp3 = CI_PrintTemplate(pPrivateKeyTemplate,ulPrivateKeyAttributeCount),
		  ulPrivateKeyAttributeCount,
		  phPublicKey,
		  phPrivateKey);
  TC_free(tmp1);
  TC_free(tmp2);
  TC_free(tmp3);

  DO_FKT( C_GenerateKeyPair, (hSession, pMechanism, 
			      pPublicKeyTemplate, ulPublicKeyAttributeCount, 
			      pPrivateKeyTemplate, ulPrivateKeyAttributeCount, 
			      phPublicKey, phPrivateKey));

  CI_LogEntry("C_GenerateKeyPair", "...complete", rv, 1);

  return rv;
}
/* }}} */
/* {{{ PlC_WrapKey */
CK_DEFINE_FUNCTION(CK_RV, PlC_WrapKey)
(
  CK_SESSION_HANDLE hSession,        /* the session's handle */
  CK_MECHANISM_PTR  pMechanism,      /* the wrapping mechanism */
  CK_OBJECT_HANDLE  hWrappingKey,    /* wrapping key */
  CK_OBJECT_HANDLE  hKey,            /* key to be wrapped */
  CK_BYTE_PTR       pWrappedKey,     /* gets wrapped key */
  CK_ULONG_PTR      pulWrappedKeyLen /* gets wrapped key size */
)
{
  CK_RV rv = CKR_OK;
  CK_BYTE_PTR tmp = NULL_PTR;

  CI_LogEntry("C_WrapKey", "starting...", rv, 1);
  CI_CodeFktEntry("C_WrapKey", "%i,%s,%i,%i,%p,%p", 
                  hSession,
		  tmp = CI_ScanableMechanism(pMechanism),
		  hWrappingKey,
		  hKey,
		  pWrappedKey,
		  pulWrappedKeyLen);
  TC_free(tmp);

  CI_VarLogEntry("C_WrapKey", "*pulWrappedKeyLen: %i", rv, 1, *pulWrappedKeyLen);
		  
  DO_FKT( C_WrapKey, (hSession, pMechanism, hWrappingKey, hKey, pWrappedKey, pulWrappedKeyLen));

  CI_LogEntry("C_WrapKey", "...complete", rv, 1);

  return rv;
}
/* }}} */
/* {{{ PlC_UnwrapKey */
/* PlC_UnwrapKey unwraps (decrypts) a wrapped key, creating a new
 * key object. */
CK_DEFINE_FUNCTION(CK_RV, PlC_UnwrapKey)
(
  CK_SESSION_HANDLE    hSession,          /* session's handle */
  CK_MECHANISM_PTR     pMechanism,        /* unwrapping mech. */
  CK_OBJECT_HANDLE     hUnwrappingKey,    /* unwrapping key */
  CK_BYTE_PTR          pWrappedKey,       /* the wrapped key */
  CK_ULONG             ulWrappedKeyLen,   /* wrapped key len */
  CK_ATTRIBUTE_PTR     pTemplate,         /* new key template */
  CK_ULONG             ulAttributeCount,  /* template length */
  CK_OBJECT_HANDLE_PTR phKey              /* gets new handle */
)
{
  CK_RV rv = CKR_OK;
  CK_CHAR_PTR tmp1, tmp2, tmp3;

  CI_LogEntry("C_UnwrapKey", "starting...", rv, 1);
  CI_CodeFktEntry("C_UnwrapKey", "%i,%s,%i,%s,%i,%s,%i,%p", 
                  hSession,
                  tmp1 = CI_ScanableMechanism(pMechanism),
		  hUnwrappingKey,
		  tmp2 = CI_ScanableByteStream(pWrappedKey,ulWrappedKeyLen),
		  ulWrappedKeyLen,
		  tmp3 = CI_PrintTemplate(pTemplate,ulAttributeCount),
		  ulAttributeCount,
		  phKey);
  TC_free(tmp1);
  TC_free(tmp2);
  TC_free(tmp3);
  
  DO_FKT( C_UnwrapKey, (hSession, pMechanism, hUnwrappingKey, 
			pWrappedKey, ulWrappedKeyLen, 
			pTemplate, ulAttributeCount, 
			phKey));

  CI_LogEntry("C_UnwrapKey", "...complete", rv, 1);

  return rv;
}
/* }}} */
/* {{{ PlC_DeriveKey */
/* PlC_DeriveKey derives a key from a base key, creating a new key
 * object. */
CK_DEFINE_FUNCTION(CK_RV, PlC_DeriveKey)
(
  CK_SESSION_HANDLE    hSession,          /* session's handle */
  CK_MECHANISM_PTR     pMechanism,        /* key deriv. mech. */
  CK_OBJECT_HANDLE     hBaseKey,          /* base key */
  CK_ATTRIBUTE_PTR     pTemplate,         /* new key template */
  CK_ULONG             ulAttributeCount,  /* template length */
  CK_OBJECT_HANDLE_PTR phKey              /* gets new handle */
)
{
  CK_RV rv = CKR_OK;
  CK_BYTE_PTR tmp1 = NULL_PTR;
  CK_BYTE_PTR tmp2 = NULL_PTR;

  CI_LogEntry("C_DeriveKey", "starting...", rv, 1);
  CI_CodeFktEntry("C_DeriveKey", "%i,%s,%i,%s,%i,%p", 
                  hSession,
                  tmp1 = CI_ScanableMechanism(pMechanism),
		  hBaseKey,
		  tmp2 = CI_PrintTemplate(pTemplate,ulAttributeCount),
		  ulAttributeCount,
		  phKey);

  TC_free(tmp1);
  TC_free(tmp2);
  
  DO_FKT( C_DeriveKey, (hSession, pMechanism, hBaseKey, pTemplate, ulAttributeCount, phKey));

  CI_LogEntry("C_DeriveKey", "...complete", rv, 1);

  return rv;
}
/* }}} */
/* {{{ PlC_CreateObject */
CK_DEFINE_FUNCTION(CK_RV, PlC_CreateObject)(
        CK_SESSION_HANDLE hSession,
        CK_ATTRIBUTE_PTR pTemplate,
        CK_ULONG ulCount,
        CK_OBJECT_HANDLE_PTR phObject
      )
{
  CK_RV rv = CKR_OK;
  CK_BYTE_PTR tmp_str = NULL_PTR;

  CI_LogEntry("C_CreateObject", "starting...", rv, 1);
  CI_CodeFktEntry("C_CreateObject", "%lu,%s,%lu,%p", 
                  hSession,
		  tmp_str = CI_PrintTemplate(pTemplate,ulCount),
		  ulCount,
		  phObject);

  if(tmp_str)TC_free(tmp_str);

  DO_FKT( C_CreateObject, (hSession, pTemplate, ulCount, phObject));

  CI_VarLogEntry("C_CreateObject", 
		 "Object Handle: %lu ...complete", 
		 rv, 1, *phObject);

  return rv;
}
/* }}} */
/* {{{ PlC_DestroyObject */
CK_DEFINE_FUNCTION(CK_RV, PlC_DestroyObject)(
        CK_SESSION_HANDLE hSession,
        CK_OBJECT_HANDLE hObject
      )
{
  CK_RV rv = CKR_OK;

  CI_LogEntry("C_DestroyObject", "starting...", rv , 1);	  
  CI_CodeFktEntry("C_DestroyObject", "%u,%u", 
                  hSession,
		  hObject);

  DO_FKT( C_DestroyObject, (hSession, hObject));

  CI_LogEntry("C_DestroyObject", "...complete", rv , 1);	  

  return rv;
}
/* }}} */
/* {{{ PlC_CopyObject */
CK_DEFINE_FUNCTION(CK_RV, PlC_CopyObject)(
        CK_SESSION_HANDLE hSession,
        CK_OBJECT_HANDLE hObject,
        CK_ATTRIBUTE_PTR pTemplate,
        CK_ULONG ulCount,
        CK_OBJECT_HANDLE_PTR phNewObject
      )
{
  CK_RV rv = CKR_OK;
  CK_BYTE_PTR tmp_str = NULL_PTR;

  CI_LogEntry("C_CopyObject", "starting...", rv , 1);
  CI_CodeFktEntry("C_CopyObject", "%lu,%lu,%s,%lu,%p", 
                  hSession,
		  hObject,
		  tmp_str = CI_PrintTemplate(pTemplate,ulCount),
		  ulCount,
		  phNewObject);

  TC_free(tmp_str);

  DO_FKT( C_CopyObject, (hSession, hObject, pTemplate, ulCount, phNewObject));

  CI_LogEntry("C_CopyObject", "...complete", rv , 1);	  

  return CKR_OK;
}
/* }}} */
/* {{{ PlC_GetAttributeValue */
CK_DEFINE_FUNCTION(CK_RV, PlC_GetAttributeValue)(
        CK_SESSION_HANDLE hSession,
        CK_OBJECT_HANDLE hObject,
        CK_ATTRIBUTE_PTR pTemplate,
        CK_ULONG ulCount
      )
{
  CK_RV rv = CKR_OK;
  CK_BYTE_PTR tmp_str = NULL_PTR;

  CI_LogEntry("C_GetAttributeValue", "starting...", rv , 1);	  
  CI_CodeFktEntry("C_GetAttributeValue", "%lu,%lu,%s,%lu", 
                  hSession,
		  hObject,
		  tmp_str = CI_PrintTemplate(pTemplate, ulCount),
		  ulCount);

  TC_free(tmp_str);

  DO_FKT( C_GetAttributeValue, (hSession, hObject, pTemplate, ulCount));
  
  CI_LogEntry("C_GetAttributeValue", "...complete", rv , 1);	  

  return rv;
}
/* }}} */
/* {{{ PlC_SetAttributeValue */
CK_DEFINE_FUNCTION(CK_RV, PlC_SetAttributeValue)(
        CK_SESSION_HANDLE hSession,
        CK_OBJECT_HANDLE hObject,
        CK_ATTRIBUTE_PTR pTemplate,
        CK_ULONG ulCount
	)
{
  CK_RV rv = CKR_OK;
  CK_BYTE_PTR tmp_str = NULL_PTR;
  
  CI_LogEntry("C_SetAttributeValue", "starting...", rv , 1);	  
  CI_CodeFktEntry("C_SetAttributeValue", "%lu,%lu,%s%,%lu", 
                  hSession,
		  hObject,
		  tmp_str = CI_PrintTemplate(pTemplate,ulCount),
		  ulCount);

  TC_free(tmp_str);

  DO_FKT( C_SetAttributeValue, (hSession, hObject, pTemplate, ulCount));

  CI_LogEntry("C_SetAttributeValue", "...complete", rv , 1);	  
  
  return rv;
  
}
/* }}} */
/* {{{ PlC_FindObjectsInit */
/* PlC_FindObjectsInit initializes a search for token and session
 * objects that match a template. */
CK_DEFINE_FUNCTION(CK_RV, PlC_FindObjectsInit)
     (
      CK_SESSION_HANDLE hSession,   /* the session's handle */
      CK_ATTRIBUTE_PTR  pTemplate,  /* attribute values to match */
      CK_ULONG          ulCount     /* attrs in search template */
      )
{
  CK_RV rv =CKR_OK;
  CK_BYTE_PTR tmp_str = NULL_PTR;

  CI_LogEntry("C_FindObjectsInit", "starting...", rv , 1);	  
  CI_CodeFktEntry("C_FindObjectsInit", "%lu,%s,%lu", 
                  hSession,
		  tmp_str = CI_PrintTemplate(pTemplate,ulCount),
		  ulCount);

  TC_free(tmp_str);

  DO_FKT( C_FindObjectsInit, (hSession, pTemplate, ulCount));

  CI_LogEntry("C_FindObjectsInit", "...complete", rv , 1);	  

  return CKR_OK;
}
/* }}} */
/* {{{ PlC_FindObjects */
/* PlC_FindObjects continues a search for token and session
 * objects that match a template, obtaining additional object
 * handles. */
CK_DEFINE_FUNCTION(CK_RV, PlC_FindObjects)(
  CK_SESSION_HANDLE    hSession,          /* session's handle */
  CK_OBJECT_HANDLE_PTR phObject,          /* gets obj. handles */
  CK_ULONG             ulMaxObjectCount,  /* max handles to get */
  CK_ULONG_PTR         pulObjectCount     /* actual # returned */
)
{
  CK_RV rv = CKR_OK;

  CI_LogEntry("C_FindObjects", "starting...", rv , 1);	  
  CI_CodeFktEntry("C_FindObjects", "%lu,%p,%lu,%p", 
                  hSession,
		  phObject,
		  ulMaxObjectCount,
		  pulObjectCount);

  CI_VarLogEntry("C_FindObjects", "hSession: %lu", rv , 2, hSession);
  if(phObject == NULL_PTR) CI_LogEntry("C_FindObjects", "phObject == NULL_PTR", rv , 2);
  CI_VarLogEntry("C_FindObjects", "ulMaxObjectCount: %lu", rv , 2, ulMaxObjectCount);

  DO_FKT( C_FindObjects, (hSession, phObject, ulMaxObjectCount, pulObjectCount));

  CI_LogEntry("C_FindObjects", "...complete", rv , 1);	  

  return rv;
}
/* }}} */
/* {{{ PlC_FindObjectsFinal */
/* PlC_FindObjectsFinal finishes a search for token and session
 * objects. */
CK_DEFINE_FUNCTION(CK_RV, PlC_FindObjectsFinal)
(
  CK_SESSION_HANDLE hSession  /* the session's handle */
)
{
  CK_RV rv = CKR_OK;

  CI_LogEntry("C_FindObjectsFinal", "starting...", rv , 1);	  
  CI_CodeFktEntry("C_FindObjectsFinal", "%lu", 
                  hSession);

  DO_FKT( C_FindObjectsFinal, (hSession));

  CI_LogEntry("C_FindObjectsFinal", "...complete", rv , 0);	  

  return rv;
}
/* }}} */
/* {{{ PlC_GetObjectSize */
/* PlC_GetObjectSize gets the size of an object in bytes. */
CK_DEFINE_FUNCTION(CK_RV, PlC_GetObjectSize)
(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_OBJECT_HANDLE  hObject,   /* the object's handle */
  CK_ULONG_PTR      pulSize    /* receives size of object */
)
{
  CK_RV rv = CKR_OK;

  CI_LogEntry("C_GetObjectSize", "starting...", rv, 1);

  DO_FKT( C_GetObjectSize, (hSession, hObject, pulSize));

  CI_LogEntry("C_GetObjectSize", "...complete", rv, 1);
  return rv;
}
/* }}} */
/* {{{ PlC_GetFunctionStatus */
CK_DEFINE_FUNCTION(CK_RV, PlC_GetFunctionStatus)
(
  CK_SESSION_HANDLE hSession  /* the session's handle */
)
{
  CK_RV rv = CKR_OK;

  CI_LogEntry("C_GetFunctionStatus", "starting...", rv, 1);

  DO_FKT( C_GetFunctionStatus, (hSession));

  CI_LogEntry("C_GetFunctionStatus", "...complete", rv, 1);
  return rv;
}
/* }}} */
/* {{{ PlC_CancelFunction */
CK_DEFINE_FUNCTION(CK_RV, PlC_CancelFunction)
(
  CK_SESSION_HANDLE hSession  /* the session's handle */
)
{
  CK_RV rv = CKR_OK;

  CI_LogEntry("C_CancelFunction", "starting...", rv, 1);

  DO_FKT( C_CancelFunction, (hSession));

  CI_LogEntry("C_CancelFunction", "...complete", rv, 1);
  return rv;
}
/* }}} */
/* {{{ PlC_WaitForSlotEvent */
CK_DEFINE_FUNCTION(CK_RV, PlC_WaitForSlotEvent)
(
  CK_FLAGS flags,        /* blocking/nonblocking flag */
  CK_SLOT_ID_PTR pSlot,  /* location that receives the slot ID */
  CK_VOID_PTR pReserved   /* reserved.  Should be NULL_PTR */
)
{
  CK_RV rv = CKR_OK;

  CI_LogEntry("C_WaitForSlotEvent", "starting...", rv, 1);

  DO_FKT( C_WaitForSlotEvent, (flags, pSlot, pReserved));

  CI_LogEntry("C_WaitForSlotEvent", "...complete", rv, 1);
  return rv;
}
/* }}} */
/* {{{ PlC_SeedRandom */
CK_DEFINE_FUNCTION(CK_RV, PlC_SeedRandom)(
        CK_SESSION_HANDLE hSession,
        CK_BYTE_PTR pSeed,
        CK_ULONG ulSeedLen
      )
{
  CK_RV rv = CKR_OK;

  CI_LogEntry("C_SeedRandom", "starting...", rv, 1);

  DO_FKT( C_SeedRandom, (hSession, pSeed, ulSeedLen));

  CI_LogEntry("C_SeedRandom", "...complete", rv, 1);
  return rv; 
}
/* }}} */
/* {{{ PlC_GenerateRandom */
CK_DEFINE_FUNCTION(CK_RV, PlC_GenerateRandom)(
        CK_SESSION_HANDLE hSession,
        CK_BYTE_PTR pRandomData,
        CK_ULONG ulRandomLen
      )
{
  CK_RV rv = CKR_OK;

  CI_LogEntry("C_GenerateRandom", "starting...", rv, 1);

  DO_FKT( C_GenerateRandom, (hSession, pRandomData, ulRandomLen));

  CI_LogEntry("C_GenerateRandom", "...complete", rv, 1);

  return rv;
}
/* }}} */
/* {{{ PlC_OpenSession */
CK_DEFINE_FUNCTION(CK_RV, PlC_OpenSession)(
        CK_SLOT_ID slotID,
        CK_FLAGS flags,
        CK_VOID_PTR pApplication,
        CK_NOTIFY Notify,
        CK_SESSION_HANDLE_PTR phSession
      )
{
  CK_RV rv = CKR_OK;

  CI_LogEntry("C_OpenSession", "starting...", rv, 1);
  CI_CodeFktEntry("C_OpenSession", "%lu,%x,%p,%p,%p", 
                  slotID,
		  flags,
		  pApplication,
		  Notify,
		  phSession);

  DO_FKT( C_OpenSession, (slotID, flags, pApplication, Notify, phSession));

  CI_VarLogEntry("C_OpenSession", "for Session %lu...complete", rv, 1,*phSession);
  return rv;
}
/* }}} */
/* {{{ PlC_CloseSession */
CK_DEFINE_FUNCTION(CK_RV, PlC_CloseSession)(
        CK_SESSION_HANDLE hSession
      )
{
  CK_RV rv = CKR_OK;

  CI_VarLogEntry("C_CloseSession", "starting...Session: %lu", rv, 1,hSession);
  CI_CodeFktEntry("C_CloseSession", "%lu", 
                  hSession);

  DO_FKT( C_CloseSession, (hSession));

  CI_LogEntry("C_CloseSession", "...complete", rv, 1);

  return rv; 
}
/* }}} */
/* {{{ PlC_CloseAllSessions */
/* PlC_CloseAllSessions closes all sessions with a token. */
CK_DEFINE_FUNCTION(CK_RV, PlC_CloseAllSessions)
(
  CK_SLOT_ID     slotID  /* the token's slot */
)
{
  CK_RV rv= CKR_OK;

  CI_LogEntry("C_CloseAllSessions", "starting...", rv, 1);
  CI_CodeFktEntry("C_CloseAllSession", "%lu", 
                  slotID);

  DO_FKT( C_CloseAllSessions, (slotID));

  CI_LogEntry("C_CloseAllSessions", "...complete", rv, 1);

  return rv;
}
/* }}} */
/* {{{ PlC_GetSessionInfo */
CK_DEFINE_FUNCTION(CK_RV, PlC_GetSessionInfo)(
        CK_SESSION_HANDLE hSession,
        CK_SESSION_INFO_PTR pInfo
      )
{
  CK_RV rv = CKR_OK;

  CI_LogEntry("C_GetSessionInfo", "starting...", rv, 1);
  CI_CodeFktEntry("C_DigestInit", "%lu,%p", 
                  hSession,
                  pInfo);

  DO_FKT(C_GetSessionInfo, (hSession, pInfo));

  CI_LogEntry("C_GetSessionInfo", "...complete", rv, 1);

  return CKR_OK;
}
/* }}} */
/* {{{ PlC_Login */
/* PlC_Login logs a user into a token. */
CK_DEFINE_FUNCTION(CK_RV, PlC_Login)
(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_USER_TYPE      userType,  /* the user type */
  CK_CHAR_PTR       pPin,      /* the user's PIN */
  CK_ULONG          ulPinLen   /* the length of the PIN */
)
{
  CK_RV rv = CKR_OK;
  CK_CHAR_PTR tmp;

  CI_LogEntry("C_Login", "starting...", rv, 1);
  CI_CodeFktEntry("C_DigestInit", "%lu,%x,%s,%lu", 
                  hSession,
		  userType,
                  tmp = CI_ScanableByteStream(pPin,ulPinLen),
		  ulPinLen);
  TC_free(tmp);

  DO_FKT( C_Login, (hSession, userType, pPin, ulPinLen));
  
  CI_LogEntry("C_Login", "...complete", rv, 1);

  return rv;
}
/* }}} */
/* {{{ PlC_Logout */
/* PlC_Logout logs a user out from a token. */
CK_DEFINE_FUNCTION(CK_RV, PlC_Logout)(
  CK_SESSION_HANDLE hSession  /* the session's handle */
)
{
  CK_RV rv = CKR_OK;

  CI_LogEntry("C_Logout", "starting...", rv, 1);
  CI_CodeFktEntry("C_DigestInit", "%lu", 
                  hSession);

  DO_FKT( C_Logout, (hSession));
  
  CI_LogEntry("C_Logout", "...complete", rv, 1);

  return rv;
}
/* }}} */
/* {{{ PlC_GetOperationState */
/* PlC_GetOperationState obtains the state of the cryptographic operation
 * in a session. */
CK_DEFINE_FUNCTION(CK_RV, PlC_GetOperationState)
(
  CK_SESSION_HANDLE hSession,             /* session's handle */
  CK_BYTE_PTR       pOperationState,      /* gets state */
  CK_ULONG_PTR      pulOperationStateLen  /* gets state length */
)
{
  CK_RV rv = CKR_OK;

  CI_LogEntry("C_GetOperationState", "starting...", rv, 1);

  DO_FKT( C_GetOperationState, (hSession, pOperationState, pulOperationStateLen));

  CI_LogEntry("C_GetOperationState", "...complete", rv, 1);

  return rv;
}
/* }}} */
/* {{{ PlC_SetOperationState */
/* PlC_SetOperationState restores the state of the cryptographic
 * operation in a session. */
CK_DEFINE_FUNCTION(CK_RV, PlC_SetOperationState)
(
  CK_SESSION_HANDLE hSession,            /* session's handle */
  CK_BYTE_PTR      pOperationState,      /* holds state */
  CK_ULONG         ulOperationStateLen,  /* holds state length */
  CK_OBJECT_HANDLE hEncryptionKey,       /* en/decryption key */
  CK_OBJECT_HANDLE hAuthenticationKey    /* sign/verify key */
)
{
  CK_RV rv = CKR_OK;

  CI_LogEntry("C_SetOperationState", "starting...", rv, 1);

  DO_FKT( C_SetOperationState, (hSession, pOperationState, ulOperationStateLen, 
				hEncryptionKey, hAuthenticationKey));

  CI_LogEntry("C_SetOperationState", "...complete", rv, 1);

  return rv;
}
/* }}} */
/* {{{ PlC_SignInit */
CK_DEFINE_FUNCTION(CK_RV, PlC_SignInit)(
        CK_SESSION_HANDLE hSession,
        CK_MECHANISM_PTR pMechanism,
        CK_OBJECT_HANDLE hKey
      )
{
  CK_RV rv = CKR_OK;
  CK_BYTE_PTR tmp = NULL_PTR;
  
  CI_LogEntry("C_SignInit", "starting...",rv,1);
  CI_CodeFktEntry("C_SignInit", "%i,%s,%i", 
		  hSession,
		  tmp = CI_ScanableMechanism(pMechanism),
		  hKey);
  TC_free(tmp);

  DO_FKT( C_SignInit, (hSession, pMechanism, hKey));

  CI_LogEntry("C_SignInit", "...complete", rv, 1);

  return rv;
}
/* }}} */
/* {{{ PlC_Sign */
CK_DEFINE_FUNCTION(CK_RV, PlC_Sign)(
        CK_SESSION_HANDLE hSession,            /* session's handle */
        CK_BYTE_PTR       pData,               /* gets plaintext */
        CK_ULONG          ulDataLen,           /* gets p-text size */
        CK_BYTE_PTR       pSignature,          /* the Signature */
        CK_ULONG_PTR      pulSignatureLen      /* bytes of Signature */
      )
{
  CK_RV rv = CKR_OK;
  CK_BYTE_PTR tmp = NULL_PTR;
  
  CI_VarLogEntry("C_Sign", "starting... Session: %i", rv, 1,hSession);
  CI_CodeFktEntry("C_Sign", "%i,%s,%i,%p,%p", 
		  hSession,
		  tmp = CI_ScanableByteStream(pData, ulDataLen),
		  ulDataLen,
		  pSignature,
		  pulSignatureLen);
  CI_VarLogEntry("C_Sign", "*pulSignatureLen: %i", rv, 1, *pulSignatureLen);
  TC_free(tmp);

  DO_FKT( C_Sign, (hSession, pData, ulDataLen, pSignature, pulSignatureLen));

  CI_LogEntry("C_Sign", "...complete", rv, 1);

  return rv;
}
/* }}} */
/* {{{ PlC_SignUpdate */
CK_DEFINE_FUNCTION(CK_RV, PlC_SignUpdate)(
        CK_SESSION_HANDLE hSession,  /* the session's handle */
        CK_BYTE_PTR pPart,           /* the data to sign */
        CK_ULONG ulPartLen           /* count of bytes to sign */
      )
{
  CK_RV rv = CKR_OK;
  CK_BYTE_PTR tmp = NULL_PTR;

  CI_LogEntry("C_SignUpdate", "starting...", rv, 1);
  CI_CodeFktEntry("C_SignUpdate", "%i,%s,%i", 
		  hSession,
		  tmp = CI_ScanableByteStream(pPart, ulPartLen),
		  ulPartLen);
  TC_free(tmp);

  DO_FKT( C_SignUpdate, (hSession, pPart, ulPartLen));

  CI_LogEntry("C_SignUpdate", "...complete", rv, 1);

  return rv;
}
/* }}} */
/* {{{ PlC_SignFinal */
CK_DEFINE_FUNCTION(CK_RV, PlC_SignFinal)(
        CK_SESSION_HANDLE hSession,
        CK_BYTE_PTR pSignature,
        CK_ULONG_PTR pulSignatureLen
      )
{
  CK_RV rv = CKR_OK;

  CI_LogEntry("C_SignFinal", "starting...", rv, 1);
  CI_CodeFktEntry("C_SignFinal", "%i,%p,%p", 
		  hSession,
		  pSignature,
		  pulSignatureLen);
  CI_VarLogEntry("C_SignFinal", "*pulSignatureLen: %i", rv, 1, *pulSignatureLen);

  DO_FKT( C_SignFinal, (hSession, pSignature, pulSignatureLen));

  CI_LogEntry("C_SignFinal", "...complete", rv, 1);

  return rv;
}
/* }}} */
/* {{{ PlC_SignRecoverInit */
/* PlC_SignRecoverInit initializes a signature operation, where
 * the data can be recovered from the signature. */
CK_DEFINE_FUNCTION(CK_RV, PlC_SignRecoverInit)

(
  CK_SESSION_HANDLE hSession,   /* the session's handle */
  CK_MECHANISM_PTR  pMechanism, /* the signature mechanism */
  CK_OBJECT_HANDLE  hKey        /* handle of the signature key */
)
{
  CK_RV rv = CKR_OK;
  CK_BYTE_PTR tmp = NULL_PTR;

  CI_LogEntry("C_SignRecoverInit", "starting", rv, 1);
  CI_CodeFktEntry("C_SignRecoverInit", "%i,%s,%i", 
		  hSession,
		  tmp = CI_ScanableMechanism(pMechanism),
		  hKey);
  TC_free(tmp);

  DO_FKT( C_SignRecoverInit, (hSession, pMechanism, hKey));
  
  CI_LogEntry("C_SignRecoverInit", "...complete", rv, 1); 

  return rv;
}
/* }}} */
/* {{{ PlC_SignRecover */
/* PlC_SignRecover signs data in a single operation, where the
 * data can be recovered from the signature. */
CK_DEFINE_FUNCTION(CK_RV, PlC_SignRecover)

(
  CK_SESSION_HANDLE hSession,        /* the session's handle */
  CK_BYTE_PTR       pData,           /* the data to sign */
  CK_ULONG          ulDataLen,       /* count of bytes to sign */
  CK_BYTE_PTR       pSignature,      /* gets the signature */
  CK_ULONG_PTR      pulSignatureLen  /* gets signature length */
)
{
  CK_RV rv = CKR_OK;
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

  DO_FKT( C_SignRecover, (hSession, pData, ulDataLen, pSignature, pulSignatureLen));
  
  CI_LogEntry("C_SignRecover", "complete", rv, 1);

  return rv;
}
/* }}} */
/* {{{ PlC_GetSlotList */
CK_DEFINE_FUNCTION(CK_RV, PlC_GetSlotList)(
        CK_BBOOL tokenPresent,
        CK_SLOT_ID_PTR pSlotList,
        CK_ULONG_PTR pulCount
      )
{
  CK_RV rv = CKR_OK;

  CI_LogEntry("C_GetSlotList", "starting...", rv, 1);
  CI_CodeFktEntry("C_GetSlotList", "%s,%p,%p", 
                  (tokenPresent = TRUE)?"TRUE":"FALSE",
                  pSlotList,
		  pulCount);
  CI_VarLogEntry("C_GetSlotList", "*pulCount: %i", rv, 1, *pulCount);
 
  DO_FKT( C_GetSlotList, (tokenPresent, pSlotList, pulCount));
  
  CI_LogEntry("C_GetSlotList", "...complete", rv, 1);

  return CKR_OK;  
}
/* }}} */
/* {{{ PlC_GetSlotInfo */
CK_DEFINE_FUNCTION(CK_RV, PlC_GetSlotInfo)(
        CK_SLOT_ID slotID,
        CK_SLOT_INFO_PTR pInfo
      )
{
  CK_RV rv = CKR_OK;

  CI_LogEntry("C_GetSlotInfo", "starting...", rv, 1);
  CI_CodeFktEntry("C_GetSlotInfo", "%i,%p", 
                  slotID,
                  pInfo);

  DO_FKT( C_GetSlotInfo, (slotID, pInfo));

  CI_LogEntry("C_GetSlotInfo", "...complete", rv, 1);

  return rv;
}
/* }}} */
/* {{{ PlC_GetTokenInfo */
CK_DEFINE_FUNCTION(CK_RV, PlC_GetTokenInfo)(
        CK_SLOT_ID slotID,
        CK_TOKEN_INFO_PTR pInfo
      )
{
  CK_RV rv = CKR_OK;

  CI_LogEntry("C_GetTokenInfo", "starting...", rv, 1);
  CI_CodeFktEntry("C_GetTokenInfo", "%i,%p", 
                  slotID,
                  pInfo);

  DO_FKT( C_GetTokenInfo, (slotID, pInfo));

  CI_LogEntry("C_GetTokenInfo", "...complete", rv, 1);
  
  return rv;
}
/* }}} */
/* {{{ PlC_GetMechanismList */
CK_DEFINE_FUNCTION(CK_RV, PlC_GetMechanismList)(
        CK_SLOT_ID slotID,
        CK_MECHANISM_TYPE_PTR pMechanismList,
        CK_ULONG_PTR pulCount
      )
{
  CK_RV rv = CKR_OK;

  CI_LogEntry("C_GetMechanismList", "starting...", rv, 1);
  CI_CodeFktEntry("C_GetMechanismList", "%i,%p,%p", 
                  slotID,
                  pMechanismList,
		  pulCount);
  CI_VarLogEntry("C_GetMechanismList", "*pulCount: %i", rv, 1,*pulCount);

  DO_FKT( C_GetMechanismList, (slotID, pMechanismList, pulCount));

  CI_LogEntry("C_GetMechanismList", "...complete", rv, 1);

  return rv;
}
/* }}} */
/* {{{ PlC_GetMechanismInfo */
CK_DEFINE_FUNCTION(CK_RV, PlC_GetMechanismInfo)(
        CK_SLOT_ID slotID,
        CK_MECHANISM_TYPE type,
        CK_MECHANISM_INFO_PTR pInfo
      )
{
  CK_RV rv=CKR_OK;

  CI_LogEntry("C_GetMechanismInfo", "starting...", rv, 1);
  CI_CodeFktEntry("C_GetMechanismInfo", "%i,%x,%p", 
                  slotID,
                  CI_MechanismStr(type),
		  pInfo);

  DO_FKT( C_GetMechanismInfo, (slotID, type, pInfo));

  CI_LogEntry("C_GetMechanismInfo", "...complete", rv, 1);

  return rv;
}
/* }}} */
/* {{{ PlC_InitPIN */
/* PlC_InitPIN initializes the normal user's PIN. */
CK_DEFINE_FUNCTION(CK_RV, PlC_InitPIN)
(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_CHAR_PTR       pPin,      /* the normal user's PIN */
  CK_ULONG          ulPinLen   /* length in bytes of the PIN */
)
{
  CK_RV rv = CKR_OK;
  CK_CHAR_PTR tmp;

  CI_LogEntry("C_InitPIN", "starting...", rv, 1);
  CI_CodeFktEntry("C_InitPin", "%i,%s,%i", 
                  hSession,
                  tmp = CI_ScanableByteStream(pPin,ulPinLen),
		  ulPinLen);
  TC_free( tmp);

  DO_FKT( C_InitPIN, (hSession, pPin, ulPinLen));

  CI_LogEntry("C_InitPIN", "...complete", rv, 1);

  return rv;
}
/* }}} */
/* {{{ PlC_SetPIN */
/* PlC_SetPIN modifies the PIN of the user who is logged in. */
CK_DEFINE_FUNCTION(CK_RV, PlC_SetPIN)
(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_CHAR_PTR       pOldPin,   /* the old PIN */
  CK_ULONG          ulOldLen,  /* length of the old PIN */
  CK_CHAR_PTR       pNewPin,   /* the new PIN */
  CK_ULONG          ulNewLen   /* length of the new PIN */
)
{
  CK_RV rv = CKR_OK;

  CI_LogEntry("C_SetPIN", "starting...", rv, 1);
  CI_CodeFktEntry("C_SetPIN", "%i,%s,%i,%s,%i", 
                  hSession,
                  CI_ScanableByteStream(pOldPin,ulOldLen),
		  ulOldLen,
                  CI_ScanableByteStream(pNewPin,ulNewLen),
		  ulNewLen);

  DO_FKT( C_SetPIN, (hSession, pOldPin, ulOldLen, pNewPin, ulNewLen));

  CI_LogEntry("C_SetPIN", "...complete", rv, 1);

  return rv;
}
/* }}} */
/* {{{ PlC_VerifyInit */
CK_DEFINE_FUNCTION(CK_RV, PlC_VerifyInit)(
        CK_SESSION_HANDLE hSession,
        CK_MECHANISM_PTR pMechanism,
        CK_OBJECT_HANDLE hKey
      )
{
  CK_RV rv = CKR_OK;
  CK_BYTE_PTR tmp = NULL_PTR;

  CI_VarLogEntry("C_VerifyInit", "starting... Session: %i, Key: %i", 
		 rv, 1, hSession,hKey);
  CI_CodeFktEntry("C_VerifyInit", "%i,%s,%i", 
		  hSession,
		  tmp = CI_ScanableMechanism(pMechanism),
		  hKey);
  TC_free(tmp);
  
  DO_FKT( C_VerifyInit, (hSession, pMechanism, hKey));
  
  CI_LogEntry("C_VerifyInit", "...complete", rv, 1);
  
  return rv;
}
/* }}} */
/* {{{ PlC_Verify */
CK_DEFINE_FUNCTION(CK_RV, PlC_Verify)(
        CK_SESSION_HANDLE hSession,            /* session's handle */
        CK_BYTE_PTR       pData,               /* gets plaintext */
        CK_ULONG          ulDataLen,           /* gets p-text size */
        CK_BYTE_PTR       pSignature,          /* the Signature */
        CK_ULONG          ulSignatureLen      /* bytes of Signature */
      )
{
  CK_RV rv = CKR_OK;
  CK_BYTE_PTR tmp_str1 = NULL_PTR, tmp_str2 = NULL_PTR;

  CI_VarLogEntry("C_Verify", "starting... Session: %i", rv, 1, hSession);
  CI_CodeFktEntry("C_Verify", "%i,%s,%i,%s,%i", 
		  hSession,
		  tmp_str1 = CI_ScanableByteStream(pData,ulDataLen),
		  ulDataLen,
		  tmp_str2 = CI_ScanableByteStream(pSignature,ulSignatureLen),
		  ulSignatureLen);
  TC_free(tmp_str1);
  TC_free(tmp_str2);

  DO_FKT( C_Verify, (hSession, pData, ulDataLen, pSignature, ulSignatureLen));

  CI_LogEntry("C_Verify", "...complete", rv, 1);

  return rv;
}
/* }}} */
/* {{{ PlC_VerifyUpdate */
CK_DEFINE_FUNCTION(CK_RV, PlC_VerifyUpdate)(
        CK_SESSION_HANDLE hSession,  /* the session's handle */
        CK_BYTE_PTR pPart,           /* the data to verify */
        CK_ULONG ulPartLen           /* count of bytes to verify */
      )
{
  CK_RV rv = CKR_OK;

  CI_VarLogEntry("C_VerifyUpdate", "starting... Session: %i", rv, 1, hSession);
  CI_CodeFktEntry("C_VerifyUpdate", "%i,%s,%i,", 
		  hSession,
		  CI_PrintableByteStream(pPart,ulPartLen),
		  ulPartLen);

  DO_FKT( C_VerifyUpdate, (hSession, pPart, ulPartLen));

  CI_LogEntry("C_VerifyUpdate", "...complete", rv, 1);

  return rv;
}
/* }}} */
/* {{{ PlC_VerifyFinal */
CK_DEFINE_FUNCTION(CK_RV, PlC_VerifyFinal)(
        CK_SESSION_HANDLE hSession,
        CK_BYTE_PTR       pSignature,
        CK_ULONG          ulSignatureLen
      )
{
  CK_RV rv = CKR_OK;

  CI_VarLogEntry("C_VerifyFinal", "starting... Session: %i", rv, 1, hSession);
  CI_CodeFktEntry("C_VerifyFinal", "%i,%s,%i,", 
		  hSession,
		  CI_PrintableByteStream(pSignature,ulSignatureLen),
		  ulSignatureLen);

  DO_FKT( C_VerifyFinal, (hSession, pSignature, ulSignatureLen));

  CI_LogEntry("C_VerifyFinal", "...complete", rv, 1);

  return rv;
}
/* }}} */
/* {{{ PlC_VerifyRecoverInit */
/* PlC_VerifyRecoverInit initializes a signature verification
 * operation, where the data is recovered from the signature. */
CK_DEFINE_FUNCTION(CK_RV, PlC_VerifyRecoverInit)
(
  CK_SESSION_HANDLE hSession,    /* the session's handle */
  CK_MECHANISM_PTR  pMechanism,  /* the verification mechanism */
  CK_OBJECT_HANDLE  hKey         /* verification key */
)
{
  CK_RV rv = CKR_OK;

  CI_VarLogEntry("C_VerifyRecoverInit", "starting... Session: %i", rv, 1, hSession);
  CI_CodeFktEntry("C_VerifyRecoverInit", "%i,%s,%i", 
		  hSession,
		  CI_ScanableMechanism(pMechanism),
		  hKey);

  DO_FKT( C_VerifyRecoverInit, (hSession, pMechanism, hKey));

  CI_LogEntry("C_VerifyRecoverInit", "...complete", rv, 1);

  return rv;
}
/* }}} */
/* {{{ PlC_VerifyRecover */
/* PlC_VerifyRecover verifies a signature in a single-part
 * operation, where the data is recovered from the signature. */
CK_DEFINE_FUNCTION(CK_RV, PlC_VerifyRecover)
(
  CK_SESSION_HANDLE hSession,        /* the session's handle */
  CK_BYTE_PTR       pSignature,      /* signature to verify */
  CK_ULONG          ulSignatureLen,  /* signature length */
  CK_BYTE_PTR       pData,           /* gets signed data */
  CK_ULONG_PTR      pulDataLen       /* gets signed data len */
)
{
  CK_RV rv = CKR_OK;

  CI_LogEntry("C_VerifyRecover", "starting...", rv, 1);
  CI_CodeFktEntry("C_VerifyRecover", "%i,%s,%i,%p,%p", 
		  hSession,
		  CI_ScanableByteStream(pSignature,ulSignatureLen),
		  ulSignatureLen,
		  pData,
		  pulDataLen);
  CI_VarLogEntry("C_VerifyRecover", "*pulDataLen: %lu", rv, 1, *pulDataLen);

  DO_FKT( C_VerifyRecover, (hSession, pSignature, ulSignatureLen, pData, pulDataLen));

  CI_LogEntry("C_VerifyRecover", "...complete", rv, 1);

  return rv;
}
/* }}} */

/*
 * Local variables:
 * folded-file: t
 * end:
 */

