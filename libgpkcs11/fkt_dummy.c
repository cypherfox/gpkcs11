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
 * NAME:        fkt_dummy.c
 * SYNOPSIS:    -
 * DESCRIPTION: Provide dummies for all functions of the PKCS11 interface that 
 *              will only return CKR_NOT_SUPPORTED after logging its call.
 * FILES:       -
 * SEE/ALSO:    -
 * AUTHOR:      lbe
 * BUGS: *      -
 * HISTORY:     $Log$
 * HISTORY:     Revision 1.7  2000/03/08 09:59:07  lbe
 * HISTORY:     fix SIGBUS in cryptdb, improve readeability for C_FindObject log output
 * HISTORY:
 * HISTORY:     Revision 1.6  2000/01/31 18:09:02  lbe
 * HISTORY:     lockdown prior to win_gdbm change
 * HISTORY:
 * HISTORY:     Revision 1.5  1999/11/25 19:14:07  lbe
 * HISTORY:     lockdown after windows compile
 * HISTORY:
 * HISTORY:     Revision 1.4  1999/11/25 16:46:51  lbe
 * HISTORY:     moved all lib version defines into the conf.h
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
 * HISTORY:     Revision 1.3  1999/01/19 12:19:40  lbe
 * HISTORY:     first release lockdown
 * HISTORY:
 * HISTORY:     Revision 1.2  1998/12/07 13:20:03  lbe
 * HISTORY:     TC_free von parametern für Zeile und Datei befreit.
 * HISTORY:
 * HISTORY:     Revision 1.1  1998/11/03 15:59:41  lbe
 * HISTORY:     auto-lockdown
 * HISTORY:
 */
/* Diese Liste stellt nicht die Funktion C_GetFunctionList zu Verfügung, da diese Fkts. nur
 * bei anderen Gruppen zum einsatz kommen und nicht als eigenständige Bibliothek arbeiten. 
 */

static char RCSID[]="$Id$";
const char* Version_fkt_dummy_c(){return RCSID;}

#ifndef CK_I_library_build
#define CK_I_library_build
#endif

#include <stdio.h>

#include "fkt_dummy.h"
#include "internal.h"
#include "error.h"


/* {{{ FdC_Initialize */
CK_DEFINE_FUNCTION(CK_RV, FdC_Initialize)(
 CK_VOID_PTR pInitArgs
)
{
  CK_RV rv = CKR_OK;

  CI_LogEntry("C_Initialize", "starting...", rv, 1);
  CI_CodeFktEntry("C_Initialize", "%p", 
		  pInitArgs);

  rv = CKR_FUNCTION_NOT_SUPPORTED;

  CI_LogEntry("C_Initialize", "...complete", rv, 1);
  return rv;
}
/* }}} */
/* {{{ FdC_Finalize */
/* FdC_Finalize indicates that an application is done with the
 * Cryptoki library. */
CK_DEFINE_FUNCTION(CK_RV, FdC_Finalize)(
        CK_VOID_PTR pReserved
)
{
  CK_RV rv = CKR_OK;

  CI_LogEntry("C_Finalize", "starting...", rv, 1);

  rv = CKR_FUNCTION_NOT_SUPPORTED;

  CI_LogEntry("C_Finalize", "...complete", rv, 1);
  return rv;
}
/* }}} */
/* {{{ FdC_InitToken */
CK_DEFINE_FUNCTION(CK_RV, FdC_InitToken)
(
  CK_SLOT_ID     slotID,    /* ID of the token's slot */
  CK_CHAR_PTR    pPin,      /* the SO's initial PIN */
  CK_ULONG       ulPinLen,  /* length in bytes of the PIN */
  CK_CHAR_PTR    pLabel     /* 32-byte token label (blank padded) */
)
{
  CK_RV rv = CKR_OK;

  CI_LogEntry("C_InitToken", "starting...", rv, 1);

  rv = CKR_FUNCTION_NOT_SUPPORTED;

  CI_LogEntry("C_InitToken", "...complete", rv, 1);
  
  return rv;
}

/* }}} */
/* {{{ FdC_DecryptInit */
CK_DEFINE_FUNCTION(CK_RV, FdC_DecryptInit)(
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

  rv = CKR_FUNCTION_NOT_SUPPORTED;

  CI_LogEntry("C_DecryptInit", "...complete", rv , 1);	  

  return rv;
}
/* }}} */
/* {{{ FdC_Decrypt */
CK_DEFINE_FUNCTION(CK_RV, FdC_Decrypt)(
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

  rv = CKR_FUNCTION_NOT_SUPPORTED;

  CI_LogEntry("C_Decrypt", "...complete", rv , 0);	  

  return rv;
}
/* }}} */
/* {{{ FdC_DecryptUpdate */
CK_DEFINE_FUNCTION(CK_RV, FdC_DecryptUpdate)(
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

  rv = CKR_FUNCTION_NOT_SUPPORTED;

  CI_LogEntry("C_DecryptUpdate", "...complete", rv , 0);	  

  return rv;
}
/* }}} */
/* {{{ FdC_DecryptFinal */
CK_DEFINE_FUNCTION(CK_RV, FdC_DecryptFinal)(
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

  rv = CKR_FUNCTION_NOT_SUPPORTED;

  CI_LogEntry("C_DecryptFinal", "...complete", rv , 0);	  

  return rv;
}
/* }}} */
/* {{{ FdC_DigestInit */
CK_DEFINE_FUNCTION(CK_RV, FdC_DigestInit)(
      CK_SESSION_HANDLE hSession,
      CK_MECHANISM_PTR pMechanism
      )
{
  CK_RV rv = CKR_OK;

  CI_VarLogEntry("C_DigestInit", "starting...Session:%i", rv, 1,hSession);
  CI_CodeFktEntry("C_DigestInit", "%i,%s", 
		  hSession,
		  CI_ScanableMechanism(pMechanism));

  rv = CKR_FUNCTION_NOT_SUPPORTED;
  
  CI_LogEntry("C_DigestInit", "...complete", rv, 1);

  return rv;
}
/* }}} */
/* {{{ FdC_Digest */
CK_DEFINE_FUNCTION(CK_RV, FdC_Digest)(
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

  rv = CKR_FUNCTION_NOT_SUPPORTED;

  CI_LogEntry("C_Digest", "...complete", rv, 1);

  return rv;
}
/* }}} */
/* {{{ FdC_DigestUpdate */
CK_DEFINE_FUNCTION(CK_RV, FdC_DigestUpdate)(
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

  rv = CKR_FUNCTION_NOT_SUPPORTED;

  CI_LogEntry("C_DigestUpdate", "...complete", rv, 1);

  return rv;
}
/* }}} */
/* {{{ FdC_DigestKey */
/* FdC_DigestKey continues a multi-part message-digesting
 * operation, by digesting the value of a secret key as part of
 * the data already digested. */
CK_DEFINE_FUNCTION(CK_RV, FdC_DigestKey)
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

  rv = CKR_FUNCTION_NOT_SUPPORTED;

  CI_LogEntry("C_DigestKey", "...complete", rv, 1);

  return rv;
}
/* }}} */
/* {{{ FdC_DigestFinal */
CK_DEFINE_FUNCTION(CK_RV, FdC_DigestFinal)(
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

  rv = CKR_FUNCTION_NOT_SUPPORTED;

  CI_LogEntry("C_DigestFinal", "...complete", rv, 1);

  return rv;
}
/* }}} */
/* {{{ FdC_DigestEncryptUpdate */
/* FdC_DigestEncryptUpdate continues a multiple-part digesting
 * and encryption operation. */
CK_DEFINE_FUNCTION(CK_RV, FdC_DigestEncryptUpdate)
(
  CK_SESSION_HANDLE hSession,            /* session's handle */
  CK_BYTE_PTR       pPart,               /* the plaintext data */
  CK_ULONG          ulPartLen,           /* plaintext length */
  CK_BYTE_PTR       pEncryptedPart,      /* gets ciphertext */
  CK_ULONG_PTR      pulEncryptedPartLen  /* gets c-text length */
)
{
  CK_RV rv = CKR_OK;
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

  rv = CKR_FUNCTION_NOT_SUPPORTED;

  CI_LogEntry("C_DigestEncryptUpdate", "...complete", rv, 1);

  return rv;
}
/* }}} */
/* {{{ FdC_DecryptDigestUpdate */
/* FdC_DecryptDigestUpdate continues a multiple-part decryption and
 * digesting operation. */
CK_DEFINE_FUNCTION(CK_RV, FdC_DecryptDigestUpdate)

(
  CK_SESSION_HANDLE hSession,            /* session's handle */
  CK_BYTE_PTR       pEncryptedPart,      /* ciphertext */
  CK_ULONG          ulEncryptedPartLen,  /* ciphertext length */
  CK_BYTE_PTR       pPart,               /* gets plaintext */
  CK_ULONG_PTR      pulPartLen           /* gets plaintext len */
)
{
  CK_RV rv = CKR_OK;
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

  rv = CKR_FUNCTION_NOT_SUPPORTED;

  CI_LogEntry("C_DecryptDigestUpdate", "...complete", rv, 1);

  return rv;
}
/* }}} */
/* {{{ FdC_SignEncryptUpdate */
/* FdC_SignEncryptUpdate continues a multiple-part signing and
 * encryption operation. */
CK_DEFINE_FUNCTION(CK_RV, FdC_SignEncryptUpdate)

(
  CK_SESSION_HANDLE hSession,            /* session's handle */
  CK_BYTE_PTR       pPart,               /* the plaintext data */
  CK_ULONG          ulPartLen,           /* plaintext length */
  CK_BYTE_PTR       pEncryptedPart,      /* gets ciphertext */
  CK_ULONG_PTR      pulEncryptedPartLen  /* gets c-text length */
)
{
  CK_RV rv = CKR_OK;
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

  rv = CKR_FUNCTION_NOT_SUPPORTED;

  CI_LogEntry("C_SignEncryptUpdate", "...complete", rv, 1);

  return rv;
}
 /* }}} */
/* {{{ FdC_DecryptVerifyUpdate */
 /* FdC_DecryptVerifyUpdate continues a multiple-part decryption and
 * verify operation. */
CK_DEFINE_FUNCTION(CK_RV, FdC_DecryptVerifyUpdate)
(
  CK_SESSION_HANDLE hSession,            /* session's handle */
  CK_BYTE_PTR       pEncryptedPart,      /* ciphertext */
  CK_ULONG          ulEncryptedPartLen,  /* ciphertext length */
  CK_BYTE_PTR       pPart,               /* gets plaintext */
  CK_ULONG_PTR      pulPartLen           /* gets p-text length */
)
{
  CK_RV rv = CKR_OK;
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

  rv = CKR_FUNCTION_NOT_SUPPORTED;

  CI_LogEntry("C_DecryptVerifyUpdate", "...complete", rv, 1);

  return rv;
}
/* }}} */
/* {{{ FdC_EncryptInit */
CK_DEFINE_FUNCTION(CK_RV, FdC_EncryptInit)(
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

  rv = CKR_FUNCTION_NOT_SUPPORTED;
  
  CI_LogEntry("C_EncryptInit", "...complete", rv, 1);

  return rv;
}
/* }}} */
/* {{{ FdC_Encrypt */
CK_DEFINE_FUNCTION(CK_RV, FdC_Encrypt)(
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

  rv = CKR_FUNCTION_NOT_SUPPORTED;

  CI_LogEntry("C_Encrypt", "...complete", rv, 1);

  return rv;
}
/* }}} */
/* {{{ FdC_EncryptUpdate */
CK_DEFINE_FUNCTION(CK_RV, FdC_EncryptUpdate)(
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

  rv = CKR_FUNCTION_NOT_SUPPORTED;

  CI_LogEntry("C_EncryptUpdate", "...complete", rv, 1);

  return rv;
}
/* }}} */
/* {{{ FdC_EncryptFinal */
CK_DEFINE_FUNCTION(CK_RV, FdC_EncryptFinal)(
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

  rv = CKR_FUNCTION_NOT_SUPPORTED;

  CI_LogEntry("C_EncryptFinal", "...complete", rv, 1);

  return rv;
}
/* }}} */
/* {{{ FdC_GetInfo */
CK_DEFINE_FUNCTION(CK_RV, FdC_GetInfo)(
 CK_INFO_PTR pInfo
)
{
  CK_RV rv = CKR_OK;

  CI_LogEntry("C_GetInfo", "starting...", rv, 1);
  CI_CodeFktEntry("C_GetInfo", "%p", 
                  pInfo);

  rv = CKR_FUNCTION_NOT_SUPPORTED;

  CI_LogEntry("C_GetInfo", "...complete", rv, 1);

  return rv;
}
/* }}} */
/* {{{ FdC_GenerateKey */
CK_DEFINE_FUNCTION(CK_RV, FdC_GenerateKey)(
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
  
  rv = CKR_FUNCTION_NOT_SUPPORTED;

  CI_VarLogEntry("C_GenerateKey", "new key object: %i", rv, 1,*phKey);
  CI_LogEntry("C_GenerateKey", "...complete", rv, 1);

  return rv;
}
/* }}} */
/* {{{ FdC_GenerateKeyPair */
CK_DEFINE_FUNCTION(CK_RV, FdC_GenerateKeyPair)(
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

  rv = CKR_FUNCTION_NOT_SUPPORTED;

  CI_LogEntry("C_GenerateKeyPair", "...complete", rv, 1);

  return rv;
}
/* }}} */
/* {{{ FdC_WrapKey */
CK_DEFINE_FUNCTION(CK_RV, FdC_WrapKey)
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
		  
rv = CKR_FUNCTION_NOT_SUPPORTED;

  CI_LogEntry("C_WrapKey", "...complete", rv, 1);

  return rv;
}
/* }}} */
/* {{{ FdC_UnwrapKey */
/* FdC_UnwrapKey unwraps (decrypts) a wrapped key, creating a new
 * key object. */
CK_DEFINE_FUNCTION(CK_RV, FdC_UnwrapKey)
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
  
  rv = CKR_FUNCTION_NOT_SUPPORTED;

  CI_LogEntry("C_UnwrapKey", "...complete", rv, 1);

  return rv;
}
/* }}} */
/* {{{ FdC_DeriveKey */
/* FdC_DeriveKey derives a key from a base key, creating a new key
 * object. */
CK_DEFINE_FUNCTION(CK_RV, FdC_DeriveKey)
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
  
rv = CKR_FUNCTION_NOT_SUPPORTED;

  CI_LogEntry("C_DeriveKey", "...complete", rv, 1);

  return rv;
}
/* }}} */
/* {{{ FdC_CreateObject */
CK_DEFINE_FUNCTION(CK_RV, FdC_CreateObject)(
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

  rv = CKR_FUNCTION_NOT_SUPPORTED;

  CI_VarLogEntry("C_CreateObject", 
		 "Object Handle: %lu ...complete", 
		 rv, 1, *phObject);

  return rv;
}
/* }}} */
/* {{{ FdC_DestroyObject */
CK_DEFINE_FUNCTION(CK_RV, FdC_DestroyObject)(
        CK_SESSION_HANDLE hSession,
        CK_OBJECT_HANDLE hObject
      )
{
  CK_RV rv = CKR_OK;

  CI_LogEntry("C_DestroyObject", "starting...", rv , 1);	  
  CI_CodeFktEntry("C_DestroyObject", "%u,%u", 
                  hSession,
		  hObject);

  rv = CKR_FUNCTION_NOT_SUPPORTED;

  CI_LogEntry("C_DestroyObject", "...complete", rv , 1);	  

  return rv;
}
/* }}} */
/* {{{ FdC_CopyObject */
CK_DEFINE_FUNCTION(CK_RV, FdC_CopyObject)(
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

  rv = CKR_FUNCTION_NOT_SUPPORTED;

  CI_LogEntry("C_CopyObject", "...complete", rv , 1);	  

  return CKR_OK;
}
/* }}} */
/* {{{ FdC_GetAttributeValue */
CK_DEFINE_FUNCTION(CK_RV, FdC_GetAttributeValue)(
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

  rv = CKR_FUNCTION_NOT_SUPPORTED;
  
  CI_LogEntry("C_GetAttributeValue", "...complete", rv , 1);	  

  return rv;
}
/* }}} */
/* {{{ FdC_SetAttributeValue */
CK_DEFINE_FUNCTION(CK_RV, FdC_SetAttributeValue)(
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

  rv = CKR_FUNCTION_NOT_SUPPORTED;

  CI_LogEntry("C_SetAttributeValue", "...complete", rv , 1);	  
  
  return rv;
  
}
/* }}} */
/* {{{ FdC_FindObjectsInit */
/* FdC_FindObjectsInit initializes a search for token and session
 * objects that match a template. */
CK_DEFINE_FUNCTION(CK_RV, FdC_FindObjectsInit)
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

  rv = CKR_FUNCTION_NOT_SUPPORTED;

  CI_LogEntry("C_FindObjectsInit", "...complete", rv , 1);	  

  return CKR_OK;
}
/* }}} */
/* {{{ FdC_FindObjects */
/* FdC_FindObjects continues a search for token and session
 * objects that match a template, obtaining additional object
 * handles. */
CK_DEFINE_FUNCTION(CK_RV, FdC_FindObjects)(
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

  rv = CKR_FUNCTION_NOT_SUPPORTED;

  CI_LogEntry("C_FindObjects", "...complete", rv , 1);	  

  return rv;
}
/* }}} */
/* {{{ FdC_FindObjectsFinal */
/* FdC_FindObjectsFinal finishes a search for token and session
 * objects. */
CK_DEFINE_FUNCTION(CK_RV, FdC_FindObjectsFinal)
(
  CK_SESSION_HANDLE hSession  /* the session's handle */
)
{
  CK_RV rv = CKR_OK;

  CI_LogEntry("C_FindObjectsFinal", "starting...", rv , 1);	  
  CI_CodeFktEntry("C_FindObjectsFinal", "%lu", 
                  hSession);

  rv = CKR_FUNCTION_NOT_SUPPORTED;

  CI_LogEntry("C_FindObjectsFinal", "...complete", rv , 0);	  

  return rv;
}
/* }}} */
/* {{{ FdC_GetObjectSize */
/* FdC_GetObjectSize gets the size of an object in bytes. */
CK_DEFINE_FUNCTION(CK_RV, FdC_GetObjectSize)
(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_OBJECT_HANDLE  hObject,   /* the object's handle */
  CK_ULONG_PTR      pulSize    /* receives size of object */
)
{
  CK_RV rv = CKR_OK;

  CI_LogEntry("C_GetObjectSize", "starting...", rv, 1);

  rv = CKR_FUNCTION_NOT_SUPPORTED;

  CI_LogEntry("C_GetObjectSize", "...complete", rv, 1);
  return rv;
}
/* }}} */
/* {{{ FdC_GetFunctionStatus */
CK_DEFINE_FUNCTION(CK_RV, FdC_GetFunctionStatus)
(
  CK_SESSION_HANDLE hSession  /* the session's handle */
)
{
  CK_RV rv = CKR_OK;

  CI_LogEntry("C_GetFunctionStatus", "starting...", rv, 1);

  rv = CKR_FUNCTION_NOT_SUPPORTED;

  CI_LogEntry("C_GetFunctionStatus", "...complete", rv, 1);
  return rv;
}
/* }}} */
/* {{{ FdC_CancelFunction */
CK_DEFINE_FUNCTION(CK_RV, FdC_CancelFunction)
(
  CK_SESSION_HANDLE hSession  /* the session's handle */
)
{
  CK_RV rv = CKR_OK;

  CI_LogEntry("C_CancelFunction", "starting...", rv, 1);

  rv = CKR_FUNCTION_NOT_SUPPORTED;

  CI_LogEntry("C_CancelFunction", "...complete", rv, 1);
  return rv;
}
/* }}} */
/* {{{ FdC_WaitForSlotEvent */
CK_DEFINE_FUNCTION(CK_RV, FdC_WaitForSlotEvent)
(
  CK_FLAGS flags,        /* blocking/nonblocking flag */
  CK_SLOT_ID_PTR pSlot,  /* location that receives the slot ID */
  CK_VOID_PTR pReserved   /* reserved.  Should be NULL_PTR */
)
{
  CK_RV rv = CKR_OK;

  CI_LogEntry("C_WaitForSlotEvent", "starting...", rv, 1);

  rv = CKR_FUNCTION_NOT_SUPPORTED;

  CI_LogEntry("C_WaitForSlotEvent", "...complete", rv, 1);
  return rv;
}
/* }}} */
/* {{{ FdC_SeedRandom */
CK_DEFINE_FUNCTION(CK_RV, FdC_SeedRandom)(
        CK_SESSION_HANDLE hSession,
        CK_BYTE_PTR pSeed,
        CK_ULONG ulSeedLen
      )
{
  CK_RV rv = CKR_OK;

  CI_LogEntry("C_SeedRandom", "starting...", rv, 1);

  rv = CKR_FUNCTION_NOT_SUPPORTED;

  CI_LogEntry("C_SeedRandom", "...complete", rv, 1);
  return rv; 
}
/* }}} */
/* {{{ FdC_GenerateRandom */
CK_DEFINE_FUNCTION(CK_RV, FdC_GenerateRandom)(
        CK_SESSION_HANDLE hSession,
        CK_BYTE_PTR pRandomData,
        CK_ULONG ulRandomLen
      )
{
  CK_RV rv = CKR_OK;

  CI_LogEntry("C_GenerateRandom", "starting...", rv, 1);

  rv = CKR_FUNCTION_NOT_SUPPORTED;

  CI_LogEntry("C_GenerateRandom", "...complete", rv, 1);

  return rv;
}
/* }}} */
/* {{{ FdC_OpenSession */
CK_DEFINE_FUNCTION(CK_RV, FdC_OpenSession)(
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

  rv = CKR_FUNCTION_NOT_SUPPORTED;

  CI_VarLogEntry("C_OpenSession", "for Session %lu...complete", rv, 1,*phSession);
  return rv;
}
/* }}} */
/* {{{ FdC_CloseSession */
CK_DEFINE_FUNCTION(CK_RV, FdC_CloseSession)(
        CK_SESSION_HANDLE hSession
      )
{
  CK_RV rv = CKR_OK;

  CI_VarLogEntry("C_CloseSession", "starting...Session: %lu", rv, 1,hSession);
  CI_CodeFktEntry("C_CloseSession", "%lu", 
                  hSession);

  rv = CKR_FUNCTION_NOT_SUPPORTED;

  CI_LogEntry("C_CloseSession", "...complete", rv, 1);

  return rv; 
}
/* }}} */
/* {{{ FdC_CloseAllSessions */
/* FdC_CloseAllSessions closes all sessions with a token. */
CK_DEFINE_FUNCTION(CK_RV, FdC_CloseAllSessions)
(
  CK_SLOT_ID     slotID  /* the token's slot */
)
{
  CK_RV rv= CKR_OK;

  CI_LogEntry("C_CloseAllSessions", "starting...", rv, 1);
  CI_CodeFktEntry("C_CloseAllSession", "%lu", 
                  slotID);

  rv = CKR_FUNCTION_NOT_SUPPORTED;

  CI_LogEntry("C_CloseAllSessions", "...complete", rv, 1);

  return rv;
}
/* }}} */
/* {{{ FdC_GetSessionInfo */
CK_DEFINE_FUNCTION(CK_RV, FdC_GetSessionInfo)(
        CK_SESSION_HANDLE hSession,
        CK_SESSION_INFO_PTR pInfo
      )
{
  CK_RV rv = CKR_OK;

  CI_LogEntry("C_GetSessionInfo", "starting...", rv, 1);
  CI_CodeFktEntry("C_DigestInit", "%lu,%p", 
                  hSession,
                  pInfo);

  rv = CKR_FUNCTION_NOT_SUPPORTED;

  CI_LogEntry("C_GetSessionInfo", "...complete", rv, 1);

  return CKR_OK;
}
/* }}} */
/* {{{ FdC_Login */
/* FdC_Login logs a user into a token. */
CK_DEFINE_FUNCTION(CK_RV, FdC_Login)
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

  rv = CKR_FUNCTION_NOT_SUPPORTED;
  
  CI_LogEntry("C_Login", "...complete", rv, 1);

  return rv;
}
/* }}} */
/* {{{ FdC_Logout */
/* FdC_Logout logs a user out from a token. */
CK_DEFINE_FUNCTION(CK_RV, FdC_Logout)(
  CK_SESSION_HANDLE hSession  /* the session's handle */
)
{
  CK_RV rv = CKR_OK;

  CI_LogEntry("C_Logout", "starting...", rv, 1);
  CI_CodeFktEntry("C_DigestInit", "%lu", 
                  hSession);

  rv = CKR_FUNCTION_NOT_SUPPORTED;
  
  CI_LogEntry("C_Logout", "...complete", rv, 1);

  return rv;
}
/* }}} */
/* {{{ FdC_GetOperationState */
/* FdC_GetOperationState obtains the state of the cryptographic operation
 * in a session. */
CK_DEFINE_FUNCTION(CK_RV, FdC_GetOperationState)
(
  CK_SESSION_HANDLE hSession,             /* session's handle */
  CK_BYTE_PTR       pOperationState,      /* gets state */
  CK_ULONG_PTR      pulOperationStateLen  /* gets state length */
)
{
  CK_RV rv = CKR_OK;

  CI_LogEntry("C_GetOperationState", "starting...", rv, 1);

  rv = CKR_FUNCTION_NOT_SUPPORTED;

  CI_LogEntry("C_GetOperationState", "...complete", rv, 1);

  return rv;
}
/* }}} */
/* {{{ FdC_SetOperationState */
/* FdC_SetOperationState restores the state of the cryptographic
 * operation in a session. */
CK_DEFINE_FUNCTION(CK_RV, FdC_SetOperationState)
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

  rv = CKR_FUNCTION_NOT_SUPPORTED;

  CI_LogEntry("C_SetOperationState", "...complete", rv, 1);

  return rv;
}
/* }}} */
/* {{{ FdC_SignInit */
CK_DEFINE_FUNCTION(CK_RV, FdC_SignInit)(
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

  rv = CKR_FUNCTION_NOT_SUPPORTED;

  CI_LogEntry("C_SignInit", "...complete", rv, 1);

  return rv;
}
/* }}} */
/* {{{ FdC_Sign */
CK_DEFINE_FUNCTION(CK_RV, FdC_Sign)(
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

  rv = CKR_FUNCTION_NOT_SUPPORTED;

  CI_LogEntry("C_Sign", "...complete", rv, 1);

  return rv;
}
/* }}} */
/* {{{ FdC_SignUpdate */
CK_DEFINE_FUNCTION(CK_RV, FdC_SignUpdate)(
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

  rv = CKR_FUNCTION_NOT_SUPPORTED;

  CI_LogEntry("C_SignUpdate", "...complete", rv, 1);

  return rv;
}
/* }}} */
/* {{{ FdC_SignFinal */
CK_DEFINE_FUNCTION(CK_RV, FdC_SignFinal)(
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

  rv = CKR_FUNCTION_NOT_SUPPORTED;

  CI_LogEntry("C_SignFinal", "...complete", rv, 1);

  return rv;
}
/* }}} */
/* {{{ FdC_SignRecoverInit */
/* FdC_SignRecoverInit initializes a signature operation, where
 * the data can be recovered from the signature. */
CK_DEFINE_FUNCTION(CK_RV, FdC_SignRecoverInit)

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

  rv = CKR_FUNCTION_NOT_SUPPORTED;
  
  CI_LogEntry("C_SignRecoverInit", "...complete", rv, 1); 

  return rv;
}
/* }}} */
/* {{{ FdC_SignRecover */
/* FdC_SignRecover signs data in a single operation, where the
 * data can be recovered from the signature. */
CK_DEFINE_FUNCTION(CK_RV, FdC_SignRecover)

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

  rv = CKR_FUNCTION_NOT_SUPPORTED;
  
  CI_LogEntry("C_SignRecover", "complete", rv, 1);

  return rv;
}
/* }}} */
/* {{{ FdC_GetSlotList */
CK_DEFINE_FUNCTION(CK_RV, FdC_GetSlotList)(
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
 
  rv = CKR_FUNCTION_NOT_SUPPORTED;
  
  CI_LogEntry("C_GetSlotList", "...complete", rv, 1);

  return CKR_OK;  
}
/* }}} */
/* {{{ FdC_GetSlotInfo */
CK_DEFINE_FUNCTION(CK_RV, FdC_GetSlotInfo)(
        CK_SLOT_ID slotID,
        CK_SLOT_INFO_PTR pInfo
      )
{
  CK_RV rv = CKR_OK;

  CI_LogEntry("C_GetSlotInfo", "starting...", rv, 1);
  CI_CodeFktEntry("C_GetSlotInfo", "%i,%p", 
                  slotID,
                  pInfo);

  rv = CKR_FUNCTION_NOT_SUPPORTED;

  CI_LogEntry("C_GetSlotInfo", "...complete", rv, 1);

  return rv;
}
/* }}} */
/* {{{ FdC_GetTokenInfo */
CK_DEFINE_FUNCTION(CK_RV, FdC_GetTokenInfo)(
        CK_SLOT_ID slotID,
        CK_TOKEN_INFO_PTR pInfo
      )
{
  CK_RV rv = CKR_OK;

  CI_LogEntry("C_GetTokenInfo", "starting...", rv, 1);
  CI_CodeFktEntry("C_GetTokenInfo", "%i,%p", 
                  slotID,
                  pInfo);

  rv = CKR_FUNCTION_NOT_SUPPORTED;

  CI_LogEntry("C_GetTokenInfo", "...complete", rv, 1);
  
  return rv;
}
/* }}} */
/* {{{ FdC_GetMechanismList */
CK_DEFINE_FUNCTION(CK_RV, FdC_GetMechanismList)(
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

  rv = CKR_FUNCTION_NOT_SUPPORTED;

  CI_LogEntry("C_GetMechanismList", "...complete", rv, 1);

  return rv;
}
/* }}} */
/* {{{ FdC_GetMechanismInfo */
CK_DEFINE_FUNCTION(CK_RV, FdC_GetMechanismInfo)(
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

  rv = CKR_FUNCTION_NOT_SUPPORTED;

  CI_LogEntry("C_GetMechanismInfo", "...complete", rv, 1);

  return rv;
}
/* }}} */
/* {{{ FdC_InitPIN */
/* FdC_InitPIN initializes the normal user's PIN. */
CK_DEFINE_FUNCTION(CK_RV, FdC_InitPIN)
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
  TC_free(tmp);

  rv = CKR_FUNCTION_NOT_SUPPORTED;

  CI_LogEntry("C_InitPIN", "...complete", rv, 1);

  return rv;
}
/* }}} */
/* {{{ FdC_SetPIN */
/* FdC_SetPIN modifies the PIN of the user who is logged in. */
CK_DEFINE_FUNCTION(CK_RV, FdC_SetPIN)
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

  rv = CKR_FUNCTION_NOT_SUPPORTED;

  CI_LogEntry("C_SetPIN", "...complete", rv, 1);

  return rv;
}
/* }}} */
/* {{{ FdC_VerifyInit */
CK_DEFINE_FUNCTION(CK_RV, FdC_VerifyInit)(
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
  
  rv = CKR_FUNCTION_NOT_SUPPORTED;
  
  CI_LogEntry("C_VerifyInit", "...complete", rv, 1);
  
  return rv;
}
/* }}} */
/* {{{ FdC_Verify */
CK_DEFINE_FUNCTION(CK_RV, FdC_Verify)(
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

  rv = CKR_FUNCTION_NOT_SUPPORTED;

  CI_LogEntry("C_Verify", "...complete", rv, 1);

  return rv;
}
/* }}} */
/* {{{ FdC_VerifyUpdate */
CK_DEFINE_FUNCTION(CK_RV, FdC_VerifyUpdate)(
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

  rv = CKR_FUNCTION_NOT_SUPPORTED;

  CI_LogEntry("C_VerifyUpdate", "...complete", rv, 1);

  return rv;
}
/* }}} */
/* {{{ FdC_VerifyFinal */
CK_DEFINE_FUNCTION(CK_RV, FdC_VerifyFinal)(
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

  rv = CKR_FUNCTION_NOT_SUPPORTED;

  CI_LogEntry("C_VerifyFinal", "...complete", rv, 1);

  return rv;
}
/* }}} */
/* {{{ FdC_VerifyRecoverInit */
/* FdC_VerifyRecoverInit initializes a signature verification
 * operation, where the data is recovered from the signature. */
CK_DEFINE_FUNCTION(CK_RV, FdC_VerifyRecoverInit)
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

  rv = CKR_FUNCTION_NOT_SUPPORTED;

  CI_LogEntry("C_VerifyRecoverInit", "...complete", rv, 1);

  return rv;
}
/* }}} */
/* {{{ FdC_VerifyRecover */
/* FdC_VerifyRecover verifies a signature in a single-part
 * operation, where the data is recovered from the signature. */
CK_DEFINE_FUNCTION(CK_RV, FdC_VerifyRecover)
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

  rv = CKR_FUNCTION_NOT_SUPPORTED;

  CI_LogEntry("C_VerifyRecover", "...complete", rv, 1);

  return rv;
}
/* }}} */

/*
 * Local variables:
 * folded-file: t
 * end:
 */

