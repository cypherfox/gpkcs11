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
 * NAME:        getInfo.c
 * SYNOPSIS:    -
 * DESCRIPTION: -
 * FILES:       -
 * SEE/ALSO:    -
 * AUTHOR:      lbe
 * BUGS: *      -
 * HISTORY:     $Log$
 * HISTORY:     Revision 1.5  2000/01/31 18:09:02  lbe
 * HISTORY:     lockdown prior to win_gdbm change
 * HISTORY:
 * HISTORY:     Revision 1.4  1999/11/02 13:47:18  lbe
 * HISTORY:     change of structures and bug fix in slot.c, add more files for tcsc_token: emptyfuncs and general_data
 * HISTORY:
 * HISTORY:     Revision 1.3  1999/10/06 07:57:22  lbe
 * HISTORY:     solved netscape symbol clash problem
 * HISTORY:
 * HISTORY:     Revision 1.2  1999/07/20 17:40:01  lbe
 * HISTORY:     fix bug in gdbm Makefile: there is not allways an 'install' around
 * HISTORY:
 * HISTORY:     Revision 1.1  1999/06/16 09:46:08  lbe
 * HISTORY:     reorder files
 * HISTORY:
 * HISTORY:     Revision 1.8  1999/01/22 08:35:32  lbe
 * HISTORY:     full build with new perisistant storage complete
 * HISTORY:
 * HISTORY:     Revision 1.7  1999/01/19 12:19:40  lbe
 * HISTORY:     first release lockdown
 * HISTORY:
 * HISTORY:     Revision 1.6  1998/11/03 15:59:30  lbe
 * HISTORY:     auto-lockdown
 * HISTORY:
 * HISTORY:     Revision 1.5  1998/10/12 10:00:07  lbe
 * HISTORY:     clampdown
 * HISTORY:
 * HISTORY:     Revision 1.4  1998/08/05 08:57:22  lbe
 * HISTORY:     *** empty log message ***
 * HISTORY:
 * HISTORY:     Revision 1.3  1998/07/30 15:31:17  lbe
 * HISTORY:     Win32 Port
 * HISTORY:
 * HISTORY:     Revision 1.2  1998/07/23 15:18:09  lbe
 * HISTORY:     working
 * HISTORY:
 * HISTORY:     Revision 1.1  1998/07/02 17:13:50  lbe
 * HISTORY:     Initial revision
 * HISTORY:
 */
 
static char RCSID[]="$Id$";
const char* Version_getInfo_c(){return RCSID;}

/* Needed for Win32-isms in cryptoki.h */
#ifndef CK_I_library_build
#define CK_I_library_build
#endif

#include "internal.h"
#include "fkt_dummy.h"
#include "error.h"

#include <string.h>
#include <stdio.h>
#include <signal.h>

#if defined(CK_Win32) 
#include "windows.h"
#include "winuser.h"
#endif 

/* {{{ C_GetInfo */
CK_DEFINE_FUNCTION(CK_RV, C_GetInfo)(
 CK_INFO_PTR pInfo
)
{
  CK_RV rv = CKR_OK;

  CI_LogEntry("C_GetInfo", "starting...", rv, 1);
  CI_CodeFktEntry("C_GetInfo", "%p", 
                  pInfo);

  /* make sure we are initialized */
  if (!(CK_I_global_flags & CK_IGF_INITIALIZED)) 
    return CKR_CRYPTOKI_NOT_INITIALIZED;

  pInfo->cryptokiVersion.major=0x2;
  pInfo->cryptokiVersion.minor=0x1;

  strncpy((char*)pInfo->manufacturerID, "TrustCenter GmbH Hamburg       ", 32);

  pInfo->flags = 0;

#if defined(BUILD_MAMOOTH)
  strncpy((char*) pInfo->libraryDescription, "TrustCenter PKCS#11 Library(M)  ", 32);
#else
  strncpy((char*) pInfo->libraryDescription, "TrustCenter PKCS#11 Library     ", 32);
#endif

  pInfo->libraryVersion.major=LIBRARY_VERSION_MAJOR;
  pInfo->libraryVersion.minor=LIBRARY_VERSION_MINOR;

  CI_LogEntry("C_GetInfo", "...complete", rv, 1);

  return rv;
}
/* }}} */
/* {{{ C_GetFunctionList */
CK_FUNCTION_LIST ck_function_list;

void set_function_list(void);

void set_function_list(void)
{
  ck_function_list.version.major=         LIBRARY_VERSION_MAJOR;
  ck_function_list.version.minor=         LIBRARY_VERSION_MINOR;
  ck_function_list.C_Initialize= 	  &C_Initialize;
  ck_function_list.C_Finalize= 		  &C_Finalize;
  ck_function_list.C_GetInfo= 		  &C_GetInfo;
  ck_function_list.C_GetFunctionList= 	  &C_GetFunctionList;
  ck_function_list.C_GetSlotList= 	  &C_GetSlotList;
  ck_function_list.C_GetSlotInfo= 	  &C_GetSlotInfo;
  ck_function_list.C_GetTokenInfo= 	  &C_GetTokenInfo;
  ck_function_list.C_GetMechanismList= 	  &C_GetMechanismList;
  ck_function_list.C_GetMechanismInfo= 	  &C_GetMechanismInfo;
  ck_function_list.C_InitToken= 	  &C_InitToken;
  ck_function_list.C_InitPIN= 		  &C_InitPIN;
  ck_function_list.C_SetPIN= 		  &C_SetPIN;
  ck_function_list.C_OpenSession= 	  &C_OpenSession;
  ck_function_list.C_CloseSession= 	  &C_CloseSession;
  ck_function_list.C_CloseAllSessions= 	  &C_CloseAllSessions;
  ck_function_list.C_GetSessionInfo= 	  &C_GetSessionInfo;
  ck_function_list.C_GetOperationState=   &C_GetOperationState;
  ck_function_list.C_SetOperationState=   &C_SetOperationState;
  ck_function_list.C_Login= 		  &C_Login;
  ck_function_list.C_Logout= 		  &C_Logout;
  ck_function_list.C_CreateObject= 	  &C_CreateObject;
  ck_function_list.C_CopyObject= 	  &C_CopyObject;
  ck_function_list.C_DestroyObject= 	  &C_DestroyObject;
  ck_function_list.C_GetObjectSize= 	  &C_GetObjectSize;
  ck_function_list.C_GetAttributeValue=   &C_GetAttributeValue;
  ck_function_list.C_SetAttributeValue=   &C_SetAttributeValue;
  ck_function_list.C_FindObjectsInit= 	  &C_FindObjectsInit;
  ck_function_list.C_FindObjects= 	  &C_FindObjects;
  ck_function_list.C_FindObjectsFinal= 	  &C_FindObjectsFinal;
  ck_function_list.C_EncryptInit= 	  &C_EncryptInit;
  ck_function_list.C_Encrypt= 		  &C_Encrypt;
  ck_function_list.C_EncryptUpdate= 	  &C_EncryptUpdate;
  ck_function_list.C_EncryptFinal= 	  &C_EncryptFinal;
  ck_function_list.C_DecryptInit= 	  &C_DecryptInit;
  ck_function_list.C_Decrypt= 		  &C_Decrypt;
  ck_function_list.C_DecryptUpdate= 	  &C_DecryptUpdate;
  ck_function_list.C_DecryptFinal= 	  &C_DecryptFinal;
  ck_function_list.C_DigestInit= 	  &C_DigestInit;
  ck_function_list.C_Digest= 		  &C_Digest;
  ck_function_list.C_DigestUpdate= 	  &C_DigestUpdate;
  ck_function_list.C_DigestKey= 	  &C_DigestKey;
  ck_function_list.C_DigestFinal= 	  &C_DigestFinal;
  ck_function_list.C_SignInit= 		  &C_SignInit;
  ck_function_list.C_Sign= 		  &C_Sign;
  ck_function_list.C_SignUpdate= 	  &C_SignUpdate;
  ck_function_list.C_SignFinal= 	  &C_SignFinal;
  ck_function_list.C_SignRecoverInit= 	  &C_SignRecoverInit;
  ck_function_list.C_SignRecover= 	  &C_SignRecover;
  ck_function_list.C_VerifyInit= 	  &C_VerifyInit;
  ck_function_list.C_Verify= 		  &C_Verify;
  ck_function_list.C_VerifyUpdate= 	  &C_VerifyUpdate;
  ck_function_list.C_VerifyFinal= 	  &C_VerifyFinal;
  ck_function_list.C_VerifyRecoverInit=   &C_VerifyRecoverInit;
  ck_function_list.C_VerifyRecover= 	  &C_VerifyRecover;
  ck_function_list.C_DigestEncryptUpdate= &C_DigestEncryptUpdate;
  ck_function_list.C_DecryptDigestUpdate= &C_DecryptDigestUpdate;
  ck_function_list.C_SignEncryptUpdate=   &C_SignEncryptUpdate;
  ck_function_list.C_DecryptVerifyUpdate= &C_DecryptVerifyUpdate;
  ck_function_list.C_GenerateKey= 	  &C_GenerateKey;
  ck_function_list.C_GenerateKeyPair= 	  &C_GenerateKeyPair;
  ck_function_list.C_WrapKey= 		  &C_WrapKey;
  ck_function_list.C_UnwrapKey= 	  &C_UnwrapKey;
  ck_function_list.C_DeriveKey= 	  &C_DeriveKey;
  ck_function_list.C_SeedRandom= 	  &C_SeedRandom;
  ck_function_list.C_GenerateRandom= 	  &C_GenerateRandom;
  ck_function_list.C_GetFunctionStatus=   &C_GetFunctionStatus;
  ck_function_list.C_CancelFunction= 	  &C_CancelFunction;
  ck_function_list.C_WaitForSlotEvent= 	  &C_WaitForSlotEvent;

  CK_I_global_flags |= CK_IGF_FUNCTIONLIST_SET;
}

CK_DEFINE_FUNCTION(CK_RV, C_GetFunctionList)(
 CK_FUNCTION_LIST_PTR_PTR ppFunctionList
 )
{
  CK_RV rv = CKR_OK;

  CI_LogEntry("C_GetFunctionList", "starting...", rv, 1); 
  CI_CodeFktEntry("C_GetFunctionList", "%p", 
                  ppFunctionList);

 if(!(CK_I_global_flags & CK_IGF_FUNCTIONLIST_SET))
   set_function_list();

 if(ppFunctionList == NULL_PTR)
   {
     rv = CKR_GENERAL_ERROR;
     CI_LogEntry("C_GetFunctionList", "Pointer to function list not valid", rv, 0);
     return rv;
   }

  *ppFunctionList = &ck_function_list;

  CI_LogEntry("C_GetFunctionList", "...complete", rv, 1); 

  return rv;
}
/* }}} */

/*
 * Local variables:
 * folded-file: t
 * end:
 */




