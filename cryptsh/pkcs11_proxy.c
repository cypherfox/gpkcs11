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
 * NAME:        pkcs11_proxy.c
 * SYNOPSIS:    -
 * DESCRIPTION: -
 * FILES:       -
 * SEE/ALSO:    -
 * AUTHOR:      lbe
 * BUGS: *      -
 * HISTORY:     $Log$
 * HISTORY:     Revision 1.1.1.1  2000/10/15 16:48:15  cypherfox
 * HISTORY:     import of gpkcs11-0.7.2, first version for SourceForge
 * HISTORY:
 * HISTORY:     Revision 1.1  2000/02/07 14:04:08  lbe
 * HISTORY:     release 0.6 and clean up of files
 * HISTORY:
 * HISTORY:     Revision 1.4  2000/01/31 18:09:03  lbe
 * HISTORY:     lockdown prior to win_gdbm change
 * HISTORY:
 * HISTORY:     Revision 1.3  1999/12/01 13:44:47  lbe
 * HISTORY:     debug build system for missing central lib directory and debug afchine changes
 * HISTORY:
 * HISTORY:     Revision 1.2  1999/10/06 07:57:22  lbe
 * HISTORY:     solved netscape symbol clash problem
 * HISTORY:
 * HISTORY:     Revision 1.1  1999/06/16 09:46:10  lbe
 * HISTORY:     reorder files
 * HISTORY:
 * HISTORY:     Revision 1.2  1999/01/19 12:19:45  lbe
 * HISTORY:     first release lockdown
 * HISTORY:
 * HISTORY:     Revision 1.1  1998/11/04 17:45:07  lbe
 * HISTORY:     debug-lockdown
 * HISTORY:
 */
 
static char RCSID[]="$Id$";
const char* Version_pkcs11_proxy_c(){return RCSID;} 

/* This code proxies a pkcs11 connection to a (possibly) remote cryptsh
 * process.
 * It uses the guile library to parse the data comming over the network connection
 * this should avoid the need for bit twidling even if it is no the fastes solution.
 */


#include "pkcs11_proxy.h"
#include "error.h"

#ifdef CK_GENERIC
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <strings.h>
#include <unistd.h>
#endif

#include <string.h>
#include <stdio.h>
#include <errno.h>

/* name and port of the pkcs11 server */
#define CRYPTSH_SERVER "localhost"
#define CRYPTSH_PORT 4711

static int client_sock;

/* {{{ CI_OpenSocket */
CK_DEFINE_FUNCTION(int, CI_OpenSocket)()
{
  struct protoent *proto;
  struct sockaddr_in server;
  struct hostent *hp;

  /* error recording for the while thing */
  proto = getprotobyname("tcp");
  client_sock = socket(AF_INET, SOCK_STREAM, proto->p_proto);
  if(client_sock <0)
    {
      CI_VarLogEntry("CI_OpenSocket","error opening socket: %s",
		     CKR_GENERAL_ERROR,0,
		     strerror(errno));
      return CKR_GENERAL_ERROR;
    }


  hp = gethostbyname(CRYPTSH_SERVER);
  if (hp == 0) 
    {
      CI_VarLogEntry("C_OpenSocket","%s: unknown machine\n", 
		     CKR_GENERAL_ERROR, 0, 
		     CRYPTSH_SERVER);
      return CKR_GENERAL_ERROR;
    }
 
  bcopy(hp->h_addr, &(server.sin_addr), hp->h_length);
  server.sin_port = htons(CRYPTSH_PORT);
  server.sin_family = AF_INET;

  /* open the conection to the pkcs11 server */
  if (connect(client_sock, (struct sockaddr*)(&server), sizeof(server)) < 0) 
    {
      CI_VarLogEntry("C_OpenSocket", "connecting server stream socket: %s",
		     CKR_GENERAL_ERROR,0,
		     strerror(errno));
      return CKR_GENERAL_ERROR;
    }

  return CKR_OK;
}
/* }}} */ 
/* {{{ CI_CloseSocket */
CK_DEFINE_FUNCTION(void, CI_CloseSocket)()
{
  close(client_sock);

  return;
}
/* }}} */ 
/* {{{ CI_SendString */
CK_DEFINE_FUNCTION(CK_RV, CI_SendString)(
 CK_C_CHAR_PTR string,
 CK_CHAR_PTR CK_PTR retval
)
{
#define BUF_LEN 2048
  CK_ULONG pos=0;
  int len =0;
  CK_CHAR_PTR buff;

  buff = malloc(BUF_LEN+1);
  if(buff == NULL_PTR) return CKR_HOST_MEMORY;
  
  write(client_sock,string, strlen(string));

  do
    {
      if ((len = read(client_sock, &(buff[pos]), BUF_LEN-pos)) < 0)
	{
	  perror("reading stream message");
	  return CKR_GENERAL_ERROR;
	}      
      pos+=len;
      printf("read %ld characters: %.*s\n",pos,pos,buff);
    }
  while(len != 0);

  *retval = buff;
  /*  *retlen=pos; */
  (*retval)[pos+1]='\0';
  return CKR_OK;
}
/* }}} */
/* {{{ CI_ParseString */
CK_DEFINE_FUNCTION(CK_RV, CI_ParseString)(
  CK_CHAR_PTR retstring,
  SCM *retlist
)
{
  CK_CHAR_PTR buff;
  CK_RV rv;
  SCM retval;

  printf("ParseString!\n");
  printf("ParseString(%s,SCM)\n",retstring);
  /* wrap the string with  '(quote ' ')' */
  buff= malloc(strlen(retstring)+8+1);

  printf("ParseString2\n");
  if(buff == NULL_PTR) return CKR_HOST_MEMORY;

  printf("ParseString3\n");
  sprintf(buff, "(quote %s)", retstring);

  printf("ParseString4\n");
  *retlist = gh_eval_str(buff);

  printf("ParseString5\n");
  free(buff);
  
  printf("ParseString6\n");
  retval = gh_car(*retlist);

  printf("ParseString7\n");
  *retlist = gh_cdr(*retlist);

  printf("ParseString8\n");
  rv = gh_scm2ulong(retval);
  
  return rv;
}
/* }}} */

/* {{{ C_GetInfo */
CK_DEFINE_FUNCTION(CK_RV, C_GetInfo)(
 CK_INFO_PTR pInfo
)
{
  CK_RV retval = CKR_OK;
  CK_CHAR_PTR retstr;
  SCM retlist;

  CI_OpenSocket();
  CI_SendString("(C-GetInfo)",&retstr);
  CI_CloseSocket();

  retval = CI_ParseString(retstr,&retlist);
  if(retval != CKR_OK) return retval;

  /* TODO: this needs a lot of error checking */
  pInfo->cryptokiVersion.major= gh_scm2int(gh_caar(retlist));
  pInfo->cryptokiVersion.minor= gh_scm2int(gh_cdar(retlist));
  retlist=gh_cdr(retlist);

  gh_get_substr(gh_car(retlist),pInfo->manufacturerID,0,32);
  retlist=gh_cdr(retlist);

  pInfo->flags= gh_scm2ulong(gh_car(retlist));
  retlist=gh_cdr(retlist);

  gh_get_substr(gh_car(retlist),pInfo->libraryDescription,0,32);
  retlist=gh_cdr(retlist);
  
  pInfo->libraryVersion.major= gh_scm2int(gh_caar(retlist));
  pInfo->libraryVersion.minor= gh_scm2int(gh_cdar(retlist));

  return retval;
}
/* }}} */
/* {{{ C_Initialize */
CK_DEFINE_FUNCTION(CK_RV, C_Initialize)(
 CK_VOID_PTR pInitArgs
)
{
  CK_CHAR_PTR retstr;
  SCM retlist;
  CK_RV retval;

  /* send the call and recieve the returned text */
  CI_OpenSocket();
  CI_SendString("(C-Initialize)",&retstr);
  CI_CloseSocket();

  retval = CI_ParseString(retstr,&retlist);
  
  return retval;
}
/* }}} */
/* {{{ C_Finalize */
/* C_Finalize indicates that an application is done with the
 * Cryptoki library. */
CK_DEFINE_FUNCTION(CK_RV, C_Finalize)(
        CK_VOID_PTR pReserved
)
{
  CK_CHAR_PTR retstr;
  SCM retlist;
  CK_RV retval;

  /* send the call and recieve the returned text */
  CI_OpenSocket();
  CI_SendString("(C-Finalize)",&retstr);
  CI_CloseSocket();

  retval = CI_ParseString(retstr,&retlist);
  
  return retval;
}
/* }}} */
/* {{{ C_InitToken */
CK_DEFINE_FUNCTION(CK_RV, C_InitToken)
(
  CK_SLOT_ID     slotID,    /* ID of the token's slot */
  CK_CHAR_PTR    pPin,      /* the SO's initial PIN */
  CK_ULONG       ulPinLen,  /* length in bytes of the PIN */
  CK_CHAR_PTR    pLabel     /* 32-byte token label (blank padded) */
)
{
  CK_CHAR_PTR retstr, newstr;
  int newstr_len;
  SCM retlist;
  CK_RV retval;
  CK_CHAR_PTR buff;

  /* strlen("(C-InitToken  \"\" ")+8+(ulPinLen*3)+2+strlen(")")+1 */
  buff = malloc(28+ulPinLen);
  if(buff == NULL_PTR) return CKR_HOST_MEMORY;

  sprintf(buff,"(C-InitToken %.8ld \"%s\")",slotID,
	  CI_PrintableByteStream(pPin,ulPinLen));

  /* send the call and recieve the returned text */
  CI_OpenSocket();
  CI_SendString(buff,&retstr);
  CI_CloseSocket();
  free(buff);

  retval = CI_ParseString(retstr,&retlist);
  
  newstr = gh_scm2newstr(gh_car(retlist),&newstr_len);
  if(newstr_len != 32) return CKR_GENERAL_ERROR;

  memcpy(pLabel, newstr,32);
  free(newstr);

  return retval;
}
/* }}} */
/* {{{ C_GetFunctionList */
CK_FUNCTION_LIST ck_function_list;
 
void set_function_list(CK_FUNCTION_LIST_PTR ck_function_list);

/* {{{ void set_function_list(CK_FUNCTION_LIST_PTR ck_function_list) */
void set_function_list(CK_FUNCTION_LIST_PTR ck_function_list)
{
  ck_function_list->version.major=         0;
  ck_function_list->version.minor=         1;
  ck_function_list->C_Initialize=          &C_Initialize;
  ck_function_list->C_Finalize=            &C_Finalize;
  ck_function_list->C_GetInfo=             &C_GetInfo;
  ck_function_list->C_GetFunctionList=     &C_GetFunctionList;
  ck_function_list->C_GetSlotList=         &C_GetSlotList;
  ck_function_list->C_GetSlotInfo=         &C_GetSlotInfo;
  ck_function_list->C_GetTokenInfo=        &C_GetTokenInfo;
  ck_function_list->C_GetMechanismList=    &C_GetMechanismList;
  ck_function_list->C_GetMechanismInfo=    &C_GetMechanismInfo;
  ck_function_list->C_InitToken=           &C_InitToken;
  ck_function_list->C_InitPIN=             &C_InitPIN;
  ck_function_list->C_SetPIN=              &C_SetPIN;
  ck_function_list->C_OpenSession=         &C_OpenSession;
  ck_function_list->C_CloseSession=        &C_CloseSession;
  ck_function_list->C_CloseAllSessions=    &C_CloseAllSessions;
  ck_function_list->C_GetSessionInfo=      &C_GetSessionInfo;
  ck_function_list->C_GetOperationState=   &C_GetOperationState;
  ck_function_list->C_SetOperationState=   &C_SetOperationState;
  ck_function_list->C_Login=               &C_Login;
  ck_function_list->C_Logout=              &C_Logout;
  ck_function_list->C_CreateObject=        &C_CreateObject;
  ck_function_list->C_CopyObject=          &C_CopyObject;
  ck_function_list->C_DestroyObject=       &C_DestroyObject;
  ck_function_list->C_GetObjectSize=       &C_GetObjectSize;
  ck_function_list->C_GetAttributeValue=   &C_GetAttributeValue;
  ck_function_list->C_SetAttributeValue=   &C_SetAttributeValue;
  ck_function_list->C_FindObjectsInit=     &C_FindObjectsInit;
  ck_function_list->C_FindObjects=         &C_FindObjects;
  ck_function_list->C_FindObjectsFinal=    &C_FindObjectsFinal;
  ck_function_list->C_EncryptInit=         &C_EncryptInit;
  ck_function_list->C_Encrypt=             &C_Encrypt;
  ck_function_list->C_EncryptUpdate=       &C_EncryptUpdate;
  ck_function_list->C_EncryptFinal=        &C_EncryptFinal;
  ck_function_list->C_DecryptInit=         &C_DecryptInit;
  ck_function_list->C_Decrypt=             &C_Decrypt;
  ck_function_list->C_DecryptUpdate=       &C_DecryptUpdate;
  ck_function_list->C_DecryptFinal=        &C_DecryptFinal;
  ck_function_list->C_DigestInit=          &C_DigestInit;
  ck_function_list->C_Digest=              &C_Digest;
  ck_function_list->C_DigestUpdate=        &C_DigestUpdate;
  ck_function_list->C_DigestKey=           &C_DigestKey;
  ck_function_list->C_DigestFinal=         &C_DigestFinal;
  ck_function_list->C_SignInit=            &C_SignInit;
  ck_function_list->C_Sign=                &C_Sign;
  ck_function_list->C_SignUpdate=          &C_SignUpdate;
  ck_function_list->C_SignFinal=           &C_SignFinal;
  ck_function_list->C_SignRecoverInit=     &C_SignRecoverInit;
  ck_function_list->C_SignRecover=         &C_SignRecover;
  ck_function_list->C_VerifyInit=          &C_VerifyInit;
  ck_function_list->C_Verify=              &C_Verify;
  ck_function_list->C_VerifyUpdate=        &C_VerifyUpdate;
  ck_function_list->C_VerifyFinal=         &C_VerifyFinal;
  ck_function_list->C_VerifyRecoverInit=   &C_VerifyRecoverInit;
  ck_function_list->C_VerifyRecover=       &C_VerifyRecover;
  ck_function_list->C_DigestEncryptUpdate= &C_DigestEncryptUpdate;
  ck_function_list->C_DecryptDigestUpdate= &C_DecryptDigestUpdate;
  ck_function_list->C_SignEncryptUpdate=   &C_SignEncryptUpdate;
  ck_function_list->C_DecryptVerifyUpdate= &C_DecryptVerifyUpdate;
  ck_function_list->C_GenerateKey=         &C_GenerateKey;
  ck_function_list->C_GenerateKeyPair=     &C_GenerateKeyPair;
  ck_function_list->C_WrapKey=             &C_WrapKey;
  ck_function_list->C_UnwrapKey=           &C_UnwrapKey;
  ck_function_list->C_DeriveKey=           &C_DeriveKey;
  ck_function_list->C_SeedRandom=          &C_SeedRandom;
  ck_function_list->C_GenerateRandom=      &C_GenerateRandom;
  ck_function_list->C_GetFunctionStatus=   &C_GetFunctionStatus;
  ck_function_list->C_CancelFunction=      &C_CancelFunction;
  ck_function_list->C_WaitForSlotEvent=    &C_WaitForSlotEvent;
}
/* }}} */

CK_DEFINE_FUNCTION(CK_RV, C_GetFunctionList)(
 CK_FUNCTION_LIST_PTR_PTR ppFunctionList
 )
{
  set_function_list(&ck_function_list);

  *ppFunctionList = &ck_function_list;
  return CKR_OK;
}

/* }}} */
/* {{{ C_DecryptInit */
CK_DEFINE_FUNCTION(CK_RV, C_DecryptInit)(
        CK_SESSION_HANDLE hSession,
        CK_MECHANISM_PTR pMechanism,
        CK_OBJECT_HANDLE hKey
      )
{
  CK_CHAR_PTR retstr, mechanism;
  SCM retlist;
  CK_RV retval;
  CK_CHAR_PTR buff;

  mechanism = CI_ScanableMechanism(pMechanism);
  
  buff = malloc(strlen("(C-DecryptInit )")+8+strlen(mechanism)+8+1);
  if(buff == NULL_PTR) return CKR_HOST_MEMORY;

  sprintf(buff,"(C-DecryptInit %.8ld %s %.8ld)",hSession,mechanism,hKey);
  free(mechanism);

  /* send the call and recieve the returned text */
  CI_OpenSocket();
  CI_SendString(buff,&retstr);
  CI_CloseSocket();
  free(buff);

  retval = CI_ParseString(retstr,&retlist);
  
  return retval;
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
  CK_CHAR_PTR retstr, newstr;
  int newstr_len;
  SCM retlist;
  CK_RV retval;
  CK_CHAR_PTR buff;

  buff = malloc(strlen("(C-Decrypt \"\"  )")+8+(ulEncryptedDataLen*3)+2);
  if(buff == NULL_PTR) return CKR_HOST_MEMORY;

  sprintf(buff,"(C-Decrypt %.8ld \"%s\"%s)",hSession,
	  CI_PrintableByteStream(pEncryptedData,ulEncryptedDataLen),
	  (pData == NULL_PTR)?" #t":"");

  /* send the call and recieve the returned text */
  CI_OpenSocket();
  CI_SendString(buff,&retstr);
  CI_CloseSocket();
  free(buff);

  retval = CI_ParseString(retstr,&retlist);
  if(retval != CKR_OK) return retval;

  newstr = gh_scm2newstr(gh_car(retlist),&newstr_len);

  if(pData == NULL_PTR)
    *pulDataLen= newstr_len;
  else if(*pulDataLen <= newstr_len)
    memcpy(pData, newstr,newstr_len);
  else
    retval = CKR_BUFFER_TOO_SMALL; 

  free(newstr);

  return retval;
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
  CK_CHAR_PTR retstr, newstr;
  int newstr_len;
  SCM retlist;
  CK_RV retval;
  CK_CHAR_PTR buff;

  buff = malloc(strlen("(C-DecryptUpdate \"\"  )")+8+(ulEncryptedPartLen*3)+3);
  if(buff == NULL_PTR) return CKR_HOST_MEMORY;

  sprintf(buff,"(C-DecryptUpdate %.8ld \"%s\"%s)",
	  hSession,
	  CI_PrintableByteStream(pEncryptedPart,ulEncryptedPartLen),
	  (pPart == NULL_PTR)?" #t":"");

  /* send the call and recieve the returned text */
  CI_OpenSocket();
  CI_SendString(buff,&retstr);
  CI_CloseSocket();
  free(buff);

  retval = CI_ParseString(retstr,&retlist);
  if(retval != CKR_OK) return retval;

  newstr = gh_scm2newstr(gh_car(retlist),&newstr_len);

  if(pPart == NULL_PTR)
    *pulPartLen= newstr_len;
  else if(*pulPartLen <= newstr_len)
    memcpy(pPart, newstr,newstr_len);
  else
    retval = CKR_BUFFER_TOO_SMALL; 

  free(newstr);

  return retval;
}
/* }}} */
/* {{{ C_DecryptFinal */
CK_DEFINE_FUNCTION(CK_RV, C_DecryptFinal)(
        CK_SESSION_HANDLE hSession,
        CK_BYTE_PTR pLastPart,
        CK_ULONG_PTR pulLastPartLen
      )
{
  CK_CHAR_PTR retstr, newstr;
  int newstr_len;
  SCM retlist;
  CK_RV retval;
  CK_CHAR_PTR buff;

  buff = malloc(strlen("(C-DecryptFinal   )")+8+2);
  if(buff == NULL_PTR) return CKR_HOST_MEMORY;

  sprintf(buff,"(C-DecryptFinal %.8ld)%s",hSession,
	  (pLastPart == NULL_PTR)?" #f":"");

  /* send the call and recieve the returned text */
  CI_OpenSocket();
  CI_SendString(buff,&retstr);
  CI_CloseSocket();
  free(buff);

  retval = CI_ParseString(retstr,&retlist);
  if(retval != CKR_OK) return retval;

  newstr = gh_scm2newstr(gh_car(retlist),&newstr_len);

  if(pLastPart == NULL_PTR)
    *pulLastPartLen= newstr_len;
  else if(*pulLastPartLen <= newstr_len)
    memcpy(pLastPart, newstr,newstr_len);
  else
    retval = CKR_BUFFER_TOO_SMALL; 

  free(newstr);

  return retval;
}
/* }}} */
/* {{{ C_DigestInit */
CK_DEFINE_FUNCTION(CK_RV, C_DigestInit)(
      CK_SESSION_HANDLE hSession,
      CK_MECHANISM_PTR pMechanism
      )
{
  CK_CHAR_PTR retstr, mechanism;
  SCM retlist;
  CK_RV retval;
  CK_CHAR_PTR buff;

  mechanism = CI_ScanableMechanism(pMechanism);
  
  buff = malloc(strlen("(C-DigestInit )")+8+strlen(mechanism)+1);
  if(buff == NULL_PTR) return CKR_HOST_MEMORY;

  sprintf(buff,"(C-DigestInit %.8ld %s)",hSession,mechanism);
  free(mechanism);

  /* send the call and recieve the returned text */
  CI_OpenSocket();
  CI_SendString(buff,&retstr);
  CI_CloseSocket();
  free(buff);

  retval = CI_ParseString(retstr,&retlist);
  
  return retval;
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
  CK_CHAR_PTR retstr, newstr;
  int newstr_len;
  SCM retlist;
  CK_RV retval;
  CK_CHAR_PTR buff;

  buff = malloc(strlen("(C-Digest  \"\" )")+8+(ulDataLen*3)+2);
  if(buff == NULL_PTR) return CKR_HOST_MEMORY;

  sprintf(buff,"(C-Digest %.8ld \"%s\"%s)",
	  hSession,
	  CI_PrintableByteStream(pData,ulDataLen),
	  (pData == NULL_PTR)?" #t":"");

  /* send the call and recieve the returned text */
  CI_OpenSocket();
  CI_SendString(buff,&retstr);
  CI_CloseSocket();
  free(buff);

  retval = CI_ParseString(retstr,&retlist);
  if(retval != CKR_OK) return retval;

  newstr = gh_scm2newstr(gh_car(retlist),&newstr_len);

  if(pData == NULL_PTR)
    *pulDigestLen= newstr_len;
  else if(*pulDigestLen <= newstr_len)
    memcpy(pDigest, newstr,newstr_len);
  else
    retval = CKR_BUFFER_TOO_SMALL; 

  free(newstr);

  return retval;
}
/* }}} */
/* {{{ C_DigestUpdate */
CK_DEFINE_FUNCTION(CK_RV, C_DigestUpdate)(
        CK_SESSION_HANDLE hSession,
        CK_BYTE_PTR pPart,
        CK_ULONG ulPartLen
      )
{
  CK_CHAR_PTR retstr;
  SCM retlist;
  CK_RV retval;
  CK_CHAR_PTR buff;

  buff = malloc(strlen("(C-DigestUpdate \"\"  )")+8+(ulPartLen*3)+2);
  if(buff == NULL_PTR) return CKR_HOST_MEMORY;

  sprintf(buff,"(C-DigestUpdate %.8ld \"%s\")",
	  hSession,CI_PrintableByteStream(pPart,ulPartLen));

  /* send the call and recieve the returned text */
  CI_OpenSocket();
  CI_SendString(buff,&retstr);
  CI_CloseSocket();
  free(buff);

  retval = CI_ParseString(retstr,&retlist);

  return retval;
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
  CK_CHAR_PTR retstr;
  SCM retlist;
  CK_RV retval;
  CK_CHAR_PTR buff;

  buff = malloc(strlen("(C-DigestKey  )")+16+2);
  if(buff == NULL_PTR) return CKR_HOST_MEMORY;

  sprintf(buff,"(C-DigestKey %.8ld %.8ld)",hSession,hKey);

  /* send the call and recieve the returned text */
  CI_OpenSocket();
  CI_SendString(buff,&retstr);
  CI_CloseSocket();
  free(buff);

  retval = CI_ParseString(retstr,&retlist);

  return retval;
}
/* }}} */
/* {{{ C_DigestFinal */
CK_DEFINE_FUNCTION(CK_RV, C_DigestFinal)(
        CK_SESSION_HANDLE hSession,
        CK_BYTE_PTR pDigest,
        CK_ULONG_PTR pulDigestLen
      )
{
  CK_CHAR_PTR retstr, newstr;
  int newstr_len;
  SCM retlist;
  CK_RV retval;
  CK_CHAR_PTR buff;

  buff = malloc(strlen("(C-DigestFinal   )")+8+2);
  if(buff == NULL_PTR) return CKR_HOST_MEMORY;

  sprintf(buff,"(C-DigestFinal %.8ld%s)",hSession,
	  (pDigest == NULL_PTR)?" #t":"");

  /* send the call and recieve the returned text */
  CI_OpenSocket();
  CI_SendString(buff,&retstr);
  CI_CloseSocket();
  free(buff);

  retval = CI_ParseString(retstr,&retlist);
  if(retval != CKR_OK) return retval;

  newstr = gh_scm2newstr(gh_car(retlist),&newstr_len);

  if(pDigest == NULL_PTR)
    *pulDigestLen= newstr_len;
  else if(*pulDigestLen <= newstr_len)
    memcpy(pDigest, newstr,newstr_len);
  else
    retval = CKR_BUFFER_TOO_SMALL; 

  free(newstr);

  return retval;
}
/* }}} */
/* {{{ C_EncryptInit */
CK_DEFINE_FUNCTION(CK_RV, C_EncryptInit)(
        CK_SESSION_HANDLE hSession,
        CK_MECHANISM_PTR pMechanism,
        CK_OBJECT_HANDLE hKey
      )
{
  CK_CHAR_PTR retstr, mechanism;
  SCM retlist;
  CK_RV retval;
  CK_CHAR_PTR buff;

  mechanism = CI_ScanableMechanism(pMechanism);
  
  buff = malloc(strlen("(C-EncryptInit )")+8+strlen(mechanism)+8+1);
  if(buff == NULL_PTR) return CKR_HOST_MEMORY;

  sprintf(buff,"(C-EncryptInit %.8ld %s %.8ld)",hSession,mechanism,hKey);
  free(mechanism);

  /* send the call and recieve the returned text */
  CI_OpenSocket();
  CI_SendString(buff,&retstr);
  CI_CloseSocket();
  free(buff);

  retval = CI_ParseString(retstr,&retlist);
  
  return retval;
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
  CK_CHAR_PTR retstr, newstr;
  int newstr_len;
  SCM retlist;
  CK_RV retval;
  CK_CHAR_PTR buff;

  buff = malloc(strlen("(C-Encrypt   )")+8+ulDataLen+2);
  if(buff == NULL_PTR) return CKR_HOST_MEMORY;

  sprintf(buff,"(C-Encrypt %.8ld \"%s\"%s)",
	  hSession,
	  CI_PrintableByteStream(pData,ulDataLen),
	  (pEncryptedData == NULL_PTR)?" #t":"");

  /* send the call and recieve the returned text */
  CI_OpenSocket();
  CI_SendString(buff,&retstr);
  CI_CloseSocket();
  free(buff);

  retval = CI_ParseString(retstr,&retlist);
  if(retval != CKR_OK) return retval;

  newstr = gh_scm2newstr(gh_car(retlist),&newstr_len);

  if(pEncryptedData == NULL_PTR)
    *pulEncryptedDataLen= newstr_len;
  else if(*pulEncryptedDataLen <= newstr_len)
    memcpy(pEncryptedData, newstr,newstr_len);
  else
    retval = CKR_BUFFER_TOO_SMALL; 

  free(newstr);

  return retval;
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
  CK_CHAR_PTR retstr, newstr;
  int newstr_len;
  SCM retlist;
  CK_RV retval;
  CK_CHAR_PTR buff;

  buff = malloc(strlen("(C-EncryptUpdate \"\"  )")+8+(ulPartLen*3)+2);
  if(buff == NULL_PTR) return CKR_HOST_MEMORY;

  sprintf(buff,"(C-EncryptUpdate %.8ld \"%s\"%s)",
	  hSession,
	  CI_PrintableByteStream(pPart,ulPartLen),
	  (pEncryptedPart == NULL_PTR)?" #t":"");

  /* send the call and recieve the returned text */
  CI_OpenSocket();
  CI_SendString(buff,&retstr);
  CI_CloseSocket();
  free(buff);

  retval = CI_ParseString(retstr,&retlist);
  if(retval != CKR_OK) return retval;

  newstr = gh_scm2newstr(gh_car(retlist),&newstr_len);

  if(pEncryptedPart == NULL_PTR)
    *pulEncryptedPartLen= newstr_len;
  else if(*pulEncryptedPartLen <= newstr_len)
    memcpy(pEncryptedPart, newstr,newstr_len);
  else
    retval = CKR_BUFFER_TOO_SMALL; 

  free(newstr);

  return retval;
}
/* }}} */
/* {{{ C_EncryptFinal */
CK_DEFINE_FUNCTION(CK_RV, C_EncryptFinal)(
        CK_SESSION_HANDLE hSession,
        CK_BYTE_PTR pLastEncryptedPart,
        CK_ULONG_PTR pulLastEncryptedPartLen
      )
{
  CK_CHAR_PTR retstr, newstr;
  int newstr_len;
  SCM retlist;
  CK_RV retval;
  CK_CHAR_PTR buff;

  buff = malloc(strlen("(C-DecryptFinal   )")+8+2);
  if(buff == NULL_PTR) return CKR_HOST_MEMORY;

  sprintf(buff,"(C-DecryptFinal %.8ld%s)",hSession,
	  (pLastEncryptedPart == NULL_PTR)?" #t":"");

  /* send the call and recieve the returned text */
  CI_OpenSocket();
  CI_SendString(buff,&retstr);
  CI_CloseSocket();
  free(buff);

  retval = CI_ParseString(retstr,&retlist);
  if(retval != CKR_OK) return retval;

  newstr = gh_scm2newstr(gh_car(retlist),&newstr_len);

  if(pLastEncryptedPart == NULL_PTR)
    *pulLastEncryptedPartLen= newstr_len;
  else if(*pulLastEncryptedPartLen <= newstr_len)
    memcpy(pLastEncryptedPart, newstr,newstr_len);
  else
    retval = CKR_BUFFER_TOO_SMALL; 

  free(newstr);

  return retval;
}
/* }}} */
/* {{{ C_GetSlotList */
CK_DEFINE_FUNCTION(CK_RV, C_GetSlotList)(
        CK_BBOOL tokenPresent,
        CK_SLOT_ID_PTR pSlotList,
        CK_ULONG_PTR pulCount
      )
{
  CK_RV retval = CKR_OK;
  CK_CHAR_PTR retstr;
  SCM retlist;
  CK_CHAR_PTR buff;
  CK_ULONG len;
  int i;

  if(tokenPresent)
    buff="(C-GetSlotList #f)";
  else
    buff="(C-GetSlotList #t)";

  CI_OpenSocket();
  CI_SendString(buff,&retstr);
  CI_CloseSocket();

  retval = CI_ParseString(retstr,&retlist);
  if(retval != CKR_OK) return gh_scm2ulong(retval);

  len = gh_length(retlist);

  if(pSlotList == NULL_PTR)
    *pulCount = len;
  else if(*pulCount <= len)
    {
      for(i=0;i<len; i++,retlist = gh_cdr(retlist))
	pSlotList[i] = gh_scm2ulong(gh_car(retlist));
    }
  else
    retval = CKR_BUFFER_TOO_SMALL; 

  return gh_scm2ulong(retval);
}
/* }}} */
/* {{{ C_GetSlotInfo */
CK_DEFINE_FUNCTION(CK_RV, C_GetSlotInfo)(
        CK_SLOT_ID slotID,
        CK_SLOT_INFO_PTR pInfo
      )
{
  CK_RV retval = CKR_OK;
  CK_CHAR_PTR retstr;
  SCM retlist;
  CK_CHAR buff[40];

  sprintf(buff,"(C-GetSlotInfo %ld)",slotID);

  CI_OpenSocket();
  CI_SendString(buff,&retstr);
  CI_CloseSocket();

  retval = CI_ParseString(retstr,&retlist);
  if(retval != CKR_OK) return retval;

  gh_get_substr(gh_car(retlist),pInfo->slotDescription,0,64);
  retlist = gh_cdr(retlist);
  gh_get_substr(gh_car(retlist),pInfo->manufacturerID,0,32);
  retlist = gh_cdr(retlist);
  pInfo->flags = gh_scm2ulong(gh_car(retlist));
  retlist = gh_cdr(retlist);
  pInfo->hardwareVersion.major= gh_scm2int(gh_caar(retlist));
  pInfo->hardwareVersion.minor= gh_scm2int(gh_cdar(retlist));
  retlist=gh_cdr(retlist);
  pInfo->firmwareVersion.major= gh_scm2int(gh_caar(retlist));
  pInfo->firmwareVersion.minor= gh_scm2int(gh_cdar(retlist));
  retlist=gh_cdr(retlist);

  return retval;  
}
/* }}} */
/* {{{ C_GetTokenInfo */
CK_DEFINE_FUNCTION(CK_RV, C_GetTokenInfo)(
        CK_SLOT_ID slotID,
        CK_TOKEN_INFO_PTR pInfo
      )
{
  CK_RV retval = CKR_OK;
  CK_CHAR_PTR retstr;
  SCM retlist;
  CK_CHAR buff[40];

  sprintf(buff,"(C-GetTokenInfo %ld)",slotID);

  CI_OpenSocket();
  CI_SendString(buff,&retstr);
  CI_CloseSocket();

  retval = CI_ParseString(retstr,&retlist);
  if(retval != CKR_OK) return retval;

  gh_get_substr(gh_car(retlist),pInfo->label,0,32);
  retlist = gh_cdr(retlist);
  gh_get_substr(gh_car(retlist),pInfo->manufacturerID,0,32);
  retlist = gh_cdr(retlist);
  gh_get_substr(gh_car(retlist),pInfo->model,0,16);
  retlist = gh_cdr(retlist);
  gh_get_substr(gh_car(retlist),pInfo->serialNumber,0,16);
  retlist = gh_cdr(retlist);
  pInfo->flags = gh_scm2ulong(gh_car(retlist));
  retlist = gh_cdr(retlist);
  pInfo->ulMaxSessionCount = gh_scm2ulong(gh_car(retlist));
  retlist = gh_cdr(retlist);
  pInfo->ulSessionCount = gh_scm2ulong(gh_car(retlist));
  retlist = gh_cdr(retlist);
  pInfo->ulMaxRwSessionCount = gh_scm2ulong(gh_car(retlist));
  retlist = gh_cdr(retlist);
  pInfo->ulRwSessionCount = gh_scm2ulong(gh_car(retlist));
  retlist = gh_cdr(retlist);
  pInfo->ulMaxPinLen = gh_scm2ulong(gh_car(retlist));
  retlist = gh_cdr(retlist);
  pInfo->ulMinPinLen = gh_scm2ulong(gh_car(retlist));
  retlist = gh_cdr(retlist);
  pInfo->ulTotalPublicMemory = gh_scm2ulong(gh_car(retlist));
  retlist = gh_cdr(retlist);
  pInfo->ulFreePublicMemory = gh_scm2ulong(gh_car(retlist));
  retlist = gh_cdr(retlist);
  pInfo->ulTotalPrivateMemory = gh_scm2ulong(gh_car(retlist));
  retlist = gh_cdr(retlist);
  pInfo->ulFreePrivateMemory = gh_scm2ulong(gh_car(retlist));
  retlist = gh_cdr(retlist);
  pInfo->hardwareVersion.major= gh_scm2int(gh_caar(retlist));
  pInfo->hardwareVersion.minor= gh_scm2int(gh_cdar(retlist));
  retlist=gh_cdr(retlist);
  pInfo->firmwareVersion.major= gh_scm2int(gh_caar(retlist));
  pInfo->firmwareVersion.minor= gh_scm2int(gh_cdar(retlist));
  retlist=gh_cdr(retlist);
  gh_get_substr(gh_car(retlist),pInfo->utcTime,0,16);
  retlist = gh_cdr(retlist);

  return retval;  
}
/* }}} */
/* {{{ C_GetMechanismList */
CK_DEFINE_FUNCTION(CK_RV, C_GetMechanismList)(
        CK_SLOT_ID slotID,
        CK_MECHANISM_TYPE_PTR pMechanismList,
        CK_ULONG_PTR pulCount
      )
{
  CK_RV retval = CKR_OK;
  CK_CHAR_PTR retstr;
  SCM retlist;
  CK_CHAR buff[40];
  CK_ULONG len;
  int i;

  sprintf(buff,"(C-GetMechansimList %ld)", slotID);

  CI_OpenSocket();
  CI_SendString(buff,&retstr);
  CI_CloseSocket();

  retval = CI_ParseString(retstr,&retlist);
  if(retval != CKR_OK) return retval;

  len = gh_length(retlist);

  if(pMechanismList == NULL_PTR)
    *pulCount = len;
  else if(*pulCount <= len)
    {
      for(i=0;i<len; i++,retlist = gh_cdr(retlist))
	pMechanismList[i] = gh_scm2ulong(gh_car(retlist));
    }
  else
    retval = CKR_BUFFER_TOO_SMALL; 

  return retval;
}
/* }}} */
/* {{{ C_GetMechanismInfo */
CK_DEFINE_FUNCTION(CK_RV, C_GetMechanismInfo)(
        CK_SLOT_ID slotID,
        CK_MECHANISM_TYPE type,
        CK_MECHANISM_INFO_PTR pInfo
      )
{
  CK_RV retval = CKR_OK;
  CK_CHAR_PTR retstr;
  SCM retlist;
  CK_CHAR buff[50];

  sprintf(buff,"(C-GetSlotInfo %ld %ld)",slotID,type);

  CI_OpenSocket();
  CI_SendString(buff,&retstr);
  CI_CloseSocket();

  retval = CI_ParseString(retstr,&retlist);
  if(retval != CKR_OK) return retval;

  return gh_cons(gh_ulong2scm(retval),
		 gh_list(gh_ulong2scm(pInfo->ulMinKeySize),
			 gh_ulong2scm(pInfo->ulMaxKeySize),
			 gh_ulong2scm(pInfo->flags),
			 SCM_UNDEFINED));

  pInfo->ulMinKeySize = gh_scm2ulong(gh_car(retlist));
  retlist = gh_cdr(retlist);
  pInfo->ulMinKeySize = gh_scm2ulong(gh_car(retlist));
  retlist = gh_cdr(retlist);
  pInfo->flags = gh_scm2ulong(gh_car(retlist));
  retlist = gh_cdr(retlist);

  return retval;  
}
/* }}} */
/* {{{ C_FindObjectsInit */
/* C_FindObjectsInit initializes a search for token and session
 * objects that match a template. */
CK_DEFINE_FUNCTION(CK_RV, C_FindObjectsInit)
     (
      CK_SESSION_HANDLE hSession,   /* the session's handle */
      CK_ATTRIBUTE_PTR  pTemplate,  /* attribute values to match */
      CK_ULONG          ulCount     /* attrs in search template */
      )
{
  CK_CHAR_PTR obj_desc;
  CK_CHAR_PTR buff;
  CK_RV retval = CKR_OK;
  CK_CHAR_PTR retstr;
  SCM retlist;

  obj_desc = CI_PrintTemplate(pTemplate,ulCount);

  buff = malloc(strlen(obj_desc)+strlen("(C-FindObjectsInit  )")+8+1);
  if(buff == NULL_PTR) return CKR_HOST_MEMORY;

  sprintf(buff,"(C-FindObjectsInit %ld %s)",hSession,obj_desc);

  CI_OpenSocket();
  CI_SendString(buff,&retstr);
  CI_CloseSocket();
  free(buff);

  retval = CI_ParseString(retstr,&retlist);
  free(retstr);
  
  return retval;  
}
/* }}} */
/* {{{ C_FindObjects */
/* C_FindObjects continues a search for token and session
 * objects that match a template, obtaining additional object
 * handles. */
CK_DEFINE_FUNCTION(CK_RV, C_FindObjects)(
  CK_SESSION_HANDLE    hSession,          /* session's handle */
  CK_OBJECT_HANDLE_PTR phObject,          /* gets obj. handles */
  CK_ULONG             ulMaxObjectCount,  /* max handles to get */
  CK_ULONG_PTR         pulObjectCount     /* actual # returned */
)
{
  CK_CHAR buff[40];
  CK_RV retval = CKR_OK;
  CK_CHAR_PTR retstr;
  SCM retlist;
  int i;

  sprintf(buff,"(C-FindObjectsInit %ld %ld)",hSession,ulMaxObjectCount);

  CI_OpenSocket();
  CI_SendString(buff,&retstr);
  CI_CloseSocket();
  free(buff);

  /* this asumes that the guile function ensures that not too many handles are xmitted */

  retval = CI_ParseString(retstr,&retlist);
  free(retstr);
  if(retval != CKR_OK) return retval;

  *pulObjectCount = gh_length(retlist);

  for(i=0;i < *pulObjectCount; i++,retlist = gh_cdr(retlist))
    phObject[i] = gh_scm2ulong(gh_car(retlist));
  
  return retval;    
}
/* }}} */
/* {{{ C_FindObjectsFinal */
/* C_FindObjectsFinal finishes a search for token and session
 * objects. */
CK_DEFINE_FUNCTION(CK_RV, C_FindObjectsFinal)
(
  CK_SESSION_HANDLE hSession  /* the session's handle */
)
{
  CK_CHAR buff[40];
  CK_RV retval = CKR_OK;
  CK_CHAR_PTR retstr;
  SCM retlist;

  sprintf(buff,"(C-FindObjectsFinal %ld)",hSession);

  CI_OpenSocket();
  CI_SendString(buff,&retstr);
  CI_CloseSocket();
  free(buff);

  retval = CI_ParseString(retstr,&retlist);
  free(retstr);
  
  return retval;  
}
/* }}} */
/* {{{ C_OpenSession */
CK_DEFINE_FUNCTION(CK_RV, C_OpenSession)(
        CK_SLOT_ID slotID,
        CK_FLAGS flags,
        CK_VOID_PTR pApplication,
        CK_NOTIFY Notify,
        CK_SESSION_HANDLE_PTR phSession
      )
{
  CK_CHAR buff[40];
  CK_RV retval = CKR_OK;
  CK_CHAR_PTR retstr;
  SCM retlist;

  sprintf(buff,"(C-OpenSession %ld %ld)",slotID, flags);

  CI_OpenSocket();
  CI_SendString(buff,&retstr);
  CI_CloseSocket();
  free(buff);

  retval = CI_ParseString(retstr,&retlist);
  free(retstr);
  if(retval != CKR_OK) return retval;

  *phSession = gh_scm2ulong(gh_car(retlist));

  return retval;  
}
/* }}} */
/* {{{ C_CloseSession */
CK_DEFINE_FUNCTION(CK_RV, C_CloseSession)(
        CK_SESSION_HANDLE hSession
      )
{
  CK_CHAR buff[40];
  CK_RV retval = CKR_OK;
  CK_CHAR_PTR retstr;
  SCM retlist;

  sprintf(buff,"(C-CloseSession %ld)",hSession);

  CI_OpenSocket();
  CI_SendString(buff,&retstr);
  CI_CloseSocket();
  free(buff);

  retval = CI_ParseString(retstr,&retlist);
  free(retstr);
  
  return retval;  
}
/* }}} */
/* {{{ C_CreateObject */
CK_DEFINE_FUNCTION(CK_RV, C_CreateObject)(
        CK_SESSION_HANDLE hSession,
        CK_ATTRIBUTE_PTR pTemplate,
        CK_ULONG ulCount,
        CK_OBJECT_HANDLE_PTR phObject
      )
{
  CK_CHAR_PTR obj_desc;
  CK_CHAR_PTR buff;
  CK_RV retval = CKR_OK;
  CK_CHAR_PTR retstr;
  SCM retlist;

  obj_desc = CI_PrintTemplate(pTemplate,ulCount);

  buff = malloc(strlen(obj_desc)+strlen("(C-CreateObject  )")+8+1);
  if(buff == NULL_PTR) return CKR_HOST_MEMORY;

  sprintf(buff,"(C-CreateObject %ld %s)",hSession,obj_desc);

  CI_OpenSocket();
  CI_SendString(buff,&retstr);
  CI_CloseSocket();
  free(buff);

  retval = CI_ParseString(retstr,&retlist);
  free(retstr);
  if(retval != CKR_OK) return retval;

  *phObject = gh_scm2ulong(gh_car(retlist));
  
  return retval;  
}
/* }}} */
/* {{{ C_DestroyObject */
CK_DEFINE_FUNCTION(CK_RV, C_DestroyObject)(
        CK_SESSION_HANDLE hSession,
        CK_OBJECT_HANDLE hObject
      )
{
  CK_CHAR buff[40];
  CK_RV retval = CKR_OK;
  CK_CHAR_PTR retstr;
  SCM retlist;

  sprintf(buff,"(C-DestroyObject %ld %ld)",hSession, hObject);

  CI_OpenSocket();
  CI_SendString(buff,&retstr);
  CI_CloseSocket();
  free(buff);

  retval = CI_ParseString(retstr,&retlist);
  free(retstr);

  return retval;  
}
/* }}} */
/* {{{ C_SignInit */
CK_DEFINE_FUNCTION(CK_RV, C_SignInit)(
        CK_SESSION_HANDLE hSession,
        CK_MECHANISM_PTR pMechanism,
        CK_OBJECT_HANDLE hKey
      )
{
  CK_CHAR_PTR retstr, mechanism;
  SCM retlist;
  CK_RV retval;
  CK_CHAR_PTR buff;

  mechanism = CI_ScanableMechanism(pMechanism);
  
  buff = malloc(strlen("(C-SignInit )")+8+strlen(mechanism)+8+1);
  if(buff == NULL_PTR) return CKR_HOST_MEMORY;

  sprintf(buff,"(C-SignInit %.8ld %s %.8ld)",hSession,mechanism,hKey);
  free(mechanism);

  /* send the call and recieve the returned text */
  CI_OpenSocket();
  CI_SendString(buff,&retstr);
  CI_CloseSocket();
  free(buff);

  retval = CI_ParseString(retstr,&retlist);
  
  return retval;
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
  CK_CHAR_PTR retstr, newstr;
  int newstr_len;
  SCM retlist;
  CK_RV retval;
  CK_CHAR_PTR buff;

  buff = malloc(strlen("(C-Sign  \"\"    )")+8+(ulDataLen*3)+2);
  if(buff == NULL_PTR) return CKR_HOST_MEMORY;

  sprintf(buff,"(C-Sign %.8ld \"%s\"%s)",hSession,
	  CI_PrintableByteStream(pData,ulDataLen),
	  (pSignature == NULL_PTR)?" #t":"");

  /* send the call and recieve the returned text */
  CI_OpenSocket();
  CI_SendString(buff,&retstr);
  CI_CloseSocket();
  free(buff);

  retval = CI_ParseString(retstr,&retlist);
  free(retstr);
  if(retval != CKR_OK) return retval;

  newstr = gh_scm2newstr(gh_car(retlist),&newstr_len);

  if(pData == NULL_PTR)
    *pulSignatureLen= newstr_len;
  else if(*pulSignatureLen <= newstr_len)
    memcpy(pSignature, newstr,newstr_len);
  else
    retval = CKR_BUFFER_TOO_SMALL; 

  free(newstr);

  return retval;
}
/* }}} */
/* {{{ C_SignUpdate */
CK_DEFINE_FUNCTION(CK_RV, C_SignUpdate)(
        CK_SESSION_HANDLE hSession,  /* the session's handle */
        CK_BYTE_PTR pPart,           /* the data to sign */
        CK_ULONG ulPartLen           /* count of bytes to sign */
      )
{
  CK_CHAR_PTR retstr;
  SCM retlist;
  CK_RV retval;
  CK_CHAR_PTR buff;

  buff = malloc(strlen("(C-SignUpdate \"\"  )")+8+(ulPartLen*3)+2);
  if(buff == NULL_PTR) return CKR_HOST_MEMORY;

  sprintf(buff,"(C-SignUpdate %.8ld \"%s\")",hSession,
	  CI_PrintableByteStream(pPart,ulPartLen));

  /* send the call and recieve the returned text */
  CI_OpenSocket();
  CI_SendString(buff,&retstr);
  CI_CloseSocket();
  free(buff);

  retval = CI_ParseString(retstr,&retlist);

  return gh_scm2ulong(retval);
}
/* }}} */
/* {{{ C_SignFinal */
CK_DEFINE_FUNCTION(CK_RV, C_SignFinal)(
        CK_SESSION_HANDLE hSession,
        CK_BYTE_PTR pSignature,
        CK_ULONG_PTR pulSignatureLen
      )
{
  CK_CHAR_PTR retstr, newstr;
  int newstr_len;
  SCM retlist;
  CK_RV retval;
  CK_CHAR_PTR buff;

  buff = malloc(strlen("(C-SignFinal   )")+8+2);
  if(buff == NULL_PTR) return CKR_HOST_MEMORY;

  sprintf(buff,"(C-SignFinal %.8ld %s)",hSession,(pSignature == NULL_PTR)?" #t":"");

  /* send the call and recieve the returned text */
  CI_OpenSocket();
  CI_SendString(buff,&retstr);
  CI_CloseSocket();
  free(buff);

  retval = CI_ParseString(retstr,&retlist);
  free(retstr);
  if(retval != CKR_OK) return retval;

  newstr = gh_scm2newstr(gh_car(retlist),&newstr_len);

  if(pSignature == NULL_PTR)
    *pulSignatureLen= newstr_len;
  else if(*pulSignatureLen <= newstr_len)
    memcpy(pSignature, newstr,newstr_len);
  else
    retval = CKR_BUFFER_TOO_SMALL; 

  free(newstr);

  return gh_scm2ulong(retval);
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
  CK_CHAR_PTR retstr, mechanism;
  SCM retlist;
  CK_RV retval;
  CK_CHAR_PTR buff;

  mechanism = CI_ScanableMechanism(pMechanism);
  
  buff = malloc(strlen("(C-SignRecoverInit )")+8+strlen(mechanism)+8+1);
  if(buff == NULL_PTR) return CKR_HOST_MEMORY;

  sprintf(buff,"(C-SignRecoverInit %.8ld %s %.8ld)",hSession,mechanism,hKey);
  free(mechanism);

  /* send the call and recieve the returned text */
  CI_OpenSocket();
  CI_SendString(buff,&retstr);
  CI_CloseSocket();
  free(buff);

  retval = CI_ParseString(retstr,&retlist);
  
  return retval;
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
  SCM retlist;
  CK_RV retval;
  CK_CHAR_PTR retstr, newstr;
  int newstr_len;
  CK_CHAR_PTR buff;

  buff = malloc(strlen("(C-SignRecover   )")+8+ulDataLen+2);
  if(buff == NULL_PTR) return CKR_HOST_MEMORY;
  sprintf(buff,"(C-SignRecover %.8ld %s%s)",hSession,
	  CI_PrintableByteStream(pData,ulDataLen),
	  (pSignature == NULL_PTR)?" #t":"");

  /* send the call and recieve the returned text */
  CI_OpenSocket();
  CI_SendString(buff,&retstr);
  CI_CloseSocket();
  free(buff);

  retval = CI_ParseString(retstr,&retlist);
  if(retval != CKR_OK) return retval;

  newstr = gh_scm2newstr(gh_car(retlist),&newstr_len);

  if(pData == NULL_PTR)
    *pulSignatureLen= newstr_len;
  else if(*pulSignatureLen <= newstr_len)
    memcpy(pSignature, newstr,newstr_len);
  else
    retval = CKR_BUFFER_TOO_SMALL; 

  free(newstr);

  return retval;
}
/* }}} */
/* {{{ C_GenerateKey */
CK_DEFINE_FUNCTION(CK_RV, C_GenerateKey)(
        CK_SESSION_HANDLE hSession,
        CK_MECHANISM_PTR pMechanism,
        CK_ATTRIBUTE_PTR pTemplate,
        CK_ULONG ulCount,
        CK_OBJECT_HANDLE_PTR phKey
      )
{
  SCM retlist;
  CK_RV retval;
  CK_CHAR_PTR retstr;
  CK_CHAR_PTR template;
  CK_CHAR_PTR mechanism;
  CK_CHAR_PTR buff;

  mechanism = CI_ScanableMechanism(pMechanism);
  template = CI_PrintTemplate(pTemplate,ulCount);
  
  buff = malloc(strlen("(C-GenerateKeyPair    )")+8+
		strlen(mechanism)+
		strlen(template)+1);
  if(buff == NULL_PTR) return CKR_HOST_MEMORY;

  sprintf(buff, "(C-GenerateKeyPair %ld %s %s)",hSession,mechanism,
	  template);
  free(mechanism);
  free(template);

  /* send the call and recieve the returned text */
  CI_OpenSocket();
  CI_SendString(buff,&retstr);
  CI_CloseSocket();
  free(buff);

  retval = CI_ParseString(retstr,&retlist);
  free(retstr);
  if(retval != CKR_OK) return retval;

  *phKey = gh_scm2ulong(gh_car(retlist));

  return retval;
}
/* }}} */
/* {{{ C_GenerateKeyPair */
CK_DEFINE_FUNCTION(CK_RV, C_GenerateKeyPair)(
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
  SCM retlist;
  CK_RV retval;
  CK_CHAR_PTR retstr;
  CK_CHAR_PTR public_template;
  CK_CHAR_PTR private_template;
  CK_CHAR_PTR mechanism;
  CK_CHAR_PTR buff;

  mechanism = CI_ScanableMechanism(pMechanism);
  public_template = CI_PrintTemplate(pPublicKeyTemplate,ulPublicKeyAttributeCount);
  private_template = CI_PrintTemplate(pPrivateKeyTemplate,ulPrivateKeyAttributeCount);
  
  buff = malloc(strlen("(C-GenerateKeyPair    )")+8+
		strlen(mechanism)+
		strlen(public_template)+
		strlen(private_template)+1);
  if(buff == NULL_PTR) return CKR_HOST_MEMORY;

  sprintf(buff, "(C-GenerateKeyPair %ld %s %s %s)",hSession,mechanism,
	  public_template,private_template);
  free(mechanism);
  free(public_template);
  free(private_template);

  /* send the call and recieve the returned text */
  CI_OpenSocket();
  CI_SendString(buff,&retstr);
  CI_CloseSocket();
  free(buff);

  retval = CI_ParseString(retstr,&retlist);
  free(retstr);
  if(retval != CKR_OK) return retval;

  *phPublicKey = gh_scm2ulong(gh_car(retlist));
  *phPrivateKey = gh_scm2ulong(gh_cadr(retlist));

  return retval;
}
/* }}} */
/* {{{ C_VerifyInit */
CK_DEFINE_FUNCTION(CK_RV, C_VerifyInit)(
        CK_SESSION_HANDLE hSession,
        CK_MECHANISM_PTR pMechanism,
        CK_OBJECT_HANDLE hKey
      )
{
  CK_CHAR_PTR retstr, mechanism;
  SCM retlist;
  CK_RV retval;
  CK_CHAR_PTR buff;

  mechanism = CI_ScanableMechanism(pMechanism);
  
  buff = malloc(strlen("(C-VerifyInit )")+8+strlen(mechanism)+8+1);
  if(buff == NULL_PTR) return CKR_HOST_MEMORY;

  sprintf(buff,"(C-VerifyInit %.8ld %s %.8ld)",hSession,mechanism,hKey);
  free(mechanism);

  /* send the call and recieve the returned text */
  CI_OpenSocket();
  CI_SendString(buff,&retstr);
  CI_CloseSocket();
  free(buff);

  retval = CI_ParseString(retstr,&retlist);
  
  return retval;
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
  CK_CHAR_PTR retstr;
  SCM retlist;
  CK_RV retval;
  CK_CHAR_PTR buff,tmp1,tmp2;

  tmp1=CI_PrintableByteStream(pData, ulDataLen);
  tmp2=CI_PrintableByteStream(pSignature, ulSignatureLen);

  buff = malloc(strlen("(C-Verify     )")+8+strlen(tmp1)+strlen(tmp2)+2);

  if(buff == NULL_PTR) return CKR_HOST_MEMORY;
  sprintf(buff,"(C-Verify %.8ld %s %s)",hSession, 
	  tmp1,tmp2);
  free(tmp1);
  free(tmp2);

  /* send the call and recieve the returned text */
  CI_OpenSocket();
  CI_SendString(buff,&retstr);
  CI_CloseSocket();
  free(buff);

  retval = CI_ParseString(retstr,&retlist);

  return retval;
}
/* }}} */
/* {{{ C_VerifyUpdate */
CK_DEFINE_FUNCTION(CK_RV, C_VerifyUpdate)(
        CK_SESSION_HANDLE hSession,  /* the session's handle */
        CK_BYTE_PTR pPart,           /* the data to verify */
        CK_ULONG ulPartLen           /* count of bytes to verify */
      )
{
  CK_CHAR_PTR retstr;
  SCM retlist;
  CK_RV retval;
  CK_CHAR_PTR buff,tmp;

  tmp = CI_PrintableByteStream(pPart,ulPartLen);

  buff = malloc(strlen("(C-VerifyUpdate   )")+8+strlen(tmp)+2);
  if(buff == NULL_PTR) return CKR_HOST_MEMORY;

  sprintf(buff,"(C-VerifyUpdate %.8ld %s)",hSession,tmp);
  free(tmp);

  /* send the call and recieve the returned text */
  CI_OpenSocket();
  CI_SendString(buff,&retstr);
  CI_CloseSocket();
  free(buff);

  retval = CI_ParseString(retstr,&retlist);

  return gh_scm2ulong(retval);
}
/* }}} */
/* {{{ C_VerifyFinal */
CK_DEFINE_FUNCTION(CK_RV, C_VerifyFinal)(
        CK_SESSION_HANDLE hSession,
        CK_BYTE_PTR       pSignature,
        CK_ULONG          ulSignatureLen
      )
{
  CK_CHAR_PTR retstr;
  SCM retlist;
  CK_RV retval;
  CK_CHAR_PTR buff,tmp;

  tmp = CI_PrintableByteStream(pSignature,ulSignatureLen);

  buff = malloc(strlen("(C-VerifyFinal   )")+8+strlen(tmp)+2);
  if(buff == NULL_PTR) return CKR_HOST_MEMORY;

  sprintf(buff,"(C-VerifyFinal %.8ld %s)",hSession,tmp);
  free(tmp);

  /* send the call and recieve the returned text */
  CI_OpenSocket();
  CI_SendString(buff,&retstr);
  CI_CloseSocket();
  free(buff);

  retval = CI_ParseString(retstr,&retlist);
  free(retstr);
  
  return retval;
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
  CK_CHAR_PTR retstr, mechanism;
  SCM retlist;
  CK_RV retval;
  CK_CHAR_PTR buff;

  mechanism = CI_ScanableMechanism(pMechanism);
  
  buff = malloc(strlen("(C-VerifyRecoverInit  )")+8+strlen(mechanism)+8+1);
  if(buff == NULL_PTR) return CKR_HOST_MEMORY;

  sprintf(buff,"(C-VerifyRecoverInit %.8ld %s %.8ld)",hSession,mechanism,hKey);
  free(mechanism);

  /* send the call and recieve the returned text */
  CI_OpenSocket();
  CI_SendString(buff,&retstr);
  CI_CloseSocket();
  free(buff);

  retval = CI_ParseString(retstr,&retlist);
  
  return retval;
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
  SCM retlist;
  CK_RV retval;
  CK_CHAR_PTR retstr, newstr;
  int newstr_len;
  CK_CHAR_PTR buff,tmp;

  tmp = CI_PrintableByteStream(pSignature,ulSignatureLen);

  buff = malloc(strlen("(C-VerifyRecover   )")+8+strlen(tmp)+2);
  if(buff == NULL_PTR) return CKR_HOST_MEMORY;

  sprintf(buff,"(C-SignRecover %.8ld %s%s)",hSession,
	  tmp,(pSignature == NULL_PTR)?" #t":"");
  free(tmp);

  /* send the call and recieve the returned text */
  CI_OpenSocket();
  CI_SendString(buff,&retstr);
  CI_CloseSocket();
  free(buff);

  retval = CI_ParseString(retstr,&retlist);
  if(retval != CKR_OK) return retval;

  newstr = gh_scm2newstr(gh_car(retlist),&newstr_len);

  if(pSignature == NULL_PTR)
    *pulDataLen= newstr_len;
  else if(*pulDataLen <= newstr_len)
    memcpy(pData, newstr,newstr_len);
  else
    retval = CKR_BUFFER_TOO_SMALL; 

  free(newstr);

  return retval;
}
/* }}} */
/* {{{ C_Login */
/* C_Login logs a user into a token. */
CK_DEFINE_FUNCTION(CK_RV, C_Login)
(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_USER_TYPE      userType,  /* the user type */
  CK_CHAR_PTR       pPin,      /* the user's PIN */
  CK_ULONG          ulPinLen   /* the length of the PIN */
)
{
  CK_CHAR_PTR retstr;
  SCM retlist;
  CK_RV retval;
  CK_CHAR_PTR buff,tmp;

  tmp = CI_PrintableByteStream(pPin,ulPinLen);

  buff = malloc(strlen("(C-Login   )")+8+1+strlen(tmp)+1);
  if(buff == NULL_PTR) return CKR_HOST_MEMORY;

  sprintf(buff,"(C-Login %.8ld %.1ld %s)",hSession,userType,
	  tmp);
  free(tmp);

  /* send the call and recieve the returned text */
  CI_OpenSocket();
  CI_SendString(buff,&retstr);
  CI_CloseSocket();
  free(buff);

  retval = CI_ParseString(retstr,&retlist);
  
  return retval;
}
/* }}} */
/* {{{ C_Logout */
/* C_Logout logs a user out from a token. */
CK_DEFINE_FUNCTION(CK_RV, C_Logout)(
  CK_SESSION_HANDLE hSession  /* the session's handle */
)
{
  CK_CHAR_PTR retstr;
  SCM retlist;
  CK_RV retval;
  CK_CHAR_PTR buff;
  
  buff = malloc(strlen("(C-Logout   )")+8+1);
  if(buff == NULL_PTR) return CKR_HOST_MEMORY;

  sprintf(buff,"(C-Login %.8ld)",hSession);

  /* send the call and recieve the returned text */
  CI_OpenSocket();
  CI_SendString(buff,&retstr);
  CI_CloseSocket();
  free(buff);

  retval = CI_ParseString(retstr,&retlist);
  
  return retval;
}
/* }}} */
/* {{{ C_InitPIN */
/* C_InitPIN initializes the normal user's PIN. */
CK_DEFINE_FUNCTION(CK_RV, C_InitPIN)
(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_CHAR_PTR       pPin,      /* the normal user's PIN */
  CK_ULONG          ulPinLen   /* length in bytes of the PIN */
)
{
  CK_CHAR_PTR retstr;
  SCM retlist;
  CK_RV retval;
  CK_CHAR_PTR buff,tmp;

  tmp = CI_PrintableByteStream(pPin,ulPinLen);

  buff = malloc(strlen("(C-InitPIN   )")+8+strlen(tmp)+1);
  if(buff == NULL_PTR) return CKR_HOST_MEMORY;

  sprintf(buff,"(C-InitPIN %.8ld %s)",hSession,
	  tmp);
  free(tmp);

  /* send the call and recieve the returned text */
  CI_OpenSocket();
  CI_SendString(buff,&retstr);
  CI_CloseSocket();
  free(buff);

  retval = CI_ParseString(retstr,&retlist);
  
  return retval;
}
/* }}} */
/* {{{ C_SetPIN */
/* C_SetPIN modifies the PIN of the user who is logged in. */
CK_DEFINE_FUNCTION(CK_RV, C_SetPIN)
(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_CHAR_PTR       pOldPin,   /* the old PIN */
  CK_ULONG          ulOldLen,  /* length of the old PIN */
  CK_CHAR_PTR       pNewPin,   /* the new PIN */
  CK_ULONG          ulNewLen   /* length of the new PIN */
)
{
  CK_CHAR_PTR retstr;
  SCM retlist;
  CK_RV retval;
  CK_CHAR_PTR buff,tmp1,tmp2;
  
  tmp1 = CI_PrintableByteStream(pOldPin,ulOldLen);
  tmp2 = CI_PrintableByteStream(pNewPin,ulNewLen);

  buff = malloc(strlen("(C-InitPIN    )")+8+strlen(tmp1)+strlen(tmp2)+1);
  if(buff == NULL_PTR) return CKR_HOST_MEMORY;

  sprintf(buff,"(C-InitPIN %.8ld %s %s)",hSession,
	  tmp1,tmp2);
  free(tmp1);
  free(tmp2);

  /* send the call and recieve the returned text */
  CI_OpenSocket();
  CI_SendString(buff,&retstr);
  CI_CloseSocket();
  free(buff);

  retval = CI_ParseString(retstr,&retlist);
  
  return retval;
}
/* }}} */
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
  CK_CHAR_PTR retstr,newstr;
  int newstr_len;
  SCM retlist;
  CK_RV retval;
  CK_CHAR_PTR buff,tmp;
  
  tmp = CI_PrintableByteStream(pPart,ulPartLen);

  buff = malloc(strlen("(C-DigestEncryptUpdate    )")+8+strlen(tmp)+1);
  if(buff == NULL_PTR) return CKR_HOST_MEMORY;

  sprintf(buff,"(C-DigestEncryptUpdate %.8ld %s%s)",hSession,
	  tmp,(pEncryptedPart == NULL_PTR)?" #t":"");
  free(tmp);

  /* send the call and recieve the returned text */
  CI_OpenSocket();
  CI_SendString(buff,&retstr);
  CI_CloseSocket();
  free(buff);

  retval = CI_ParseString(retstr,&retlist);
  if(retval != CKR_OK) return retval;

  newstr = gh_scm2newstr(gh_car(retlist),&newstr_len);

  if(pEncryptedPart == NULL_PTR)
    *pulEncryptedPartLen= newstr_len;
  else if(*pulEncryptedPartLen <= newstr_len)
    memcpy(pEncryptedPart, newstr,newstr_len);
  else
    retval = CKR_BUFFER_TOO_SMALL; 

  free(newstr);
    
  return CKR_OK;
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
  CK_CHAR_PTR retstr,newstr;
  int newstr_len;
  SCM retlist;
  CK_RV retval;
  CK_CHAR_PTR buff,tmp;
  
  tmp = CI_PrintableByteStream(pEncryptedPart,ulEncryptedPartLen);

  buff = malloc(strlen("(C-DecryptDigestUpdate    )")+8+strlen(tmp)+1);
  if(buff == NULL_PTR) return CKR_HOST_MEMORY;

  sprintf(buff,"(C-DecryptDigestUpdate %.8ld %s%s)",hSession,
	  tmp,(pPart == NULL_PTR)?" #t":"");
  free(tmp);

  /* send the call and recieve the returned text */
  CI_OpenSocket();
  CI_SendString(buff,&retstr);
  CI_CloseSocket();
  free(buff);

  retval = CI_ParseString(retstr,&retlist);
  if(retval != CKR_OK) return retval;

  newstr = gh_scm2newstr(gh_car(retlist),&newstr_len);

  if(pPart == NULL_PTR)
    *pulPartLen= newstr_len;
  else if(*pulPartLen <= newstr_len)
    memcpy(pPart, newstr,newstr_len);
  else
    retval = CKR_BUFFER_TOO_SMALL; 

  free(newstr);
    
  return CKR_OK;
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
  CK_CHAR_PTR retstr,newstr;
  int newstr_len;
  SCM retlist;
  CK_RV retval;
  CK_CHAR_PTR buff,tmp;
  
  tmp = CI_PrintableByteStream(pPart,ulPartLen);

  buff = malloc(strlen("(C-SignEncryptUpdate    )")+8+strlen(tmp)+1);
  if(buff == NULL_PTR) return CKR_HOST_MEMORY;

  sprintf(buff,"(C-SignEncryptUpdate %.8ld %s%s)",hSession,
	  tmp,(pEncryptedPart == NULL_PTR)?" #t":"");
  free(tmp);

  /* send the call and recieve the returned text */
  CI_OpenSocket();
  CI_SendString(buff,&retstr);
  CI_CloseSocket();
  free(buff);

  retval = CI_ParseString(retstr,&retlist);
  if(retval != CKR_OK) return retval;

  newstr = gh_scm2newstr(gh_car(retlist),&newstr_len);

  if(pEncryptedPart == NULL_PTR)
    *pulEncryptedPartLen= newstr_len;
  else if(*pulEncryptedPartLen <= newstr_len)
    memcpy(pEncryptedPart, newstr,newstr_len);
  else
    retval = CKR_BUFFER_TOO_SMALL; 

  free(newstr);
    
  return CKR_OK;
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
  CK_CHAR_PTR retstr, newstr;
  int newstr_len;
  SCM retlist;
  CK_RV retval;
  CK_CHAR_PTR buff,tmp;
  
  tmp = CI_PrintableByteStream(pEncryptedPart,ulEncryptedPartLen);

  buff = malloc(strlen("(C-DecryptVerifyUpdate    )")+8+strlen(tmp)+1);
  if(buff == NULL_PTR) return CKR_HOST_MEMORY;

  sprintf(buff,"(C-DecryptVerifyUpdate %.8ld %s%s)",hSession,
	  tmp,(pPart == NULL_PTR)?" #t":"");
  free(tmp);

  /* send the call and recieve the returned text */
  CI_OpenSocket();
  CI_SendString(buff,&retstr);
  CI_CloseSocket();
  free(buff);

  retval = CI_ParseString(retstr,&retlist);
  if(retval != CKR_OK) return retval;

  newstr = gh_scm2newstr(gh_car(retlist),&newstr_len);

  if(pPart == NULL_PTR)
    *pulPartLen= newstr_len;
  else if(*pulPartLen <= newstr_len)
    memcpy(pPart, newstr,newstr_len);
  else
    retval = CKR_BUFFER_TOO_SMALL; 

  free(newstr);
    
  return CKR_OK;
}
/* }}} */
/* {{{ C_WrapKey */
CK_DEFINE_FUNCTION(CK_RV, C_WrapKey)
(
  CK_SESSION_HANDLE hSession,        /* the session's handle */
  CK_MECHANISM_PTR  pMechanism,      /* the wrapping mechanism */
  CK_OBJECT_HANDLE  hWrappingKey,    /* wrapping key */
  CK_OBJECT_HANDLE  hKey,            /* key to be wrapped */
  CK_BYTE_PTR       pWrappedKey,     /* gets wrapped key */
  CK_ULONG_PTR      pulWrappedKeyLen /* gets wrapped key size */
)
{
  CK_CHAR_PTR retstr, newstr;
  int newstr_len;
  SCM retlist;
  CK_RV retval;
  CK_CHAR_PTR buff;
  CK_CHAR_PTR mechanism;
  
  mechanism = CI_ScanableMechanism(pMechanism);

  buff = malloc(strlen("(C-WrapKey     )")+8+8+8+strlen(mechanism)+1);
  if(buff == NULL_PTR) return CKR_HOST_MEMORY;

  sprintf(buff,"(C-WrapKey %.8ld %s %.8ld %.8ld%s)",hSession,mechanism,
	  hWrappingKey,hKey,
	  (pWrappedKey == NULL_PTR)?" #t":"");

  /* send the call and recieve the returned text */
  CI_OpenSocket();
  CI_SendString(buff,&retstr);
  CI_CloseSocket();
  free(buff);

  retval = CI_ParseString(retstr,&retlist);
  free(retstr);
  if(retval != CKR_OK) return retval;

  if(pWrappedKey == NULL_PTR)
    *pulWrappedKeyLen= newstr_len;
  else if(*pulWrappedKeyLen <= newstr_len)
    memcpy(pWrappedKey, newstr,newstr_len);
  else
    retval = CKR_BUFFER_TOO_SMALL; 

  free(newstr);

  return retval;
}
/* }}} */
/* {{{ C_UnwrapKey */
/* C_UnwrapKey unwraps (decrypts) a wrapped key, creating a new
 * key object. */
CK_DEFINE_FUNCTION(CK_RV, C_UnwrapKey)
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
  CK_CHAR_PTR buff;
  CK_RV retval = CKR_OK;
  CK_CHAR_PTR retstr, mechanism,tmp,obj_desc;
  SCM retlist;

  obj_desc = CI_PrintTemplate(pTemplate,ulAttributeCount);
  mechanism = CI_ScanableMechanism(pMechanism);
  tmp = CI_PrintableByteStream(pWrappedKey,ulWrappedKeyLen);

  buff = malloc(strlen(obj_desc)+strlen("(C-CreateObject   \"\"    )")
		+8+strlen(mechanism)
		+8+strlen(tmp)
		+strlen(obj_desc)
		+1);

  if(buff == NULL_PTR) return CKR_HOST_MEMORY;

  sprintf(buff,"(C-UnwrapKey %ld %s %ld %s %s)",hSession,
	  mechanism,hUnwrappingKey,
	  tmp,obj_desc);
  free(tmp);
  free(obj_desc);
  free(mechanism);

  CI_OpenSocket();
  CI_SendString(buff,&retstr);
  CI_CloseSocket();
  free(buff);

  retval = CI_ParseString(retstr,&retlist);
  free(retstr);
  if(retval != CKR_OK) return retval;

  *phKey = gh_scm2ulong(gh_car(retlist));
  
  return retval;  
}
/* }}} */
/* {{{ C_DeriveKey */
/* C_DeriveKey derives a key from a base key, creating a new key
 * object. */
CK_DEFINE_FUNCTION(CK_RV, C_DeriveKey)
(
  CK_SESSION_HANDLE    hSession,          /* session's handle */
  CK_MECHANISM_PTR     pMechanism,        /* key deriv. mech. */
  CK_OBJECT_HANDLE     hBaseKey,          /* base key */
  CK_ATTRIBUTE_PTR     pTemplate,         /* new key template */
  CK_ULONG             ulAttributeCount,  /* template length */
  CK_OBJECT_HANDLE_PTR phKey              /* gets new handle */
)
{
  CK_CHAR_PTR obj_desc;
  CK_CHAR_PTR buff;
  CK_RV retval = CKR_OK;
  CK_CHAR_PTR retstr, mechanism;
  SCM retlist;

  obj_desc = CI_PrintTemplate(pTemplate,ulAttributeCount);
  mechanism = CI_ScanableMechanism(pMechanism);

  buff = malloc(strlen(obj_desc)+strlen("(C-CreateObject       )")
		+8+strlen(mechanism)
		+8+strlen(obj_desc)
		+1);

  if(buff == NULL_PTR) return CKR_HOST_MEMORY;

  sprintf(buff,"(C-DeriveKey %ld %s %ld %s)",hSession,mechanism,hBaseKey,obj_desc);

  CI_OpenSocket();
  CI_SendString(buff,&retstr);
  CI_CloseSocket();
  free(buff);

  retval = CI_ParseString(retstr,&retlist);
  free(retstr);
  if(retval != CKR_OK) return retval;

  *phKey = gh_scm2ulong(gh_car(retlist));
  
  return retval;  
}
/* }}} */
/* {{{ C_CopyObject */
CK_DEFINE_FUNCTION(CK_RV, C_CopyObject)(
        CK_SESSION_HANDLE hSession,
        CK_OBJECT_HANDLE hObject,
        CK_ATTRIBUTE_PTR pTemplate,
        CK_ULONG ulCount,
        CK_OBJECT_HANDLE_PTR phNewObject
      )
{
  CK_CHAR_PTR obj_desc;
  CK_CHAR_PTR buff;
  CK_RV retval = CKR_OK;
  CK_CHAR_PTR retstr;
  SCM retlist;

  obj_desc = CI_PrintTemplate(pTemplate,ulCount);

  buff = malloc(strlen("(C-CopyObject   )")
		+8+strlen(obj_desc)
		+1);

  if(buff == NULL_PTR) return CKR_HOST_MEMORY;

  sprintf(buff,"(C-CopyObject %ld %ld %s)",hSession,hObject,obj_desc);

  CI_OpenSocket();
  CI_SendString(buff,&retstr);
  CI_CloseSocket();
  free(buff);

  retval = CI_ParseString(retstr,&retlist);
  free(retstr);
  if(retval != CKR_OK) return retval;

  *phNewObject = gh_scm2ulong(gh_car(retlist));
  
  return retval;  
}
/* }}} */
/* {{{ C_GetAttributeValue TODO */
CK_DEFINE_FUNCTION(CK_RV, C_GetAttributeValue)(
        CK_SESSION_HANDLE hSession,
        CK_OBJECT_HANDLE hObject,
        CK_ATTRIBUTE_PTR pTemplate,
        CK_ULONG ulCount
      )
{
  CK_CHAR_PTR obj_desc;
  CK_CHAR_PTR buff;
  CK_RV retval = CKR_OK;
  CK_CHAR_PTR retstr;
  SCM retlist;

  obj_desc = CI_PrintTemplate(pTemplate,ulCount);

  buff = malloc(strlen("(C-GetAttributeValue   )")
		+8+strlen(obj_desc)
		+1);
  if(buff == NULL_PTR) return CKR_HOST_MEMORY;

  sprintf(buff,"(C-GetAttributeValue %ld %ld %s)",hSession,hObject,obj_desc);

  CI_OpenSocket();
  CI_SendString(buff,&retstr);
  CI_CloseSocket();
  free(buff);

  retval = CI_ParseString(retstr,&retlist);
  free(retstr);
  if(retval != CKR_OK) return retval;

  
  return retval;  
}
/* }}} */
/* {{{ C_SetAttributeValue */
CK_DEFINE_FUNCTION(CK_RV, C_SetAttributeValue)(
        CK_SESSION_HANDLE hSession,
        CK_OBJECT_HANDLE hObject,
        CK_ATTRIBUTE_PTR pTemplate,
        CK_ULONG ulCount
	)
{
  CK_CHAR_PTR obj_desc;
  CK_CHAR_PTR buff;
  CK_RV retval = CKR_OK;
  CK_CHAR_PTR retstr;
  SCM retlist;

  obj_desc = CI_PrintTemplate(pTemplate,ulCount);

  buff = malloc(strlen("(C-SetAttributeValue   )")
		+8+strlen(obj_desc)
		+1);

  if(buff == NULL_PTR) return CKR_HOST_MEMORY;

  sprintf(buff,"(C-SetAttributeValue %ld %ld %s)",hSession,hObject,obj_desc);

  CI_OpenSocket();
  CI_SendString(buff,&retstr);
  CI_CloseSocket();
  free(buff);

  retval = CI_ParseString(retstr,&retlist);
  free(retstr);
  
  return retval;  
}
/* }}} */
/* {{{ C_GetObjectSize */
/* C_GetObjectSize gets the size of an object in bytes. */
CK_DEFINE_FUNCTION(CK_RV, C_GetObjectSize)
(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_OBJECT_HANDLE  hObject,   /* the object's handle */
  CK_ULONG_PTR      pulSize    /* receives size of object */
)
{
  CK_CHAR_PTR buff;
  CK_RV retval = CKR_OK;
  CK_CHAR_PTR retstr;
  SCM retlist;

  buff = malloc(strlen("(C-GetObjectSize   )")
		+8+8+1);

  if(buff == NULL_PTR) return CKR_HOST_MEMORY;

  sprintf(buff,"(C-GetObjectSize %ld %ld)",hSession,hObject);

  CI_OpenSocket();
  CI_SendString(buff,&retstr);
  CI_CloseSocket();
  free(buff);

  retval = CI_ParseString(retstr,&retlist);
  free(retstr);
  
  if(retval != CKR_OK) return retval;

  *pulSize = gh_scm2ulong(gh_car(retlist));

  return retval;  
}
/* }}} */
/* {{{ C_GetFunctionStatus */
CK_DEFINE_FUNCTION(CK_RV, C_GetFunctionStatus)
(
  CK_SESSION_HANDLE hSession  /* the session's handle */
)
{
  CK_CHAR_PTR buff;
  CK_RV retval = CKR_OK;
  CK_CHAR_PTR retstr;
  SCM retlist;

  buff = malloc(strlen("(C-GetFunctionStatus   )")
		+8+1);

  if(buff == NULL_PTR) return CKR_HOST_MEMORY;

  sprintf(buff,"(C-GetFunctionStatus %ld)",hSession);

  CI_OpenSocket();
  CI_SendString(buff,&retstr);
  CI_CloseSocket();
  free(buff);

  retval = CI_ParseString(retstr,&retlist);
  free(retstr);
  
  return retval;  
}
/* }}} */
/* {{{ C_CancelFunction */
CK_DEFINE_FUNCTION(CK_RV, C_CancelFunction)
(
  CK_SESSION_HANDLE hSession  /* the session's handle */
)
{
  CK_CHAR_PTR buff;
  CK_RV retval = CKR_OK;
  CK_CHAR_PTR retstr;
  SCM retlist;

  buff = malloc(strlen("(C-CancelFunction   )")
		+8+1);

  if(buff == NULL_PTR) return CKR_HOST_MEMORY;

  sprintf(buff,"(C-CancelFunction %ld)",hSession);

  CI_OpenSocket();
  CI_SendString(buff,&retstr);
  CI_CloseSocket();
  free(buff);

  retval = CI_ParseString(retstr,&retlist);
  free(retstr);
  
  return retval;  
}
/* }}} */
/* {{{ C_WaitForSlotEvent */
CK_DEFINE_FUNCTION(CK_RV, C_WaitForSlotEvent)
(
  CK_FLAGS flags,        /* blocking/nonblocking flag */
  CK_SLOT_ID_PTR pSlot,  /* location that receives the slot ID */
  CK_VOID_PTR pReserved   /* reserved.  Should be NULL_PTR */
)
{
  CK_CHAR_PTR buff;
  CK_RV retval = CKR_OK;
  CK_CHAR_PTR retstr;
  SCM retlist;

  buff = malloc(strlen("(C-WaitForSlotEvent   )")
		+8+1);

  if(buff == NULL_PTR) return CKR_HOST_MEMORY;

  sprintf(buff,"(C-WaitForSlotEvent %ld)",flags);

  CI_OpenSocket();
  CI_SendString(buff,&retstr);
  CI_CloseSocket();
  free(buff);

  retval = CI_ParseString(retstr,&retlist);
  free(retstr);
  if(retval != CKR_OK) return retval;

  *pSlot = gh_scm2ulong(gh_car(retlist));

  return retval;  
}
/* }}} */
/* {{{ C_SeedRandom */
CK_DEFINE_FUNCTION(CK_RV, C_SeedRandom)(
        CK_SESSION_HANDLE hSession,
        CK_BYTE_PTR pSeed,
        CK_ULONG ulSeedLen
      )
{
  CK_CHAR_PTR buff;
  CK_RV retval = CKR_OK;
  CK_CHAR_PTR retstr,tmp;
  SCM retlist;

  tmp = CI_PrintableByteStream(pSeed,ulSeedLen);

  buff = malloc(strlen("(C-SeedRandom  \"\")")
		+8+strlen(tmp)+1);

  if(buff == NULL_PTR) return CKR_HOST_MEMORY;

  sprintf(buff,"(C-SeedRandom %ld %s)",hSession, tmp);
  free(tmp);

  CI_OpenSocket();
  CI_SendString(buff,&retstr);
  CI_CloseSocket();
  free(buff);

  retval = CI_ParseString(retstr,&retlist);
  free(retstr);
  
  return retval;  
}
/* }}} */
/* {{{ C_GenerateRandom */
CK_DEFINE_FUNCTION(CK_RV, C_GenerateRandom)(
        CK_SESSION_HANDLE hSession,
        CK_BYTE_PTR pRandomData,
        CK_ULONG ulRandomLen
      )
{
  CK_CHAR_PTR retstr, newstr;
  int newstr_len;
  SCM retlist;
  CK_RV retval;
  CK_CHAR_PTR buff;

  buff = malloc(strlen("(C-GenerateRandom     )")+8+8+1);
  if(buff == NULL_PTR) return CKR_HOST_MEMORY;

  sprintf(buff,"(C-GenerateRandom %ld %ld)",hSession,ulRandomLen);

  /* send the call and recieve the returned text */
  CI_OpenSocket();
  CI_SendString(buff,&retstr);
  CI_CloseSocket();
  free(buff);

  retval = CI_ParseString(retstr,&retlist);
  free(retstr);
  if(retval != CKR_OK) return retval;

  newstr = gh_scm2newstr(gh_car(retlist),&newstr_len);
  memcpy(pRandomData, newstr,newstr_len);
  free(newstr);

  return retval;
}
/* }}} */
/* {{{ C_CloseAllSessions */
/* C_CloseAllSessions closes all sessions with a token. */
CK_DEFINE_FUNCTION(CK_RV, C_CloseAllSessions)
(
  CK_SLOT_ID     slotID  /* the token's slot */
)
{
  CK_CHAR_PTR buff;
  CK_RV retval = CKR_OK;
  CK_CHAR_PTR retstr;
  SCM retlist;

  buff = malloc(strlen("(C-CloseAllSessions )")
		+8+1);

  if(buff == NULL_PTR) return CKR_HOST_MEMORY;

  sprintf(buff,"(C-CloseAllSessions %ld)",slotID);

  CI_OpenSocket();
  CI_SendString(buff,&retstr);
  CI_CloseSocket();
  free(buff);

  retval = CI_ParseString(retstr,&retlist);
  free(retstr);
  
  return retval;  
}
/* }}} */
/* {{{ C_GetSessionInfo */
CK_DEFINE_FUNCTION(CK_RV, C_GetSessionInfo)(
        CK_SESSION_HANDLE hSession,
        CK_SESSION_INFO_PTR pInfo
      )
{
  CK_RV retval = CKR_OK;
  CK_CHAR_PTR retstr;
  SCM retlist;
  CK_CHAR buff[29];

  sprintf(buff,"(C-GetSessionInfo %ld)",hSession);

  CI_OpenSocket();
  CI_SendString(buff,&retstr);
  CI_CloseSocket();

  retval = CI_ParseString(retstr,&retlist);
  if(retval != CKR_OK) return retval;

  pInfo->slotID = gh_scm2ulong(gh_car(retlist));
  retlist = gh_cdr(retlist);
  pInfo->state = gh_scm2ulong(gh_car(retlist));
  retlist = gh_cdr(retlist);
  pInfo->flags = gh_scm2ulong(gh_car(retlist));
  retlist = gh_cdr(retlist);
  pInfo->ulDeviceError = gh_scm2ulong(gh_car(retlist));
  retlist = gh_cdr(retlist);

  return retval;  
}
/* }}} */
/* {{{ C_GetOperationState */
/* C_GetOperationState obtains the state of the cryptographic operation
 * in a session. */
CK_DEFINE_FUNCTION(CK_RV, C_GetOperationState)
(
  CK_SESSION_HANDLE hSession,             /* session's handle */
  CK_BYTE_PTR       pOperationState,      /* gets state */
  CK_ULONG_PTR      pulOperationStateLen  /* gets state length */
)
{
  CK_CHAR_PTR retstr, newstr;
  int newstr_len;
  SCM retlist;
  CK_RV retval;
  CK_CHAR_PTR buff;

  buff = malloc(strlen("(C-GetOperationState   )")+8+2);
  if(buff == NULL_PTR) return CKR_HOST_MEMORY;

  sprintf(buff,"(C-SignFinal %.8ld %s)",hSession,(pOperationState == NULL_PTR)?" #t":"");

  /* send the call and recieve the returned text */
  CI_OpenSocket();
  CI_SendString(buff,&retstr);
  CI_CloseSocket();
  free(buff);

  retval = CI_ParseString(retstr,&retlist);
  free(retstr);
  if(retval != CKR_OK) return retval;

  newstr = gh_scm2newstr(gh_car(retlist),&newstr_len);

  if(pOperationState == NULL_PTR)
    *pulOperationStateLen= newstr_len;
  else if(*pulOperationStateLen <= newstr_len)
    memcpy(pOperationState, newstr,newstr_len);
  else
    retval = CKR_BUFFER_TOO_SMALL; 

  free(newstr);

  return gh_scm2ulong(retval);
}
/* }}} */
/* {{{ C_SetOperationState */
/* C_SetOperationState restores the state of the cryptographic
 * operation in a session. */
CK_DEFINE_FUNCTION(CK_RV, C_SetOperationState)
(
  CK_SESSION_HANDLE hSession,            /* session's handle */
  CK_BYTE_PTR      pOperationState,      /* holds state */
  CK_ULONG         ulOperationStateLen,  /* holds state length */
  CK_OBJECT_HANDLE hEncryptionKey,       /* en/decryption key */
  CK_OBJECT_HANDLE hAuthenticationKey    /* sign/verify key */
)
{
  CK_RV retval = CKR_OK;
  CK_CHAR_PTR retstr,buff,tmp;
  SCM retlist;

  tmp = CI_PrintableByteStream(pOperationState,ulOperationStateLen);

  buff = malloc(strlen("(C-CreateObject       )")
		+8+strlen(tmp)
		+8+8+1);
  if(buff == NULL_PTR) return CKR_HOST_MEMORY;

  sprintf(buff,"(C-UnwrapKey %ld %s %ld %ld)",hSession,
	  tmp,hEncryptionKey, hAuthenticationKey);
  free(tmp);

  CI_OpenSocket();
  CI_SendString(buff,&retstr);
  CI_CloseSocket();
  free(buff);

  retval = CI_ParseString(retstr,&retlist);
  free(retstr);

  return retval;  
}
/* }}} */


/*
 * Local variables:
 * folded-file: t
 * end:
 */


