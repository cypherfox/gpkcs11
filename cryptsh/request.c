
/*
 * Copyright (c) TC TrustCenter - Projekt GPKCS11 - all rights reserved
 * RCSID:       $Id$
 * Source:      $Source$
 * Last Delta:  $Date$ $Revision$ $Author$
 * State:       $State$ $Locker$
 * NAME:        GenKeys.c
 * SYNOPSIS:    -
 * DESCRIPTION: Generation of Certificate Reques
 * FILES:       -
 * SEE/ALSO:    -
 * AUTHOR:      lbe
 * BUGS: *      -
 * HISTORY:     $Log$
 * HISTORY:     Revision 1.2  1999/10/06 07:57:20  lbe
 * HISTORY:     solved netscape symbol clash problem
 * HISTORY:
 * HISTORY:     Revision 1.1  1999/08/02 12:40:22  lbe
 * HISTORY:     more CVS cleanup
 * HISTORY:
 */

static char RCSID[]="$Id$";
const char *request_c_Version(void){ return RCSID; }


#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/objects.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/buffer.h>

#include "request.h"
#include "utils.h"
#include <assert.h>

#ifndef LIST_SEPARATOR_CHAR
#define LIST_SEPARATOR_CHAR ';'
#endif

#define OWNFLUSH
#define Log_Log(a,b,c) printf("%s (sev: %d): %s\n",a,b,c) 
#define Log_LogLong(a,b,c,d) printf("%s (sev: %d): %s '%ld'\n",a,b,c,(long)d) 

/* from Cert.c / CertMgmt.h : */
extern long Cert_ExpandHash(const unsigned char *inHash,char *outHashLong);

static unsigned long SortNids[]=
{
   NID_countryName,
   NID_stateOrProvinceName,
   NID_localityName,
   NID_organizationName,
   NID_organizationalUnitName,
   NID_commonName,
   0
};

static const char *SortNidsNames[]=
{
   "NID_countryName",
   "NID_stateOrProvinceName",
   "NID_localityName",
   "NID_organizationName",
   "NID_organizationalUnitName",
   "NID_commonName",
   0
};

#define HEX2BIN(x) \
( ( (x) >= '0' && (x) <= '9')?(x)-'0':\
  ( (x) >= 'A' && (x) <= 'F')?(x)-'A'+0x0A:\
  ( (x) >= 'a' && (x) <= 'f')?(x)-'a'+0x0A:-1)
 
static const char bin2hex[]=
{
   '0','1','2','3',
   '4','5','6','7',
   '8','9','A','B',
   'C','D','E','F'
};

// Internal
#if 0
static int  GenCert_AskPW(char *buf, long len, long verify);
static long OutputSave(GenCert *self, BUF_MEM *out);
#endif

static void OutName(const char *where, X509_NAME *out);

#ifdef DEBUG
static void GenCert_GKCallBack(int int1,int int2,char *data);
#else
#define GenCert_GKCallBack NULL
#endif


/* {{{ X509_NAME *GenCert_SortName(X509_NAME *name) */
X509_NAME *GenCert_SortName(X509_NAME *name)
{
  long nRetVal=TRUE;
  long nSortIndex;
  long nSearchIndex;
  long nInsertIndex;
  X509_NAME_ENTRY *ne;
  X509_NAME *sorted;
  
  if (!name || !name->entries)
    return 0;
  //   return TRUE;
  
  sorted=X509_NAME_new();
  if (!sorted)
    {
      Log_Log("SortName",0,"out of mem (X509_NAME)");
      return 0;
    }
  for(nInsertIndex=1,nSortIndex=0;SortNids[nSortIndex];nSortIndex++)
    {
      OutName("SortName",name);
      while((nSearchIndex=X509_NAME_get_index_by_NID(name,
                                                     SortNids[nSortIndex],
                                                     -1))>=0)
	{
	  Log_LogLong("SortName",0,SortNidsNames[nSortIndex],nSearchIndex);
	  ne=X509_NAME_delete_entry(name,nSearchIndex);
	  OutName("SortName",name);
	  if (ne)
	    {
	      Log_Log("SortName",0,ASN1_STRING_data(X509_NAME_ENTRY_get_data(ne)));
	      if (X509_NAME_add_entry(sorted,ne,nInsertIndex++,TRUE)<=0)
		nRetVal = FALSE;
	      OutName("SortName",sorted);
	    }
	}
    }
  while(X509_NAME_entry_count(name)>0)
    {
      OutName("SortName",name);
      ne=X509_NAME_delete_entry(name,0);
      OutName("SortName",name);
      if (ne)
	{
	  if (X509_NAME_add_entry(sorted,ne,nInsertIndex++,TRUE))
            nRetVal=FALSE;
	  OutName("SortName",name);
	}
      else
	break;
    }
  return sorted;
}
/* }}} */

/* {{{ static void OutName(const char *where,X509_NAME *out) */
static void OutName(const char *where,X509_NAME *out)
{
   long max=X509_NAME_entry_count(out);
   long act=0;
   X509_NAME_ENTRY *ne;
   char fullname[BUFFSIZE+1];

   if (max <= 0)
      return;
   Log_Log(where,max,X509_NAME_oneline(out,fullname,BUFFSIZE));
   return;
   
   while(act<max)
   {
      ne=X509_NAME_get_entry(out,act);
      if (ne)
      {
         Log_Log(    where,act,ASN1_STRING_data(X509_NAME_ENTRY_get_data(ne)));
         Log_LogLong(where,act,"set:",ne->set);
      }
      act++;
   }
}
/* }}} */

/* {{{ long req_FlushFile(BIO *spFileBio) */
long req_FlushFile(BIO *spFileBio)
{
#ifdef OWNFLUSH
   FILE *fp = NULL;

   if (BIO_get_fp(spFileBio,&fp) <= 0)
      return FALSE;
   if (!fp)
      return FALSE;
   if (!fflush(fp))
      return TRUE;
   return FALSE;
#else
   return BIO_flush(spFileBio);
#endif
}
/* }}} */

/* {{{ X509_NAME_ENTRY *req_GetNameENidI(X509_NAME *,unsigned long,long) */
X509_NAME_ENTRY *req_GetNameENidI(X509_NAME *name, unsigned long nid, long offset)
{
   long index;

   if (!name)
      return NULL;
   index=X509_NAME_get_index_by_NID(name,nid,offset);
   if (index < 0)
      return NULL;
   return X509_NAME_get_entry(name,index);
}
/* }}} */
/* {{{ ASN1_STRING *req_GetNameNidI(  X509_NAME *name, unsigned long nid) */
ASN1_STRING *req_GetNameNidI(  X509_NAME *name, unsigned long nid)
{
   X509_NAME_ENTRY *ne = req_GetNameENidI(name,nid,-1);

   if (!ne)
      return NULL;
   return X509_NAME_ENTRY_get_data(ne);
}
/* }}} */
/* {{{ unsigned char*req_GetNameNid(  X509_NAME *name, unsigned long nid) */
unsigned char*req_GetNameNid(  X509_NAME *name, unsigned long nid)
{
   ASN1_STRING *str=req_GetNameNidI(name,nid);

   if (!str)
      return NULL;
   return ASN1_STRING_data(str);
}
/* }}} */

/* {{{ const char *req_GetName_C(    X509_NAME *name) */
const char *req_GetName_C(    X509_NAME *name)
{
   return req_GetNameNid(name,NID_countryName);
}
/* }}} */
/* {{{ const char *req_GetName_L(    X509_NAME *name) */
const char *req_GetName_L(    X509_NAME *name)
{
   return req_GetNameNid(name,NID_localityName);
}
/* }}} */
/* {{{ const char *req_GetName_SP(   X509_NAME *name) */
const char *req_GetName_SP(   X509_NAME *name)
{
   return req_GetNameNid(name,NID_stateOrProvinceName);
}
/* }}} */
/* {{{ const char *req_GetName_O(    X509_NAME *name) */
const char *req_GetName_O(    X509_NAME *name)
{
   return req_GetNameNid(name,NID_organizationName);
}
/* }}} */
/* {{{ const char *req_GetName_OU(   X509_NAME *name) */
const char *req_GetName_OU(   X509_NAME *name)
{
   return req_GetNameNid(name,NID_organizationalUnitName);
}
/* }}} */
/* {{{ const char *req_GetName_CN(   X509_NAME *name) */
const char *req_GetName_CN(   X509_NAME *name)
{
   return req_GetNameNid(name,NID_commonName);
}
/* }}} */
/* {{{ const char *req_GetName_EMail(X509_NAME *name) */
const char *req_GetName_EMail(X509_NAME *name)
{
   return req_GetNameNid(name,NID_pkcs9_emailAddress);
}
/* }}} */

/* {{{ long req_SetName_C(X509_NAME *name, const char *value) */
long req_SetName_C(    X509_NAME *name, const char *value)
{
   return req_AddNameNid(name,NID_countryName,value,req_SETNAMEMODE_C);
}
/* }}} */
/* {{{ long req_SetName_L(X509_NAME *name, const char *value) */
long req_SetName_L(    X509_NAME *name, const char *value)
{
   return req_AddNameNid(name,NID_localityName,value,req_SETNAMEMODE_L);
}
/* }}} */
/* {{{ long req_SetName_SP(X509_NAME *name, const char *value) */
long req_SetName_SP(   X509_NAME *name, const char *value)
{
   return req_AddNameNid(name,NID_stateOrProvinceName,value,req_SETNAMEMODE_SP);
}
/* }}} */
/* {{{ long req_SetName_O(X509_NAME *name, const char *value) */
long req_SetName_O(    X509_NAME *name, const char *value)
{
   return req_AddNameNid(name,NID_organizationName,value,req_SETNAMEMODE_O);
}
/* }}} */
/* {{{ long req_SetName_OU(X509_NAME *name, const char *value) */
long req_SetName_OU(X509_NAME *name, const char *value)
{
   return req_AddNameNid(name,NID_organizationalUnitName,value,req_SETNAMEMODE_OU);
}
/* }}} */
/* {{{ long req_SetName_CN(X509_NAME *name, const char *value) */
long req_SetName_CN(X509_NAME *name, const char *value)
{
  return req_AddNameNid(name,NID_commonName,value,req_SETNAMEMODE_CN);
}
/* }}} */
/* {{{ long req_SetName_EMail(X509_NAME *name, const char *value) */
long req_SetName_EMail(X509_NAME *name, const char *value)
{
   return req_AddNameNid(name,NID_pkcs9_emailAddress,value,req_SETNAMEMODE_EMAIL);
}
/* }}} */

/* {{{ long req_AddNameNid(X509_NAME*, unsigned long, const char*, req_NameDo action) */
long req_AddNameNid(X509_NAME *name, unsigned long nid, const char *value, req_NameDo action)
{
   X509_NAME_ENTRY *newEntry =NULL;
   ASN1_STRING     *entryData=NULL;
   char             caTemp[BUFFSIZE];
   char             caTemp2[BUFFSIZE];
   unsigned long    nType;

   Log_Log("req_AddNameNid",0,value);
   OutName("req_AddNameNid",name);
   nType = ASN1_PRINTABLE_type((char *)value,-1);
   switch(nid)
   {
   case NID_pkcs9_unstructuredName:
      if (nType==V_ASN1_T61STRING)
      {
         nType = -1;
         break;
      }
   case NID_pkcs9_emailAddress:
      nType=V_ASN1_IA5STRING;
      break;
   case NID_commonName:
   case NID_pkcs9_challengePassword:
      if (nType == V_ASN1_IA5STRING)
         nType = V_ASN1_T61STRING;
      break;
   }
   if (nType == -1)
   {
      Log_Log("req_AddNid",0,"unknown NID type");
      return FALSE;
   }
   if (action == req_Set || action == req_AddPre || action == req_AddPost)
      newEntry = req_GetNameENidI(name,nid,-1);
   if (newEntry)
   {
      entryData=X509_NAME_ENTRY_get_data(newEntry);
      caTemp2[0]=0x00;
      caTemp[0] =0x00;
      if (entryData)
      {
         strncpy(caTemp,ASN1_STRING_data(entryData),BUFFSIZE);
         caTemp[BUFFSIZE-1]=0x00;
      }
      else
         caTemp[0]=0x00;
      switch(action)
      {
      case req_Set:
         {
            strncpy(caTemp2,value,BUFFSIZE);
            caTemp2[BUFFSIZE-1]=0x00;
            break;
         }
      case req_AddPre:
         {
            strncpy(caTemp2,value,BUFFSIZE-1);
            caTemp2[BUFFSIZE-1]=0x00;
            if ((strlen(caTemp2)<BUFFSIZE-3) && caTemp[0])
            {
               strcat(caTemp2," ");
               strncat(caTemp2,caTemp,BUFFSIZE-1-strlen(caTemp2));
               caTemp2[BUFFSIZE-1]=0x00;
            }
            break;
         }
      case req_AddPost:
         {
            strcpy(caTemp2,caTemp);
            if (strlen(caTemp2)<BUFFSIZE-3)
            {
               strcat(caTemp2," ");
               strncat(caTemp2,value,BUFFSIZE-1-strlen(caTemp2));
               caTemp2[BUFFSIZE-1]=0x00;
            }
            break;
         }
      case req_Add:
         break;
      }
      nType = ASN1_PRINTABLE_type(caTemp2,-1);
      switch(nid)
      {
      case NID_pkcs9_unstructuredName:
         if (nType==V_ASN1_T61STRING)
         {
            nType = -1;
            break;
         }
      case NID_pkcs9_emailAddress:
         nType=V_ASN1_IA5STRING;
         break;
      case NID_commonName:
      case NID_pkcs9_challengePassword:
         if (nType == V_ASN1_IA5STRING)
            nType = V_ASN1_T61STRING;
         break;
      }
      if (nType == -1)
      {
         Log_Log("req_AddNid",0,"unknown NID type");
         return FALSE;
      }
      if (!X509_NAME_ENTRY_set_data(newEntry,nType,caTemp2,strlen(caTemp2)))
      {
         Log_Log("req_AddNid",0,"can't set data to entry");
         Log_Log("req_AddNid",0,caTemp2);
         return FALSE;
      }
   }
   else
   {
      newEntry=X509_NAME_ENTRY_create_by_NID(&newEntry,nid,nType,(char *)value,strlen(value));
      if (!newEntry)
      {
         Log_Log("req_AddNid",0,"no X509_NAME_ENTRY");
         return FALSE;
      }
      if (!X509_NAME_add_entry(name,newEntry,-1,-1))
      {
         X509_NAME_ENTRY_free(newEntry);
         Log_Log("req_AddNid",0,"can't add entry");
         Log_Log("req_AddNid",0,value);
         return FALSE;
      }
      X509_NAME_ENTRY_free(newEntry);
   }
   OutName("req_AddNameNid",name);
   return TRUE;
}
/* }}} */

#if 0
/* old stuff from GenCert.c */
static int GenCert_AskPW(char *buf, long len, long verify);
static long ExpandHash(const unsigned char *inHash, char *outLongHash,
		       long nHashSize);

/* {{{ long GenCert_AddNamePart(GenCert*, const char*, const char*, req_NameDo)*/
long GenCert_AddNamePart(GenCert *self, const char *name,
			 const char *value, req_NameDo action)
{
   unsigned long nid=NID_undef;
   unsigned long nCount;
   const char   *name2;

   if (!self || !name || !value)
      return FALSE;
   if (!strncasecmp(name,GENCERT_SPECIALNAMEINTRO,strlen(GENCERT_SPECIALNAMEINTRO)))
      name2=name+strlen(GENCERT_SPECIALNAMEINTRO);
   else
      name2=name;
   if (name2[0])
   {
      nid = OBJ_txt2nid((char *)name2);
      if (nid == NID_undef)
      {
         for(nCount=0;name2[nCount];nCount++)
         {
            if (name2[nCount] != '.' && !(name2[nCount] >= '0' && name2[nCount] <= '9'))
               break;
         }
         if (!name2[nCount])
         {
            nid=OBJ_create_and_add_object((char *)name2,(char *)name2,(char *)name2);
            if (nid == NID_undef)
               Log_Log("GK_AddNewObj",0,"can't create new Object");
         }
      }
   }
   if (nid == NID_undef)
   {
      Log_Log("GKAddNameP",0,"unknown object");
      Log_Log("GKAddNameP",0,name);
      return FALSE;
   }
   return GenCert_AddNameNid(self,nid,value,action);
}
/* }}} */

#endif /* 0 */

/*
 * Local variables:
 * folded-file: t
 * end:
 */
