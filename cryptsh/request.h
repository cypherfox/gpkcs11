/*
 * Copyright (c) TC TrustCenter - Projekt GPKCS11 - all rights reserved
 * RCSID:       $Id$
 * Source:      $Source$
 * Last Delta:  $Date$ $Revision$ $Author$
 * State:       $State$ $Locker$
 * NAME:        GenKeys.h
 * SYNOPSIS:    -
 * DESCRIPTION: Generation of Certificate Request
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
#ifndef REQUEST_H
#define REQUEST_H

#include <openssl/buffer.h>
#include <openssl/x509.h>
#include <openssl/evp.h>

#define CERT_HASH_SIZE MD5_DIGEST_LENGTH

#ifdef  __cplusplus
extern "C" {
#endif

#if 0
}
#endif

#define req_SPECIALNAMEINTRO  "X509_NAME_"
#define REQF_HASHNAME      "PubKeyHash="
#define CERTF_PKEYNAME     "PrivateKey="
#define CERTF_SUBJECTNAME  "Subject="
#define MSG_NEWPKEYPW   225

#define BUFFSIZE 1024
#define NAMEBUFFSIZE 1024
#define KEY_LEN_DEFAULT 1024
#define KEY_LEN_MIN 512
#define KEY_LEN_MAX 4096

#define CERT_HASH_ALLG EVP_md5() 

#define EVP_PUBKEY_digest(data,type,md,len)\
   ASN1_digest((int (*)())i2d_PublicKey,(type),(char *)(data),(md),(len))

/* internal allg. for hashing of data in Cert structure */
typedef enum
{
   req_Set,
   req_Add,
   req_AddPre,
   req_AddPost
} req_NameDo;

long req_FlushFile(BIO *spFileBio);


#define req_SETNAMEMODE_C  req_Set
#define req_SETNAMEMODE_SP req_Set
#define req_SETNAMEMODE_L  req_Set
#define req_SETNAMEMODE_O  req_Set
#define req_SETNAMEMODE_OU req_Add
#define req_SETNAMEMODE_CN req_Set
#define req_SETNAMEMODE_EMAIL req_Add

const char *req_GetName_C(X509_NAME *name);
const char *req_GetName_SP(X509_NAME *name);
const char *req_GetName_L(X509_NAME *name);
const char *req_GetName_O(X509_NAME *name);
const char *req_GetName_OU(X509_NAME *name);
const char *req_GetName_CN(X509_NAME *name);
const char *req_GetName_EMail(X509_NAME *name);

long req_SetName_C(X509_NAME *name, const char *value);
long req_SetName_SP(X509_NAME *name, const char *value);
long req_SetName_L(X509_NAME *name, const char *value);
long req_SetName_O(X509_NAME *name, const char *value);
long req_SetName_OU(X509_NAME *name, const char *value);
long req_SetName_CN(X509_NAME *name, const char *value);
long req_SetName_EMail(X509_NAME *name, const char *value);

X509_NAME_ENTRY *req_GetNameENidI(X509_NAME *name, unsigned long nid, long offset);
long req_AddNameNid(X509_NAME* name,unsigned long nid, const char *value, req_NameDo action);


#if 0
/* old stuff from GenCert */
unsigned long req_GetSize(GenCert *self);
long req_SetKeySize(GenCert *self, unsigned long size);
const char *req_GetSizeStr(GenCert *self);
long req_SetKeySizeStr(GenCert *self, const char *size);

const char *req_GetReq(GenCert *self);
long req_SetReq(GenCert *self,const char *value);

long req_AddNamePart(GenCert *self, const char *name, const char *value, req_NameDo action);


long req_AddOther(X509_NAME *name, const char *name, const char *value, const char *raw);
const char *req_GetOther(X509_NAME *name);

long          req_SortName(     GenCert *self);
long          req_GenerateKey(  GenCert *self,long nStrong);
long          req_GenerateReq(  GenCert *self);
long          req_StoreReq(     GenCert *self, const char *file);
long          req_StorePKey(    GenCert *self, const char *file);

long Cert_ExpandHash(const unsigned char *inHash, char *outLongHash);

#endif /* 0 */


#ifdef  __cplusplus
}
#endif

#endif /* REQUEST_H */
