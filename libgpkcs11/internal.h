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
 * NAME:        internal.h
 * SYNOPSIS:    -
 * DESCRIPTION: -
 * FILES:       -
 * SEE/ALSO:    -
 * AUTHOR:      lbe
 * BUGS:        -
 */

#ifndef _INTERNAL_H_
#define _INTERNAL_H_

#include "cryptoki.h"

#include "hash.h"

/* {{{ ### general stuff ### */
extern CK_CHAR CK_I_empty_str[];
extern CK_BYTE CK_I_empty_bytes[];
extern CK_BBOOL CK_I_true;
extern CK_BBOOL CK_I_false;
extern CK_ULONG CK_I_ulEmpty;

/* new return values */
#define CKR_FILE_NOT_FOUND        0x80000000+0x00000001
#define CKR_NO_TOKEN_OBJ          0x80000000+0x00000002
/* }}} */

/* ### forward declarations ### */
typedef struct ck_i_obj_st CK_I_OBJ;
typedef CK_I_OBJ CK_PTR CK_I_OBJ_PTR;

typedef struct ck_i_slot_data_st CK_I_SLOT_DATA;
typedef CK_I_SLOT_DATA CK_PTR CK_I_SLOT_DATA_PTR;

typedef struct ck_i_session_data_st CK_I_SESSION_DATA;
typedef CK_I_SESSION_DATA CK_PTR CK_I_SESSION_DATA_PTR;

/* {{{ ### library initialisation ### */
typedef struct CK_I_EXT_FUNCTION_LIST {
  CK_CREATEMUTEX _CreateMutex;
  CK_DESTROYMUTEX _DestroyMutex;
  CK_LOCKMUTEX _LockMutex;
  CK_UNLOCKMUTEX _UnlockMutex;
} CK_I_EXT_FUNCTION_LIST;

extern CK_ULONG CK_I_global_flags;
extern CK_I_EXT_FUNCTION_LIST CK_I_ext_functions;

#define CK_IGF_INITIALIZED        1
#define CK_IGF_SINGLE_THREAD      2
#define CK_IGF_FUNCTIONLIST_SET   4
/* }}} */

/* {{{ ### internal interface ### */
/* {{{ CK_I_CALL_TOKEN_METHOD */
/** access token methods.
 * the macro returns CKR_OK for a not supported method. this makes it simpler 
 * to write the methods that use functions of the token only for token specific
 * extension to the base library function, e.g. OpenSession etc. 
 * <p>
 * <b>The parameters need to be wrapped in '()' !</b>
 */
#define CK_I_CALL_TOKEN_METHOD(_method_retval, _method, params)             \
do {                                                                        \
  CIP_##_method CK_I_Method_P = session_data->slot_data->methods->_method; \
  if(CK_I_Method_P == NULL_PTR) _method_retval = CKR_OK;                    \
  else _method_retval = CK_I_Method_P params;                               \
} while(0)
/* }}} */

/* {{{ internal interface function definitions */
/** Functions that may be used by a mechanism.
 */
typedef CK_CALLBACK_FUNCTION(CK_RV, CIP_GetTokenInfo)(
  CK_I_SLOT_DATA_PTR  slot_data,
  CK_TOKEN_INFO_PTR pInfo    /* receives the token information */
);

/** get the List of mechanisms supported by the token.
  
  @param pMechanismList If set to NULL_PTR, the lenght of the buffer 
                        needed will be put into <b>pulCount</b>
  @param pulCount       number of elements in the list provided. Address 
                        pointed to will be set to the number of entries in 
                        the list when returned.
 */
typedef CK_CALLBACK_FUNCTION(CK_RV, CIP_GetMechanismList)(
  CK_MECHANISM_TYPE_PTR pMechanismList,  /* gets mech. array */
  CK_ULONG_PTR          pulCount         /* gets # of mechs. */
);

/**
 */
typedef CK_CALLBACK_FUNCTION(CK_RV, CIP_GetMechanismInfo)(
  CK_MECHANISM_TYPE     type,    /* type of mechanism */
  CK_MECHANISM_INFO_PTR pInfo    /* receives mechanism info */
);

/**
 */
typedef CK_CALLBACK_FUNCTION(CK_RV, CIP_InitToken)(
  CK_CHAR_PTR       pPin,      /* the SO's initial PIN */
  CK_ULONG          ulPinLen,  /* length in bytes of the PIN */
  CK_CHAR_PTR       pLabel     /* 32-byte token label (blank padded) */
);

/**
 */
typedef CK_CALLBACK_FUNCTION(CK_RV, CIP_FinalizeToken)(
  CK_I_SLOT_DATA_PTR slot_data /* data of the token to be finalized */
);

/**
 */
typedef CK_CALLBACK_FUNCTION(CK_RV, CIP_InitPIN)(
  CK_I_SESSION_DATA_PTR session_data,  
  CK_CHAR_PTR       pPin,      /* the normal user's PIN */
  CK_ULONG          ulPinLen   /* length in bytes of the PIN */
);

/**
 */
typedef CK_CALLBACK_FUNCTION(CK_RV, CIP_SetPIN)(
  CK_I_SESSION_DATA_PTR session_data,  
  CK_CHAR_PTR       pOldPin,   /* the old PIN */
  CK_ULONG          ulOldLen,  /* length of the old PIN */
  CK_CHAR_PTR       pNewPin,   /* the new PIN */
  CK_ULONG          ulNewLen   /* length of the new PIN */
);

/* perform token specific operations when opening a session.
 *
 * Token must implement this function if it holds some internal 
 * representation of each session. The nessecary base operations are handled 
 * by the outer library code.
 */
typedef CK_CALLBACK_FUNCTION(CK_RV, CIP_OpenSession)(
  CK_I_SESSION_DATA_PTR   session_data   
);

/* perform token specific operations when closing a session.
 * 
 * Token must implement this function if it holds some internal representation 
 * of each session.
 */
typedef CK_CALLBACK_FUNCTION(CK_RV, CIP_CloseSession)(
  CK_I_SESSION_DATA_PTR   session_data
);

/**
 */
typedef CK_CALLBACK_FUNCTION(CK_RV, CIP_GetOperationState)(
  CK_I_SESSION_DATA_PTR session_data,     
  CK_BYTE_PTR           pOperationState,      /* gets state */
  CK_ULONG_PTR          pulOperationStateLen  /* gets state length */
);

/**
 */
typedef CK_CALLBACK_FUNCTION(CK_RV, CIP_SetOperationState)(
  CK_I_SESSION_DATA_PTR session_data,     
  CK_BYTE_PTR           pOperationState,      /* holds state */
  CK_ULONG              ulOperationStateLen,  /* holds state length */
  CK_I_OBJ_PTR          encrypt_key_obj,      /* en/decryption key */
  CK_I_OBJ_PTR          auth_key_obj          /* sign/verify key */
);

/**
 */
typedef CK_CALLBACK_FUNCTION(CK_RV, CIP_Login)(
  CK_I_SESSION_DATA_PTR session_data,  /* the session's handle */
  CK_USER_TYPE          userType,      /* the user type */
  CK_CHAR_PTR           pPin,          /* the user's PIN */
  CK_ULONG              ulPinLen       /* the length of the PIN */
);

/**
 */
typedef CK_CALLBACK_FUNCTION(CK_RV, CIP_Logout)(
  CK_I_SESSION_DATA_PTR session_data  /* the session's handle */
);

/**
 */
typedef CK_CALLBACK_FUNCTION(CK_RV, CIP_EncryptInit)(
  CK_I_SESSION_DATA_PTR  session_data,
  CK_MECHANISM_PTR       pMechanism,  /* the encryption mechanism */
  CK_I_OBJ_PTR           key_obj      /* handle of encryption key */
);

/**
 */
typedef CK_CALLBACK_FUNCTION(CK_RV, CIP_Encrypt)(
  CK_I_SESSION_DATA_PTR  session_data,
  CK_BYTE_PTR       pData,               /* the plaintext data */
  CK_ULONG          ulDataLen,           /* bytes of plaintext */
  CK_BYTE_PTR       pEncryptedData,      /* gets ciphertext */
  CK_ULONG_PTR      pulEncryptedDataLen  /* gets c-text size */
);

/**
 */
typedef CK_CALLBACK_FUNCTION(CK_RV, CIP_EncryptUpdate)(
  CK_I_SESSION_DATA_PTR  session_data,
  CK_BYTE_PTR       pPart,              /* the plaintext data */
  CK_ULONG          ulPartLen,          /* plaintext data len */
  CK_BYTE_PTR       pEncryptedPart,     /* gets ciphertext */
  CK_ULONG_PTR      pulEncryptedPartLen /* gets c-text size */
);

/**
 */
typedef CK_CALLBACK_FUNCTION(CK_RV, CIP_EncryptFinal)(
  CK_I_SESSION_DATA_PTR  session_data,
  CK_BYTE_PTR       pLastEncryptedPart,      /* last c-text */
  CK_ULONG_PTR      pulLastEncryptedPartLen  /* gets last size */
);

/**
 */
typedef CK_CALLBACK_FUNCTION(CK_RV, CIP_DecryptInit)(
  CK_I_SESSION_DATA_PTR  session_data,
  CK_MECHANISM_PTR  pMechanism,     /* the decryption mechanism */
  CK_I_OBJ_PTR      key_obj         /* handle of decryption key */
);

/**
 */
typedef CK_CALLBACK_FUNCTION(CK_RV, CIP_Decrypt)(
  CK_I_SESSION_DATA_PTR  session_data,
  CK_BYTE_PTR       pEncryptedData,     /* ciphertext */
  CK_ULONG          ulEncryptedDataLen, /* ciphertext length */
  CK_BYTE_PTR       pData,              /* gets plaintext */
  CK_ULONG_PTR      pulDataLen          /* gets p-text size */
);

/**
 */
typedef CK_CALLBACK_FUNCTION(CK_RV, CIP_DecryptUpdate)(
  CK_I_SESSION_DATA_PTR  session_data,
  CK_BYTE_PTR       pEncryptedPart,      /* encrypted data */
  CK_ULONG          ulEncryptedPartLen,  /* input length */
  CK_BYTE_PTR       pPart,               /* gets plaintext */
  CK_ULONG_PTR      pulPartLen           /* p-text size */
);

/**
 */
typedef CK_CALLBACK_FUNCTION(CK_RV, CIP_DecryptFinal)(
  CK_I_SESSION_DATA_PTR  session_data,
  CK_BYTE_PTR       pLastPart,      /* gets plaintext */
  CK_ULONG_PTR      pulLastPartLen  /* p-text size */
);

/**
 */
typedef CK_CALLBACK_FUNCTION(CK_RV, CIP_DigestInit)(
  CK_I_SESSION_DATA_PTR  session_data,
  CK_MECHANISM_PTR  pMechanism  /* the digesting mechanism */
);

/**
 */
typedef CK_CALLBACK_FUNCTION(CK_RV, CIP_Digest)(
  CK_I_SESSION_DATA_PTR  session_data,
  CK_BYTE_PTR       pData,        /* data to be digested */
  CK_ULONG          ulDataLen,    /* bytes of data to digest */
  CK_BYTE_PTR       pDigest,      /* gets the message digest */
  CK_ULONG_PTR      pulDigestLen  /* gets digest length */
);

/**
 */
typedef CK_CALLBACK_FUNCTION(CK_RV, CIP_DigestUpdate)(
  CK_I_SESSION_DATA_PTR  session_data,
  CK_C_BYTE_PTR     pPart,     /* data to be digested */
  CK_ULONG          ulPartLen  /* bytes of data to be digested */
);

/**
 */
typedef CK_CALLBACK_FUNCTION(CK_RV, CIP_DigestKey)(
  CK_I_SESSION_DATA_PTR  session_data,
  CK_I_OBJ_PTR           key_obj       /* secret key to digest */
);

/**
 */
typedef CK_CALLBACK_FUNCTION(CK_RV, CIP_DigestFinal)(
  CK_I_SESSION_DATA_PTR  session_data,
  CK_BYTE_PTR       pDigest,      /* gets the message digest */
  CK_ULONG_PTR      pulDigestLen  /* gets byte count of digest */
);

/**
 */
typedef CK_CALLBACK_FUNCTION(CK_RV, CIP_SignInit)(
  CK_I_SESSION_DATA_PTR  session_data,
  CK_MECHANISM_PTR  pMechanism,  /* the signature mechanism */
  CK_I_OBJ_PTR      key_obj      /* handle of signature key */
);

/**
 */
typedef CK_CALLBACK_FUNCTION(CK_RV, CIP_Sign)(
  CK_I_SESSION_DATA_PTR  session_data,
  CK_BYTE_PTR       pData,           /* the data to sign */
  CK_ULONG          ulDataLen,       /* count of bytes to sign */
  CK_BYTE_PTR       pSignature,      /* gets the signature */
  CK_ULONG_PTR      pulSignatureLen  /* gets signature length */
);

/**
 */
typedef CK_CALLBACK_FUNCTION(CK_RV, CIP_SignUpdate)(
  CK_I_SESSION_DATA_PTR  session_data,
  CK_BYTE_PTR       pPart,     /* the data to sign */
  CK_ULONG          ulPartLen  /* count of bytes to sign */
);

/**
 */
typedef CK_CALLBACK_FUNCTION(CK_RV, CIP_SignFinal)(
  CK_I_SESSION_DATA_PTR  session_data,
  CK_BYTE_PTR       pSignature,      /* gets the signature */
  CK_ULONG_PTR      pulSignatureLen  /* gets signature length */
);

/**
 */
typedef CK_CALLBACK_FUNCTION(CK_RV, CIP_SignRecoverInit)(
  CK_I_SESSION_DATA_PTR  session_data,
  CK_MECHANISM_PTR  pMechanism, /* the signature mechanism */
  CK_I_OBJ_PTR      key_obj     /* handle of the signature key */
);

/**
 */
typedef CK_CALLBACK_FUNCTION(CK_RV, CIP_SignRecover)(
  CK_I_SESSION_DATA_PTR  session_data,
  CK_BYTE_PTR       pData,           /* the data to sign */
  CK_ULONG          ulDataLen,       /* count of bytes to sign */
  CK_BYTE_PTR       pSignature,      /* gets the signature */
  CK_ULONG_PTR      pulSignatureLen  /* gets signature length */
);

/**
 */
typedef CK_CALLBACK_FUNCTION(CK_RV, CIP_VerifyInit)(
  CK_I_SESSION_DATA_PTR  session_data,
  CK_MECHANISM_PTR  pMechanism,  /* the verification mechanism */
  CK_I_OBJ_PTR      key_obj    /* verification key */ 
);

/**
 */
typedef CK_CALLBACK_FUNCTION(CK_RV, CIP_Verify)(
  CK_I_SESSION_DATA_PTR  session_data,
  CK_BYTE_PTR       pData,          /* signed data */
  CK_ULONG          ulDataLen,      /* length of signed data */
  CK_BYTE_PTR       pSignature,     /* signature */
  CK_ULONG          ulSignatureLen  /* signature length*/
);

/**
 */
typedef CK_CALLBACK_FUNCTION(CK_RV, CIP_VerifyUpdate)(
  CK_I_SESSION_DATA_PTR  session_data,
  CK_BYTE_PTR       pPart,     /* signed data */
  CK_ULONG          ulPartLen  /* length of signed data */
);

/**
 */
typedef CK_CALLBACK_FUNCTION(CK_RV, CIP_VerifyFinal)(
  CK_I_SESSION_DATA_PTR  session_data,
  CK_BYTE_PTR       pSignature,     /* signature to verify */
  CK_ULONG          ulSignatureLen  /* signature length */
);

/**
 */
typedef CK_CALLBACK_FUNCTION(CK_RV, CIP_VerifyRecoverInit)(
  CK_I_SESSION_DATA_PTR  session_data,
  CK_MECHANISM_PTR  pMechanism,  /* the verification mechanism */
  CK_I_OBJ_PTR      key_obj      /* verification key */
);

/**
 */
typedef CK_CALLBACK_FUNCTION(CK_RV, CIP_VerifyRecover)(
  CK_I_SESSION_DATA_PTR  session_data,
  CK_BYTE_PTR       pSignature,      /* signature to verify */
  CK_ULONG          ulSignatureLen,  /* signature length */
  CK_BYTE_PTR       pData,           /* gets signed data */
  CK_ULONG_PTR      pulDataLen       /* gets signed data len */
);

/**
 */
typedef CK_CALLBACK_FUNCTION(CK_RV, CIP_DigestEncryptUpdate)(
  CK_I_SESSION_DATA_PTR  session_data,
  CK_BYTE_PTR       pPart,               /* the plaintext data */
  CK_ULONG          ulPartLen,           /* plaintext length */
  CK_BYTE_PTR       pEncryptedPart,      /* gets ciphertext */
  CK_ULONG_PTR      pulEncryptedPartLen  /* gets c-text length */
);

/**
 */
typedef CK_CALLBACK_FUNCTION(CK_RV, CIP_DecryptDigestUpdate)(
  CK_I_SESSION_DATA_PTR  session_data,
  CK_BYTE_PTR       pEncryptedPart,      /* ciphertext */
  CK_ULONG          ulEncryptedPartLen,  /* ciphertext length */
  CK_BYTE_PTR       pPart,               /* gets plaintext */
  CK_ULONG_PTR      pulPartLen           /* gets plaintext len */
);

/**
 */
typedef CK_CALLBACK_FUNCTION(CK_RV, CIP_SignEncryptUpdate)(
  CK_I_SESSION_DATA_PTR  session_data,
  CK_BYTE_PTR       pPart,               /* the plaintext data */
  CK_ULONG          ulPartLen,           /* plaintext length */
  CK_BYTE_PTR       pEncryptedPart,      /* gets ciphertext */
  CK_ULONG_PTR      pulEncryptedPartLen  /* gets c-text length */
);

/**
 */
typedef CK_CALLBACK_FUNCTION(CK_RV, CIP_DecryptVerifyUpdate)(
  CK_I_SESSION_DATA_PTR  session_data,
  CK_BYTE_PTR       pEncryptedPart,      /* ciphertext */
  CK_ULONG          ulEncryptedPartLen,  /* ciphertext length */
  CK_BYTE_PTR       pPart,               /* gets plaintext */
  CK_ULONG_PTR      pulPartLen           /* gets p-text length */
);

/**
 */
typedef CK_CALLBACK_FUNCTION(CK_RV, CIP_GenerateKey)(
  CK_I_SESSION_DATA_PTR  session_data,
  CK_MECHANISM_PTR       pMechanism,  /* key generation mech. */
  CK_I_OBJ_PTR           key          /* place to put new key */
);

/**
 */
typedef CK_CALLBACK_FUNCTION(CK_RV, CIP_GenerateKeyPair)(
  CK_I_SESSION_DATA_PTR  session_data,
  CK_MECHANISM_PTR       pMechanism,     /* key-gen mech. */
  CK_I_OBJ_PTR           public_key,     /* place to put new public key */
  CK_I_OBJ_PTR           private_key     /* place to put new private key */
);

/**
 */
typedef CK_CALLBACK_FUNCTION(CK_RV, CIP_WrapKey)(
  CK_I_SESSION_DATA_PTR  session_data,
  CK_MECHANISM_PTR  pMechanism,      /* the wrapping mechanism */
  CK_I_OBJ_PTR      wrap_key_obj,    /* wrapping key */
  CK_I_OBJ_PTR      key_obj,         /* key to be wrapped */
  CK_BYTE_PTR       pWrappedKey,     /* gets wrapped key */
  CK_ULONG_PTR      pulWrappedKeyLen /* gets wrapped key size */
);

/**
 */
typedef CK_CALLBACK_FUNCTION(CK_RV, CIP_UnwrapKey)(
  CK_I_SESSION_DATA_PTR  session_data,
  CK_MECHANISM_PTR     pMechanism,        /* unwrapping mech. */
  CK_I_OBJ_PTR         unwrap_key_obj,    /* unwrapping key */
  CK_BYTE_PTR          pWrappedKey,       /* the wrapped key */
  CK_ULONG             ulWrappedKeyLen,   /* wrapped key len */
  CK_I_OBJ_PTR         key_obj            /* object for key to be unwrapped */
);

/**
 */
typedef CK_CALLBACK_FUNCTION(CK_RV, CIP_DeriveKey)(
  CK_I_SESSION_DATA_PTR  session_data,
  CK_MECHANISM_PTR       pMechanism,        /* key deriv. mech. */
  CK_I_OBJ_PTR           base_key,          /* base key */
  CK_I_OBJ_PTR           derived_ky         /* derived key */
);

/**
 */
typedef CK_CALLBACK_FUNCTION(CK_RV, CIP_SeedRandom)(
  CK_I_SESSION_DATA_PTR  session_data,
  CK_BYTE_PTR       pSeed,     /* the seed material */
  CK_ULONG          ulSeedLen  /* length of seed material */
);

/**
 */
typedef CK_CALLBACK_FUNCTION(CK_RV, CIP_GenerateRandom)(
  CK_I_SESSION_DATA_PTR  session_data,
  CK_BYTE_PTR       pRandomData,  /* receives the random data */
  CK_ULONG          ulRandomLen  /* # of bytes to generate */
);

/**
 */
typedef CK_CALLBACK_FUNCTION(CK_RV, CIP_GetFunctionStatus)(
  CK_I_SESSION_DATA_PTR  session_data
);

/**
 */
typedef CK_CALLBACK_FUNCTION(CK_RV, CIP_CancelFunction)(
  CK_I_SESSION_DATA_PTR  session_data
);

/**
 */
typedef CK_CALLBACK_FUNCTION(CK_RV, CIP_WaitForSlotEvent)(
  CK_FLAGS flags,        /* blocking/nonblocking flag */
  CK_SLOT_ID_PTR pSlot,  /* location that receives the slot ID */
  CK_VOID_PTR pRserved   /* reserved.  Should be NULL_PTR */
);

/**
 */
typedef CK_CALLBACK_FUNCTION(CK_RV, CIP_TokenObjRetrieve)(
  CK_I_SESSION_DATA_PTR  session_data,
  CK_OBJECT_HANDLE phObject, 
  CK_I_OBJ_PTR CK_PTR ppNewObject
);

/**
 */
typedef CK_CALLBACK_FUNCTION(CK_RV, CIP_TokenObjCommit)(
  CK_I_SESSION_DATA_PTR  session_data,
  CK_OBJECT_HANDLE       hObject,
  CK_I_OBJ_PTR           pObject
);

/**
 */
typedef CK_CALLBACK_FUNCTION(CK_RV, CIP_TokenObjAdd)(
  CK_I_SESSION_DATA_PTR  session_data,
  CK_OBJECT_HANDLE phObject, 
  CK_I_OBJ_PTR pNewObject
);

/**
 */
typedef CK_CALLBACK_FUNCTION(CK_RV, CIP_TokenObjDelete)(
  CK_I_SESSION_DATA_PTR  session_data,
  CK_OBJECT_HANDLE phObject
);
/* }}} */

/* {{{ CK_I_TOKEN_METHODS */
/** List of methods token implements.
 */
typedef struct ck_i_token_methods_st {
  CIP_GetTokenInfo GetTokenInfo;
  CIP_GetMechanismList GetMechanismList;
  CIP_GetMechanismInfo GetMechanismInfo;
  CIP_InitToken InitToken;
  CIP_FinalizeToken FinalizeToken;
  CIP_InitPIN InitPIN;
  CIP_SetPIN SetPIN;
  CIP_OpenSession OpenSession;
  CIP_CloseSession CloseSession;
  CIP_GetOperationState GetOperationState;
  CIP_SetOperationState SetOperationState;
  CIP_Login Login;
  CIP_Logout Logout;
  CIP_EncryptInit EncryptInit;
  CIP_Encrypt Encrypt;
  CIP_EncryptUpdate EncryptUpdate;
  CIP_EncryptFinal EncryptFinal;
  CIP_DecryptInit DecryptInit;
  CIP_Decrypt Decrypt;
  CIP_DecryptUpdate DecryptUpdate;
  CIP_DecryptFinal DecryptFinal;
  CIP_DigestInit DigestInit;
  CIP_Digest Digest;
  CIP_DigestUpdate DigestUpdate;
  CIP_DigestKey DigestKey;
  CIP_DigestFinal DigestFinal;
  CIP_SignInit SignInit;
  CIP_Sign Sign;
  CIP_SignUpdate SignUpdate;
  CIP_SignFinal SignFinal;
  CIP_SignRecoverInit SignRecoverInit;
  CIP_SignRecover SignRecover;
  CIP_VerifyInit VerifyInit;
  CIP_Verify Verify;
  CIP_VerifyUpdate VerifyUpdate;
  CIP_VerifyFinal VerifyFinal;
  CIP_VerifyRecoverInit VerifyRecoverInit;
  CIP_VerifyRecover VerifyRecover;
  CIP_DigestEncryptUpdate DigestEncryptUpdate;
  CIP_DecryptDigestUpdate DecryptDigestUpdate;
  CIP_SignEncryptUpdate SignEncryptUpdate;
  CIP_DecryptVerifyUpdate DecryptVerifyUpdate;
  CIP_GenerateKey GenerateKey;
  CIP_GenerateKeyPair GenerateKeyPair;
  CIP_WrapKey WrapKey;
  CIP_UnwrapKey UnwrapKey;
  CIP_DeriveKey DeriveKey;
  CIP_SeedRandom SeedRandom;
  CIP_GenerateRandom GenerateRandom;
  CIP_GetFunctionStatus GetFunctionStatus;
  CIP_CancelFunction CancelFunction;
  CIP_WaitForSlotEvent WaitForSlotEvent;

  /* object access methods */
  CIP_TokenObjAdd TokenObjAdd;
  CIP_TokenObjCommit TokenObjCommit;
  CIP_TokenObjDelete TokenObjDelete;
} CK_I_TOKEN_METHODS ;

typedef CK_I_TOKEN_METHODS CK_PTR CK_I_TOKEN_METHODS_PTR;

/* }}} */
/* {{{ CK_I_TOKEN_DATA */
/** Structure into which the token writes basic information.
 *
 * @param token_info    pointer to the structure defined in the PKCS11 Standard
 * @param methods       structure of function pointers containing of the functions 
 *                      provieded by the token.
 * @param slot          number of the slot this token resides in 
 * @param token_objects object visible to all session of the application
 * @param impl_data     pointer to token implementation specific structures.
 */
typedef struct ck_i_token_data_st {
  CK_TOKEN_INFO_PTR token_info;
  CK_SLOT_ID slot; 
  CK_I_HASHTABLE_PTR object_list;      /* Objects of this application */
  CK_VOID_PTR impl_data; 
} CK_I_TOKEN_DATA;

typedef CK_I_TOKEN_DATA CK_PTR CK_I_TOKEN_DATA_PTR;

#define CK_I_object_list_size 200
/* }}} */

/** called by init to make token known to the library.
 */
CK_DECLARE_FUNCTION(CK_RV, CI_RegisterSlot)(
 CK_ULONG slotID,
 /* The data structure CK_I_SLOT_DATA is then defined in the so-called 
  * token module
  */
 CK_I_SLOT_DATA_PTR slot_data
);
/* }}} */

/* {{{ ### Slot and token management ### */

struct ck_i_slot_data_st {
  CK_ULONG flags;
 /* section of the config file that containes information about this slot/token */
  CK_CHAR_PTR config_section_name;
  CK_SLOT_INFO_PTR slot_info;
  CK_I_TOKEN_DATA_PTR token_data;
  CK_I_TOKEN_METHODS_PTR methods;
};



/* internal session flags (Internal_SlotInfoFlag_)*/
#define CK_I_SIF_USER_SESSION      1
#define CK_I_SIF_RW_SO_SESSION     2

/* the slots are read from gpkcs11.rc the variable 
 *CK_I_SLOT_ANZ is initialized in C_Initialize()
 */
extern CK_ULONG CK_I_SLOT_ANZ;
/* }}} */

/* {{{ ### Object Management ### */
/* {{{ Internal Attribute numbers */
#define CK_IA_CLASS              0
#define CK_IA_TOKEN              1
#define CK_IA_PRIVATE            2
#define CK_IA_MODIFIABLE         3
#define CK_IA_LABEL              4
#define CK_IA_APPLICATION        5
#define CK_IA_VALUE              6
#define CK_IA_CERTIFICATE_TYPE   7
#define CK_IA_ISSUER             8
#define CK_IA_SERIAL_NUMBER      9
#define CK_IA_SUBJECT           10
#define CK_IA_KEY_TYPE          11
#define CK_IA_ID                12
#define CK_IA_START_DATE        13
#define CK_IA_END_DATE          14
#define CK_IA_DERIVE            15
#define CK_IA_LOCAL             16
#define CK_IA_ENCRYPT           17
#define CK_IA_VERIFY            18
#define CK_IA_VERIFY_RECOVER    19
#define CK_IA_WRAP              20
#define CK_IA_MODULUS           21
#define CK_IA_MODULUS_BITS      22
#define CK_IA_PUBLIC_EXPONENT   23
#define CK_IA_PRIME             24
#define CK_IA_SUBPRIME          25
#define CK_IA_BASE              26
#define CK_IA_ECDSA_PARAMS      27
#define CK_IA_EC_POINT          28
#define CK_IA_SENSITIVE         29
#define CK_IA_DECRYPT           30
#define CK_IA_SIGN              31
#define CK_IA_SIGN_RECOVER      32
#define CK_IA_UNWRAP            33
#define CK_IA_EXTRACTABLE       34
#define CK_IA_ALWAYS_SENSITIVE  35
#define CK_IA_NEVER_EXTRACTABLE 36
#define CK_IA_PRIVATE_EXPONENT  37
#define CK_IA_PRIME_1           38
#define CK_IA_PRIME_2           39
#define CK_IA_EXPONENT_1        40
#define CK_IA_EXPONENT_2        41
#define CK_IA_COEFFICIENT       42
#define CK_IA_VALUE_BITS        43
#define CK_IA_VALUE_LEN         44

/* Vendor Defined */
#define CK_IA_SSL_VERSION       45
#define CK_IA_PERSISTENT_KEY     46

/* number of different attributes */
#define I_ATT_MAX_NUM 47


/* }}} */

/* object container size per session */
#define CK_I_OBJ_LIST_SIZE      50

typedef CK_ATTRIBUTE_PTR CK_PTR CK_ATTRIBUTE_PTR_PTR;

struct ck_i_obj_st {
  CK_I_HASHTABLE_PTR table;
  CK_ATTRIBUTE_PTR CK_PTR lookup; /* CK_TEMPLATE_PTR[I_ATT_MAX_NUM] */
  CK_I_SESSION_DATA_PTR session; /* the session to which I belong */
  CK_BBOOL changed; /* this object was changed since the last commit */
  CK_ULONG ref_count; /* reference count. If it falls to 0 the object needs to be deleted */
};

#define CK_I_OBJ_INITIAL_SIZE   50

/* }}} */

/* {{{ ### Session Management */
/* state structure for object search (C_FindObjects...) */
typedef struct CK_I_FIND_STATE {
  CK_I_HASH_ITERATOR_PTR search_iter;
  CK_I_OBJ_PTR pTemplate;
  /* are we currently searching through the session private and token objs? */
  CK_BBOOL searching_private; 
} CK_I_FIND_STATE;

typedef CK_I_FIND_STATE CK_PTR CK_I_FIND_STATE_PTR;

typedef struct CK_I_APP_DATA {
  CK_I_HASHTABLE_PTR session_table;    /* sessions of this application */
} CK_I_APP_DATA;

typedef CK_I_APP_DATA CK_PTR CK_I_APP_DATA_PTR;

/* Session management information */

struct ck_i_session_data_st {
  CK_SESSION_HANDLE session_handle;    /* the handle of this session */
  CK_USER_TYPE user_type;              /* Type of user that runs this session */
  CK_VOID_PTR pApplication;            /* Information to be returned when using a callback */
  CK_I_APP_DATA app_data;              /* my application */
  CK_NOTIFY Notify;
  CK_SESSION_INFO_PTR session_info;
  CK_I_SLOT_DATA_PTR slot_data;      /* Pointer to the structure representing the token 
					  of this session */ 
  CK_I_HASHTABLE_PTR object_list;      /* Objects of this session, deep copies of supplied templates */
  CK_I_FIND_STATE_PTR find_state;      /* internal state for the FindObject functions */
  CK_VOID_PTR digest_state;            /* Created by C_DigestInit */
  CK_MECHANISM_TYPE digest_mechanism;  /* mechanism of active digest if digest_state != NULL_PTR */
  CK_VOID_PTR encrypt_state;           /* Created by C_EncryptInit */
  CK_MECHANISM_TYPE encrypt_mechanism; /* mechanism of active encryption if encrypt_state != NULL_PTR */
  CK_VOID_PTR decrypt_state;           /* Created by C_DecryptInit */
  CK_MECHANISM_TYPE decrypt_mechanism; /* mechanism of active decryption if decrypt_state != NULL_PTR */
  CK_VOID_PTR sign_state;              /* Created by C_SignInit */
  CK_MECHANISM_TYPE sign_mechanism;    /* mechanism of active signing if sign_state != NULL_PTR */   
  CK_VOID_PTR verify_state;            /* Created by C_VerifyInit */
  CK_MECHANISM_TYPE verify_mechanism;  /* mechanism of active verifying if verify_state != NULL_PTR */   
  CK_VOID_PTR implement_data;          /* Pointer to data required by a given token implementation */
};

/* }}} */

/* finding the token of a session (takes CK_I_SESSION_DATA)*/
#define SESS_TOKEN(_sess) (_sess->slot_data->token_data)
/* finding the methods of a session (takes CK_I_SESSION_DATA) */
#define SESS_METHODS(_sess) (_sess->slot_data->methods)

/* TODO: there is only one application information structure, since there is
 * no mult app handling at the moment. this must change (the space is 
 * allocated in objects.c) 
 */
extern CK_I_APP_DATA CK_I_app_table;

#endif /* _INTERNAL_DEF_H_ */

/*
 * Local variables:
 * folded-file: t
 * end:
 */
