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
 * NAME:        ceay_token.h
 * SYNOPSIS:    -
 * DESCRIPTION: -
 * FILES:       -
 * SEE/ALSO:    -
 * AUTHOR:      lbe
 * BUGS:        -
 */

#include "internal.h"
#include "cryptdb.h"

/* *** includes of the crypto lib *** */
/* for bn.h */
#ifndef WIN16
#include <stdio.h>
#endif
#include <openssl/rsa.h>

#include <openssl/des.h>
#include <openssl/rc2.h>
#include <openssl/idea.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/dsa.h>

/* ### mechanism information ### */
#define USE_ALL_CRYPT
#ifdef USE_ALL_CRYPT
# define CK_I_CEAY_MECHANISM_NUM 32
#else
# define CK_I_CEAY_MECHANISM_NUM 3
#endif

#define CK_I_SERIAL_LENGTH	16

extern CK_MECHANISM_TYPE ceay_mechanism_list[];
extern CK_MECHANISM_INFO ceay_mechanism_info_list[];
extern CK_I_TOKEN_DATA Ceay_token_data;
extern CK_I_SLOT_DATA Ceay_slot_data;

/* to make getting to the implementation data easier */
#define IMPL_DATA( _field) (((CK_I_CEAY_IMPL_DATA_PTR)(Ceay_token_data.impl_data))->_field)
/* and analog to the implementation specific information in the session */
#define SESS_IMPL_DATA( _field) (((CK_I_CEAY_SESS_IMPL_DATA_PTR)(session_data->implement_data))->_field)
/* finding the config section for this slot */
#define CEAY_CONFIG_SECTION (Ceay_slot_data.config_section_name)

/* ### various mechanism Definitions ### */
/* You can argue that they clutter the namespace as this might be included 
 * in other application as well. But I believe that definitions are to be 
 * put into a header and not into the code. 
 */
#define CK_I_SSL3_PRE_MASTER_SIZE 48
#define CK_I_SSL3_KEY_BLOCK_SIZE 48
#define CK_I_IVEC_LEN 8
#define CK_I_DSA_SIGN_LEN 48
#define CK_I_DSA_DIGEST_LEN 20

/* minimal lenght of padding/blocktype+marker bytes in a PKCS#1 key */
#define CK_I_PKCS1_MIN_PADDING 3
/**
 */
CK_DECLARE_FUNCTION(CK_RV, CI_Ceay_GetTokenInfo)(
  CK_I_SLOT_DATA_PTR  slot_data,
  CK_TOKEN_INFO_PTR pInfo    /* receives the token information */
);

/**
 */
CK_DECLARE_FUNCTION(CK_RV, CI_Ceay_GetMechanismList)(
  CK_MECHANISM_TYPE_PTR pMechanismList,  /* gets mech. array */
  CK_ULONG_PTR          pulCount         /* gets # of mechs. */
);

/**
 */
CK_DECLARE_FUNCTION(CK_RV, CI_Ceay_GetMechanismInfo)(
  CK_MECHANISM_TYPE     type,    /* type of mechanism */
  CK_MECHANISM_INFO_PTR pInfo    /* receives mechanism info */
);

/**
 */
CK_DECLARE_FUNCTION(CK_RV, CI_Ceay_InitToken)(
  CK_CHAR_PTR       pPin,      /* the SO's initial PIN */
  CK_ULONG          ulPinLen,  /* length in bytes of the PIN */
  CK_CHAR_PTR       pLabel     /* 32-byte token label (blank padded) */
);

/**
 */
CK_DECLARE_FUNCTION(CK_RV, CI_Ceay_FinalizeToken)(
  CK_I_SLOT_DATA_PTR slot_data
);

/**
 */
CK_DECLARE_FUNCTION(CK_RV, CI_Ceay_InitPIN)(
  CK_I_SESSION_DATA_PTR session_data,  
  CK_CHAR_PTR       pPin,      /* the normal user's PIN */
  CK_ULONG          ulPinLen   /* length in bytes of the PIN */
);

/**
 */
CK_DECLARE_FUNCTION(CK_RV, CI_Ceay_SetPIN)(
  CK_I_SESSION_DATA_PTR session_data,  
  CK_CHAR_PTR       pOldPin,   /* the old PIN */
  CK_ULONG          ulOldLen,  /* length of the old PIN */
  CK_CHAR_PTR       pNewPin,   /* the new PIN */
  CK_ULONG          ulNewLen   /* length of the new PIN */
);

/**
 */
CK_DECLARE_FUNCTION(CK_RV, CI_Ceay_EncryptInit)(
  CK_I_SESSION_DATA_PTR  session_data,
  CK_MECHANISM_PTR       pMechanism,  /* the encryption mechanism */
  CK_I_OBJ_PTR           key_obj      /* handle of encryption key */
);

/**
 */
CK_DECLARE_FUNCTION(CK_RV, CI_Ceay_Encrypt)(
  CK_I_SESSION_DATA_PTR  session_data,
  CK_BYTE_PTR       pData,               /* the plaintext data */
  CK_ULONG          ulDataLen,           /* bytes of plaintext */
  CK_BYTE_PTR       pEncryptedData,      /* gets ciphertext */
  CK_ULONG_PTR      pulEncryptedDataLen  /* gets c-text size */
);

/**
 */
CK_DECLARE_FUNCTION(CK_RV, CI_Ceay_EncryptUpdate)(
  CK_I_SESSION_DATA_PTR  session_data,
  CK_BYTE_PTR       pPart,              /* the plaintext data */
  CK_ULONG          ulPartLen,          /* plaintext data len */
  CK_BYTE_PTR       pEncryptedPart,     /* gets ciphertext */
  CK_ULONG_PTR      pulEncryptedPartLen /* gets c-text size */
);

/**
 */
CK_DECLARE_FUNCTION(CK_RV, CI_Ceay_EncryptFinal)(
  CK_I_SESSION_DATA_PTR  session_data,
  CK_BYTE_PTR       pLastEncryptedPart,      /* last c-text */
  CK_ULONG_PTR      pulLastEncryptedPartLen  /* gets last size */
);

/**
 */
CK_DECLARE_FUNCTION(CK_RV, CI_Ceay_DecryptInit)(
  CK_I_SESSION_DATA_PTR  session_data,
  CK_MECHANISM_PTR  pMechanism,     /* the decryption mechanism */
  CK_I_OBJ_PTR      key_obj         /* handle of decryption key */
);

/**
 */
CK_DECLARE_FUNCTION(CK_RV, CI_Ceay_Decrypt)(
  CK_I_SESSION_DATA_PTR  session_data,
  CK_BYTE_PTR       pEncryptedData,     /* ciphertext */
  CK_ULONG          ulEncryptedDataLen, /* ciphertext length */
  CK_BYTE_PTR       pData,              /* gets plaintext */
  CK_ULONG_PTR      pulDataLen          /* gets p-text size */
);

/**
 */
CK_DECLARE_FUNCTION(CK_RV, CI_Ceay_DecryptUpdate)(
  CK_I_SESSION_DATA_PTR  session_data,
  CK_BYTE_PTR       pEncryptedPart,      /* encrypted data */
  CK_ULONG          ulEncryptedPartLen,  /* input length */
  CK_BYTE_PTR       pPart,               /* gets plaintext */
  CK_ULONG_PTR      pulPartLen           /* p-text size */
);

/**
 */
CK_DECLARE_FUNCTION(CK_RV, CI_Ceay_DecryptFinal)(
  CK_I_SESSION_DATA_PTR  session_data,
  CK_BYTE_PTR       pLastPart,      /* gets plaintext */
  CK_ULONG_PTR      pulLastPartLen  /* p-text size */
);

/**
 */
CK_DECLARE_FUNCTION(CK_RV, CI_Ceay_DigestInit)(
  CK_I_SESSION_DATA_PTR  session_data,
  CK_MECHANISM_PTR  pMechanism  /* the digesting mechanism */
);

/**
 */
CK_DECLARE_FUNCTION(CK_RV, CI_Ceay_Digest)(
  CK_I_SESSION_DATA_PTR  session_data,
  CK_BYTE_PTR       pData,        /* data to be digested */
  CK_ULONG          ulDataLen,    /* bytes of data to digest */
  CK_BYTE_PTR       pDigest,      /* gets the message digest */
  CK_ULONG_PTR      pulDigestLen  /* gets digest length */
);

/**
 */
CK_DECLARE_FUNCTION(CK_RV, CI_Ceay_DigestUpdate)(
  CK_I_SESSION_DATA_PTR  session_data,
  CK_C_BYTE_PTR       pPart,     /* data to be digested */
  CK_ULONG          ulPartLen  /* bytes of data to be digested */
);

/**
 */
CK_DECLARE_FUNCTION(CK_RV, CI_Ceay_DigestKey)(
  CK_I_SESSION_DATA_PTR  session_data,
  CK_I_OBJ_PTR           key_obj       /* secret key to digest */
);

/**
 */
CK_DECLARE_FUNCTION(CK_RV, CI_Ceay_DigestFinal)(
  CK_I_SESSION_DATA_PTR  session_data,
  CK_BYTE_PTR       pDigest,      /* gets the message digest */
  CK_ULONG_PTR      pulDigestLen  /* gets byte count of digest */
);

/**
 */
CK_DECLARE_FUNCTION(CK_RV, CI_Ceay_SignInit)(
  CK_I_SESSION_DATA_PTR  session_data,
  CK_MECHANISM_PTR  pMechanism,  /* the signature mechanism */
  CK_I_OBJ_PTR      key_obj      /* handle of signature key */
);

/**
 */
CK_DECLARE_FUNCTION(CK_RV, CI_Ceay_Sign)(
  CK_I_SESSION_DATA_PTR  session_data,
  CK_BYTE_PTR       pData,           /* the data to sign */
  CK_ULONG          ulDataLen,       /* count of bytes to sign */
  CK_BYTE_PTR       pSignature,      /* gets the signature */
  CK_ULONG_PTR      pulSignatureLen  /* gets signature length */
);

/**
 */
CK_DECLARE_FUNCTION(CK_RV, CI_Ceay_SignUpdate)(
  CK_I_SESSION_DATA_PTR  session_data,
  CK_BYTE_PTR       pPart,     /* the data to sign */
  CK_ULONG          ulPartLen  /* count of bytes to sign */
);

/**
 */
CK_DECLARE_FUNCTION(CK_RV, CI_Ceay_SignFinal)(
  CK_I_SESSION_DATA_PTR  session_data,
  CK_BYTE_PTR       pSignature,      /* gets the signature */
  CK_ULONG_PTR      pulSignatureLen  /* gets signature length */
);

/**
 */
CK_DECLARE_FUNCTION(CK_RV, CI_Ceay_SignRecoverInit)(
  CK_I_SESSION_DATA_PTR  session_data,
  CK_MECHANISM_PTR  pMechanism, /* the signature mechanism */
  CK_I_OBJ_PTR      key_obj     /* handle of the signature key */
);

/**
 */
CK_DECLARE_FUNCTION(CK_RV, CI_Ceay_SignRecover)(
  CK_I_SESSION_DATA_PTR  session_data,
  CK_BYTE_PTR       pData,           /* the data to sign */
  CK_ULONG          ulDataLen,       /* count of bytes to sign */
  CK_BYTE_PTR       pSignature,      /* gets the signature */
  CK_ULONG_PTR      pulSignatureLen  /* gets signature length */
);

/**
 */
CK_DECLARE_FUNCTION(CK_RV, CI_Ceay_VerifyInit)(
  CK_I_SESSION_DATA_PTR  session_data,
  CK_MECHANISM_PTR  pMechanism,  /* the verification mechanism */
  CK_I_OBJ_PTR      key_obj    /* verification key */ 
);

/**
 */
CK_DECLARE_FUNCTION(CK_RV, CI_Ceay_Verify)(
  CK_I_SESSION_DATA_PTR  session_data,
  CK_BYTE_PTR       pData,          /* signed data */
  CK_ULONG          ulDataLen,      /* length of signed data */
  CK_BYTE_PTR       pSignature,     /* signature */
  CK_ULONG          ulSignatureLen  /* signature length*/
);

/**
 */
CK_DECLARE_FUNCTION(CK_RV, CI_Ceay_VerifyUpdate)(
  CK_I_SESSION_DATA_PTR  session_data,
  CK_BYTE_PTR       pPart,     /* signed data */
  CK_ULONG          ulPartLen  /* length of signed data */
);

/**
 */
CK_DECLARE_FUNCTION(CK_RV, CI_Ceay_VerifyFinal)(
  CK_I_SESSION_DATA_PTR  session_data,
  CK_BYTE_PTR       pSignature,     /* signature to verify */
  CK_ULONG          ulSignatureLen  /* signature length */
);

/**
 */
CK_DECLARE_FUNCTION(CK_RV, CI_Ceay_VerifyRecoverInit)(
  CK_I_SESSION_DATA_PTR  session_data,
  CK_MECHANISM_PTR  pMechanism,  /* the verification mechanism */
  CK_I_OBJ_PTR      key_obj      /* verification key */
);

/**
 */
CK_DECLARE_FUNCTION(CK_RV, CI_Ceay_VerifyRecover)(
  CK_I_SESSION_DATA_PTR  session_data,
  CK_BYTE_PTR       pSignature,      /* signature to verify */
  CK_ULONG          ulSignatureLen,  /* signature length */
  CK_BYTE_PTR       pData,           /* gets signed data */
  CK_ULONG_PTR      pulDataLen       /* gets signed data len */
);

/**
 */
CK_DECLARE_FUNCTION(CK_RV, CI_Ceay_DigestEncryptUpdate)(
  CK_I_SESSION_DATA_PTR  session_data,
  CK_BYTE_PTR       pPart,               /* the plaintext data */
  CK_ULONG          ulPartLen,           /* plaintext length */
  CK_BYTE_PTR       pEncryptedPart,      /* gets ciphertext */
  CK_ULONG_PTR      pulEncryptedPartLen  /* gets c-text length */
);

/**
 */
CK_DECLARE_FUNCTION(CK_RV, CI_Ceay_DecryptDigestUpdate)(
  CK_I_SESSION_DATA_PTR  session_data,
  CK_BYTE_PTR       pEncryptedPart,      /* ciphertext */
  CK_ULONG          ulEncryptedPartLen,  /* ciphertext length */
  CK_BYTE_PTR       pPart,               /* gets plaintext */
  CK_ULONG_PTR      pulPartLen           /* gets plaintext len */
);

/**
 */
CK_DECLARE_FUNCTION(CK_RV, CI_Ceay_SignEncryptUpdate)(
  CK_I_SESSION_DATA_PTR  session_data,
  CK_BYTE_PTR       pPart,               /* the plaintext data */
  CK_ULONG          ulPartLen,           /* plaintext length */
  CK_BYTE_PTR       pEncryptedPart,      /* gets ciphertext */
  CK_ULONG_PTR      pulEncryptedPartLen  /* gets c-text length */
);

/**
 */
CK_DECLARE_FUNCTION(CK_RV, CI_Ceay_DecryptVerifyUpdate)(
  CK_I_SESSION_DATA_PTR  session_data,
  CK_BYTE_PTR       pEncryptedPart,      /* ciphertext */
  CK_ULONG          ulEncryptedPartLen,  /* ciphertext length */
  CK_BYTE_PTR       pPart,               /* gets plaintext */
  CK_ULONG_PTR      pulPartLen           /* gets p-text length */
);

/**
 */
CK_DECLARE_FUNCTION(CK_RV, CI_Ceay_GenerateKey)(
  CK_I_SESSION_DATA_PTR  session_data,
  CK_MECHANISM_PTR       pMechanism,     /* key generation mech. */
  CK_I_OBJ_PTR           key_obj         /* generated key object is put in here */
);

/**
 */
CK_DECLARE_FUNCTION(CK_RV, CI_Ceay_GenerateKeyPair)(
  CK_I_SESSION_DATA_PTR   session_data,
  CK_MECHANISM_PTR        pMechanism,      /* key-gen mech. */
  CK_I_OBJ_PTR            public_key_obj,  /* generated public key data 
			                    * is put in here */
  CK_I_OBJ_PTR            private_key_obj  /* generated private key data 
                                            * is put in here */
);

/**
 */
CK_DECLARE_FUNCTION(CK_RV, CI_Ceay_WrapKey)(
  CK_I_SESSION_DATA_PTR  session_data,
  CK_MECHANISM_PTR  pMechanism,      /* the wrapping mechanism */
  CK_I_OBJ_PTR      wrap_key_obj,    /* wrapping key */
  CK_I_OBJ_PTR      key_obj,         /* key to be wrapped */
  CK_BYTE_PTR       pWrappedKey,     /* gets wrapped key */
  CK_ULONG_PTR      pulWrappedKeyLen /* gets wrapped key size */
);

/**
 */
CK_DECLARE_FUNCTION(CK_RV, CI_Ceay_UnwrapKey)(
  CK_I_SESSION_DATA_PTR  session_data,
  CK_MECHANISM_PTR     pMechanism,        /* unwrapping mech. */
  CK_I_OBJ_PTR         unwrap_key_obj,    /* unwrapping key */
  CK_BYTE_PTR          pWrappedKey,       /* the wrapped key */
  CK_ULONG             ulWrappedKeyLen,   /* wrapped key len */
  CK_I_OBJ_PTR         key_obj           /* key to be unwrapped */
);

/**
 */
CK_DECLARE_FUNCTION(CK_RV, CI_Ceay_DeriveKey)(
  CK_I_SESSION_DATA_PTR  session_data,
  CK_MECHANISM_PTR       pMechanism,     /* key deriv. mech. */
  CK_I_OBJ_PTR           base_key,       /* base key */
  CK_I_OBJ_PTR           new_key         /* object for derived key */
);

/**
 */
CK_DECLARE_FUNCTION(CK_RV, CI_Ceay_SeedRandom)(
  CK_I_SESSION_DATA_PTR  session_data,
  CK_BYTE_PTR       pSeed,     /* the seed material */
  CK_ULONG          ulSeedLen  /* length of seed material */
);

/**
 */
CK_DECLARE_FUNCTION(CK_RV, CI_Ceay_GenerateRandom)(
  CK_I_SESSION_DATA_PTR  session_data,
  CK_BYTE_PTR       pRandomData,  /* receives the random data */
  CK_ULONG          ulRandomLen  /* # of bytes to generate */
);

/**
 */
CK_DECLARE_FUNCTION(CK_RV, CI_Ceay_GetFunctionStatus)(
  CK_I_SESSION_DATA_PTR  session_data
);

/**
 */
CK_DECLARE_FUNCTION(CK_RV, CI_Ceay_CancelFunction)(
  CK_I_SESSION_DATA_PTR  session_data
);

/**
 */
CK_DECLARE_FUNCTION(CK_RV, CI_Ceay_OpenSession)(
  CK_I_SESSION_DATA_PTR   session_data   
);

/**
 */
CK_DECLARE_FUNCTION(CK_RV, CI_Ceay_CloseSession)(
  CK_I_SESSION_DATA_PTR   session_data
);

/**
 */
CK_DECLARE_FUNCTION(CK_RV, CI_Ceay_GetOperationState)(
  CK_I_SESSION_DATA_PTR session_data,     
  CK_BYTE_PTR           pOperationState,      /* gets state */
  CK_ULONG_PTR          pulOperationStateLen  /* gets state length */
);

/**
 */
CK_DECLARE_FUNCTION(CK_RV, CI_Ceay_SetOperationState)(
  CK_I_SESSION_DATA_PTR session_data,     
  CK_BYTE_PTR           pOperationState,      /* holds state */
  CK_ULONG              ulOperationStateLen,  /* holds state length */
  CK_I_OBJ_PTR          encrypt_key_obj,      /* en/decryption key */
  CK_I_OBJ_PTR          auth_key_obj          /* sign/verify key */
);

/**
 */
CK_DECLARE_FUNCTION(CK_RV, CI_Ceay_Login)(
  CK_I_SESSION_DATA_PTR session_data,  /* the session's handle */
  CK_USER_TYPE          userType,      /* the user type */
  CK_CHAR_PTR           pPin,          /* the user's PIN */
  CK_ULONG              ulPinLen       /* the length of the PIN */
);

/**
 */
CK_DECLARE_FUNCTION(CK_RV, CI_Ceay_Logout)(
  CK_I_SESSION_DATA_PTR session_data  /* the session's handle */
);


/**
 */
CK_DECLARE_FUNCTION(CK_RV, CI_Ceay_WaitForSlotEvent)(
  CK_FLAGS flags,        /* blocking/nonblocking flag */
  CK_SLOT_ID_PTR pSlot,  /* location that receives the slot ID */
  CK_VOID_PTR pRserved   /* reserved.  Should be NULL_PTR */
);

/**
 */
CK_DECLARE_FUNCTION(CK_RV, CI_Ceay_TokenObjRetrieve)(
  CK_OBJECT_HANDLE phObject, 
  CK_I_OBJ_PTR CK_PTR ppNewObject
);

/**
 */
CK_DECLARE_FUNCTION(CK_RV, CI_Ceay_TokenObjCommit)(
  CK_I_SESSION_DATA_PTR session_data,
  CK_OBJECT_HANDLE hObject,
  CK_I_OBJ_PTR pObject
);

/**
 */
CK_DECLARE_FUNCTION(CK_RV, CI_Ceay_TokenObjAdd)(
  CK_I_SESSION_DATA_PTR session_data,
  CK_OBJECT_HANDLE phObject, 
  CK_I_OBJ_PTR pNewObject
);

/**
 */
CK_DECLARE_FUNCTION(CK_RV, CI_Ceay_TokenObjDelete)(
  CK_I_SESSION_DATA_PTR session_data,
  CK_OBJECT_HANDLE phObject
);

/**
 */
CK_DECLARE_FUNCTION(CK_RV, ceayToken_init)(
 CK_CHAR_PTR token_name,
 CK_I_SLOT_DATA_PTR CK_PTR ppSlotData
);

/******************************************************************
 *      internal function, not exported in internal_slot.h        *
 ******************************************************************/

typedef RSA CK_PTR RSA_PTR;
typedef DSA CK_PTR DSA_PTR;

/** Erzeugen einer internen struktur aus einem Template.
 * @return ceay interne RSA Schlüssel Struktur; NULL_PTR bei auftreten 
 *         eines Fehlers
 * @param  key_obj Schlüssel der in die Struktur gewandelt werden soll.
 */
CK_DECLARE_FUNCTION(RSA_PTR, CI_Ceay_Obj2RSA)(
 CK_I_OBJ_PTR key_obj
);

/** Erzeugen einer internen struktur aus einem Template.
 * @return ceay interne DSA Schlüssel Struktur; NULL_PTR bei auftreten 
 *         eines Fehlers
 * @param  key_obj Schlüssel der in die Struktur gewandelt werden soll.
 */
CK_DECLARE_FUNCTION(DSA_PTR, CI_Ceay_Obj2DSA)(
 CK_I_OBJ_PTR key_obj
);

/** Füllt Teile eines Templates aus einer internen Struktur.
 */
CK_DECLARE_FUNCTION(CK_RV, CI_Ceay_RSA2Obj)(
 RSA CK_PTR rsa_struct,
 CK_I_OBJ_PTR pKeyObj
);

/** Erzeugen eines DER-Strings aus einem Public- oder Private Key.
 */
CK_DECLARE_FUNCTION(CK_RV, CI_Ceay_MakeKeyString)(
 CK_I_OBJ_PTR key_obj,
 CK_BYTE_PTR pBuffer,
 CK_ULONG_PTR pulBufferLen
);

/** Key/Digest transformation for SSL3.
 */
CK_DECLARE_FUNCTION(CK_RV, CI_Ceay_DigestTransform)(
  CK_I_SESSION_DATA_PTR  session_data,
  CK_BYTE_PTR pSecret,
  CK_ULONG ulSecretLen,
  CK_BYTE_PTR pRandom1,
  CK_ULONG ulRandom1Len,
  CK_BYTE_PTR pRandom2,
  CK_ULONG ulRandom2Len,
  CK_BYTE_PTR pDigest  /* stuff will be written in here */
  );

/** copy/convert bignum into object(s).
 */
CK_DECLARE_FUNCTION(CK_RV, CI_Ceay_BN2ObjEntry)(
  CK_ATTRIBUTE_TYPE Attrib,
  BIGNUM*  number,
  CK_I_OBJ_PTR pPrivateObj,
  CK_I_OBJ_PTR pPublicObj
);

/** copy a Attribute value into a BigNumber.
  @param Attrib pointer to a structure that contains the value.
  @param number reference to pointer of the Big-Number structure. If 
                *number = NULL_PTR, a memory for a structure will be 
                allocated. The caller of this function is responsible
                for freeing this memory.
  @return CKR_HOST_MEMORY if the allocation of any memory failed, 
          CKR_GENERAL_ERROR if an error occoured during transformation
          of the big-number. CKR_OK otherwise.
 */
CK_DECLARE_FUNCTION(CK_RV, CI_Ceay_ObjEntry2BN)(
  CK_ATTRIBUTE_PTR Attrib,
  BIGNUM** number
);

CK_DECLARE_FUNCTION(CK_RV, CI_Ceay_GetPersistentFile)(
  FILE CK_PTR CK_PTR ppFileName,
  CK_ULONG flags
);

CK_DECLARE_FUNCTION(CK_RV, CI_Ceay_ReadPersistent)(
  CK_I_SESSION_DATA_PTR session_data,
  CK_I_HASHTABLE_PTR CK_PTR ppCache 
);

/** Load the private objects after login in
 */
CK_DECLARE_FUNCTION(CK_RV, CI_Ceay_ReadPrivate)(
  CK_I_SESSION_DATA_PTR session_data,
  CK_I_CRYPT_DB_PTR cryptdb 
);

/** Callback supplied to rsa_key_gen as wrapper for the pkcs11 callback.
 */
CK_DECLARE_FUNCTION(void, CI_Ceay_RSA_Callback)(
  int type,      /* type of callback */
  int count,     /* value of prime (?) */
  void* session_ptr  /* pointer to the session. In truth this is a CK_I_SESSION_DATA_PTR */
); 


/** Generates a SerialNumber from epoch.
 */
CK_DECLARE_FUNCTION(CK_RV, CI_Ceay_GenerateSerialNumber)(
	CK_CHAR_PTR p_serialNumber
);
/******************************************************************
 *                  internal structures                           *
 ******************************************************************/

/* scratch board for the token. Everything that needs to be kept track of */
typedef struct CK_I_CEAY_IMPL_DATA
{
  /* cache of persistent objects */
  CK_I_HASHTABLE_PTR persistent_cache;
  /* pointer to session_data as key _and_ val */
  CK_I_HASHTABLE_PTR session_list; 
  /* count of unsuccessful trial to enter correct pin */
  CK_ULONG user_trial_count;           /* user tries still availiable */
  CK_ULONG so_trial_count;             /* so tries still availiable */
  CK_CHAR_PTR so_pin;
  CK_ULONG so_pin_len;
  CK_CHAR_PTR user_pin;
  CK_ULONG user_pin_len;
} CK_I_CEAY_IMPL_DATA;

typedef CK_I_CEAY_IMPL_DATA CK_PTR CK_I_CEAY_IMPL_DATA_PTR;

/* session specific data a Ceay token needs to keep track of */
typedef struct CK_I_CEAY_SESS_IMPL_DATA
{
  int dummy;
} CK_I_CEAY_SESS_IMPL_DATA;

typedef CK_I_CEAY_SESS_IMPL_DATA CK_PTR CK_I_CEAY_SESS_IMPL_DATA_PTR;

typedef struct CK_I_CEAY_DES_INFO
{
  des_key_schedule sched;
  des_cblock ivec;
  CK_CHAR pad;
  CK_CHAR round;
  CK_CHAR lastblock[8];
} CK_I_CEAY_DES_INFO;

typedef CK_I_CEAY_DES_INFO CK_PTR CK_I_CEAY_DES_INFO_PTR;

typedef struct CK_I_CEAY_RC2_INFO
{
  RC2_KEY *key;
  unsigned char ivec[8];
} CK_I_CEAY_RC2_INFO;

typedef CK_I_CEAY_RC2_INFO CK_PTR CK_I_CEAY_RC2_INFO_PTR;

typedef struct CK_I_CEAY_DES3_INFO
{
  des_key_schedule sched[3];
  des_cblock *ivec;  /* not used with ecb */
} CK_I_CEAY_DES3_INFO;

typedef CK_I_CEAY_DES3_INFO CK_PTR CK_I_CEAY_DES3_INFO_PTR;

typedef struct CK_I_CEAY_IDEA_INFO
{
  IDEA_KEY_SCHEDULE sched;
  /* TODO: change this to uchar[8] */
  unsigned char *ivec;
} CK_I_CEAY_IDEA_INFO;

typedef CK_I_CEAY_IDEA_INFO CK_PTR CK_I_CEAY_IDEA_INFO_PTR;

typedef struct CK_I_MD5_MAC_STATE {
  MD5_CTX CK_PTR inner_CTX;
  MD5_CTX CK_PTR outer_CTX;
  CK_MAC_GENERAL_PARAMS params;
} CK_I_MD5_MAC_STATE;

typedef CK_I_MD5_MAC_STATE CK_PTR CK_I_MD5_MAC_STATE_PTR;

typedef struct CK_I_SHA_MAC_STATE {
  SHA_CTX CK_PTR inner_CTX;
  SHA_CTX CK_PTR outer_CTX;
  CK_MAC_GENERAL_PARAMS params;
} CK_I_SHA_MAC_STATE;

typedef CK_I_SHA_MAC_STATE CK_PTR CK_I_SHA_MAC_STATE_PTR;

/* For C_GetOperationState and C_SetOperationState services    */
typedef struct CK_I_OPERATION_STATE {
  CK_USER_TYPE user_type;              /* Type of user that runs this session */
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
} CK_I_OPERATION_STATE;

typedef struct CK_I_OPERATION_STATE CK_PTR CK_I_OPERATION_STATE_PTR;

/*
 * Local variables:
 * folded-file: t
 * end:
 */
