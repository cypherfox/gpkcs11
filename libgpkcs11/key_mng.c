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
 * NAME:        key_mng.c
 * SYNOPSIS:    -
 * DESCRIPTION: -
 * FILES:       -
 * SEE/ALSO:    -
 * AUTHOR:      lbe
 * BUGS:        -
 */
 
static char RCSID[]="$Id$";
const char* Version_key_mng_c(){return RCSID;}

#ifndef CK_I_library_build
#define CK_I_library_build
#endif

#include "internal.h"
#include "objects.h"
#include "error.h"

#include <stdlib.h>
#include <assert.h>

/* to stop the execution when debugging */
#include <signal.h>
#ifdef HAVE_UNISTD_H 

#include <unistd.h>
#endif /* HAVE_UNISTD_H */


/* {{{ C_GenerateKey */
CK_DEFINE_FUNCTION(CK_RV, C_GenerateKey)(
        CK_SESSION_HANDLE hSession,
        CK_MECHANISM_PTR pMechanism,
        CK_ATTRIBUTE_PTR pTemplate,
        CK_ULONG ulCount,
        CK_OBJECT_HANDLE_PTR phKey
      )
{
  CK_RV rv = CKR_OK;
  CK_I_SESSION_DATA_PTR session_data = NULL_PTR;
  CK_I_OBJ_PTR new_key = NULL_PTR;  /* object to be created */
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

  /* make sure we are initialized */
  if (!(CK_I_global_flags & CK_IGF_INITIALIZED)) 
    return CKR_CRYPTOKI_NOT_INITIALIZED;

  rv = CI_ReturnSession(hSession, &session_data);
  if(rv != CKR_OK)
    {
      CI_VarLogEntry("C_GenerateKey", "retrieve session data (hSession: %lu)", rv, 1,
                     hSession);
      return rv;
    }

  CI_ObjCreateObj(&new_key);

  /* parse the template */
  CI_ObjReadTemplate(new_key, pTemplate, ulCount);
  
  /* template must not specify an inconsistent class  */
  if( (CI_ObjLookup(new_key,CK_IA_CLASS) != NULL_PTR) && 
      (*((CK_OBJECT_CLASS_PTR)(CI_ObjLookup(new_key,CK_IA_CLASS)->pValue)) != CKO_SECRET_KEY) )
    {
      CI_ObjDestroyObj(new_key);
      rv = CKR_TEMPLATE_INCONSISTENT;
      CI_LogEntry("C_GenerateKey", "...exit: key template check", rv, 1);
      return rv ;
    }

  CI_LogEntry("C_GenerateKey", "key template consistency checked", rv, 1);

  /* ok before we do the real work we should seed the RNG a bit more */
  /* the arbitrary pointers in the template seem a good idea */
  CK_I_CALL_TOKEN_METHOD(rv, SeedRandom, (session_data,(CK_BYTE_PTR)pTemplate, sizeof(CK_ATTRIBUTE) * ulCount));

  CI_LogEntry("C_GenerateKey", "random generator seeded", rv, 1);

  CK_I_CALL_TOKEN_METHOD(rv, GenerateKey, (session_data, pMechanism, new_key));
  if(rv != CKR_OK)
    { 
      CI_ObjDestroyObj(new_key);
      CI_LogEntry("C_GenerateKey", "...exit: token method", rv, 1);
      return rv;
    }

  CI_LogEntry("C_GenerateKey", "token called", rv, 1);

  if(*((CK_BBOOL CK_PTR)CI_ObjLookup(new_key, CK_IA_EXTRACTABLE)->pValue)== FALSE)
    {
      CI_ObjSetIntAttributeValue(new_key,CK_IA_NEVER_EXTRACTABLE,&CK_I_true,sizeof(CK_I_true));
    }
  
  CI_LogEntry("C_GenerateKey", "object NEVER_EXTRACTABLE Flag set", rv, 1);

  /* put new key into session */
  rv = CI_InternalCreateObject(session_data, new_key, phKey);

  CI_VarLogEntry("C_GenerateKey", "new key object: %i", rv, 1,*phKey);
  CI_LogEntry("C_GenerateKey", "...complete", rv, 1);

  return rv;
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
  CK_RV rv = CKR_OK;
  CK_I_SESSION_DATA_PTR session_data = NULL_PTR;
  CK_I_OBJ_PTR new_private_key = NULL_PTR;  
  CK_I_OBJ_PTR new_public_key = NULL_PTR;  
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

  /* make sure we are initialized */
  if (!(CK_I_global_flags & CK_IGF_INITIALIZED)) 
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  
  /* get session info and make sure that this session exists */
  rv = CI_ReturnSession(hSession, &session_data);
  if(rv != CKR_OK)
    {
      CI_VarLogEntry("C_GenerateKeyPair", "retrieve session data (hSession: %lu)", rv, 1,
                     hSession);
      return rv;
    }
  assert(session_data->session_handle == hSession);

  CI_ObjCreateObj(&new_private_key);
  CI_ObjCreateObj(&new_public_key);
  /* parse the template */
  CI_ObjReadTemplate(new_private_key, pPrivateKeyTemplate, ulPrivateKeyAttributeCount);
  CI_ObjReadTemplate(new_public_key, pPublicKeyTemplate, ulPublicKeyAttributeCount);

  
  /* templates must not specify an inconsistent class  */
  if( ( (CI_ObjLookup(new_private_key,CK_IA_CLASS) != NULL_PTR) && 
	(*((CK_OBJECT_CLASS_PTR)(CI_ObjLookup(new_private_key,CK_IA_CLASS)->pValue)) 
	 != CKO_PRIVATE_KEY) ) ||
      ( (CI_ObjLookup(new_public_key,CK_IA_CLASS) != NULL_PTR) && 
	(*((CK_OBJECT_CLASS_PTR)(CI_ObjLookup(new_public_key,CK_IA_CLASS)->pValue)) 
	 != CKO_PUBLIC_KEY) ) )
    {
      CI_ObjDestroyObj(new_private_key);
      CI_ObjDestroyObj(new_public_key);
      rv = CKR_TEMPLATE_INCONSISTENT;
      CI_LogEntry("C_GenerateKeyPair", "check template consistency", rv, 1);
      return rv;
    }
  
  /* ok before we do the real work we should seed the RNG a bit more */
  /* the arbitrary pointers in the template seem a good idea */
  CK_I_CALL_TOKEN_METHOD(rv, SeedRandom, 
			 (session_data,(CK_BYTE_PTR)pPrivateKeyTemplate, 
			  sizeof(CK_ATTRIBUTE) * ulPrivateKeyAttributeCount));
  
  /* have the token generate the keys */
  CK_I_CALL_TOKEN_METHOD(rv, GenerateKeyPair, (session_data, pMechanism, 
					       new_public_key, new_private_key));
  if(rv != CKR_OK)
    { 
      CI_ObjDestroyObj(new_private_key);
      CI_ObjDestroyObj(new_public_key);
      return rv;
    }
  

  if(*((CK_BBOOL CK_PTR)CI_ObjLookup(new_private_key, CK_IA_EXTRACTABLE)->pValue)== FALSE)
    {
      CI_ObjSetIntAttributeValue(new_private_key,CK_IA_NEVER_EXTRACTABLE,&CK_I_true,sizeof(CK_I_true));
    }

  /* TODO: make sure that the subject as well as start and end date 
   * are the same in both templates */


  if((CI_ObjLookup(new_private_key, CK_IA_TOKEN) != NULL_PTR) &&
     (*(CK_BBOOL CK_PTR)(CI_ObjLookup(new_private_key, CK_IA_TOKEN)->pValue)) == TRUE)
    CI_ObjSetIntAttributeValue(new_public_key,CK_IA_TOKEN,&CK_I_true,sizeof(CK_I_true));


  /* put new key into session */
  rv = CI_InternalCreateObject(session_data, new_private_key, phPrivateKey);
  if(rv != CKR_OK)
    {
      CI_LogEntry("C_GenerateKeyPair", "inserting private key into session", rv, 1);
      return rv;
    }

  rv = CI_InternalCreateObject(session_data, new_public_key, phPublicKey);
  if(rv != CKR_OK)
    {
      CI_InternalDestroyObject(session_data, *phPrivateKey, TRUE); /* undo everything */
      CI_LogEntry("C_GenerateKeyPair", "inserting private key into session", rv, 1);
      return rv;
    }


  CI_VarLogEntry("C_GenerateKeyPair", "Key Pair (private: %d, public: %d) created", rv, 1, *phPrivateKey, *phPublicKey );

  CI_LogEntry("C_GenerateKeyPair", "...complete", rv, 1);

  return rv;
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
  CK_RV rv = CKR_OK;
  CK_I_OBJ_PTR key_obj = NULL_PTR;  /* key to be wrapped */
  CK_I_OBJ_PTR wrapper = NULL_PTR;  /* key to be used for wrapping */
  CK_I_SESSION_DATA_PTR session_data = NULL_PTR;
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
		  
  /* make sure we are initialized */
  if (!(CK_I_global_flags & CK_IGF_INITIALIZED)) 
    return CKR_CRYPTOKI_NOT_INITIALIZED;

  CI_VarLogEntry("C_WrapKey", "using objects hWrappingKey: %i, hKey: %i", rv, 1, hWrappingKey, hKey);

  /* get session info and make sure that this session exists */
  rv = CI_ReturnSession(hSession, &session_data);
  if(rv != CKR_OK)
    {
      CI_VarLogEntry("C_WrapKey", "retrieve session data (hSession: %lu)", rv, 1,
                     hSession);
      return rv;
    }
 
  /* Is there an active encrypting? */
  if(session_data->encrypt_state != NULL_PTR)
    {
      rv = CKR_OPERATION_ACTIVE;
      CI_LogEntry("C_WrapKey", "testing encryption state", rv, 0);
      return rv;
    }

  rv = CI_ReturnObj(session_data,hWrappingKey, &wrapper);
  if(rv != CKR_OK)
    {
      CI_VarLogEntry("C_WrapKey", "retrieve wrapper object (hSession: %lu, hKey: %lu)", rv, 1,
                     hSession, hWrappingKey);
      return rv;
    }

  rv = CI_ReturnObj(session_data,hKey, &key_obj);
  if(rv != CKR_OK)
    {
      CI_VarLogEntry("C_WrapKey", "retrieve wrappee object (hSession: %lu, hKey: %lu)", rv, 1,
                     hSession, hKey);
      return rv;
    }
  
  /* Does the wrapping key allow wrapping? */
  if((CI_ObjLookup(wrapper,CK_IA_WRAP) != NULL_PTR) && 
     (*((CK_BBOOL CK_PTR)CI_ObjLookup(wrapper,CK_IA_WRAP)->pValue) != TRUE))
    {
      rv = CKR_KEY_TYPE_INCONSISTENT;
      CI_LogEntry("C_WrapKey", "testing key for wrapping permission", rv, 0);
      return rv;
    }

  /* Does the wrappee allow to be wrapped? */
  if((CI_ObjLookup(key_obj,CK_IA_EXTRACTABLE) != NULL_PTR) && 
     (*((CK_BBOOL CK_PTR)CI_ObjLookup(key_obj,CK_IA_EXTRACTABLE)->pValue) != TRUE))
    {
      rv = CKR_KEY_NOT_WRAPPABLE;
      CI_LogEntry("C_WrapKey", "testing key for extraction permission of wrappee", rv, 0);
      return rv;
    }

  rv = CI_ReturnObj(session_data,hKey, &key_obj);
  if(rv != CKR_OK)
    {
      CI_VarLogEntry("C_WrapKey", "retrieve object list (hSession: %lu, hKey: %lu)", rv, 1,
                     hSession, hKey);
      return rv;
    }
  
  CK_I_CALL_TOKEN_METHOD(rv, WrapKey, (session_data, pMechanism, wrapper, 
				       key_obj, pWrappedKey, pulWrappedKeyLen));

  CI_LogEntry("C_WrapKey", "...complete", rv, 1);

  return rv;
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
  CK_RV rv = CKR_OK;
  CK_I_OBJ_PTR key_obj = NULL_PTR;  /* key to be wrapped */
  CK_I_OBJ_PTR wrapper = NULL_PTR;  /* key used for unwrapping */
  CK_I_SESSION_DATA_PTR session_data = NULL_PTR;

  CI_LogEntry("C_UnwrapKey", "starting...", rv, 1);
  CI_CodeFktEntry("C_UnwrapKey", "%i,%s,%i,%s,%i,%s,%i,%p", 
                  hSession,
                  CI_ScanableMechanism(pMechanism),
		  hUnwrappingKey,
		  CI_ScanableByteStream(pWrappedKey,ulWrappedKeyLen),
		  ulWrappedKeyLen,
		  CI_PrintTemplate(pTemplate,ulAttributeCount),
		  ulAttributeCount,
		  phKey);

  /* make sure we are initialized */
  if (!(CK_I_global_flags & CK_IGF_INITIALIZED)) 
    return CKR_CRYPTOKI_NOT_INITIALIZED;

  /* get session info and make sure that this session exists */
  rv = CI_ReturnSession(hSession, &session_data);
  if(rv != CKR_OK)
    {
      CI_VarLogEntry("C_UnwrapKey", "retrieve session data (hSession: %lu)", rv, 1,
                     hSession);
      return rv;
    }
 
  /* Is there an active decryption? */
  if(session_data->decrypt_state != NULL_PTR)
    {
      rv = CKR_OPERATION_ACTIVE;
      CI_LogEntry("C_UnwrapKey", "check operation status", rv, 1);
      return rv;
    }

  rv = CI_ReturnObj(session_data,hUnwrappingKey, &wrapper);
  if(rv != CKR_OK)
    {
      CI_VarLogEntry("C_UnWrapKey", "retrieve unwrapping key (hSession: %lu, hKey: %lu)", rv, 1,
                     hSession, hUnwrappingKey);
      return rv;
    }

  /* check that key supports unwrapping */
  if(*((CK_BBOOL CK_PTR)CI_ObjLookup(wrapper,CK_IA_UNWRAP)->pValue) != TRUE)
    {
      rv = CKR_KEY_TYPE_INCONSISTENT;
      CI_LogEntry("C_UnwrapKey", "check unwrappping capability", rv, 1);
      return rv;
    }

  /* prepare the object to be created */
  rv = CI_ObjCreateObj(&key_obj);
  if(rv != CKR_OK)
    {
      CI_LogEntry("C_UnwrapKey", "object creation", rv, 0);
      return rv;
    }

  CI_ObjReadTemplate(key_obj,pTemplate, ulAttributeCount);
  if(rv != CKR_OK)
    {
      CI_ObjDestroyObj(key_obj);
      CI_LogEntry("C_UnwrapKey", "reading key template", rv, 0);
      return rv;
    }
  
  /* make sure we know the type of key we are unwrapping ( for the asn.1 routines ) */
  if((CI_ObjLookup(key_obj,CK_IA_KEY_TYPE) == NULL_PTR) ||
     (CI_ObjLookup(key_obj,CK_IA_CLASS) == NULL_PTR))
    {
      CI_ObjDestroyObj(key_obj);
      rv = CKR_TEMPLATE_INCOMPLETE;
      CI_LogEntry("C_UnwrapKey", "check type of key for unwrapping", rv, 0);
      return rv;
    }

  /* make sure that the template containes some fields */
  if(CI_ObjLookup(key_obj,CK_IA_LOCAL) == NULL_PTR) 
    { CI_ObjSetIntAttributeValue(key_obj, CK_IA_LOCAL, &CK_I_false , sizeof(CK_I_false)); }
  if(CI_ObjLookup(key_obj,CK_IA_ALWAYS_SENSITIVE) == NULL_PTR) 
    { CI_ObjSetIntAttributeValue(key_obj, CK_IA_ALWAYS_SENSITIVE, &CK_I_false , sizeof(CK_I_false)); }
  if(CI_ObjLookup(key_obj,CK_IA_EXTRACTABLE) == NULL_PTR) 
    { CI_ObjSetIntAttributeValue(key_obj, CK_IA_EXTRACTABLE, &CK_I_true , sizeof(CK_I_true)); }


  /* will copy this functions static variables used above. So there should be no worry that 
   * they will be modified */

  CK_I_CALL_TOKEN_METHOD(rv, UnwrapKey, (session_data, pMechanism, wrapper, 
					 pWrappedKey, ulWrappedKeyLen, key_obj));
  if(rv != CKR_OK)
    {
      CI_ObjDestroyObj(key_obj);
      return rv;
    }

  /* Force some values in the key */
  CI_ObjSetIntAttributeValue(key_obj, CK_IA_LOCAL, &CK_I_false , sizeof(CK_I_false));  
  CI_ObjSetIntAttributeValue(key_obj, CK_IA_ALWAYS_SENSITIVE, &CK_I_false , sizeof(CK_I_false));
  CI_ObjSetIntAttributeValue(key_obj, CK_IA_EXTRACTABLE, &CK_I_true , sizeof(CK_I_true));

  /* put new key into session */
  rv = CI_InternalCreateObject(session_data, key_obj, phKey);

  CI_LogEntry("C_UnwrapKey", "...complete", rv, 1);

  return rv;
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
  CK_RV rv = CKR_OK;
  CK_I_SESSION_DATA_PTR session_data = NULL_PTR;
  CK_I_OBJ_PTR base_key = NULL_PTR;  /* object to be derived from */
  CK_I_OBJ_PTR new_key = NULL_PTR;  /* object to be created */
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
  
  /* make sure we are initialized */
  if (!(CK_I_global_flags & CK_IGF_INITIALIZED)) 
    return CKR_CRYPTOKI_NOT_INITIALIZED;

  /* get session info and make sure that this session exists */
    rv = CI_ReturnSession(hSession, &session_data);
  if(rv != CKR_OK)
    {
      CI_VarLogEntry("C_DeriveKey", "retrieve session data (hSession: %lu)", rv, 1,
                     hSession);
      return rv;
    }


  rv = CI_ReturnObj(session_data,hBaseKey, &base_key);
  if(rv != CKR_OK)
    {
      CI_VarLogEntry("C_DeriveKey", "retrieve base key (hSession: %lu, hKey: %lu)", rv, 1,
                     hSession, hBaseKey);
      return rv;
    }

  /* parse the template */
  rv = CI_ObjCreateObj(&new_key);
  if(rv != CKR_OK)
    {
      CI_LogEntry("C_DeriveKey", "creating object", rv, 1);
      return rv;
    }

  rv = CI_ObjReadTemplate(new_key, pTemplate, ulAttributeCount);
  if(rv != CKR_OK)
    {
      CI_ObjDestroyObj(new_key);
      CI_LogEntry("C_DeriveKey", "reading template", rv, 1);
      return rv;
    }
  
  /* 
   * TODO: maybe we can find some additional fields that have to match. 
   * Constraints for CKA_SENSITIVE, CKA_ALWAYS_SENSITIVE, CKA_EXTRACTABLE, 
   * and CKA_NEVER_EXTRACTABLE are handled by the mechanisms.
   */

  CK_I_CALL_TOKEN_METHOD(rv, DeriveKey, (session_data, pMechanism, base_key, new_key));
  if(rv != CKR_OK)
    { 
      CI_ObjDestroyObj(new_key);
      CI_LogEntry("C_DeriveKey", "calling token", rv, 1);
      return rv;
    }

  /* put new key into session */
  rv = CI_InternalCreateObject(session_data, new_key, phKey);

  CI_LogEntry("C_DeriveKey", "...complete", rv, 1);

  return rv;
}
/* }}} */
/*
 * Local variables:
 * folded-file: t
 * end:
 */



