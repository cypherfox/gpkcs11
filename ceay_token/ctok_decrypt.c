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
 * NAME:        ctok_decrypt.c
 * SYNOPSIS:    -
 * DESCRIPTION: function to handle data decryption in the ceay token
 * FILES:       -
 * SEE/ALSO:    -
 * AUTHOR:      lbe
 * BUGS:        -
 */
static char RCSID[]="$Id$";
const char* ctok_decrypt_c_version(){return RCSID;}

/* Stupid Windows-isms */
#ifndef CK_I_library_build
#define  CK_I_library_build
#endif /* CK_I_library_build */

#include "ceay_token.h"
#include "objects.h"
#include "pkcs11_error.h"
#include "mutex.h"
#include "init.h"
#include "ctok_mem.h"

#include <assert.h>

/* {{{ CI_Ceay_DecryptInit */
CK_DEFINE_FUNCTION(CK_RV, CI_Ceay_DecryptInit)(
  CK_I_SESSION_DATA_PTR  session_data,
  CK_MECHANISM_PTR  pMechanism,     /* the decryption mechanism */
  CK_I_OBJ_PTR      key_obj         /* handle of decryption key */
)
{
  CK_RV rv = CKR_OK;

  CI_LogEntry("C_DecryptInit", "starting...", rv , 0);	  

  switch(pMechanism->mechanism)
    {

      /* {{{ CKM_RSA_PKCS */
    case CKM_RSA_PKCS:
      {
	RSA CK_PTR internal_key_obj = NULL_PTR;

	/* check that object is a private key */
	if((CI_ObjLookup(key_obj,CK_IA_CLASS) == NULL_PTR) || 
	   (*((CK_OBJECT_CLASS CK_PTR)CI_ObjLookup(key_obj,CK_IA_CLASS)->pValue) != CKO_PRIVATE_KEY))
	  return CKR_KEY_TYPE_INCONSISTENT;

	CI_LogEntry("C_Ceay_DecryptInit", "RSA PKCS starting", rv, 2);	  

	internal_key_obj = CI_Ceay_Obj2RSA(key_obj);
	if(internal_key_obj == NULL_PTR)
	  return CKR_HOST_MEMORY;
      
	session_data->decrypt_state = (CK_VOID_PTR)internal_key_obj;
	session_data->decrypt_mechanism = CKM_RSA_PKCS;
      }
      break;

      /* }}} */
      /* {{{ CKM_RSA_X_509 */
    case CKM_RSA_X_509:
      {
	RSA CK_PTR internal_key_obj = NULL_PTR;

	/* check that object is a private key */
	if((CI_ObjLookup(key_obj,CK_IA_CLASS) == NULL_PTR) || 
	   (*((CK_OBJECT_CLASS CK_PTR)CI_ObjLookup(key_obj,CK_IA_CLASS)->pValue) != CKO_PRIVATE_KEY))
	  return CKR_KEY_TYPE_INCONSISTENT;

	CI_LogEntry("C_Ceay_DecryptInit", "RSA X509 starting", rv, 2);

	internal_key_obj = CI_Ceay_Obj2RSA(key_obj);
	if(internal_key_obj == NULL_PTR)
	  return CKR_HOST_MEMORY;
      
	session_data->decrypt_state = (CK_VOID_PTR)internal_key_obj;
	session_data->decrypt_mechanism = CKM_RSA_X_509;
      }
      break;
      /* }}} */
      /* {{{ CKM_RC4 */
    case CKM_RC4:
      {
	RC4_KEY CK_PTR internal_obj = NULL_PTR;
	CK_ULONG key_len;

	CI_LogEntry("C_Ceay_DecryptInit", "RC4 starting", rv, 2);	  

	internal_obj = CI_RC4Key_new();
	if(internal_obj == NULL_PTR)
	  return CKR_HOST_MEMORY;

	if(CI_ObjLookup(key_obj,CK_IA_VALUE_LEN) != NULL_PTR)
	  key_len = *((CK_ULONG_PTR)(CI_ObjLookup(key_obj,CK_IA_VALUE_LEN)->pValue));
	else
	  key_len = (CI_ObjLookup(key_obj,CK_IA_VALUE)->ulValueLen);

	RC4_set_key(internal_obj,
		    key_len,
		    CI_ObjLookup(key_obj,CK_IA_VALUE)->pValue);

	session_data->decrypt_state = (CK_VOID_PTR)internal_obj;
	session_data->decrypt_mechanism = CKM_RC4;

      }
      break;
      /* }}} */
      /* {{{ CKM_RC2_ECB */
    case CKM_RC2_ECB:
      {
	RC2_KEY CK_PTR internal_obj = NULL_PTR;
	CK_ULONG key_len;

	/* check correct parameter */
	if((pMechanism->pParameter == NULL_PTR) ||
	   (pMechanism->ulParameterLen != sizeof(CK_RC2_PARAMS)))
	  return CKR_MECHANISM_PARAM_INVALID;

	CI_LogEntry("C_CL_DecryptInit", "RC2 ECB starting", rv, 2);	  

	internal_obj = CI_RC2Key_new();
	if(internal_obj == NULL_PTR)
	  return CKR_HOST_MEMORY;

	if(CI_ObjLookup(key_obj,CK_IA_VALUE_LEN) != NULL_PTR)
	  key_len = *((CK_ULONG_PTR)(CI_ObjLookup(key_obj,CK_IA_VALUE_LEN)->pValue));
	else
	  key_len = CI_ObjLookup(key_obj,CK_IA_VALUE)->ulValueLen;

	RC2_set_key(internal_obj,
		    key_len,
		    CI_ObjLookup(key_obj,CK_IA_VALUE)->pValue,
		    (int)pMechanism->pParameter);

	session_data->decrypt_state = (CK_VOID_PTR)internal_obj;
	session_data->decrypt_mechanism = CKM_RC2_ECB;
      }
      break;
      /* }}} */
      /* {{{ CKM_RC2_CBC */
    case CKM_RC2_CBC:
      {
	CK_I_CEAY_RC2_INFO_PTR internal_obj = NULL_PTR;
	CK_ULONG key_len;
	
	CK_RC2_CBC_PARAMS_PTR para = pMechanism->pParameter; 

	rv = CKR_OK;

	internal_obj= CI_RC2_INFO_new();
	if(internal_obj == NULL_PTR)
	  {
	    rv = CKR_HOST_MEMORY;
	    goto decrypt_init_rc2_error;
	  }

	CI_LogEntry("C_CL_DecryptInit", "RC2 CBC starting", rv, 2);

	/* Ok, alles alloziert, jetzt die wirklichen Werte eintragen */
	/* Mechanism zuerst, denn da kann ja der Parameter fehlen */
	if((pMechanism->pParameter == NULL_PTR) ||
	   (pMechanism->ulParameterLen != sizeof(CK_RC2_CBC_PARAMS)))
	  {
	    rv = CKR_MECHANISM_PARAM_INVALID;
	    goto decrypt_init_rc2_error;
	  }
	/* Na da wolle wir mal besser sicher gehen das ceay und pkcs11 vom gleichen reden! */
	assert(sizeof(CK_BYTE) == sizeof(unsigned char));
	memcpy(internal_obj->ivec,para->iv, sizeof(CK_BYTE)*8);
	{
	  CK_BYTE_PTR tmp_str = NULL_PTR;
	  
	  CI_VarLogEntry("CI_Ceay_EncryptInit", "RC2 CBC ivec: %s", rv, 2,
			 tmp_str = CI_PrintableByteStream(internal_obj->ivec,
							  sizeof(CK_BYTE)*8));
	  TC_free(tmp_str);
	}

	if(CI_ObjLookup(key_obj,CK_IA_VALUE_LEN) != NULL_PTR)
	  key_len = *((CK_ULONG_PTR)(CI_ObjLookup(key_obj,CK_IA_VALUE_LEN)->pValue));
	else
	  key_len = CI_ObjLookup(key_obj,CK_IA_VALUE)->ulValueLen;

	/* TODO: check that the size of the effective Bits are valid */
	RC2_set_key(internal_obj->key,
		    key_len,
		    (unsigned char*)CI_ObjLookup(key_obj,CK_IA_VALUE)->pValue,
		    (int)para->ulEffectiveBits);

	session_data->decrypt_state = internal_obj;
	session_data->decrypt_mechanism = CKM_RC2_CBC;


      decrypt_init_rc2_error:
	if(rv != CKR_OK)
	  {
	    if(internal_obj->key) TC_free(internal_obj->key);
	    if(internal_obj) TC_free(internal_obj);
	  }
      }
      break;
      /* }}} */
      /* {{{ CKM_DES_ECB */
    case CKM_DES_ECB:
      {
	des_key_schedule CK_PTR internal_obj = NULL_PTR;
	CK_BYTE_PTR tmp_key_data;

	internal_obj = TC_malloc(sizeof(des_key_schedule));
	if(internal_obj == NULL_PTR)
	  return CKR_HOST_MEMORY;

	CI_LogEntry("C_CL_DecryptInit", "DES ECB starting", rv, 2);	  

	tmp_key_data = CI_ObjLookup(key_obj,CK_IA_VALUE)->pValue;
	if(tmp_key_data == NULL_PTR)
	  return CKR_KEY_TYPE_INCONSISTENT;

	des_set_key((des_cblock*)tmp_key_data,
		    *((des_key_schedule CK_PTR)internal_obj));

	session_data->decrypt_state = (CK_VOID_PTR)internal_obj;
	session_data->decrypt_mechanism = CKM_DES_ECB;
      }
      break;
      /* }}} */
      /* {{{ CKM_DES_CBC */
    case CKM_DES_CBC:
      {
	CK_I_CEAY_DES_INFO_PTR internal_obj = NULL_PTR;
	CK_BYTE_PTR tmp_key_data;

	rv = CKR_OK; /* positiv denken */

	CI_LogEntry("C_CL_DecryptInit", "DES CBC starting", rv, 2);	  

	internal_obj= CI_DES_INFO_new();
	if(internal_obj == NULL_PTR)
	  {
	    rv = CKR_HOST_MEMORY;
	    goto decrypt_init_des_error;
	  }

	/* Ok, alles alloziert, jetzt die wirklichen Werte eintragen */
	/* Mechanism zuerst, denn da kann ja der Parameter fehlen */
	if((pMechanism->pParameter == NULL_PTR) ||
	   (pMechanism->ulParameterLen != sizeof(des_cblock)))
	  {
	    rv = CKR_MECHANISM_PARAM_INVALID;
	    goto decrypt_init_des_error;
	  }
	memcpy(internal_obj->ivec,pMechanism->pParameter, sizeof(des_cblock));
	{
	  CK_BYTE_PTR tmp_str = NULL_PTR;
	  
	  CI_VarLogEntry("CI_Ceay_EncryptInit", "DES CBC ivec: %s", rv, 2,
			 tmp_str = CI_PrintableByteStream((CK_BYTE_PTR)internal_obj->ivec,
							  sizeof(des_cblock)));
	  TC_free(tmp_str);
	}

	tmp_key_data = CI_ObjLookup(key_obj,CK_IA_VALUE)->pValue;
	if(tmp_key_data == NULL_PTR) return CKR_KEY_TYPE_INCONSISTENT;

	des_set_key((des_cblock*)tmp_key_data,internal_obj->sched);

	session_data->decrypt_state = internal_obj;
	session_data->decrypt_mechanism = CKM_DES_CBC;

	/* ugly global value from the ceay lib */
	des_rw_mode = DES_CBC_MODE;

      decrypt_init_des_error:
	if(rv != CKR_OK)
	  CI_DES_INFO_delete(internal_obj);
      }
      break;
      /* }}} */
      /* {{{ CKM_DES_CBC_PAD */
    case CKM_DES_CBC_PAD:
      {
	CK_I_CEAY_DES_INFO_PTR internal_obj = NULL_PTR;
	CK_BYTE_PTR tmp_key_data;

	rv = CKR_OK; /* positiv denken */

	internal_obj= CI_DES_INFO_new();
	if(internal_obj == NULL_PTR)
	  {
	    rv = CKR_HOST_MEMORY;
	    goto decrypt_init_des_error;
	  }

	/* Ok, alles alloziert, jetzt die wirklichen Werte eintragen */
	/* Mechanism zuerst, denn da kann ja der Parameter fehlen */
	if((pMechanism->pParameter == NULL_PTR) ||
	   (pMechanism->ulParameterLen != sizeof(des_cblock)))
	  {
	    rv = CKR_MECHANISM_PARAM_INVALID;
	    goto decrypt_init_des_pad_error;
	  }
	memcpy(internal_obj->ivec,pMechanism->pParameter, sizeof(des_cblock));
	{
	  CK_BYTE_PTR tmp_str = NULL_PTR;
	  
	  CI_VarLogEntry("CI_Ceay_EncryptInit", "DES CBC PAD ivec: %s", rv, 2,
			 tmp_str = CI_PrintableByteStream((CK_BYTE_PTR)internal_obj->ivec,
							  sizeof(des_cblock)));
	  TC_free(tmp_str);
	}

	tmp_key_data = CI_ObjLookup(key_obj,CK_IA_VALUE)->pValue;
	if(tmp_key_data == NULL_PTR) return CKR_KEY_TYPE_INCONSISTENT;

	des_set_key((des_cblock*)tmp_key_data,internal_obj->sched);

	session_data->decrypt_state = internal_obj;
	session_data->decrypt_mechanism = CKM_DES_CBC_PAD;
	((CK_I_CEAY_DES_INFO_PTR)session_data->decrypt_state)->pad = 0;
	memset(((CK_I_CEAY_DES_INFO_PTR)session_data->decrypt_state)->lastblock, 0, 8);
	/* ugly global value from the ceay lib */
	des_rw_mode = DES_CBC_MODE;

      decrypt_init_des_pad_error:
	if(rv != CKR_OK)
	  CI_DES_INFO_delete(internal_obj);
      }
      break;
      /* }}} */
      /* {{{ CKM_DES3_ECB */
    case CKM_DES3_ECB:
      {
	CK_I_CEAY_DES3_INFO_PTR internal_obj = NULL_PTR;
	
	CI_LogEntry("C_CL_DecryptInit", "DES3 ECB starting", rv, 2);	  

	/* TODO: change this into des_cblock[3] */
	internal_obj = CI_DES3_INFO_new(CI_ObjLookup(key_obj,CK_IA_VALUE)->pValue);
	if(internal_obj == NULL_PTR)
	  return CKR_HOST_MEMORY;


	session_data->decrypt_state = (CK_VOID_PTR)internal_obj;
	session_data->decrypt_mechanism = CKM_DES3_ECB;
      }
      break;
      /* }}} */
      /* {{{ CKM_DES3_CBC */
    case CKM_DES3_CBC:
      {
	CK_I_CEAY_DES3_INFO_PTR internal_obj = NULL_PTR;

	rv = CKR_OK; /* positiv denken */

	/* Mechanism zuerst prüfen, denn da kann ja der Parameter fehlen */
	if((pMechanism->pParameter == NULL_PTR) ||
	   (pMechanism->ulParameterLen != sizeof(des_cblock)))
	  return CKR_MECHANISM_PARAM_INVALID;

	CI_LogEntry("C_CL_DecryptInit", "DES3 CBC/PAD starting", rv, 2);	  

	internal_obj= CI_DES3_INFO_new(CI_ObjLookup(key_obj,CK_IA_VALUE)->pValue);
	if(internal_obj == NULL_PTR)
	  return CKR_HOST_MEMORY;

	/* Ok, alles alloziert, jetzt die wirklichen Werte eintragen */
	memcpy(internal_obj->ivec,pMechanism->pParameter, sizeof(des_cblock));
	{
	  CK_BYTE_PTR tmp_str = NULL_PTR;
	  
	  CI_VarLogEntry("CI_Ceay_EncryptInit", "DES3 CBC ivec: %s", rv, 2,
			 tmp_str = CI_PrintableByteStream((CK_BYTE_PTR)internal_obj->ivec,
							  sizeof(des_cblock)));
	  TC_free(tmp_str);
	}

	session_data->decrypt_state = internal_obj;
	session_data->decrypt_mechanism = CKM_DES3_CBC;

	/* ugly global value from the ceay lib */
	des_rw_mode = DES_CBC_MODE;

      }
      break;
      /* }}} */
      /* {{{ CKM_IDEA_ECB */
    case CKM_IDEA_ECB:
      {
	IDEA_KEY_SCHEDULE CK_PTR internal_obj = NULL_PTR;
	IDEA_KEY_SCHEDULE temp_sched;

	CI_LogEntry("C_CL_DecryptInit", "IDEA ECB starting", rv, 2);	  

	internal_obj = CI_IDEA_KEY_SCHEDULE_new();
	if(internal_obj == NULL_PTR)
	  return CKR_HOST_MEMORY;

	/* 
	 * This is the IDEA way: generate an encryption key and then convert
	 * it to a decrypt key 
	 */
	idea_set_encrypt_key(CI_ObjLookup(key_obj,CK_IA_VALUE)->pValue,
			     &temp_sched);
	idea_set_decrypt_key(&temp_sched,internal_obj);

	session_data->decrypt_state = (CK_VOID_PTR)internal_obj;
	session_data->decrypt_mechanism = CKM_IDEA_ECB;

	rv = CKR_OK;

      }
      break;
      /* }}} */
      /* {{{ CKM_IDEA_CBC */
    case CKM_IDEA_CBC:
      {
	CK_I_CEAY_IDEA_INFO_PTR internal_obj = NULL_PTR;
	IDEA_KEY_SCHEDULE temp_sched;

	rv = CKR_OK; /* positiv denken */

	/* check Mechanism first, there might be a parameter missing */
	if((pMechanism->pParameter == NULL_PTR) ||
	   (pMechanism->ulParameterLen != sizeof(des_cblock)))
	    return CKR_MECHANISM_PARAM_INVALID;

	CI_LogEntry("C_CL_DecryptInit", "IDEA CBC starting", rv, 2);	  

	internal_obj= CI_IDEA_INFO_new();
	if(internal_obj == NULL_PTR)
	    return CKR_HOST_MEMORY;

	/* Ok, alles alloziert, jetzt die wirklichen Werte eintragen */
	memcpy(internal_obj->ivec,pMechanism->pParameter, sizeof(des_cblock));
	{
	  CK_BYTE_PTR tmp_str = NULL_PTR;
	  
	  CI_VarLogEntry("CI_Ceay_EncryptInit", "IDEA CBC ivec: %s", rv, 2,
			 tmp_str = CI_PrintableByteStream(internal_obj->ivec,
							  sizeof(des_cblock)));
	  TC_free(tmp_str);
	}

	idea_set_encrypt_key(CI_ObjLookup(key_obj,CK_IA_VALUE)->pValue,&temp_sched);
	idea_set_decrypt_key(&temp_sched,&(internal_obj->sched));

	session_data->decrypt_state = internal_obj;
	session_data->decrypt_mechanism = CKM_IDEA_CBC;
      }
      break;
      /* }}} */
    default:
      rv = CKR_MECHANISM_INVALID;

      CI_VarLogEntry("C_DecryptInit", "algorithm specified: %s", rv, 0, 
		     CI_MechanismStr(pMechanism->mechanism));

    }
  
  return rv;
}
/* }}} */
/* {{{ CI_Ceay_Decrypt */
CK_DEFINE_FUNCTION(CK_RV, CI_Ceay_Decrypt)(
  CK_I_SESSION_DATA_PTR  session_data,
  CK_BYTE_PTR       pEncryptedData,     /* ciphertext */
  CK_ULONG          ulEncryptedDataLen, /* ciphertext length */
  CK_BYTE_PTR       pData,              /* gets plaintext */
  CK_ULONG_PTR      pulDataLen          /* gets p-text size */
)
{
  CK_RV rv;

  switch(session_data->decrypt_mechanism)
    {
      /* {{{ CKM_RSA_PKCS */
    case CKM_RSA_PKCS:
      {
	CK_BYTE_PTR tmp_buf = NULL_PTR;
	CK_ULONG key_len;
	long processed; /* number of bytes processed by the crypto routine */
	
	rv = CKR_OK;
	
	CI_LogEntry("C_Decrypt", "RSA PKCS", rv , 0);     
	key_len = CI_Ceay_RSA_size((RSA CK_PTR)session_data->decrypt_state);
	
	/* check if this is only a call for the length of the output buffer */
	if(pData == NULL_PTR)
	  {
	    *pulDataLen = key_len-CK_I_PKCS1_MIN_PADDING;
	    CI_VarLogEntry("C_Decrypt", "RSA PKCS Datalength calculated (%i)", 
			   rv , 0, *pulDataLen);
	    CI_LogEntry("C_Decrypt", "...completed", rv , 0);         
	    return CKR_OK;
	  }
	
	/* check for length of input */
	if(ulEncryptedDataLen != key_len)
	  { rv = CKR_DATA_LEN_RANGE; goto rsa_pkcs1_err; }
	
	tmp_buf = CI_ByteStream_new(key_len);
	
	processed = RSA_private_decrypt(ulEncryptedDataLen,pEncryptedData, 
					tmp_buf,session_data->decrypt_state, 
					RSA_PKCS1_PADDING);
	
	if(processed == -1)
	  { 
	    rv = CKR_GENERAL_ERROR; 
	    goto rsa_pkcs1_err; 
	  }
	
	if(*pulDataLen < (unsigned long)processed) 
	  {
	    *pulDataLen = processed;
	    rv = CKR_BUFFER_TOO_SMALL;
	    goto rsa_pkcs1_err; 
	  }
	
	*pulDataLen = processed;
	
	memcpy(pData, tmp_buf, processed);
	
      rsa_pkcs1_err:
	if(tmp_buf != NULL_PTR) 
	  TC_free(tmp_buf);
	if(session_data->decrypt_state != NULL_PTR)
	  { 
	    RSA_free(session_data->decrypt_state); 
	    session_data->decrypt_state = NULL_PTR;
	  }
	break;
      }
      
      /* }}} */
      /* {{{ CKM_RSA_X_509 */
    case CKM_RSA_X_509:
      {
	CK_BYTE_PTR tmp_buf = NULL_PTR;
	CK_ULONG key_len;
	long processed; /* number of bytes processed by the crypto routine */

	CI_LogEntry("C_Decrypt", "RSA X509", rv , 0);     

	rv = CKR_OK;
	key_len = RSA_size((RSA CK_PTR)session_data->decrypt_state);

	/* terminate operation */
	if(pulDataLen == NULL_PTR) 
	  {
	    rv = CKR_OK; goto rsa_x509_err;
	  }

	/* check if this is only a call for the length of the output buffer */
	if(pData == NULL_PTR)
	  {
	    *pulDataLen = key_len;
	    rv = CKR_OK; break;
	  }
	else /* check that buffer is of sufficent size */
	  {
	    if(*pulDataLen < key_len)
	      {
		*pulDataLen = key_len;
		rv = CKR_BUFFER_TOO_SMALL; break;
	      }
	  }
	
	/* check for length of input */
	if(ulEncryptedDataLen != key_len)
	  { rv = CKR_DATA_LEN_RANGE; goto rsa_x509_err; }
	
	tmp_buf = CI_ByteStream_new(key_len);
	if(tmp_buf == NULL_PTR) { rv = CKR_HOST_MEMORY; goto rsa_x509_err; }
	
	processed = RSA_private_decrypt(ulEncryptedDataLen,pEncryptedData,
					tmp_buf,session_data->decrypt_state,
					RSA_NO_PADDING);
	if(processed == -1)
	  { rv = CKR_GENERAL_ERROR; goto rsa_x509_err; }
	*pulDataLen = processed;

	memcpy(pData,tmp_buf,key_len);
	
      rsa_x509_err:
	if(tmp_buf != NULL_PTR) TC_free(tmp_buf);
	if(session_data->decrypt_state != NULL_PTR)
	  { 
	    RSA_free(session_data->decrypt_state); 
	    session_data->decrypt_state = NULL_PTR;
	  }
	break;
      }
      /* }}} */
      /* {{{ CKM_RC4 */
    case CKM_RC4:
      {
	/* terminate operation */
	if(pulDataLen == NULL_PTR) 
	  {
	    rv = CKR_OK; goto rc4_err;
	  }
	/* is this just a test for the length of the recieving buffer? */

    rv = CKR_OK;
	CI_LogEntry("C_Decrypt", "RC4", rv , 0);	  

	if(pData == NULL_PTR)
	  {
	    *pulDataLen = ulEncryptedDataLen;
	    rv = CKR_OK; break;
	  }
	
	/* is the supplied buffer long enough? */
	if(*pulDataLen < ulEncryptedDataLen)
	  {
	    *pulDataLen = ulEncryptedDataLen;
	    rv = CKR_BUFFER_TOO_SMALL; break;
	  }

	/* OK all set. lets compute */
	RC4(session_data->decrypt_state,ulEncryptedDataLen,pEncryptedData,pData);
	
	*pulDataLen=ulEncryptedDataLen;
	rv = CKR_OK;

rc4_err:
	if(session_data->decrypt_state != NULL_PTR)
	  TC_free(session_data->decrypt_state);
	session_data->decrypt_state = NULL_PTR;

      }
      break;
      /* }}} */
      /* {{{ CKM_RC2_ECB */
    case CKM_RC2_ECB:
      {
	CK_ULONG count;

	/* terminate operation */
	if(pulDataLen == NULL_PTR) 
	  {
	    rv = CKR_OK; goto rc2_cbc_err;
	  }
	/* RC2 always takes multiples of 8 bytes */
	if(ulEncryptedDataLen%8 != 0)
	  { rv = CKR_DATA_LEN_RANGE; goto rc2_ecb_err; }

	/* is this just a test for the length of the recieving buffer? */
	if(pData == NULL_PTR)
	  {
	    *pulDataLen = ulEncryptedDataLen;
	    rv = CKR_OK; break;
	  }
	
	/* is the supplied buffer long enough? */
	if(*pulDataLen < ulEncryptedDataLen)
	  {
	    *pulDataLen = ulEncryptedDataLen;
	    rv = CKR_BUFFER_TOO_SMALL; break;
	  }

	/* OK all set. lets compute */
	/* in blocks of 8 bytes. */
	for(count=0; count<ulEncryptedDataLen ; count+=8)
	  {
	    RC2_ecb_encrypt(&(pEncryptedData[count]),&(pData[count]), 
			    session_data->decrypt_state,
			    RC2_DECRYPT);	    
	  }
	
	*pulDataLen=ulEncryptedDataLen;
	rv = CKR_OK;

    rc2_ecb_err:
	if(session_data->decrypt_state != NULL_PTR)
	  TC_free(session_data->decrypt_state);
	session_data->decrypt_state = NULL_PTR;

      }
      break;
      /* }}} */
      /* {{{ CKM_RC2_CBC */
    case CKM_RC2_CBC:
      {
	/* terminate operation */
	if(pulDataLen == NULL_PTR) 
	  {
	    rv = CKR_OK; goto rc2_cbc_err;
	  }
	/* is the length of the supplied data a multiple of 8 to create des-blocks? */
	if(ulEncryptedDataLen%8 != 0)
	  { rv = CKR_DATA_LEN_RANGE; goto rc2_cbc_err; }

	/* is this just a test for the length of the recieving buffer? */
	if(pData == NULL_PTR)
	  {
	    *pulDataLen = ulEncryptedDataLen;
	    rv = CKR_OK; break;
	  }

	/* is the supplied buffer long enough? */
	if(*pulDataLen < ulEncryptedDataLen)
	  {
	    *pulDataLen = ulEncryptedDataLen;
	    rv = CKR_BUFFER_TOO_SMALL; break;
	  }

	/* OK all set. lets compute */
	RC2_cbc_encrypt((unsigned char*)pEncryptedData, (unsigned char*)pData, 
			 ulEncryptedDataLen, 
			 ((CK_I_CEAY_RC2_INFO_PTR)session_data->decrypt_state)->key, 
			 ((CK_I_CEAY_RC2_INFO_PTR)session_data->decrypt_state)->ivec, 
			 RC2_DECRYPT);

	rv = CKR_OK;

    rc2_cbc_err:
	CI_RC2_INFO_delete(session_data->decrypt_state);
	session_data->decrypt_state = NULL_PTR;

      }
      break;
      /* }}} */
      /* {{{ CKM_DES_ECB */
    case CKM_DES_ECB:
      {
	CK_ULONG count;

	/* terminate operation */
	if(pulDataLen == NULL_PTR) 
	  {
	    rv = CKR_OK; goto des_ecb_err;
	  }
	/* DES allways takes multiples of 8 bytes */
	if(ulEncryptedDataLen%8 != 0)
	  {
	    rv = CKR_DATA_LEN_RANGE; goto des_ecb_err;
	  }

	/* is this just a test for the length of the recieving buffer? */
	if(pData == NULL_PTR)
	  {
	    *pulDataLen = ulEncryptedDataLen;
	    rv = CKR_OK; break;
	  }
	
	/* is the supplied buffer long enough? */
	if(*pulDataLen < ulEncryptedDataLen)
	  {
	    *pulDataLen = ulEncryptedDataLen;
	    rv = CKR_BUFFER_TOO_SMALL; break;
	  }

	/* OK all set. lets compute */
	/* in blocks of 8 bytes. */
	for(count=0; count<ulEncryptedDataLen ; count+=8)
	  {
	    des_ecb_encrypt((des_cblock*)(&(pEncryptedData[count])),
			    (des_cblock*)(&(pData[count])),
			    session_data->decrypt_state,
			    DES_DECRYPT);
	  }
	
	*pulDataLen=ulEncryptedDataLen;

	rv = CKR_OK;

      des_ecb_err:
	if(session_data->decrypt_state != NULL_PTR)
	  TC_free(session_data->decrypt_state);
	session_data->decrypt_state = NULL_PTR;

      }
      break;
      /* }}} */
      /* {{{ CKM_DES_CBC */
    case CKM_DES_CBC:
      {
	/* terminate operation */
	if(pulDataLen == NULL_PTR) 
	  {
	    rv = CKR_OK; goto des_cbc_err;
	  }
	/* is the length of the supplied data a multiple of 8 to create des-blocks? */
	if(ulEncryptedDataLen%8 != 0)
	  {
	    rv = CKR_DATA_LEN_RANGE; goto des_cbc_err;
	  }

	/* is this just a test for the length of the recieving buffer? */
	if(pData == NULL_PTR)
	  {
	    *pulDataLen = ulEncryptedDataLen;
	    rv = CKR_OK; break;
	  }

	/* is the supplied buffer long enough? */
	if(*pulDataLen < ulEncryptedDataLen)
	  {
	    *pulDataLen = ulEncryptedDataLen;
	    rv = CKR_BUFFER_TOO_SMALL; break;
	  }

	/* OK all set. lets compute */
	des_ncbc_encrypt(pEncryptedData, 
			 pData, 
			 ulEncryptedDataLen, 
			 ((CK_I_CEAY_DES_INFO_PTR)session_data->decrypt_state)->sched, 
			 &(((CK_I_CEAY_DES_INFO_PTR)session_data->decrypt_state)->ivec), 
			 DES_DECRYPT);

	*pulDataLen=ulEncryptedDataLen;

	rv = CKR_OK;

      des_cbc_err:
	if(session_data->decrypt_state!= NULL_PTR)
	  TC_free(session_data->decrypt_state);
	session_data->decrypt_state = NULL_PTR;
	
      }
      break;
      /* }}} */
      /* {{{ CKM_DES_CBC_PAD */
    case CKM_DES_CBC_PAD:
      {
	CK_BYTE PadValue;
	CK_ULONG ulPaddingLen, i;

	/* terminate operation */
	if(pulDataLen == NULL_PTR) 
	  {
	    rv = CKR_OK; goto des_cbc_pad_err;
	  }
	/* is the length of the supplied data a multiple of 8 to create des-blocks? */
	if(ulEncryptedDataLen%8 != 0)
	  {
	    rv = CKR_DATA_LEN_RANGE; break;
	  }

	/* is this just a test for the length of the recieving buffer? */
	if(pData == NULL_PTR)
	  {
	    *pulDataLen = ulEncryptedDataLen;
	    rv = CKR_OK; break;
	  }

	/* is the supplied buffer long enough? */
	if(*pulDataLen < ulEncryptedDataLen)
	  {
	    *pulDataLen = ulEncryptedDataLen;
	    rv = CKR_BUFFER_TOO_SMALL; goto des_cbc_pad_err;
	  }

	/* OK all set. lets compute */
	des_ncbc_encrypt(pEncryptedData, 
			 pData, 
			 ulEncryptedDataLen, 
			 ((CK_I_CEAY_DES_INFO_PTR)session_data->decrypt_state)->sched, 
			 &(((CK_I_CEAY_DES_INFO_PTR)session_data->decrypt_state)->ivec), 
			 DES_DECRYPT);

	if((CK_BYTE)((pData[ulEncryptedDataLen-1] >= 1 ) && (CK_BYTE)(pData[ulEncryptedDataLen-1] <= 8)))
	{ 
	  PadValue = (CK_BYTE)(pData[ulEncryptedDataLen-1]);
	  ulPaddingLen = (CK_ULONG)PadValue;
	}
	else
	  { ulPaddingLen = 0; }

	for (i=0; i<ulPaddingLen; i++)
	  if ((CK_BYTE)(pData[ulEncryptedDataLen-1-i]) != PadValue)
	  { rv = CKR_GENERAL_ERROR; goto des_cbc_pad_err; }

	*pulDataLen=ulEncryptedDataLen-ulPaddingLen;

	rv = CKR_OK;

      des_cbc_pad_err:
	if(session_data->decrypt_state!= NULL_PTR)
	  TC_free(session_data->decrypt_state);
	session_data->decrypt_state = NULL_PTR;

      }
      break;
      /* }}} */
      /* {{{ CKM_DES3_ECB */
    case CKM_DES3_ECB:
      {
	CK_ULONG count;

	/* terminate operation */
	if(pulDataLen == NULL_PTR) 
	  {
	    rv = CKR_OK; goto des3_ecb_err;
	  }
	/* DES always takes multiples of 8 bytes */
	if(ulEncryptedDataLen%8 != 0)
	  {
	    rv = CKR_DATA_LEN_RANGE; goto des3_ecb_err;
	  }

	/* is this just a test for the length of the recieving buffer? */
	if(pData == NULL_PTR)
	  {
	    *pulDataLen = ulEncryptedDataLen;
	    rv = CKR_OK; break;
	  }
	
	/* is the supplied buffer long enough? */
	if(*pulDataLen < ulEncryptedDataLen)
	  {
	    *pulDataLen = ulEncryptedDataLen;	    
	    rv = CKR_BUFFER_TOO_SMALL; break;
	  }

	/* OK all set. lets compute */
	/* in blocks of 8 bytes. */
	for(count=0; count<ulEncryptedDataLen ; count+=8)
	  {
	    des_ecb3_encrypt((des_cblock*)(&(pEncryptedData[count])),
			     (des_cblock*)(&(pData[count])),
			     ((CK_I_CEAY_DES3_INFO_PTR)session_data->decrypt_state)->sched[0],
			     ((CK_I_CEAY_DES3_INFO_PTR)session_data->decrypt_state)->sched[1],
			     ((CK_I_CEAY_DES3_INFO_PTR)session_data->decrypt_state)->sched[2],
			     DES_DECRYPT);
	  }
	
	*pulDataLen=ulEncryptedDataLen;

	rv = CKR_OK;
      des3_ecb_err:
	if(session_data->decrypt_state!= NULL_PTR)
	  CI_DES3_INFO_delete(session_data->decrypt_state);
	session_data->decrypt_state = NULL_PTR;

      }
      break;
      /* }}} */
      /* {{{ CKM_DES3_CBC */
    case CKM_DES3_CBC:
      {
	/* terminate operation */
	if(pulDataLen == NULL_PTR) 
	  {
	    rv = CKR_OK; goto des3_cbc_err;
	  }
	/* is the length of the supplied data a multiple of 8 to create des-blocks? */
	if(ulEncryptedDataLen%8 != 0)
	  {
	    rv = CKR_DATA_LEN_RANGE; goto des3_cbc_err;
	  }

	/* is this just a test for the length of the recieving buffer? */
	if(pData == NULL_PTR)
	  {
	    *pulDataLen = ulEncryptedDataLen;
	    rv = CKR_OK; break;
	  }

	/* is the supplied buffer long enough? */
	if(*pulDataLen < ulEncryptedDataLen)
	  {
	    *pulDataLen = ulEncryptedDataLen;
	    rv = CKR_BUFFER_TOO_SMALL; break;
	  }

	/* OK all set. lets compute */
	des_ede3_cbc_encrypt(pEncryptedData, 
			     pData, 
			     ulEncryptedDataLen, 
			     ((CK_I_CEAY_DES3_INFO_PTR)session_data->decrypt_state)->sched[0], 
			     ((CK_I_CEAY_DES3_INFO_PTR)session_data->decrypt_state)->sched[1], 
			     ((CK_I_CEAY_DES3_INFO_PTR)session_data->decrypt_state)->sched[2], 
			     ((CK_I_CEAY_DES3_INFO_PTR)session_data->decrypt_state)->ivec, 
			     DES_DECRYPT);

	*pulDataLen=ulEncryptedDataLen;

	rv = CKR_OK;
	
      des3_cbc_err:
	if(session_data->decrypt_state != NULL_PTR)
	  CI_DES3_INFO_delete(session_data->decrypt_state);
	session_data->decrypt_state = NULL_PTR;
	
      }
      break;
      /* }}} */
      /* {{{ CKM_IDEA_ECB */
    case CKM_IDEA_ECB:
      {
	CK_ULONG count;
	rv = CKR_OK;

	CI_LogEntry("C_Decrypt", "IDEA ECB", rv , 0); 

	/* terminate operation */
	if(pulDataLen == NULL_PTR) 
	  {
	    rv = CKR_OK; goto idea_ecb_err;
	  }
	/* IDEA always takes multiples of 8 bytes */
	if(ulEncryptedDataLen%8 != 0)
	  {
	    rv = CKR_DATA_LEN_RANGE; goto idea_ecb_err;
	  }

	/* is this just a test for the length of the recieving buffer? */
	if(pData == NULL_PTR)
	  {
	    *pulDataLen = ulEncryptedDataLen;
	    rv = CKR_OK; break;
	  }
	
	/* is the supplied buffer long enough? */
	if(*pulDataLen < ulEncryptedDataLen)
	  {
	    *pulDataLen = ulEncryptedDataLen;
	    rv = CKR_BUFFER_TOO_SMALL; break;
	  }

	/* damit wir ne hoffnung haben */
	assert(sizeof(CK_BYTE) == sizeof(unsigned char));

	/* OK all set. lets compute */
	/* in blocks of 8 bytes. */
	for(count=0; count<ulEncryptedDataLen ; count+=8)
	  {
	    /* its the same function for decryption as well, only the key schedule differs */
	    idea_ecb_encrypt((unsigned char*)&(pEncryptedData[count]),
			     (unsigned char*)&(pData[count]), 
			     &(((CK_I_CEAY_IDEA_INFO_PTR)session_data->decrypt_state)->sched));	    
	  }
	
	*pulDataLen=ulEncryptedDataLen;
	rv = CKR_OK;

      idea_ecb_err:

	if(session_data->decrypt_state!= NULL_PTR)
	  TC_free(session_data->decrypt_state);
	session_data->decrypt_state = NULL_PTR;

      }
      break;
      /* }}} */
      /* {{{ CKM_IDEA_CBC */
    case CKM_IDEA_CBC:
      {
	/* terminate operation */
	if(pulDataLen == NULL_PTR) 
	  {
	    rv = CKR_OK; goto idea_cbc_err;
	  }
	/* is the length of the supplied data a multiple of 8 to create des-blocks? */
	if(ulEncryptedDataLen%8 != 0)
	  {
	    rv = CKR_DATA_LEN_RANGE; goto idea_cbc_err;
	  }

	/* is this just a test for the length of the recieving buffer? */
	if(pData == NULL_PTR)
	  {
	    *pulDataLen = ulEncryptedDataLen;
	    rv = CKR_OK; break;
	  }

	/* is the supplied buffer long enough? */
	if(*pulDataLen < ulEncryptedDataLen)
	  {
	    *pulDataLen = ulEncryptedDataLen;
	    rv = CKR_BUFFER_TOO_SMALL; break;
	  }

	/* OK all set. lets compute */
	idea_cbc_encrypt((unsigned char*)pEncryptedData, 
			 (unsigned char*)pData, 
			 ulEncryptedDataLen, 
			 &(((CK_I_CEAY_IDEA_INFO_PTR)session_data->decrypt_state)->sched), 
			 ((CK_I_CEAY_IDEA_INFO_PTR)session_data->decrypt_state)->ivec, 
			 IDEA_DECRYPT);

	*pulDataLen=ulEncryptedDataLen;
	rv = CKR_OK;

	if( ((CK_I_CEAY_IDEA_INFO_PTR)session_data->decrypt_state)->ivec != NULL_PTR)
	  TC_free(((CK_I_CEAY_IDEA_INFO_PTR)session_data->decrypt_state)->ivec);
    idea_cbc_err:
	if(session_data->decrypt_state)
	  TC_free(session_data->decrypt_state);
	session_data->decrypt_state = NULL_PTR;

      }
      break;
      /* }}} */
    default:
      rv = CKR_MECHANISM_INVALID;
      CI_VarLogEntry("C_Decrypt", "algorithm specified: %s", rv, 0, 
		     CI_MechanismStr(session_data->decrypt_mechanism));

    }

  CI_LogEntry("C_Decrypt", "...completed", rv , 0);

  return rv;
}
/* }}} */
/* {{{ CI_Ceay_DecryptUpdate */
CK_DEFINE_FUNCTION(CK_RV, CI_Ceay_DecryptUpdate)(
  CK_I_SESSION_DATA_PTR  session_data,
  CK_BYTE_PTR       pEncryptedPart,      /* encrypted data */
  CK_ULONG          ulEncryptedPartLen,  /* input length */
  CK_BYTE_PTR       pPart,               /* gets plaintext */
  CK_ULONG_PTR      pulPartLen           /* p-text size */
)
{
  CK_RV rv;

  switch(session_data->decrypt_mechanism)
    {
      /* {{{ CKM_RC4 */
    case CKM_RC4:
      {
	rv = CKR_OK;
	CI_LogEntry("C_DecryptUpdate", "RC4", rv , 0);    

	/* is this just a test for the length of the recieving buffer? */
	if(pPart == NULL_PTR)
	  {
	    *pulPartLen = ulEncryptedPartLen;
	    return CKR_OK;
	  }
	
	/* is the supplied buffer long enough? */
	if(*pulPartLen < ulEncryptedPartLen)
	  {
	    *pulPartLen = ulEncryptedPartLen;
	    return CKR_BUFFER_TOO_SMALL;
	  }
	
	/* OK all set. lets compute */
	RC4(session_data->decrypt_state,ulEncryptedPartLen,pEncryptedPart,pPart);
	
	*pulPartLen=ulEncryptedPartLen;
      }
      break;
      /* }}} */
      /* {{{ CKM_RC2_ECB */
    case CKM_RC2_ECB:
      {
	CK_ULONG count;

	rv = CKR_OK;
	CI_LogEntry("C_DecryptUpdate", "RC2 ECB", rv , 0);	  

	/* RC2 always takes multiples of 8 bytes */
	if(ulEncryptedPartLen%8 != 0)
	  return CKR_DATA_LEN_RANGE;

	/* is this just a test for the length of the recieving buffer? */
	if(pPart == NULL_PTR)
	  {
	    *pulPartLen = ulEncryptedPartLen;
	    return CKR_OK;
	  }
	
	/* is the supplied buffer long enough? */
	if(*pulPartLen < ulEncryptedPartLen)
	  {
	    *pulPartLen = ulEncryptedPartLen;
	    return CKR_BUFFER_TOO_SMALL;
	  }

	/* OK all set. lets compute */
	/* in blocks of 8 bytes. */
	for(count=0; count<ulEncryptedPartLen ; count+=8)
	  {
	    RC2_ecb_encrypt(&(pEncryptedPart[count]), &(pPart[count]), 
			    session_data->decrypt_state,
			    RC2_DECRYPT);	    
	  }
	
	*pulPartLen=ulEncryptedPartLen;

	rv = CKR_OK;
      }
      break;
      /* }}} */
      /* {{{ CKM_RC2_CBC */
    case CKM_RC2_CBC:
      {
	rv = CKR_OK;
	CI_LogEntry("C_DecryptUpdate", "RC2 CBC", rv , 0);	  

	/* is the length of the supplied data a multiple of 8 to create des-blocks? */
	if(ulEncryptedPartLen%8 != 0)
	  return CKR_DATA_LEN_RANGE;

	/* is this just a test for the length of the recieving buffer? */
	if(pPart == NULL_PTR)
	  {
	    *pulPartLen = ulEncryptedPartLen;
	    return CKR_OK;
	  }

	/* is the supplied buffer long enough? */
	if(*pulPartLen < ulEncryptedPartLen)
	  {
	    *pulPartLen = ulEncryptedPartLen;
	    return CKR_BUFFER_TOO_SMALL;
	  }

	/* OK all set. lets compute */
	RC2_cbc_encrypt((unsigned char*)pEncryptedPart, (unsigned char*)pPart, 
			 ulEncryptedPartLen, 
			 ((CK_I_CEAY_RC2_INFO_PTR)session_data->decrypt_state)->key, 
			 ((CK_I_CEAY_RC2_INFO_PTR)session_data->decrypt_state)->ivec, 
			 RC2_DECRYPT);
	
	*pulPartLen=ulEncryptedPartLen;

	rv = CKR_OK;
	
      }
      break;
      /* }}} */
      /* {{{ CKM_DES_ECB */
    case CKM_DES_ECB:
      {
	CK_ULONG count;

	rv = CKR_OK;
	CI_LogEntry("C_DecryptUpdate", "DES ECB", rv , 0);	  

	/* DES always takes multiples of 8 bytes */
	if(ulEncryptedPartLen%8 != 0)
	  return CKR_DATA_LEN_RANGE;

	/* is this just a test for the length of the recieving buffer? */
	if(pPart == NULL_PTR)
	  {
	    *pulPartLen = ulEncryptedPartLen;
	    return CKR_OK;
	  }
	
	/* is the supplied buffer long enough? */
	if(*pulPartLen < ulEncryptedPartLen)
	{
	  *pulPartLen = ulEncryptedPartLen;
	  return CKR_BUFFER_TOO_SMALL;
	}

	/* OK all set. lets compute */
	/* in blocks of 8 bytes. */
	for(count=0; count<ulEncryptedPartLen ; count+=8)
	  {
	    des_ecb_encrypt((des_cblock*)(&(pEncryptedPart[count])),
			    (des_cblock*)(&(pPart[count])),
			    session_data->decrypt_state,
			    DES_DECRYPT);
	  }
	
	*pulPartLen=ulEncryptedPartLen;

	rv = CKR_OK;
      }
      break;
      /* }}} */
      /* {{{ CKM_DES_CBC */
    case CKM_DES_CBC:
      {
	rv = CKR_OK;
	CI_LogEntry("C_DecryptUpdate", "DES3 CBC", rv , 0);	  

	/* is the length of the supplied data a multiple of 8 to create des-blocks? */
	if(ulEncryptedPartLen%8 != 0)
	  return CKR_DATA_LEN_RANGE;

	/* is this just a test for the length of the recieving buffer? */
	if(pPart == NULL_PTR)
	  {
	    *pulPartLen = ulEncryptedPartLen;
	    return CKR_OK;
	  }

	/* is the supplied buffer long enough? */
	if(*pulPartLen < ulEncryptedPartLen)
	{
	  *pulPartLen = ulEncryptedPartLen;
	  return CKR_BUFFER_TOO_SMALL;
	}

	/* OK all set. lets compute */
	des_ncbc_encrypt(pEncryptedPart, 
			 pPart, 
			 ulEncryptedPartLen, 
			 ((CK_I_CEAY_DES_INFO_PTR)session_data->decrypt_state)->sched, 
			 &(((CK_I_CEAY_DES_INFO_PTR)session_data->decrypt_state)->ivec), 
			 DES_DECRYPT);

	*pulPartLen=ulEncryptedPartLen;

	
	rv = CKR_OK;
	
      }
      break;
      /* }}} */
      /* {{{ CKM_DES_CBC_PAD */
    case CKM_DES_CBC_PAD:
      {
	CK_BYTE_PTR ptmpbuf = NULL_PTR;
	/* is the length of the supplied data a multiple of 8 to create des-blocks? */
	if(ulEncryptedPartLen%8 != 0)
	  return CKR_DATA_LEN_RANGE;

	/* is this just a test for the length of the recieving buffer? */
	if(pPart == NULL_PTR)
	  {
	    *pulPartLen = ulEncryptedPartLen;
	    return CKR_OK;
	  }

	/* is the supplied buffer long enough? */
	if(*pulPartLen < ulEncryptedPartLen)
	{
	  *pulPartLen = ulEncryptedPartLen;
	  return CKR_BUFFER_TOO_SMALL;
	}

	/* OK all set. lets compute */
	ptmpbuf = CI_ByteStream_new(ulEncryptedPartLen);
	if(ptmpbuf == NULL_PTR) return CKR_HOST_MEMORY; 
	if(((CK_I_CEAY_DES_INFO_PTR)session_data->decrypt_state)->pad)
	{
	  memcpy(ptmpbuf, ((CK_I_CEAY_DES_INFO_PTR)session_data->decrypt_state)->lastblock, 8);
	  memcpy(ptmpbuf+8, pEncryptedPart, ulEncryptedPartLen-8);
	  *pulPartLen = ulEncryptedPartLen;
	}
	else
	{
	  memcpy(ptmpbuf, pEncryptedPart, ulEncryptedPartLen-8);
	  *pulPartLen = ulEncryptedPartLen-8;
	  ((CK_I_CEAY_DES_INFO_PTR)session_data->decrypt_state)->pad = 8;
	}
	
	des_ncbc_encrypt(ptmpbuf, 
			 pPart, 
			 *pulPartLen, 
			 ((CK_I_CEAY_DES_INFO_PTR)session_data->decrypt_state)->sched, 
			 &(((CK_I_CEAY_DES_INFO_PTR)session_data->decrypt_state)->ivec), 
			 DES_DECRYPT);
	memcpy(((CK_I_CEAY_DES_INFO_PTR)session_data->decrypt_state)->lastblock, pEncryptedPart+ulEncryptedPartLen-8, 8);
	TC_free(ptmpbuf);

	rv = CKR_OK;
      }
    break;
      /* }}} */
      /* {{{ CKM_DES3_ECB */
    case CKM_DES3_ECB:
      {
	CK_ULONG count;

	/* DES always takes multiples of 8 bytes */
	if(ulEncryptedPartLen%8 != 0)
	  return CKR_DATA_LEN_RANGE;

	/* is this just a test for the length of the recieving buffer? */
	if(pPart == NULL_PTR)
	  {
	    *pulPartLen = ulEncryptedPartLen;
	    return CKR_OK;
	  }
	
	/* is the supplied buffer long enough? */
	if(*pulPartLen < ulEncryptedPartLen)
	  {
	    *pulPartLen = ulEncryptedPartLen;	    
	    return CKR_BUFFER_TOO_SMALL;
	  }

	/* OK all set. lets compute */
	/* in blocks of 8 bytes. */
	for(count=0; count<ulEncryptedPartLen ; count+=8)
	  {
	    des_ecb3_encrypt((des_cblock*)(&(pPart[count])),
			     (des_cblock*)(&(pEncryptedPart[count])), 
			     ((CK_I_CEAY_DES3_INFO_PTR)session_data->decrypt_state)->sched[0],
			     ((CK_I_CEAY_DES3_INFO_PTR)session_data->decrypt_state)->sched[1],
			     ((CK_I_CEAY_DES3_INFO_PTR)session_data->decrypt_state)->sched[2],
			     DES_DECRYPT);
	  }
	
	*pulPartLen=ulEncryptedPartLen;

	rv = CKR_OK;
      }
      break;
      /* }}} */
      /* {{{ CKM_DES3_CBC */
    case CKM_DES3_CBC:
      {
	
	rv = CKR_OK;
	CI_LogEntry("C_DecryptUpdate", "IDEA CBC", rv , 0);	  

	/* is the length of the supplied data a multiple of 8 to create des-blocks? */
	if(ulEncryptedPartLen%8 != 0)
	  return CKR_DATA_LEN_RANGE;

	/* is this just a test for the length of the recieving buffer? */
	if(pPart == NULL_PTR)
	  {
	    *pulPartLen = ulEncryptedPartLen;
	    return CKR_OK;
	  }

	/* is the supplied buffer long enough? */
	if(*pulPartLen < ulEncryptedPartLen)
	  {
	    *pulPartLen = ulEncryptedPartLen;
	    return CKR_BUFFER_TOO_SMALL;
	  }


	/* OK all set. lets compute */
	des_ede3_cbc_encrypt(pEncryptedPart, 
			     pPart, 
			     ulEncryptedPartLen, 
			     ((CK_I_CEAY_DES3_INFO_PTR)session_data->decrypt_state)->sched[0], 
			     ((CK_I_CEAY_DES3_INFO_PTR)session_data->decrypt_state)->sched[1], 
			     ((CK_I_CEAY_DES3_INFO_PTR)session_data->decrypt_state)->sched[2], 
			     ((CK_I_CEAY_DES3_INFO_PTR)session_data->decrypt_state)->ivec, 
			     DES_DECRYPT);

	*pulPartLen=ulEncryptedPartLen;

	rv = CKR_OK;	
      }
      break;
      /* }}} */
      /* {{{ CKM_IDEA_ECB */
    case CKM_IDEA_ECB:
      {
	CK_ULONG count;

	rv = CKR_OK;
	CI_LogEntry("C_DecryptUpdate", "IDEA ECB", rv , 0);	  

	/* DES always takes multiples of 8 bytes */
	if(ulEncryptedPartLen%8 != 0)
	  return CKR_DATA_LEN_RANGE;

	/* is this just a test for the length of the recieving buffer? */
	if(pPart == NULL_PTR)
	  {
	    *pulPartLen = ulEncryptedPartLen;
	    return CKR_OK;
	  }
	
	/* is the supplied buffer long enough? */
	if(*pulPartLen < ulEncryptedPartLen)
	  {
	    *pulPartLen = ulEncryptedPartLen;
	    return CKR_BUFFER_TOO_SMALL;
	  }

	/* damit wir ne hoffnung haben */
	assert(sizeof(CK_BYTE) == sizeof(unsigned char));

	/* OK all set. lets compute */
	/* in blocks of 8 bytes. */
	for(count=0; count<ulEncryptedPartLen ; count+=8)
	  {
	    /* its the same function for decryption as well, only the key schedule differs */
	    idea_ecb_encrypt((unsigned char*)&(pEncryptedPart[count]),
			     (unsigned char*)&(pPart[count]),
			     &(((CK_I_CEAY_IDEA_INFO_PTR)session_data->decrypt_state)->sched));	    
	  }
	
	*pulPartLen=ulEncryptedPartLen;

	rv = CKR_OK;
      }
      break;
      /* }}} */
      /* {{{ CKM_IDEA_CBC */
    case CKM_IDEA_CBC:
      {
	rv = CKR_OK;
	CI_LogEntry("C_DecryptUpdate", "IDEA CBC", rv , 0);	  

	/* is the length of the supplied data a multiple of 8 to create des-blocks? */
	if(ulEncryptedPartLen%8 != 0)
	  return CKR_DATA_LEN_RANGE;

	/* is this just a test for the length of the recieving buffer? */
	if(pPart == NULL_PTR)
	  {
	    *pulPartLen = ulEncryptedPartLen;
	    return CKR_OK;
	  }

	/* is the supplied buffer long enough? */
	if(*pulPartLen < ulEncryptedPartLen)
	  {
	    *pulPartLen = ulEncryptedPartLen;
	    return CKR_BUFFER_TOO_SMALL;
	  }

	/* OK all set. lets compute */
	idea_cbc_encrypt((unsigned char*)pEncryptedPart, 
			 (unsigned char*)pPart, 
			 ulEncryptedPartLen, 
			 &(((CK_I_CEAY_IDEA_INFO_PTR)session_data->decrypt_state)->sched), 
			 ((CK_I_CEAY_IDEA_INFO_PTR)session_data->decrypt_state)->ivec, 
			 IDEA_DECRYPT);

	*pulPartLen=ulEncryptedPartLen;

	rv = CKR_OK;
      }
      break;
      /* }}} */
    default:
      rv = CKR_MECHANISM_INVALID;
      CI_VarLogEntry("C_DecryptUpdate", "algorithm specified: %s", rv, 0, 
		     CI_MechanismStr(session_data->decrypt_mechanism));
    }
  
  CI_VarLogEntry("C_DecryptUpdate", "decryption (%s) result: %s", rv, 2,
		 CI_MechanismStr(session_data->decrypt_mechanism),
		 CI_PrintableByteStream(pPart,*pulPartLen));

  CI_LogEntry("C_DecryptUpdate", "...completed", rv , 0);	  

  return rv;
}
/* }}} */
/* {{{ CI_Ceay_DecryptFinal */
CK_DEFINE_FUNCTION(CK_RV, CI_Ceay_DecryptFinal)(
  CK_I_SESSION_DATA_PTR  session_data,
  CK_BYTE_PTR       pLastPart,      /* gets plaintext */
  CK_ULONG_PTR      pulLastPartLen  /* p-text size */
)
{
  CK_RV rv;

  switch(session_data->decrypt_mechanism)
    {
      /* {{{ CKM_RC4, CKM_DES_ECB, CKM_RC2_ECB, CKM_IDEA_ECB */
    case CKM_RC4:
    case CKM_RC2_ECB:
    case CKM_DES_ECB:
    case CKM_IDEA_ECB:
      { 
	rv = CKR_OK;
	CI_LogEntry("C_DecryptFinal", "RC4 DES-ECB RC2-ECB IDEA-ECB", rv , 0);    
 
	/* terminate operation */
	if(pulLastPartLen == NULL_PTR) 
	  {
	    rv = CKR_OK; goto des_err;
	  }
	/* is this just a test for the length of the recieving buffer? */
	if(pLastPart == NULL_PTR)
	{
	  *pulLastPartLen = 0;
	  rv = CKR_OK; break;
	}
	*pulLastPartLen=0;
	
      des_err:
	if(session_data->decrypt_state != NULL_PTR)
	  TC_free(session_data->decrypt_state);
	session_data->decrypt_state = NULL_PTR;
	rv = CKR_OK;
      }
      break;
      /* }}} */
      /* {{{ CKM_RC2_CBC */
    case CKM_RC2_CBC:
      {
	rv = CKR_OK;
	CI_LogEntry("C_DecryptFinal", "RC2", rv , 0);     

	/* terminate operation */
	if(pulLastPartLen == NULL_PTR) 
	  {
	    rv = CKR_OK; goto rc2_cbc_err;
	  }

	/* is this just a test for the length of the recieving buffer? */
	if(pLastPart == NULL_PTR)
	{
	  *pulLastPartLen = 0;
	  rv = CKR_OK; break;
	}
      *pulLastPartLen=0;

rc2_cbc_err:
      if(session_data->decrypt_state != NULL_PTR)
	{
	  CI_RC2_INFO_delete(session_data->decrypt_state);
	  session_data->decrypt_state = NULL_PTR;
	}
      
      rv = CKR_OK;
      }
      break;
      /* }}} */
      /* {{{ CKM_DES3_ECB */
    case CKM_DES3_ECB:
      {
	/* terminate operation */
	if(pulLastPartLen == NULL_PTR) 
	  {
	    rv = CKR_OK; goto des3_ecb_err;
	  }
	if(pLastPart == NULL_PTR)
	{
	  *pulLastPartLen = 0;
	  rv = CKR_OK; break;
	}
	*pulLastPartLen=0;

      des3_ecb_err:
	if(session_data->decrypt_state!= NULL_PTR)
	  CI_DES3_INFO_delete(session_data->decrypt_state);
	session_data->decrypt_state = NULL_PTR;

	rv = CKR_OK;
      }
      break;
      /* }}} */
      /* {{{ CKM_DES3_CBC */
    case CKM_DES3_CBC:
      {
	rv = CKR_OK;
	CI_LogEntry("C_DecryptFinal", "DES3 CBC", rv , 0);         

	/* terminate operation */
	if(pulLastPartLen == NULL_PTR) 
	  {
	    rv = CKR_OK; goto des3_cbc_err;
	  }
	/* is this just a test for the length of the recieving buffer? */
	if(pLastPart == NULL_PTR)
	{
	  *pulLastPartLen = 0;
	  rv = CKR_OK; break;
	}
	*pulLastPartLen=0;

      des3_cbc_err:
	if(session_data->decrypt_state != NULL_PTR)
	  CI_DES3_INFO_delete(session_data->decrypt_state);
	session_data->decrypt_state = NULL_PTR;
	
      }
      break;
      /* }}} */
      /* {{{ CKM_DES_CBC */
    case CKM_DES_CBC:
      {
	rv = CKR_OK;
	CI_LogEntry("C_DecryptFinal", "DES CBC", rv , 0);         
	
	/* terminate operation */
	if(pulLastPartLen == NULL_PTR) 
	  {
	    rv = CKR_OK; goto des_cbc_err;
	  }
	if(pLastPart == NULL_PTR)
	  {
	    *pulLastPartLen = 0;
	    rv = CKR_OK; break;
	  }
	*pulLastPartLen=0;
	
      des_cbc_err:
	if(session_data->decrypt_state != NULL_PTR)
	  TC_free(session_data->decrypt_state);
	session_data->decrypt_state = NULL_PTR;
	
      }
      break;
	/* }}} */
      /* {{{ CKM_DES_CBC_PAD */
    case CKM_DES_CBC_PAD:
      {
	/* terminate operation */
	if(pulLastPartLen == NULL_PTR) 
	  {
	    rv = CKR_OK; goto des_cbc_pad_err;
	  }
	/* is this just a test for the length of the recieving buffer? */
	if(pLastPart == NULL_PTR)
	{
	  *pulLastPartLen = 8;
	  rv = CKR_OK; break;
	}

	if(*pulLastPartLen < 8)
	{
	  *pulLastPartLen=8;
	  rv = CKR_BUFFER_TOO_SMALL; break;
	}

	des_ncbc_encrypt(((CK_I_CEAY_DES_INFO_PTR)session_data->decrypt_state)->lastblock, 
			 pLastPart, 
			 8, 
			 ((CK_I_CEAY_DES_INFO_PTR)session_data->decrypt_state)->sched, 
			 &(((CK_I_CEAY_DES_INFO_PTR)session_data->decrypt_state)->ivec), 
			 DES_DECRYPT);
	
	if (pLastPart[7] >= 1 && pLastPart[7] <= 8)
	  *pulLastPartLen -= pLastPart[7];
	else
	  rv = CKR_GENERAL_ERROR;
	
    des_cbc_pad_err:
      if(session_data->decrypt_state != NULL_PTR)
	TC_free(session_data->decrypt_state);
      session_data->decrypt_state = NULL_PTR;
      
      }
      break;
      /* }}} */
      /* {{{ CKM_IDEA_CBC */
    case CKM_IDEA_CBC:
      {
	rv = CKR_OK;
	CI_LogEntry("C_DecryptFinal", "IDEA CBC", rv , 0);        

	/* terminate operation */
	if(pulLastPartLen == NULL_PTR) 
	  {
	    goto idea_cbc_err;
	  }
	/* is this just a test for the length of the recieving buffer? */
	if(pLastPart == NULL_PTR)
	{
	  *pulLastPartLen = 0;
	  break;
	}
	*pulLastPartLen=0;
	
      idea_cbc_err:
	if(session_data->decrypt_state != NULL_PTR)
	  {
	    if( (((CK_I_CEAY_IDEA_INFO_PTR)session_data->decrypt_state)->ivec) != NULL_PTR)
	      TC_free(((CK_I_CEAY_IDEA_INFO_PTR)session_data->decrypt_state)->ivec);
	    TC_free(session_data->decrypt_state);
	  }
	session_data->decrypt_state = NULL_PTR;
      }
      break;
      /* }}} */
    default:
      rv = CKR_MECHANISM_INVALID;
      
      CI_VarLogEntry("C_DecryptFinal", "algorithm specified: %s", rv, 0, 
		     CI_MechanismStr(session_data->decrypt_mechanism));
    }
  
  CI_LogEntry("C_DecryptFinal", "...completed", rv , 0);    
  
  return rv;
}
/* }}} */

/*
 * Local variables:
 * folded-file: t
 * end:
 */
