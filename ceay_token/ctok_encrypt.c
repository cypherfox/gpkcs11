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
 * NAME:        ctok_encrypt.c
 * SYNOPSIS:    -
 * DESCRIPTION: function that handle data encrypt in the ceay token
 * FILES:       -
 * SEE/ALSO:    -
 * AUTHOR:      lbe
 * BUGS:        -
 */

static char RCSID[]="$Id$";
const char* ctok_encrypt_c_version(){return RCSID;}

/* Stupid Windows-isms */
#ifndef CK_I_library_build
#define  CK_I_library_build
#endif /* CK_I_library_build */

#include "ceay_token.h"
#include "objects.h"
#include "error.h"
#include "mutex.h"
#include "init.h"
#include "ctok_mem.h"

#include <assert.h>

/* {{{ CI_Ceay_EncryptInit */
CK_DEFINE_FUNCTION(CK_RV, CI_Ceay_EncryptInit)(
  CK_I_SESSION_DATA_PTR  session_data,
  CK_MECHANISM_PTR       pMechanism,  /* the encryption mechanism */
  CK_I_OBJ_PTR           key_obj      /* handle of encryption key */
)
{
  CK_RV rv = CKR_OK;

  switch(pMechanism->mechanism)
    {
      /* {{{ CKM_RSA_PKCS */
    case CKM_RSA_PKCS:  
      {
	RSA CK_PTR internal_key_obj = NULL_PTR;

	CI_LogEntry("CI_Ceay_EncryptInit", "starting CKM_RSA_PKCS", rv, 2);

	/* check that object is a public key */
	if((CI_ObjLookup(key_obj,CK_IA_CLASS) != NULL_PTR) && 
	   (*((CK_OBJECT_CLASS CK_PTR)CI_ObjLookup(key_obj,CK_IA_CLASS)->pValue) != CKO_PUBLIC_KEY))
	  return CKR_KEY_TYPE_INCONSISTENT;

	internal_key_obj = CI_Ceay_Obj2RSA(key_obj);
	if(internal_key_obj == NULL_PTR)
	  return CKR_HOST_MEMORY;

	session_data->encrypt_state = (CK_VOID_PTR)internal_key_obj;
	session_data->encrypt_mechanism = CKM_RSA_PKCS;
	
      }
      break;
      /* }}} */
      /* {{{ CKM_RSA_X_509 */
    case CKM_RSA_X_509:  
      {
	RSA CK_PTR internal_key_obj = NULL_PTR;

	CI_LogEntry("CI_Ceay_EncryptInit", "starting CKM_RSA_PKCS", rv, 2);

	/* check that object is a public key */
	if((CI_ObjLookup(key_obj,CK_IA_CLASS) != NULL_PTR) && 
	   (*((CK_OBJECT_CLASS CK_PTR)CI_ObjLookup(key_obj,CK_IA_CLASS)->pValue) != CKO_PUBLIC_KEY))
	  return CKR_KEY_TYPE_INCONSISTENT;

	internal_key_obj = CI_Ceay_Obj2RSA(key_obj);
	if(internal_key_obj == NULL_PTR)
	  return CKR_HOST_MEMORY;

	session_data->encrypt_state = (CK_VOID_PTR)internal_key_obj;
	session_data->encrypt_mechanism = CKM_RSA_X_509;
	
      }
      break;
      /* }}} */
      /* {{{ CKM_RC4 */
    case CKM_RC4:
      {
	RC4_KEY CK_PTR internal_obj = NULL_PTR;
	CK_ULONG key_len;

	CI_LogEntry("CI_Ceay_EncryptInit", "starting CKM_RC4", rv, 2);

	internal_obj = CI_RC4Key_new();
	if(internal_obj == NULL_PTR)
	  return CKR_HOST_MEMORY;

	if(CI_ObjLookup(key_obj,CK_IA_VALUE_LEN) == NULL_PTR)
	  {
	    key_len = CI_ObjLookup(key_obj,CK_IA_VALUE)->ulValueLen;
	    CI_LogEntry("C_Ceay_EncryptInit", 
			"RC4 Key supplied without CKA_VALUE_LEN, continuing with CKA_VALUE->ulValueLen",
			rv, 0);
	  }
	else
	  {
	    key_len = *((CK_ULONG_PTR)(CI_ObjLookup(key_obj,CK_IA_VALUE_LEN)->pValue));
	    
	    if(CI_ObjLookup(key_obj,CK_IA_VALUE)->ulValueLen != 
	       *((CK_ULONG_PTR)(CI_ObjLookup(key_obj,CK_IA_VALUE_LEN)->pValue)))
	      CI_VarLogEntry("CI_Ceay_EncryptInit", "key lens differ: pValueLen: %i VALUE_LEN: %i", 
			     rv, 0,
			     CI_ObjLookup(key_obj,CK_IA_VALUE)->ulValueLen,
			     *((CK_ULONG_PTR)(CI_ObjLookup(key_obj,CK_IA_VALUE_LEN)->pValue)));
	  }

	{
	  CK_BYTE_PTR tmp_str = NULL_PTR;
	  CI_VarLogEntry("CI_Ceay_EncryptInit", "using as key: %s", rv, 2,
			 tmp_str = CI_PrintableByteStream(CI_ObjLookup(key_obj,
								       CK_IA_VALUE)->pValue,
							  key_len));
	  TC_free(tmp_str);
	}

	RC4_set_key(internal_obj,
		    key_len,
		    CI_ObjLookup(key_obj,CK_IA_VALUE)->pValue);

	session_data->encrypt_state = (CK_VOID_PTR)internal_obj;
	session_data->encrypt_mechanism = CKM_RC4;

	rv = CKR_OK;
      }
      break;
      /* }}} */
      /* {{{ CKM_RC2_ECB */
    case CKM_RC2_ECB:
      {
	RC2_KEY CK_PTR internal_obj = NULL_PTR;
	CK_RC2_PARAMS rc2_params;
	int key_len;

	CI_LogEntry("CI_Ceay_EncryptInit", "starting CKM_RC2_ECB", rv, 2);


	if((pMechanism->pParameter == NULL_PTR) ||
	   (pMechanism->ulParameterLen < sizeof(CK_RC2_PARAMS)) )
	   {
	     rv = CKR_MECHANISM_PARAM_INVALID;
	     CI_VarLogEntry("C_Ceay_EncryptInit", 
			 "RC2-ECB Mechanism Parameter missing or of wrong size: %i", 
			 rv ,0, pMechanism->ulParameterLen);
	     return rv;
	   }

	rc2_params = *((CK_RC2_PARAMS CK_PTR)pMechanism->pParameter);

	internal_obj = CI_RC2Key_new();
	if(internal_obj == NULL_PTR)
	  return CKR_HOST_MEMORY;


	if(CI_ObjLookup(key_obj,CK_IA_VALUE_LEN) == NULL_PTR)
	  {
	    key_len = CI_ObjLookup(key_obj,CK_IA_VALUE)->ulValueLen;
	    CI_LogEntry("C_Ceay_EncryptInit", 
			"RC2-ECB Key supplied without CKA_VALUE_LEN, continuing with CKA_VALUE->ulValueLen",
			rv, 2);
	  }
	else
	  key_len = *((CK_ULONG_PTR)(CI_ObjLookup(key_obj,CK_IA_VALUE_LEN)->pValue));

	RC2_set_key(internal_obj,
		    key_len,
		    CI_ObjLookup(key_obj,CK_IA_VALUE)->pValue,
		    rc2_params);

	session_data->encrypt_state = (CK_VOID_PTR)internal_obj;
	session_data->encrypt_mechanism = CKM_RC2_ECB;

	rv = CKR_OK;
      }
      break;
      /* }}} */
      /* {{{ CKM_RC2_CBC */
    case CKM_RC2_CBC:
      {
	CK_I_CEAY_RC2_INFO_PTR internal_obj = NULL_PTR;
	CK_RC2_CBC_PARAMS_PTR para = pMechanism->pParameter;
	int key_len;

	CI_LogEntry("CI_Ceay_EncryptInit", "starting CKM_RC2_CBC", rv, 2);
 
	internal_obj= CI_RC2_INFO_new();
	if(internal_obj == NULL_PTR)
	  {
	    rv = CKR_HOST_MEMORY;
	    goto encrypt_init_rc2_error;
	  }


	if(CI_ObjLookup(key_obj,CK_IA_VALUE_LEN) == NULL_PTR)
	  {
	    key_len = CI_ObjLookup(key_obj,CK_IA_VALUE)->ulValueLen;
	    CI_LogEntry("C_Ceay_EncryptInit", 
			"RC2-CBC Key supplied without CKA_VALUE_LEN, continuing with CKA_VALUE->ulValueLen",
			rv, 2);
	  }
	else
	  key_len = *((CK_ULONG_PTR)(CI_ObjLookup(key_obj,CK_IA_VALUE_LEN)->pValue));

	/* Ok, alles alloziert, jetzt die wirklichen Werte eintragen */
	/* Mechanism zuerst, denn da kann ja der Parameter fehlen */
	if(para == NULL_PTR)
	  {
	    rv = CKR_MECHANISM_PARAM_INVALID;
	    goto encrypt_init_rc2_error;
	  }
	memcpy(internal_obj->ivec,para->iv, sizeof(CK_BYTE)*CK_I_IVEC_LEN);

	{
	  CK_BYTE_PTR tmp_str = NULL_PTR;
	  
	  CI_VarLogEntry("CI_Ceay_EncryptInit", "RC2 CBC ivec: %s", rv, 2,
			 tmp_str = CI_PrintableByteStream(internal_obj->ivec,
							  sizeof(CK_BYTE)*8));
	  TC_free(tmp_str);
	}

	/* TODO: check that the size of the effective Bits are valid */
	RC2_set_key(internal_obj->key,
		    key_len,
		    CI_ObjLookup(key_obj,CK_IA_VALUE)->pValue,
		    para->ulEffectiveBits);

	session_data->encrypt_state = internal_obj;
	session_data->encrypt_mechanism = CKM_RC2_CBC;

      encrypt_init_rc2_error:
	if(rv != CKR_OK)
	  CI_RC2_INFO_delete(internal_obj);
      }
     break;
     /* }}} */
      /* {{{ CKM_DES_ECB */
    case CKM_DES_ECB:
      {
	CK_I_CEAY_DES_INFO_PTR internal_obj = NULL_PTR;
	CK_BYTE_PTR tmp_key_data;

	CI_LogEntry("CI_Ceay_EncryptInit", "starting CKM_DES_ECB", rv, 2);

	internal_obj = CI_DES_INFO_new();
	if(internal_obj == NULL_PTR)
	  { rv = CKR_HOST_MEMORY; break; }

	/* lotsa safety checks */
	if(CI_ObjLookup(key_obj,CK_IA_VALUE)->ulValueLen != sizeof(des_cblock))
	  { rv = CKR_KEY_TYPE_INCONSISTENT; break; }
	
	if( (CI_ObjLookup(key_obj,CK_IA_VALUE_LEN) != NULL_PTR) && 
	    (*((CK_ULONG CK_PTR)CI_ObjLookup(key_obj,CK_IA_VALUE_LEN)->pValue) != sizeof(des_cblock))) 
	  { rv = CKR_KEY_TYPE_INCONSISTENT; ; break; }

	tmp_key_data = CI_ObjLookup(key_obj,CK_IA_VALUE)->pValue;
	if(tmp_key_data == NULL_PTR)
	  { rv = CKR_KEY_TYPE_INCONSISTENT; ; break; }
	  
	des_set_key((des_cblock*)tmp_key_data,
		    internal_obj->sched);


	session_data->encrypt_state = (CK_VOID_PTR)internal_obj;
	session_data->encrypt_mechanism = CKM_DES_ECB;

	rv = CKR_OK;
      }
      break;
      /* }}} */
      /* {{{ CKM_DES_CBC */
    case CKM_DES_CBC:
      {
	CK_I_CEAY_DES_INFO_PTR internal_obj = NULL_PTR;
	CK_BYTE_PTR pdes_cblock;

	CI_LogEntry("CI_Ceay_EncryptInit", "starting CKM_DES_CBC", rv, 2);

	internal_obj= CI_DES_INFO_new();
	if(internal_obj == NULL_PTR)
	  {
	    rv = CKR_HOST_MEMORY;
	    goto encrypt_init_des_error;
	  }

	/* Ok, alles alloziert, jetzt die wirklichen Werte eintragen */
	/* Mechanism zuerst, denn da kann ja der Parameter fehlen */
	if((pMechanism->pParameter == NULL_PTR) ||
	   (pMechanism->ulParameterLen != sizeof(des_cblock)))
	  {
	    rv = CKR_MECHANISM_PARAM_INVALID;
	    goto encrypt_init_des_error;
	  }
	memcpy(internal_obj->ivec,pMechanism->pParameter, sizeof(des_cblock));

	{
	  CK_BYTE_PTR tmp_str = NULL_PTR;
	  
	  CI_VarLogEntry("CI_Ceay_EncryptInit", "DES CBC ivec: %s", rv, 2,
			 tmp_str = CI_PrintableByteStream((CK_BYTE_PTR)internal_obj->ivec,
							  sizeof(des_cblock)));
	  TC_free(tmp_str);
	}

	pdes_cblock =(CI_ObjLookup(key_obj,CK_IA_VALUE)->pValue);
	if(pdes_cblock == NULL_PTR) return CKR_KEY_TYPE_INCONSISTENT;
	des_set_key((des_cblock*)pdes_cblock,internal_obj->sched);

	session_data->encrypt_state = internal_obj;
	session_data->encrypt_mechanism = CKM_DES_CBC;

	/* ugly global value from the ceay lib */
	des_rw_mode = DES_CBC_MODE;

      encrypt_init_des_error:
	if(rv != CKR_OK)
	  CI_DES_INFO_delete(internal_obj);
      }
      break;
      /* }}} */
      /* {{{ CKM_DES_CBC_PAD */
    case CKM_DES_CBC_PAD:
      {
	CK_I_CEAY_DES_INFO_PTR internal_obj = NULL_PTR;
	CK_BYTE_PTR pdes_cblock;

	CI_LogEntry("CI_Ceay_EncryptInit", "starting CKM_DES_CBC_PAD", rv, 2);

	internal_obj= CI_DES_INFO_new();
	if(internal_obj == NULL_PTR)
	  {
	    rv = CKR_HOST_MEMORY;
	    goto encrypt_init_des_error;
	  }

	/* Ok, alles alloziert, jetzt die wirklichen Werte eintragen */
	/* Mechanism zuerst, denn da kann ja der Parameter fehlen */
	if((pMechanism->pParameter == NULL_PTR) ||
	   (pMechanism->ulParameterLen != sizeof(des_cblock)))
	  {
	    rv = CKR_MECHANISM_PARAM_INVALID;
	    goto encrypt_init_des_pad_error;
	  }
	memcpy(internal_obj->ivec,pMechanism->pParameter, sizeof(des_cblock));

	{
	  CK_BYTE_PTR tmp_str = NULL_PTR;
	  
	  CI_VarLogEntry("CI_Ceay_EncryptInit", "DES CBC PAD ivec: %s", rv, 2,
			 tmp_str = CI_PrintableByteStream((CK_BYTE_PTR)internal_obj->ivec,
							  sizeof(des_cblock)));
	  TC_free(tmp_str);
	}

	pdes_cblock =(CI_ObjLookup(key_obj,CK_IA_VALUE)->pValue);
	if(pdes_cblock == NULL_PTR)
	{
	  rv = CKR_KEY_TYPE_INCONSISTENT;
	  goto encrypt_init_des_pad_error;
	}
	des_set_key((des_cblock*)pdes_cblock,internal_obj->sched);

	session_data->encrypt_state = internal_obj;
	session_data->encrypt_mechanism = CKM_DES_CBC_PAD;
	((CK_I_CEAY_DES_INFO_PTR)session_data->encrypt_state)->pad = 0;
	((CK_I_CEAY_DES_INFO_PTR)session_data->encrypt_state)->round = 0;
	memset(((CK_I_CEAY_DES_INFO_PTR)session_data->encrypt_state)->lastblock, 0, 8);

	/* ugly global value from the ceay lib */
	des_rw_mode = DES_CBC_MODE;

      encrypt_init_des_pad_error:
	if(rv != CKR_OK)
	  CI_DES_INFO_delete(internal_obj);
      }
      break;
      /* }}} */
      /* {{{ CKM_DES3_ECB */
    case CKM_DES3_ECB:
      {
	CK_I_CEAY_DES3_INFO_PTR internal_obj = NULL_PTR;

	CI_LogEntry("CI_Ceay_EncryptInit", "starting CKM_DES3_ECB", rv, 2);

	internal_obj = CI_DES3_INFO_new(CI_ObjLookup(key_obj,CK_IA_VALUE)->pValue);
	if(internal_obj == NULL_PTR)
	  { rv =  CKR_HOST_MEMORY; break; }
	      
	session_data->encrypt_state = (CK_VOID_PTR)internal_obj;
	session_data->encrypt_mechanism = CKM_DES3_ECB;

	rv = CKR_OK;
      }
      break;
      /* }}} */
      /* {{{ CKM_DES3_CBC */
    case CKM_DES3_CBC:
      {
	CK_I_CEAY_DES3_INFO_PTR internal_obj = NULL_PTR;

	CI_LogEntry("CI_Ceay_EncryptInit", "starting CKM_DES3_CBC", rv, 2);

	internal_obj= CI_DES3_INFO_new(CI_ObjLookup(key_obj,CK_IA_VALUE)->pValue);
	if(internal_obj == NULL_PTR)
	  {
	    rv = CKR_HOST_MEMORY;
	    goto encrypt_init_des3_error;
	  }

	/* Ok, alles alloziert, jetzt die wirklichen Werte eintragen */
	/* Mechanism zuerst, denn da kann ja der Parameter fehlen */
	if((pMechanism->pParameter == NULL_PTR) ||
	   (pMechanism->ulParameterLen != sizeof(des_cblock)))
	  {
	    rv = CKR_MECHANISM_PARAM_INVALID;
	    goto encrypt_init_des_error;
	  }
	memcpy(internal_obj->ivec,pMechanism->pParameter, sizeof(des_cblock));

	{
	  CK_BYTE_PTR tmp_str = NULL_PTR;
	  
	  CI_VarLogEntry("CI_Ceay_EncryptInit", "DES3 CBC ivec: %s", rv, 2,
			 tmp_str = CI_PrintableByteStream((CK_BYTE_PTR)internal_obj->ivec,
							  sizeof(des_cblock)));
	  TC_free(tmp_str);
	}

	session_data->encrypt_state = internal_obj;
	session_data->encrypt_mechanism = CKM_DES3_CBC;

	/* ugly global value from the ceay lib */
	des_rw_mode = DES_CBC_MODE;

      encrypt_init_des3_error:
	if(rv != CKR_OK)
	  CI_DES3_INFO_delete(internal_obj);
      }
      break;
      /* }}} */
      /* {{{ CKM_IDEA_ECB */
    case CKM_IDEA_ECB:
      {
	IDEA_KEY_SCHEDULE CK_PTR internal_obj = NULL_PTR;

	CI_LogEntry("CI_Ceay_EncryptInit", "starting CKM_IDEA_ECB", rv, 2);

	internal_obj = CI_IDEA_KEY_SCHEDULE_new();
	if(internal_obj == NULL_PTR)
	{ rv = CKR_HOST_MEMORY; break; }

	idea_set_encrypt_key(CI_ObjLookup(key_obj,CK_IA_VALUE)->pValue,
			     internal_obj);

	session_data->encrypt_state = (CK_VOID_PTR)internal_obj;
	session_data->encrypt_mechanism = CKM_IDEA_ECB;

	rv = CKR_OK;
      }
      break;
      /* }}} */
      /* {{{ CKM_IDEA_CBC */
    case CKM_IDEA_CBC:
      {
	CK_I_CEAY_IDEA_INFO_PTR internal_obj = NULL_PTR;

	CI_LogEntry("CI_Ceay_EncryptInit", "starting CKM_IDEA_CBC", rv, 2);

	/* Mechanism zuerst prüfen, denn da kann ja der Parameter fehlen */
	if((pMechanism->pParameter == NULL_PTR) ||
	   (pMechanism->ulParameterLen != sizeof(des_cblock)))
	    return CKR_MECHANISM_PARAM_INVALID;

	internal_obj= CI_IDEA_INFO_new();
	if(internal_obj == NULL_PTR)
	{ rv = CKR_HOST_MEMORY; break; }

	/* Ok, alles alloziert, jetzt die wirklichen Werte eintragen */
	memcpy(internal_obj->ivec,pMechanism->pParameter, sizeof(des_cblock));
	{
	  CK_BYTE_PTR tmp_str = NULL_PTR;
	  
	  CI_VarLogEntry("CI_Ceay_EncryptInit", "IDEA CBC ivec: %s", rv, 2,
			 tmp_str = CI_PrintableByteStream(internal_obj->ivec,
							  sizeof(des_cblock)));
	  TC_free(tmp_str);
	}

	idea_set_encrypt_key(CI_ObjLookup(key_obj,CK_IA_VALUE)->pValue,&(internal_obj->sched));

	session_data->encrypt_state = internal_obj;
	session_data->encrypt_mechanism = CKM_IDEA_CBC;
      }
      break;
      /* }}} */
    default:
      rv= CKR_MECHANISM_INVALID;
    }

  return rv;
}
/* }}} */
/* {{{ CI_Ceay_Encrypt */
CK_DEFINE_FUNCTION(CK_RV, CI_Ceay_Encrypt)(
  CK_I_SESSION_DATA_PTR  session_data,
  CK_BYTE_PTR       pData,               /* the plaintext data */
  CK_ULONG          ulDataLen,           /* bytes of plaintext */
  CK_BYTE_PTR       pEncryptedData,      /* gets ciphertext */
  CK_ULONG_PTR      pulEncryptedDataLen  /* gets c-text size */
)
{
  CK_RV rv;

  switch(session_data->encrypt_mechanism)
    {
      /* {{{ CKM_RSA_PKCS */
    case CKM_RSA_PKCS:
      {
	CK_BYTE_PTR tmp_buf = NULL_PTR;
	CK_ULONG key_len;
	long processed; /* number of bytes processed by the crypto routine */

	rv = CKR_OK;
	key_len = RSA_size((RSA CK_PTR)session_data->encrypt_state);

	/* terminate operation */
	if(pulEncryptedDataLen == NULL_PTR) 
	  {
	    rv = CKR_OK; goto rsa_pkcs1_err;
	  }

	/* check if this is only a call for the length of the output buffer */
	if(pEncryptedData == NULL_PTR)
	  {
	    *pulEncryptedDataLen = key_len;
	    rv = CKR_OK; break;
	  }
	
	/* check that the supplied buffer is large enough */
	if(*pulEncryptedDataLen < key_len)
	  { 
	    *pulEncryptedDataLen = key_len;
	    rv = CKR_BUFFER_TOO_SMALL; break;
	  }

	/* check for length of input */
	if(ulDataLen > key_len-CK_I_PKCS1_MIN_PADDING) 
	  { rv = CKR_DATA_LEN_RANGE; goto rsa_pkcs1_err; }
	
	tmp_buf = CI_ByteStream_new(key_len);
	if(tmp_buf == NULL_PTR) { rv = CKR_HOST_MEMORY; goto rsa_pkcs1_err; }

	processed = RSA_public_encrypt(ulDataLen,pData,
					       tmp_buf,
					       session_data->encrypt_state,
					       RSA_PKCS1_PADDING);
	if(processed == -1)
	  { rv = CKR_GENERAL_ERROR; goto rsa_pkcs1_err; }
	*pulEncryptedDataLen = processed;

	memcpy(pEncryptedData,tmp_buf,key_len);

    rsa_pkcs1_err:
	if(tmp_buf) { TC_free(tmp_buf); tmp_buf = NULL_PTR; }
	if(session_data->encrypt_state != NULL_PTR)
	  { 
	    RSA_free(session_data->encrypt_state); 
	    session_data->encrypt_state = NULL_PTR;
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

	rv = CKR_OK;
	key_len = RSA_size((RSA CK_PTR)session_data->encrypt_state);

	/* terminate operation */
	if(pulEncryptedDataLen == NULL_PTR) 
	  {
	    rv = CKR_OK; goto rsa_x509_err;
	  }

	/* check if this is only a call for the length of the output buffer */
	if(pEncryptedData == NULL_PTR)
	  {
	    *pulEncryptedDataLen = key_len;
	    rv = CKR_OK; break;
	  }
	/* check that the supplied buffer is large enough */
	if(*pulEncryptedDataLen < key_len)
	  { 
	    *pulEncryptedDataLen = key_len;
	    rv = CKR_BUFFER_TOO_SMALL; break;
	  }
	
	/* check for length of input */
	if(ulDataLen > key_len)
	  { rv = CKR_DATA_LEN_RANGE; goto rsa_x509_err; }
	
	tmp_buf = CI_ByteStream_new(key_len);
	if(tmp_buf == NULL_PTR) { rv = CKR_HOST_MEMORY; goto rsa_x509_err; }

	/* Pads the input data at the beginning with null characters */
	memset(tmp_buf, 0, (key_len - ulDataLen));
	memcpy(&tmp_buf[key_len - ulDataLen], pData, ulDataLen);
	
	processed = RSA_public_encrypt(ulDataLen,pData,tmp_buf,
					       session_data->encrypt_state,RSA_NO_PADDING);
	if(processed == -1)
	  { rv = CKR_GENERAL_ERROR; goto rsa_x509_err; }
	*pulEncryptedDataLen = processed;
	
	memcpy(pEncryptedData,tmp_buf,key_len);

    rsa_x509_err:
	if(tmp_buf) { TC_free(tmp_buf); tmp_buf = NULL_PTR; }
	if(session_data->encrypt_state != NULL_PTR)
	  { 
	    RSA_free(session_data->encrypt_state); 
	    session_data->encrypt_state = NULL_PTR;
	  }
	break;
      }
      /* }}} */
      /* {{{ CKM_RC4 */
    case CKM_RC4:
      {
	/* terminate operation */
	if(pulEncryptedDataLen == NULL_PTR) 
	  {
	    rv = CKR_OK; goto rc4_err;
	  }

	/* is this just a test for the length of the recieving buffer? */
	if(pEncryptedData == NULL_PTR)
	  {
	    *pulEncryptedDataLen = ulDataLen;
	    rv = CKR_OK; break;
	  }
	
	/* is the supplied buffer long enough? */
	if(*pulEncryptedDataLen < ulDataLen)
	  {
	    *pulEncryptedDataLen = ulDataLen;
	    rv = CKR_BUFFER_TOO_SMALL; break;
	  }

	/* OK all set. lets compute */
	RC4(session_data->encrypt_state,ulDataLen,pData,pEncryptedData);
	
	*pulEncryptedDataLen=ulDataLen;
	rv = CKR_OK;

    rc4_err:
	if(session_data->encrypt_state!= NULL_PTR)
	  {
	    CI_RC4Key_delete(session_data->encrypt_state);
	    session_data->encrypt_state = NULL_PTR;
	  }

      }
      break;
      /* }}} */
      /* {{{ CKM_RC2_ECB */
    case CKM_RC2_ECB:
      {
	CK_ULONG count;

	/* terminate operation */
	if(pulEncryptedDataLen == NULL_PTR) 
	  {
	    rv = CKR_OK; goto rc2_ecb_err;
	  }

	/* RC2 always takes multiples of 8 bytes */
	if(ulDataLen%8 != 0)
	  { rv = CKR_DATA_LEN_RANGE; goto rc2_ecb_err; }

	/* is this just a test for the length of the recieving buffer? */
	if(pEncryptedData == NULL_PTR)
	  {
	    *pulEncryptedDataLen = ulDataLen;
	    rv = CKR_OK; break;
	  }
	
	/* is the supplied buffer long enough? */
	if(*pulEncryptedDataLen < ulDataLen)
	  {
	    *pulEncryptedDataLen = ulDataLen;
	    rv = CKR_BUFFER_TOO_SMALL; break;
	  }

	/* OK all set. lets compute */
	/* in blocks of 8 bytes. */
	for(count=0; count<ulDataLen ; count+=8)
	  {
	    RC2_ecb_encrypt(&(pData[count]),&(pEncryptedData[count]), 
			    session_data->encrypt_state,
			    RC2_ENCRYPT);	    
	  }
	
	*pulEncryptedDataLen=ulDataLen;
	rv = CKR_OK;

    rc2_ecb_err:
	if(session_data->encrypt_state!= NULL_PTR)
	  TC_free(session_data->encrypt_state);
	session_data->encrypt_state = NULL_PTR;

      }
      break;
      /* }}} */
      /* {{{ CKM_RC2_CBC */
    case CKM_RC2_CBC:
      {
	/* terminate operation */
	if(pulEncryptedDataLen == NULL_PTR) 
	  {
	    rv = CKR_OK; goto rc2_cbc_err;
	  }
	/* RC2 always takes multiples of 8 bytes */
	if(ulDataLen%8 != 0)
	  { rv = CKR_DATA_LEN_RANGE; goto rc2_cbc_err; }

	/* is this just a test for the length of the recieving buffer? */
	if(pEncryptedData == NULL_PTR)
	  {
	    *pulEncryptedDataLen = ulDataLen;
	    rv = CKR_OK; break;
	  }
	
	/* is the supplied buffer long enough? */
	if(*pulEncryptedDataLen < ulDataLen)
	  {
	    *pulEncryptedDataLen = ulDataLen;
	    rv = CKR_BUFFER_TOO_SMALL; break;
	  }

	/* OK all set. lets compute */
	    RC2_cbc_encrypt(pData,pEncryptedData,
			    ulDataLen,
			    ((CK_I_CEAY_RC2_INFO_PTR)session_data->encrypt_state)->key,
			    ((CK_I_CEAY_RC2_INFO_PTR)session_data->encrypt_state)->ivec,
			    RC2_ENCRYPT);	    
	
	*pulEncryptedDataLen=ulDataLen;
	rv = CKR_OK;

    rc2_cbc_err:
	CI_RC2_INFO_delete(session_data->encrypt_state);
	session_data->encrypt_state = NULL_PTR;

      }
      break;
      /* }}} */
      /* {{{ CKM_DES_ECB */
    case CKM_DES_ECB:
      {
	CK_ULONG count;

	/* terminate operation */
	if(pulEncryptedDataLen == NULL_PTR) 
	  {
	    rv = CKR_OK; goto des_ecb_err;
	  }
	/* DES always takes multiples of 8 bytes */
	if(ulDataLen%8 != 0)
	  {
	    rv = CKR_DATA_LEN_RANGE; goto des_ecb_err;
	  }

	/* is this just a test for the length of the recieving buffer? */
	if(pEncryptedData == NULL_PTR)
	  {
	    *pulEncryptedDataLen = ulDataLen;
	    rv = CKR_OK; break;
	  }
	
	/* is the supplied buffer long enough? */
	if(*pulEncryptedDataLen < ulDataLen)
	  {
	    *pulEncryptedDataLen = ulDataLen;
	    rv = CKR_BUFFER_TOO_SMALL; break;
	  }

	/* OK all set. lets compute */
	/* in blocks of 8 bytes. */
	for(count=0; count<ulDataLen ; count+=8)
	  {
	    des_ecb_encrypt((des_cblock*)(&(pData[count])),
			    (des_cblock*)(&(pEncryptedData[count])),
			    ((CK_I_CEAY_DES_INFO_PTR)session_data->encrypt_state)->sched,
			    DES_ENCRYPT);
	  }
	*pulEncryptedDataLen=ulDataLen;

	rv = CKR_OK;

      des_ecb_err:
	if(session_data->encrypt_state!= NULL_PTR)
	  CI_DES_INFO_delete((CK_I_CEAY_DES_INFO_PTR)session_data->encrypt_state);
	session_data->encrypt_state = NULL_PTR;

      }
      break;
      /* }}} */
      /* {{{ CKM_DES_CBC */
    case CKM_DES_CBC:
      {
	/* terminate operation */
	if(pulEncryptedDataLen == NULL_PTR) 
	  {
	    rv = CKR_OK; goto des_cbc_err;
	  }
	/* is the length of the supplied data a multiple of 8 to create des-blocks? */
	if(ulDataLen%8 != 0)
	  {
	    rv = CKR_DATA_LEN_RANGE; goto des_cbc_err;
	  }

	/* is this just a test for the length of the recieving buffer? */
	if(pEncryptedData == NULL_PTR)
	  {
	    *pulEncryptedDataLen = ulDataLen;
	    rv = CKR_OK; break;
	  }

	/* is the supplied buffer long enough? */
	if(*pulEncryptedDataLen < ulDataLen)
	  {
	    *pulEncryptedDataLen = ulDataLen;
	    rv = CKR_BUFFER_TOO_SMALL; break;
	  }

	/* OK all set. lets compute */
	des_ncbc_encrypt(pData, 
			 pEncryptedData, 
			 ulDataLen, 
			 ((CK_I_CEAY_DES_INFO_PTR)session_data->encrypt_state)->sched, 
			 &(((CK_I_CEAY_DES_INFO_PTR)session_data->encrypt_state)->ivec), 
			 DES_ENCRYPT);

	*pulEncryptedDataLen=ulDataLen;
	rv = CKR_OK;

      des_cbc_err:
	if(session_data->encrypt_state!= NULL_PTR)
	  TC_free(session_data->encrypt_state);
	session_data->encrypt_state = NULL_PTR;
	
      }
      break;
      /* }}} */
      /* {{{ CKM_DES_CBC_PAD */
    case CKM_DES_CBC_PAD:
      {
	CK_BYTE_PTR pPadded = NULL_PTR;
	CK_ULONG ulPaddedLen, ulPaddingLen;
	CK_BYTE PadValue;

	/* terminate operation */
	if(pulEncryptedDataLen == NULL_PTR) 
	  {
	    rv = CKR_OK; goto des_cbc_pad_err;
	  }

	ulPaddingLen = 8 - (ulDataLen%8);
	PadValue = (CK_BYTE)ulPaddingLen;
	ulPaddedLen = ulDataLen + ulPaddingLen;

	/* is this just a test for the length of the recieving buffer? */
	if(pEncryptedData == NULL_PTR)
	  {
	    *pulEncryptedDataLen = ulPaddedLen;
	    rv = CKR_OK; break;
	  }

	/* is the supplied buffer long enough? */
	if(*pulEncryptedDataLen < ulPaddedLen)
	  {
	    *pulEncryptedDataLen = ulPaddedLen;
	    rv = CKR_BUFFER_TOO_SMALL; break;
	  }


	pPadded = CI_ByteStream_new(ulPaddedLen);
	if(pPadded == NULL_PTR) { rv = CKR_HOST_MEMORY; goto des_cbc_pad_err; }
	memcpy(pPadded, pData, ulDataLen);
	memset(pPadded+ulDataLen, PadValue, ulPaddingLen);

	/* OK all set. lets compute */
	des_ncbc_encrypt(pPadded, 
			 pEncryptedData, 
			 ulPaddedLen, 
			 ((CK_I_CEAY_DES_INFO_PTR)session_data->encrypt_state)->sched, 
			 &(((CK_I_CEAY_DES_INFO_PTR)session_data->encrypt_state)->ivec), 
			 DES_ENCRYPT);

	*pulEncryptedDataLen=ulPaddedLen;

	rv = CKR_OK;
	
      des_cbc_pad_err:
	if(pPadded) { TC_free(pPadded); pPadded = NULL_PTR; }
	if(session_data->encrypt_state!= NULL_PTR)
	  TC_free(session_data->encrypt_state);
	session_data->encrypt_state = NULL_PTR;

      }
      break;
      /* }}} */
      /* {{{ CKM_DES3_ECB */
    case CKM_DES3_ECB:
      {
	CK_ULONG count;

	/* terminate operation */
	if(pulEncryptedDataLen == NULL_PTR) 
	  {
	    rv = CKR_OK; goto des3_ecb_err;
	  }
	/* DES always takes multiples of 8 bytes */
	if(ulDataLen%8 != 0)
	  {
	    rv = CKR_DATA_LEN_RANGE; goto des3_ecb_err;
	  }

	/* is this just a test for the length of the recieving buffer? */
	if(pEncryptedData == NULL_PTR)
	  {
	    *pulEncryptedDataLen = ulDataLen;
	    rv = CKR_OK; break;
	  }
	
	/* is the supplied buffer long enough? */
	if(*pulEncryptedDataLen < ulDataLen)
	  {
	    *pulEncryptedDataLen = ulDataLen;
	    rv = CKR_BUFFER_TOO_SMALL; break;
	  }

	/* OK all set. lets compute */
	/* in blocks of 8 bytes. */
	for(count=0; count<ulDataLen ; count+=8)
	  {
	    des_ecb3_encrypt((des_cblock*)(&(pData[count])),
			     (des_cblock*)(&(pEncryptedData[count])),
			     ((CK_I_CEAY_DES3_INFO_PTR)session_data->encrypt_state)->sched[0],
			     ((CK_I_CEAY_DES3_INFO_PTR)session_data->encrypt_state)->sched[1],
			     ((CK_I_CEAY_DES3_INFO_PTR)session_data->encrypt_state)->sched[2],
			     DES_ENCRYPT);	    
	  }
	
	*pulEncryptedDataLen=ulDataLen;
	rv = CKR_OK;

      des3_ecb_err:
	if(session_data->encrypt_state!= NULL_PTR)
	  CI_DES3_INFO_delete(session_data->encrypt_state);
	session_data->encrypt_state = NULL_PTR;

      }
      break;
      /* }}} */
      /* {{{ CKM_DES3_CBC */
    case CKM_DES3_CBC:
      {
	/* terminate operation */
	if(pulEncryptedDataLen == NULL_PTR) 
	  {
	    rv = CKR_OK; goto des3_cbc_err;
	  }
	/* is the length of the supplied data a multiple of 8 to create des-blocks? */
	if(ulDataLen%8 != 0)
	  {
	    rv = CKR_DATA_LEN_RANGE; goto des3_cbc_err;
	  }

	/* is this just a test for the length of the recieving buffer? */
	if(pEncryptedData == NULL_PTR)
	  {
	    *pulEncryptedDataLen = ulDataLen;
	    rv = CKR_OK; break;
	  }

	/* is the supplied buffer long enough? */
	if(*pulEncryptedDataLen < ulDataLen)
	  {
	    *pulEncryptedDataLen = ulDataLen;
	    rv = CKR_BUFFER_TOO_SMALL; break;
	  }

	/* OK all set. lets compute */
	des_ede3_cbc_encrypt(pData, 
			     pEncryptedData, 
			     ulDataLen, 
			     ((CK_I_CEAY_DES3_INFO_PTR)session_data->encrypt_state)->sched[0], 
			     ((CK_I_CEAY_DES3_INFO_PTR)session_data->encrypt_state)->sched[1], 
			     ((CK_I_CEAY_DES3_INFO_PTR)session_data->encrypt_state)->sched[2], 
			     ((CK_I_CEAY_DES3_INFO_PTR)session_data->encrypt_state)->ivec, 
			     DES_ENCRYPT);

	*pulEncryptedDataLen=ulDataLen;

	rv = CKR_OK;
	
      des3_cbc_err:
	if(session_data->encrypt_state != NULL_PTR)
	  CI_DES3_INFO_delete(session_data->encrypt_state);
	session_data->encrypt_state = NULL_PTR;

      }
      break;
      /* }}} */
      /* {{{ CKM_IDEA_ECB */
    case CKM_IDEA_ECB:
      {
	CK_ULONG count;

	/* terminate operation */
	if(pulEncryptedDataLen == NULL_PTR) 
	  {
	    rv = CKR_OK; goto idea_ecb_err;
	  }
	/* DES always takes multiples of 8 bytes */
	if(ulDataLen%8 != 0)
	  {
	    rv = CKR_DATA_LEN_RANGE; goto idea_ecb_err;
	  }

	/* is this just a test for the length of the recieving buffer? */
	if(pEncryptedData == NULL_PTR)
	  {
	    *pulEncryptedDataLen = ulDataLen;
	    rv = CKR_OK; break;
	  }
	
	/* is the supplied buffer long enough? */
	if(*pulEncryptedDataLen < ulDataLen)
	  {
	    *pulEncryptedDataLen = ulDataLen;
	    rv = CKR_BUFFER_TOO_SMALL; break;
	  }

	/* damit wir ne hoffnung haben */
	assert(sizeof(CK_BYTE) == sizeof(unsigned char));

	/* OK all set. lets compute */
	/* in blocks of 8 bytes. */
	for(count=0; count<ulDataLen ; count+=8)
	  {
	    idea_ecb_encrypt(&(pData[count]),
			     &(pEncryptedData[count]),
			     &(((CK_I_CEAY_IDEA_INFO_PTR)session_data->encrypt_state)->sched));	    
	  }
	
	*pulEncryptedDataLen=ulDataLen;
	rv = CKR_OK;

      idea_ecb_err:
	if(session_data->encrypt_state!= NULL_PTR)
	  TC_free(session_data->encrypt_state);
	session_data->encrypt_state = NULL_PTR;

      }
      break;
      /* }}} */
      /* {{{ CKM_IDEA_CBC */
    case CKM_IDEA_CBC:
      {
	/* terminate operation */
	if(pulEncryptedDataLen == NULL_PTR) 
	  {
	    rv = CKR_OK; goto idea_cbc_err;
	  }
	/* is the length of the supplied data a multiple of 8 to create des-blocks? */
	if(ulDataLen%8 != 0)
	  {
	    rv = CKR_DATA_LEN_RANGE; goto idea_cbc_err;
	  }

	/* is this just a test for the length of the recieving buffer? */
	if(pEncryptedData == NULL_PTR)
	  {
	    *pulEncryptedDataLen = ulDataLen;
	    rv = CKR_OK; break;
	  }

	/* is the supplied buffer long enough? */
	if(*pulEncryptedDataLen < ulDataLen)
	  {
	    *pulEncryptedDataLen = ulDataLen;
	    rv = CKR_BUFFER_TOO_SMALL; break;
	  }

	/* OK all set. lets compute */
	idea_cbc_encrypt((unsigned char*)pData, 
			 (unsigned char*)pEncryptedData, 
			 ulDataLen, 
			 &(((CK_I_CEAY_IDEA_INFO_PTR)session_data->encrypt_state)->sched), 
			 ((CK_I_CEAY_IDEA_INFO_PTR)session_data->encrypt_state)->ivec, 
			 IDEA_ENCRYPT);

	*pulEncryptedDataLen=ulDataLen;

	rv = CKR_OK;

	TC_free(((CK_I_CEAY_IDEA_INFO_PTR)session_data->encrypt_state)->ivec);
    idea_cbc_err:
	if(session_data->encrypt_state!= NULL_PTR)
	  TC_free(session_data->encrypt_state);
	session_data->encrypt_state = NULL_PTR;


      }
      break;
      /* }}} */
    default:
      rv = CKR_MECHANISM_INVALID;
    }

  return rv;
}
/* }}} */
/* {{{ CI_Ceay_EncryptUpdate */
CK_DEFINE_FUNCTION(CK_RV, CI_Ceay_EncryptUpdate)(
  CK_I_SESSION_DATA_PTR  session_data,
  CK_BYTE_PTR       pPart,              /* the plaintext data */
  CK_ULONG          ulPartLen,          /* plaintext data len */
  CK_BYTE_PTR       pEncryptedPart,     /* gets ciphertext */
  CK_ULONG_PTR      pulEncryptedPartLen /* gets c-text size */
)
{
  CK_RV rv = CKR_OK;
  CK_BYTE_PTR tmp_str = NULL_PTR;
  
  CI_VarLogEntry("CI_Ceay_EncryptUpdate", "encryption (%s) input: %s", rv, 2,
		 CI_MechanismStr(session_data->encrypt_mechanism),
		 tmp_str = CI_PrintableByteStream(pPart,ulPartLen));
  
  TC_free(tmp_str);
  
  switch(session_data->encrypt_mechanism)
    {
      /* {{{ CKM_RC4 */
    case CKM_RC4:
      {
	/* is this just a test for the length of the recieving buffer? */
	if(pEncryptedPart == NULL_PTR)
	  {
	    *pulEncryptedPartLen = ulPartLen;
	    return CKR_OK;
	  }
	
	/* is the supplied buffer long enough? */
	if(*pulEncryptedPartLen < ulPartLen)
	  {
	    *pulEncryptedPartLen = ulPartLen;
	    return CKR_BUFFER_TOO_SMALL;
	  }

	/* OK all set. lets compute */
	RC4(session_data->encrypt_state,ulPartLen,pPart,pEncryptedPart);
	
	*pulEncryptedPartLen=ulPartLen;

	rv = CKR_OK;
      }
      break;
      /* }}} */
      /* {{{ CKM_RC2_ECB */
    case  CKM_RC2_ECB:
      {
	CK_ULONG count;

	/* RC2 always takes multiples of 8 bytes */
	if(ulPartLen%8 != 0)
	  return CKR_DATA_LEN_RANGE;

	/* is this just a test for the length of the recieving buffer? */
	if(pEncryptedPart == NULL_PTR)
	  {
	    *pulEncryptedPartLen = ulPartLen;
	    return CKR_OK;
	  }
	
	/* is the supplied buffer long enough? */
	if(*pulEncryptedPartLen < ulPartLen)
	  {
	    *pulEncryptedPartLen = ulPartLen;
	    return CKR_BUFFER_TOO_SMALL;
	  }

	/* OK all set. lets compute */
	/* in blocks of 8 bytes. */
	for(count=0; count<ulPartLen ; count+=8)
	  {
	    RC2_ecb_encrypt(&(pPart[count]),&(pEncryptedPart[count]),
			    session_data->encrypt_state,
			    RC2_ENCRYPT);	    
	  }
	
	*pulEncryptedPartLen=ulPartLen;

	rv = CKR_OK;
      }
      break;
      /* }}} */
      /* {{{ CKM_RC2_CBC */
    case  CKM_RC2_CBC:
      {
	/* RC2 always takes multiples of 8 bytes */
	if(ulPartLen%8 != 0)
	  return CKR_DATA_LEN_RANGE;

	/* is this just a test for the length of the recieving buffer? */
	if(pEncryptedPart == NULL_PTR)
	  {
	    *pulEncryptedPartLen = ulPartLen;
	    return CKR_OK;
	  }
	
	/* is the supplied buffer long enough? */
	if(*pulEncryptedPartLen < ulPartLen)
	  {
	    *pulEncryptedPartLen = ulPartLen;
	    return CKR_BUFFER_TOO_SMALL;
	  }
	
	/* OK all set. lets compute */
	RC2_cbc_encrypt(pPart,pEncryptedPart,
			ulPartLen,
			((CK_I_CEAY_RC2_INFO_PTR)session_data->encrypt_state)->key,
			((CK_I_CEAY_RC2_INFO_PTR)session_data->encrypt_state)->ivec,
			RC2_ENCRYPT);	    
	
	*pulEncryptedPartLen=ulPartLen;

	rv = CKR_OK;
      }
      break;
      /* }}} */
      /* {{{ CKM_DES_ECB */
    case  CKM_DES_ECB:
      {
	CK_ULONG count;

	/* DES always takes multiples of 8 bytes */
	if(ulPartLen%8 != 0)
	  return CKR_DATA_LEN_RANGE;

	/* is this just a test for the length of the recieving buffer? */
	if(pEncryptedPart == NULL_PTR)
	  {
	    *pulEncryptedPartLen = ulPartLen;
	    return CKR_OK;
	  }
	
	/* is the supplied buffer long enough? */
	if(*pulEncryptedPartLen < ulPartLen)
	{
	  *pulEncryptedPartLen = ulPartLen;
	  return CKR_BUFFER_TOO_SMALL;
	}

	/* OK all set. lets compute */
	/* in blocks of 8 bytes. */
	for(count=0; count<ulPartLen ; count+=8)
	  {
	    des_ecb_encrypt((des_cblock *)(&(pPart[count])),
			    (des_cblock *)(&(pEncryptedPart[count])),
			    ((CK_I_CEAY_DES_INFO_PTR)session_data->encrypt_state)->sched,
			    DES_ENCRYPT);
	  }

	*pulEncryptedPartLen=ulPartLen;

	rv = CKR_OK;
      }
      break;
      /* }}} */
      /* {{{ CKM_DES_CBC */
    case CKM_DES_CBC:
      {
	/* is the length of the supplied data a multiple of 8 to create des-blocks? */
	if(ulPartLen%8 != 0)
	  return CKR_DATA_LEN_RANGE;

	/* is this just a test for the length of the recieving buffer? */
	if(pEncryptedPart == NULL_PTR)
	  {
	    *pulEncryptedPartLen = ulPartLen;
	    return CKR_OK;
	  }

	/* is the supplied buffer long enough? */
	if(*pulEncryptedPartLen < ulPartLen)
	{
	  *pulEncryptedPartLen = ulPartLen;
	  return CKR_BUFFER_TOO_SMALL;
	}


	/* OK all set. lets compute */
	des_ncbc_encrypt(pPart, 
			 pEncryptedPart, 
			 ulPartLen, 
			 ((CK_I_CEAY_DES_INFO_PTR)session_data->encrypt_state)->sched, 
			 &(((CK_I_CEAY_DES_INFO_PTR)session_data->encrypt_state)->ivec), 
			 DES_ENCRYPT);
	
	*pulEncryptedPartLen=ulPartLen;

	rv = CKR_OK;
	
      }
      break;
      /* }}} */
      /* {{{ CKM_DES_CBC_PAD */
    case CKM_DES_CBC_PAD:
      {
	CK_BYTE_PTR ptmpbuf = NULL_PTR;
	CK_ULONG buflen, leftlen, prevlen;

	buflen = ulPartLen + ((CK_I_CEAY_DES_INFO_PTR)session_data->encrypt_state)->pad;
	leftlen = buflen%8;
	buflen -= leftlen;
	prevlen = ((CK_I_CEAY_DES_INFO_PTR)session_data->encrypt_state)->pad;

	/* is this just a test for the length of the recieving buffer? */
	if(pEncryptedPart == NULL_PTR)
	  {
	    *pulEncryptedPartLen = buflen;
//	    ((CK_I_CEAY_DES_INFO_PTR)session_data->encrypt_state)->pad = leftlen;
	    return CKR_OK;
	  }

	/* is the supplied buffer long enough? */
	if(*pulEncryptedPartLen < buflen)
	  {
	    *pulEncryptedPartLen = buflen;
	    return CKR_BUFFER_TOO_SMALL;
	  }

	if (((CK_I_CEAY_DES_INFO_PTR)session_data->encrypt_state)->round == 0)
	  {
	    ((CK_I_CEAY_DES_INFO_PTR)session_data->encrypt_state)->pad = 0;
	    buflen = ulPartLen + ((CK_I_CEAY_DES_INFO_PTR)session_data->encrypt_state)->pad;
	    leftlen = buflen%8;
	    buflen -= leftlen;
	    prevlen = ((CK_I_CEAY_DES_INFO_PTR)session_data->encrypt_state)->pad;
	  }

	((CK_I_CEAY_DES_INFO_PTR)session_data->encrypt_state)->round++ ;  
	((CK_I_CEAY_DES_INFO_PTR)session_data->encrypt_state)->pad = leftlen;

	ptmpbuf = CI_ByteStream_new(buflen);
	if(ptmpbuf == NULL_PTR) return CKR_HOST_MEMORY; 
	memcpy(ptmpbuf, ((CK_I_CEAY_DES_INFO_PTR)session_data->encrypt_state)->lastblock, prevlen);
	memcpy(ptmpbuf+prevlen, pPart, buflen-prevlen);
	memcpy(((CK_I_CEAY_DES_INFO_PTR)session_data->encrypt_state)->lastblock,
	       pPart+buflen-prevlen,
	       leftlen);
	
	*pulEncryptedPartLen=buflen;
	  
	des_ncbc_encrypt(ptmpbuf,
			 pEncryptedPart,
			 *pulEncryptedPartLen, 
			 ((CK_I_CEAY_DES_INFO_PTR)session_data->encrypt_state)->sched, 
			 &(((CK_I_CEAY_DES_INFO_PTR)session_data->encrypt_state)->ivec), 
			 DES_ENCRYPT);

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
	if(ulPartLen%8 != 0)
	  return CKR_DATA_LEN_RANGE;

	/* is this just a test for the length of the recieving buffer? */
	if(pEncryptedPart == NULL_PTR)
	  {
	    *pulEncryptedPartLen = ulPartLen;
	    return CKR_OK;
	  }
	
	/* is the supplied buffer long enough? */
	if(*pulEncryptedPartLen < ulPartLen)
	{
	  *pulEncryptedPartLen = ulPartLen;
	  return CKR_BUFFER_TOO_SMALL;
	}

	/* OK all set. lets compute */
	/* in blocks of 8 bytes. */
	for(count=0; count<ulPartLen ; count+=8)
	  {
	    des_ecb3_encrypt((des_cblock*)(&(pPart[count])),
			     (des_cblock*)(&(pEncryptedPart[count])),
			     ((CK_I_CEAY_DES3_INFO_PTR)session_data->encrypt_state)->sched[0],
			     ((CK_I_CEAY_DES3_INFO_PTR)session_data->encrypt_state)->sched[1],
			     ((CK_I_CEAY_DES3_INFO_PTR)session_data->encrypt_state)->sched[2],
			     DES_ENCRYPT);	    
	  }
	
	*pulEncryptedPartLen=ulPartLen;

	rv = CKR_OK;
      }
      break;
      /* }}} */
      /* {{{ CKM_DES3_CBC */
    case CKM_DES3_CBC:
      {
	/* is the length of the supplied data a multiple of 8 to create des-blocks? */
	if(ulPartLen%8 != 0)
	  return CKR_DATA_LEN_RANGE;

	/* is this just a test for the length of the recieving buffer? */
	if(pEncryptedPart == NULL_PTR)
	  {
	    *pulEncryptedPartLen = ulPartLen;
	    return CKR_OK;
	  }

	/* is the supplied buffer long enough? */
	if(*pulEncryptedPartLen < ulPartLen)
	{
	  *pulEncryptedPartLen = ulPartLen;
	  return CKR_BUFFER_TOO_SMALL;
	}


	/* OK all set. lets compute */
	des_ede3_cbc_encrypt(pPart, 
			     pEncryptedPart, 
			     ulPartLen, 
			     ((CK_I_CEAY_DES3_INFO_PTR)session_data->encrypt_state)->sched[0], 
			     ((CK_I_CEAY_DES3_INFO_PTR)session_data->encrypt_state)->sched[1], 
			     ((CK_I_CEAY_DES3_INFO_PTR)session_data->encrypt_state)->sched[2], 
			     ((CK_I_CEAY_DES3_INFO_PTR)session_data->encrypt_state)->ivec, 
			     DES_ENCRYPT);

	*pulEncryptedPartLen=ulPartLen;

	rv = CKR_OK;
	
      }
      break;
      /* }}} */
      /* {{{ CKM_IDEA_ECB */
    case CKM_IDEA_ECB:
      {
	CK_ULONG count;

	/* DES always takes multiples of 8 bytes */
	if(ulPartLen%8 != 0)
	  return CKR_DATA_LEN_RANGE;

	/* is this just a test for the length of the recieving buffer? */
	if(pEncryptedPart == NULL_PTR)
	  {
	    *pulEncryptedPartLen = ulPartLen;
	    return CKR_OK;
	  }
	
	/* is the supplied buffer long enough? */
	if(*pulEncryptedPartLen < ulPartLen)
	  {
	    *pulEncryptedPartLen = ulPartLen;
	    return CKR_BUFFER_TOO_SMALL;
	  }
	/* OK all set. lets compute */
	/* in blocks of 8 bytes. */
	for(count=0; count<ulPartLen ; count+=8)
	  {
	    idea_ecb_encrypt((unsigned char*)&(pPart[count]),
			     (unsigned char*)&(pEncryptedPart[count]),
			     &(((CK_I_CEAY_IDEA_INFO_PTR)session_data->encrypt_state)->sched));	    
	  }
	
	*pulEncryptedPartLen=ulPartLen;

	rv = CKR_OK;
      }
      break;
      /* }}} */
      /* {{{ CKM_IDEA_CBC */
    case CKM_IDEA_CBC:
      {
	/* is the length of the supplied data a multiple of 8 to create des-blocks? */
	if(ulPartLen%8 != 0)
	  return CKR_DATA_LEN_RANGE;

	/* is this just a test for the length of the recieving buffer? */
	if(pEncryptedPart == NULL_PTR)
	  {
	    *pulEncryptedPartLen = ulPartLen;
	    return CKR_OK;
	  }

	/* is the supplied buffer long enough? */
	if(*pulEncryptedPartLen < ulPartLen)
	  {
	    *pulEncryptedPartLen = ulPartLen;
	    return CKR_BUFFER_TOO_SMALL;
	  }

	/* OK all set. lets compute */
	idea_cbc_encrypt((unsigned char*)pPart, 
			 (unsigned char*)pEncryptedPart, 
			 ulPartLen, 
			 &((CK_I_CEAY_IDEA_INFO_PTR)session_data->encrypt_state)->sched, 
			 ((CK_I_CEAY_IDEA_INFO_PTR)session_data->encrypt_state)->ivec, 
			 IDEA_ENCRYPT);

	*pulEncryptedPartLen=ulPartLen;

	rv = CKR_OK;

      }
      break;
      /* }}} */

    default:
      rv = CKR_MECHANISM_INVALID;
    }

  CI_VarLogEntry("CI_Ceay_EncryptUpdate", "encryption (%s) result: %s", rv, 2,
		 CI_MechanismStr(session_data->encrypt_mechanism),
		 tmp_str = CI_PrintableByteStream(pEncryptedPart,*pulEncryptedPartLen));

  TC_free(tmp_str);

  return rv;
}
/* }}} */
/* {{{ CI_Ceay_EncryptFinal */
CK_DEFINE_FUNCTION(CK_RV, CI_Ceay_EncryptFinal)(
  CK_I_SESSION_DATA_PTR  session_data,
  CK_BYTE_PTR       pLastEncryptedPart,      /* last c-text */
  CK_ULONG_PTR      pulLastEncryptedPartLen  /* gets last size */
)
{
  CK_RV rv;

  switch(session_data->encrypt_mechanism)
    {
      /* {{{ CKM_RC2_CBC */
    case CKM_RC2_CBC:
      {
	/* terminate operation */
	if(pulLastEncryptedPartLen == NULL_PTR) 
	  {
	    rv = CKR_OK; goto rc2_cbc_err;
	  }
	/* is this just a test for the length of the recieving buffer? */
	if(pLastEncryptedPart == NULL_PTR)
	{
	  *pulLastEncryptedPartLen = 0;
	  rv = CKR_OK; break;
	}
      *pulLastEncryptedPartLen=0;
      
rc2_cbc_err:
      if(session_data->encrypt_state != NULL_PTR)
	{
	  CI_RC2_INFO_delete(session_data->encrypt_state);
	  session_data->encrypt_state = NULL_PTR;
	}
      
      rv = CKR_OK;
      }
      break;
      /* }}} */
      /* {{{ CKM_DES_ECB, CKM_RC2_ECB, CKM_RC4, CKM_IDEA_ECB,  CKM_DES_CBC */
    case CKM_RC2_ECB:
    case CKM_DES_ECB:
    case CKM_RC4:
    case CKM_IDEA_ECB:
    case CKM_DES_CBC:
      {
	/* terminate operation */
	if(pulLastEncryptedPartLen == NULL_PTR) 
	  {
	    rv = CKR_OK; goto des_err;
	  }
	/* is this just a test for the length of the recieving buffer? */
	if(pLastEncryptedPart == NULL_PTR)
	{
	  *pulLastEncryptedPartLen = 0;
	  rv = CKR_OK; break;
	}
	*pulLastEncryptedPartLen=0;

des_err:
	if(session_data->encrypt_state != NULL_PTR)
	  TC_free(session_data->encrypt_state);

	session_data->encrypt_state = NULL_PTR;
	rv = CKR_OK;
      }
      break;
      /* }}} */
      /* {{{ CKM_DES_CBC_PAD */
    case CKM_DES_CBC_PAD:
      {
	CK_BYTE padlen, lastlen;

	/* terminate operation */
	if(pulLastEncryptedPartLen == NULL_PTR) 
	  {
	    rv = CKR_OK; goto des_cbc_pad_err;
	  }
	/* is this just a test for the length of the recieving buffer? */
	if(pLastEncryptedPart == NULL_PTR)
	{
	  *pulLastEncryptedPartLen = 8;
	  rv = CKR_OK; break;
	}
	
	if(*pulLastEncryptedPartLen < 8) 
	{
	  *pulLastEncryptedPartLen=8;
	  rv = CKR_BUFFER_TOO_SMALL; break;
	}
	
	lastlen = ((CK_I_CEAY_DES_INFO_PTR)session_data->encrypt_state)->pad;
	padlen = 8 - lastlen;
	memset(((CK_I_CEAY_DES_INFO_PTR)session_data->encrypt_state)->lastblock+lastlen,
	       padlen, padlen);

	*pulLastEncryptedPartLen=8;

	des_ncbc_encrypt(((CK_I_CEAY_DES_INFO_PTR)session_data->encrypt_state)->lastblock, 
			 pLastEncryptedPart, 
			 *pulLastEncryptedPartLen, 
			 ((CK_I_CEAY_DES_INFO_PTR)session_data->encrypt_state)->sched, 
			 &(((CK_I_CEAY_DES_INFO_PTR)session_data->encrypt_state)->ivec), 
			 DES_ENCRYPT);

    des_cbc_pad_err:
	if(session_data->encrypt_state != NULL_PTR)
	  TC_free(session_data->encrypt_state);
	session_data->encrypt_state = NULL_PTR;
	
	rv = CKR_OK;
      }
      break;
      /* }}} */
      /* {{{ CKM_DES3_ECB */
    case CKM_DES3_ECB:
      {
	/* terminate operation */
	if(pulLastEncryptedPartLen == NULL_PTR) 
	  {
	    rv = CKR_OK; goto des3_ecb_err;
	  }
	/* is this just a test for the length of the recieving buffer? */
	if(pLastEncryptedPart == NULL_PTR)
	{
	  *pulLastEncryptedPartLen = 0;
	  rv = CKR_OK; break;
	}
	*pulLastEncryptedPartLen=0;

    des3_ecb_err:
	if(session_data->encrypt_state!= NULL_PTR)
	  CI_DES3_INFO_delete(session_data->encrypt_state);
	session_data->encrypt_state = NULL_PTR;

	rv = CKR_OK;
      }
      break;
      /* }}} */
      /* {{{ CKM_DES3_CBC */
    case CKM_DES3_CBC:
      {
	/* terminate operation */
	if(pulLastEncryptedPartLen == NULL_PTR) 
	  {
	    rv = CKR_OK; goto des3_cbc_err;
	  }
	/* is this just a test for the length of the recieving buffer? */
	if(pLastEncryptedPart == NULL_PTR)
	{
	  *pulLastEncryptedPartLen = 0;
	  rv = CKR_OK; break;
	}
	*pulLastEncryptedPartLen=0;

des3_cbc_err:
	if(session_data->encrypt_state != NULL_PTR)
	  CI_DES3_INFO_delete(session_data->encrypt_state);
	session_data->encrypt_state = NULL_PTR;

	rv = CKR_OK;
      }
      break;
      /* }}} */
      /* {{{ CKM_IDEA_CBC */
    case CKM_IDEA_CBC:
      {
	/* terminate operation */
	if(pulLastEncryptedPartLen == NULL_PTR) 
	  {
	    rv = CKR_OK; goto idea_cbc_err;
	  }
	/* is this just a test for the length of the recieving buffer? */
	if(pLastEncryptedPart == NULL_PTR)
	{
	  *pulLastEncryptedPartLen = 0;
	  rv = CKR_OK; break;
	}
	*pulLastEncryptedPartLen=0;
	
idea_cbc_err:
	if(session_data->encrypt_state != NULL_PTR)
	  {
	    if( (((CK_I_CEAY_IDEA_INFO_PTR)session_data->encrypt_state)->ivec) != NULL_PTR)
	      TC_free(((CK_I_CEAY_IDEA_INFO_PTR)session_data->encrypt_state)->ivec);
	    TC_free(session_data->encrypt_state);
	  }
	session_data->encrypt_state = NULL_PTR;

	rv = CKR_OK;

      }
      break;
      /* }}} */
    default:
      rv = CKR_MECHANISM_INVALID;
    }

  return rv;
}
/* }}} */


/*
 * Local variables:
 * folded-file: t
 * end:
 */
