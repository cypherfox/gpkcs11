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
 * NAME:        sessions.c
 * SYNOPSIS:    -
 * DESCRIPTION: -
 * FILES:       -
 * SEE/ALSO:    -
 * AUTHOR:      lbe
 * BUGS: *      -
 * HISTORY:     $Log$
 * HISTORY:     Revision 1.3  2000/09/19 09:15:05  lbe
 * HISTORY:     write flag for pin change onto SC, support Auth Pin path
 * HISTORY:
 * HISTORY:     Revision 1.2  2000/06/23 17:32:27  lbe
 * HISTORY:     release to secude, lockdown for 0_6_2
 * HISTORY:
 * HISTORY:     Revision 1.1  2000/03/15 19:37:08  lbe
 * HISTORY:     adding missing files
 * HISTORY:
 * HISTORY:     Revision 1.1  2000/01/31 18:09:07  lbe
 * HISTORY:     lockdown prior to win_gdbm change
 * HISTORY:
 */
/*
 * check that the private key signing functions work correctly.
 * - find a token that promises to handle RSA_PKCS
 * - find a RSA key on that token that can sign (private encrypt) and then 
 *   try the sign
 */ 

static char RCSID[]="$Id$";
const char* Version_C_SetPin_c(){return RCSID;}

#include "cryptoki.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

CK_RV pkcs11_find_object(CK_SESSION_HANDLE sess, 
			 CK_ATTRIBUTE_PTR template, CK_ULONG count,  
			 CK_OBJECT_HANDLE_PTR CK_PTR ppHandleArr,
			 CK_ULONG_PTR pulHandleCount);

CK_RV set_attribute(CK_ATTRIBUTE_PTR template, CK_ULONG template_len,
		    CK_ATTRIBUTE_TYPE type, 
		    CK_VOID_PTR pValue, CK_ULONG ulValueLen);

CK_RV P11_loadPubRSAKey(CK_FUNCTION_LIST_PTR pFunctionListA, CK_SESSION_HANDLE sessionA,
			CK_FUNCTION_LIST_PTR pFunctionListB, CK_SESSION_HANDLE sessionB,
			CK_OBJECT_HANDLE object, CK_OBJECT_HANDLE CK_PTR pNewObject);

CK_RV verify_vector(CK_SESSION_HANDLE sess, CK_OBJECT_HANDLE pub_key,
		    CK_CHAR_PTR ciphertext, CK_ULONG cipher_len,
		    CK_CHAR_PTR clear_text, CK_ULONG clear_len);

static void free_template(CK_ATTRIBUTE_PTR template, CK_ULONG lenght);

static CK_BBOOL user_loged_in(CK_SESSION_HANDLE sign_sess);

CK_RV find_rsa_verify(CK_FUNCTION_LIST_PTR pFunctionList, CK_SLOT_ID CK_PTR verify_slot);

CK_RV sign_and_verify(CK_SESSION_HANDLE sign_sess, CK_SESSION_HANDLE verify_sess,
		      CK_CHAR_PTR clear_text,
		      CK_OBJECT_HANDLE priv_handle, CK_OBJECT_HANDLE pub_handle,
		      char* user_pin);

/* {{{ Key Templates */

static CK_OBJECT_CLASS CK_I_public_key_class = CKO_PUBLIC_KEY;
static CK_OBJECT_CLASS CK_I_private_key_class = CKO_PRIVATE_KEY;

CK_CHAR CK_Tcsc_empty_str[] = "";
CK_BYTE CK_Tcsc_empty_bytes[] = "";
CK_BBOOL CK_Tcsc_true = TRUE;
CK_BBOOL CK_Tcsc_false = FALSE;
CK_ULONG CK_Tcsc_ulEmpty = 0;

static CK_KEY_TYPE CK_I_rsa_keyType = CKK_RSA;

/* {{{ RSA public Template */

/* empty key with the proper defaults and correct number of entries 
 * for a rsa key object 
 */

#define CK_I_rsa_public_key_count 4

static CK_ATTRIBUTE CK_I_rsa_public_key_template[CK_I_rsa_public_key_count] ={
  {CKA_CLASS, &CK_I_public_key_class, sizeof(CK_I_public_key_class)},
  {CKA_TOKEN, &CK_Tcsc_true, sizeof(CK_Tcsc_true)},
  {CKA_KEY_TYPE, &CK_I_rsa_keyType, sizeof(CK_I_rsa_keyType)},
  {CKA_ENCRYPT, &CK_Tcsc_true, sizeof(CK_Tcsc_true)}
};

/* }}} */

/* {{{ RSA private Template */

/* Template of default object (that are not global defaults) */

/* empty key with the proper defaults and correct number of entries 
 * for a rsa key object 
 */

#define CK_I_rsa_private_key_count 3

/* the label will be set when looking later on */
static CK_ATTRIBUTE CK_I_rsa_private_key_template[CK_I_rsa_private_key_count] ={
  {CKA_CLASS, &CK_I_private_key_class, sizeof(CK_I_private_key_class)},
  {CKA_ID, NULL, 0},
  {CKA_KEY_TYPE, &CK_I_rsa_keyType, sizeof(CK_I_rsa_keyType)},
};
/* }}} */

/* }}} */

/* {{{ int main(int argc, char** argv) */

CK_FUNCTION_LIST_PTR pFunctionList;

int main(int argc, char** argv, char** envp)
{
  extern char *optarg;
  extern int optind;
  CK_RV rv = CKR_OK;

  if(argc != 2) 
    {
      printf("Wrong number of arguments\nusage: %s <user_pin>\n",argv[0]);
      exit(1);
    }
  
  rv = C_GetFunctionList(&pFunctionList);
  if(rv != CKR_OK)
    {
      printf("FAIL: could not get function pointer list: %ld\n",rv);
      exit(1);
    }
  
  rv = (pFunctionList->C_Initialize)(NULL_PTR);
  if(rv != CKR_OK)
    {
      printf("FAIL: could not initialize: %ld\n",rv);
      exit(1);
    }
  
  /* get the slot list with token. this is not a test of C_OpenSession, 
   * thus only open sessions on token and not on slots 
   */	
  {
    CK_ULONG ulSlotCount;
    CK_SLOT_ID_PTR pSlotList;
    int i;

    rv = (pFunctionList->C_GetSlotList)(TRUE,NULL_PTR,&ulSlotCount);
    if(rv != CKR_OK)
      {
	printf("FAIL: could not get slot count: %ld\n",rv);
	exit(1);
      }
    
    pSlotList = malloc(sizeof(CK_SLOT_ID)*ulSlotCount);
    if(pSlotList == NULL)
      {
	printf("could not allocate slot list: %d\n",CKR_HOST_MEMORY);
	exit(1);
      }
    
    rv = (pFunctionList->C_GetSlotList)(TRUE,pSlotList,&ulSlotCount);
    if(rv != CKR_OK)
      {
	printf("FAIL: could not get slot List: %ld\n",rv);
	exit(1);
      }
    
    /* for each slot with a token */
    for(i=0;i<ulSlotCount;i++)
      {
	CK_SESSION_HANDLE sign_sess, verify_sess;
	CK_ULONG mech_count;
	CK_MECHANISM_TYPE_PTR mech_list;
	CK_ULONG j,k, pub_handle_count,priv_handle_count;
	CK_BBOOL do_token;
	CK_OBJECT_HANDLE_PTR pub_handle_arr;
	CK_OBJECT_HANDLE_PTR priv_handle_arr;
	CK_SLOT_ID verify_slot;

	printf("starting with token on slot %ld\n", pSlotList[i]);

	/* check that the token supports RSA sign */
	/* first only get the length of the list */
	(pFunctionList->C_GetMechanismList)(pSlotList[i],
					    NULL_PTR, &mech_count);

	mech_list = malloc(mech_count * sizeof(CK_MECHANISM_TYPE));
	if(mech_list == NULL_PTR)
	  {
	    printf("FAIL: mem alloc\n");
	    exit(1);
	  }

	(pFunctionList->C_GetMechanismList)(pSlotList[i],mech_list, 
					    &mech_count);
	
	/* look for the RSA operations */
	for(j=0,do_token=FALSE;j<mech_count;j++)
	  if(mech_list[j] == CKM_RSA_PKCS) do_token = TRUE;

	if(!do_token)
	  {
	    printf("FAIL: no RSA PKCS#11 on slot %lu\n",pSlotList[i]);
	    continue;
	  }
	/* clean up */
	free(mech_list);


	/* open session */
	rv = (pFunctionList->C_OpenSession)(pSlotList[i],
					    CKF_SERIAL_SESSION,
					    NULL,NULL,&sign_sess);
	if(rv != CKR_OK)
	  {
	    printf("FAIL: C_OpenSession failed on slot %ld: %ld\n",pSlotList[i],rv);
	    continue;
	  }
	
	/* find the public keys */
	rv = pkcs11_find_object(sign_sess, 
				CK_I_rsa_public_key_template, CK_I_rsa_public_key_count ,
				&pub_handle_arr, &pub_handle_count);
	if(rv != CKR_OK)
	  {
	    printf("FAIL: unable to find public key: 0x%lx\n",rv);
	    continue;
	  }

	/* find a token that supports RSA_PKCS for verify */
	rv = find_rsa_verify(pFunctionList,&verify_slot);
	if(rv != CKR_OK)
	  {
	    printf("FAIL: unable to find token for verify: 0x%lx\n",rv);
	    continue;
	  }

	if(verify_slot == pSlotList[i])
	  verify_sess = sign_sess;
	else
	  {
	    rv = (pFunctionList->C_OpenSession)(verify_slot,
						CKF_SERIAL_SESSION|CKF_RW_SESSION,
						NULL,NULL,&verify_sess);
	    if(rv != CKR_OK)
	      {
		printf("FAIL: C_OpenSession failed on slot %ld for verify: %ld\n",
		       pSlotList[i],rv);
		continue;
	      }

	  }

	for(k=0; k<pub_handle_count; k++)
	  {
	    CK_ATTRIBUTE theTemplate = {CKA_ID, NULL, 0}; 
	    CK_CHAR_PTR clear_text1 ="foobar1";
	    CK_CHAR_PTR clear_text2 ="This is a text that is too long even for a 1k key: The quick brown fox jumps over the lazy dog. 1234567890";
	    CK_OBJECT_HANDLE new_pub_handle;

	    /* set the ID of the public key in the private key */
	    rv = (pFunctionList->C_GetAttributeValue)(sign_sess, pub_handle_arr[k], &theTemplate, 1);
	    if(rv != CKR_OK)
	      {
		printf("FAIL: unable read id length for public key %li: 0x%lx\n",pub_handle_arr[k],rv);
		continue;
	      }

	    theTemplate.pValue = malloc(theTemplate.ulValueLen);
	    if(theTemplate.pValue == NULL_PTR)
	      {
		printf("FAIL: unable allocate memory for private key id\n");
		continue;
	      }
	    rv = (pFunctionList->C_GetAttributeValue)(sign_sess, pub_handle_arr[k], &theTemplate, 1);
	    if(rv != CKR_OK)
	      {
		printf("FAIL: unable to read id for public key %li: 0x%lx\n",
		       pub_handle_arr[k],rv);
		continue;
	      }

	    rv = set_attribute(CK_I_rsa_private_key_template, 
			       CK_I_rsa_private_key_count,
			       CKA_ID, 
			       theTemplate.pValue, theTemplate.ulValueLen);
	    if(rv != CKR_OK)
	      {
		printf("FAIL: unable to set id in templatee for private key: 0x%lx\n",
		       rv);
		continue;
	      }

	    /* find the matching private key */
	    rv = pkcs11_find_object(sign_sess, CK_I_rsa_private_key_template, 
				    CK_I_rsa_private_key_count,
				    &priv_handle_arr, &priv_handle_count);
	    if(rv != CKR_OK)
	      {
		printf("FAIL: unable to find public key: 0x%lx\n",rv);
		continue;
	      }
	    
	    /* is there exactly one (1) private key to this public key? */
	    if(priv_handle_count != 1)
	      {
		printf("FAIL: wrong number of private keys: %li\n",priv_handle_count);
		continue;
	      }

	    /* copy the public key if needed */
	    if(sign_sess != verify_sess)
	      {
		rv = P11_loadPubRSAKey(pFunctionList, sign_sess,
				       pFunctionList, verify_sess,
				       pub_handle_arr[k], &new_pub_handle);
	      }
	    else
	      new_pub_handle =pub_handle_arr[k];
	    	    
	    /* sign test vector */
	    rv = sign_and_verify(sign_sess,verify_sess,clear_text1,
				 priv_handle_arr[0],new_pub_handle,
				 argv[1]);
	    if(rv != CKR_OK) 
	      continue;

	    printf("sign and verify succeded for short text session %ld: 0x%08lx\n",
		   sign_sess,rv);

	    rv = sign_and_verify(sign_sess,verify_sess,clear_text2,
				 priv_handle_arr[0],new_pub_handle,
				 argv[1]);
	    if(rv == CKR_OK) 
	      {
		printf("FAIL: over long clear text did not fail");
		continue;
	      }

	    printf("verify succeded in session %ld: 0x%08lx\n",
		   sign_sess,rv);


	} /* for each public key */

	/* close session */
	rv = (pFunctionList->C_CloseSession)(sign_sess);
	if(rv != CKR_OK)
	  {
	    printf("FAIL: C_CloseSession in session %ld: %ld\n",sign_sess,rv);
	    continue;
	  }

	printf("slot %ld done\n", pSlotList[i]);


      }
    free(pSlotList);
  }
  
  (pFunctionList->C_Finalize)(NULL);

#ifdef CK_Win32
  {
    char buf[3]={1};
    printf("weiter mit return");
    _cgets(buf);
  }
#endif

  return 0;
}
/* }}} */

/* {{{ pkcs11_find_object */
/** find list of objects on an token.
 * this function tries for a certain number of objects at a time.
 * the number of objects searched in one go is an ideal parameter
 * to tune for a good equilibrium between memory usage and speed.
 * 
 * If the functions returns any thing other then CKR_OK, neither 
 * the ppHandleArr nor the pulHandleCount are changed and should 
 * not be considered valid. The memory for the handle array is 
 * allocated by the function and must be returned by the caller.
 *
 * @param sess           the session handle of a open session.
 * @param template       the array of attributes that the returned 
 *                       objects should match
 * @param count          the number of attributes in the template
 * @param ppHandleArr    the address of the pointer which points to 
 *                       the array of object handles.
 * @param pulHandleCount The addess of the number of object handles
 *                       in the returned array.
 * @return the cryptoki error code returned by any of the calls 
 *         made to the PKCS#11 module.
 */

#define HANDLE_FIELD_SIZE 10
CK_RV pkcs11_find_object(CK_SESSION_HANDLE sess, 
			 CK_ATTRIBUTE_PTR template, CK_ULONG count,  
			 CK_OBJECT_HANDLE_PTR CK_PTR ppHandleArr,
			 CK_ULONG_PTR pulHandleCount)
{
  CK_RV rv = CKR_OK;
  CK_OBJECT_HANDLE handle_field[HANDLE_FIELD_SIZE];
  CK_ULONG find_count;
  CK_ULONG handle_count,handle_count2;
  CK_OBJECT_HANDLE_PTR ret_field;

  /* Step 1: get the number of objects */

  rv = (pFunctionList->C_FindObjectsInit)(sess,
					  template, 
					  count);
  if(rv != CKR_OK)
    return rv;
  
  for(handle_count=0,find_count=HANDLE_FIELD_SIZE;
      find_count==HANDLE_FIELD_SIZE;)
    {
      rv = (pFunctionList->C_FindObjects)(sess,
					  handle_field,
					  HANDLE_FIELD_SIZE,
					  &find_count);
      if(rv != CKR_OK)
	return rv;

      handle_count+=find_count;
    }
  
  rv = (pFunctionList->C_FindObjectsFinal)(sess);
  
  /* Step 2: alloc the return array */
  ret_field = malloc(sizeof(CK_OBJECT_HANDLE)*handle_count);
  if(ret_field == NULL_PTR) 
    return CKR_HOST_MEMORY;
  
  /* Step 3: get the actual objects */
  rv = (pFunctionList->C_FindObjectsInit)(sess,
					  template,count);
  if(rv != CKR_OK)
    {
      free(ret_field);
      return rv;
    }
  
  rv = (pFunctionList->C_FindObjects)(sess,
				      ret_field,
				      handle_count,
				      &handle_count2);
  if(rv != CKR_OK)
    {
      free(ret_field);
      return rv;
    }


  /*  check that both finds returned the same number of objects */
  if(handle_count != handle_count2)
    {
      free(ret_field);
      return CKR_GENERAL_ERROR;
    }

  
  rv = (pFunctionList->C_FindObjectsFinal)(sess);
  if(rv != CKR_OK)
    {
      free(ret_field);
      return rv;
    }

  /* Step 4: actually copy the values into the parameter and return */
  
  *ppHandleArr = ret_field;
  *pulHandleCount = find_count;

  return rv;
}
/* }}} */

/* {{{ set_attribute */
CK_RV set_attribute(CK_ATTRIBUTE_PTR template, CK_ULONG template_len,
		    CK_ATTRIBUTE_TYPE type, 
		    CK_VOID_PTR pValue, CK_ULONG ulValueLen)
{
  CK_ULONG i;

  for(i=0;(i<template_len) && (template[i].type != type) ; i++);

  if(i>=template_len) return CKR_ATTRIBUTE_TYPE_INVALID;

  template[i].pValue = pValue;
  template[i].ulValueLen = ulValueLen;

  return CKR_OK;
}
/* }}} */

/* {{{ P11_loadPubRSAKey */
/** load a public RSA key from one token into another.
 */
CK_RV P11_loadPubRSAKey(CK_FUNCTION_LIST_PTR pFunctionListA, CK_SESSION_HANDLE sessionA,
			CK_FUNCTION_LIST_PTR pFunctionListB, CK_SESSION_HANDLE sessionB,
			CK_OBJECT_HANDLE object, CK_OBJECT_HANDLE CK_PTR pNewObject)
{
  /* list of attributes that will be copied */
#define attr_list_len 19

  static CK_ATTRIBUTE_TYPE attr_list[attr_list_len] = {
    CKA_CLASS,      CKA_TOKEN,        CKA_PRIVATE,        CKA_LABEL, 
    CKA_MODIFIABLE, CKA_KEY_TYPE,     CKA_ID,             CKA_START_DATE, 
    CKA_END_DATE,   CKA_DERIVE,       CKA_LOCAL,          CKA_SUBJECT, 
    CKA_ENCRYPT,    CKA_VERIFY,       CKA_VERIFY_RECOVER, CKA_WRAP, 
    CKA_MODULUS,    CKA_MODULUS_BITS, CKA_PUBLIC_EXPONENT
  };

  CK_ATTRIBUTE_PTR obj_template;
  CK_ULONG i,j,real_attr_len;
  CK_RV rv = CKR_OK;
  
  /* generate a obj_template for a full RSA public key */
  obj_template= malloc(attr_list_len*sizeof(CK_ATTRIBUTE));
  if(obj_template == NULL_PTR) return CKR_HOST_MEMORY;

  /* get the length for those values that are supported */
  for(i=0;i<attr_list_len;i++)
    {
      obj_template[i].type = attr_list[i];
      obj_template[i].pValue = NULL_PTR;
      obj_template[i].ulValueLen = 0L;      
    }

  printf("calling C_GetAttributeValue for the first time\n");

  rv = (pFunctionListA->C_GetAttributeValue)(sessionA, object, obj_template, attr_list_len);
  switch(rv)
    {
    case CKR_OK:
    case CKR_ATTRIBUTE_TYPE_INVALID:
    case CKR_ATTRIBUTE_SENSITIVE:
      printf("C_GetAttributeValue returned one of the expected rv's\n");
      break;
    default:
      printf("FAIL: P11_loadPubKey: calling C_GetAttributeValue returned 0x%08lx\n",rv);
      goto loadKey_error;
    }

  /* alloc the mem for each attribute and weed out the invalid ones */
  for(i=0,j=0;i<attr_list_len;i++)
    {
      if(obj_template[i].ulValueLen != -1L)
	{
	  obj_template[j].pValue     = malloc(obj_template[i].ulValueLen);
	  obj_template[j].ulValueLen = obj_template[i].ulValueLen;
	  obj_template[j].type       = obj_template[i].type;
	  if(obj_template[j].pValue == NULL_PTR) 
	    {
	      rv = CKR_HOST_MEMORY;
	      goto loadKey_error;
	    }      
	  j++;
	}
    }
  real_attr_len = j;

  printf("calling C_GetAttributeValue for the second time\n");

  /* get the actual values */
  rv = (pFunctionListA->C_GetAttributeValue)(sessionA, object, obj_template, real_attr_len);
  if(rv != CKR_OK)
    goto loadKey_error;

  printf("calling C_CreateObject\n");
  
  rv = (pFunctionListB->C_CreateObject)(sessionB, obj_template, real_attr_len, pNewObject);

 loadKey_error:
  free_template(obj_template,attr_list_len);
  return rv;
}
/* }}} */

/* {{{ free_template */
static void free_template(CK_ATTRIBUTE_PTR obj_template, CK_ULONG length)
{
  CK_ULONG i;
  for(i=0;i<length;i++)
    if(obj_template[i].pValue != NULL_PTR)
      free(obj_template[i].pValue);

  free(obj_template);
}
/* }}} */

/* {{{ verify_vector */
CK_RV verify_vector(CK_SESSION_HANDLE sess, CK_OBJECT_HANDLE pub_key,
		    CK_CHAR_PTR cipher_text, CK_ULONG cipher_len,
		    CK_CHAR_PTR clear_text, CK_ULONG clear_len)
 {
   CK_MECHANISM mechanism = { CKM_RSA_PKCS ,NULL_PTR, 0};
   CK_RV rv = CKR_OK;

   rv = (pFunctionList->C_VerifyInit)(sess,
				      &mechanism,
				      pub_key);
   if(rv != CKR_OK)
     {
       printf("FAIL: C_VerifyInit failed in session %ld: 0x%08lx\n",
	      sess,rv);
       return rv;
     }
   rv = (pFunctionList->C_Verify)(sess,
				  clear_text, clear_len,
				  cipher_text, cipher_len);
   if(rv != CKR_OK)
     {
       printf("FAIL: C_Verify failed in session %ld: 0x%08lx\n",
	      sess,rv);
       return rv;
     }

   return rv;
 }
/* }}} */

/* {{{ find_rsa_verify */
CK_RV find_rsa_verify(CK_FUNCTION_LIST_PTR pFunctionList, CK_SLOT_ID CK_PTR p_slot)
{
  /* get slot list for this token */
  CK_ULONG ulSlotCount;
  CK_SLOT_ID_PTR pSlotList;
  CK_ULONG i;
  CK_MECHANISM_INFO info;
  CK_RV rv = CKR_OK;

  *p_slot = 0;
  
  rv = (pFunctionList->C_GetSlotList)(TRUE,NULL_PTR,&ulSlotCount);
  if(rv != CKR_OK)
    {
      printf("FAIL: could not get slot count: 0x%08lx\n",rv);
      return rv;
    }
  
  pSlotList = malloc(sizeof(CK_SLOT_ID)*ulSlotCount);
  if(pSlotList == NULL)
    {
      rv = CKR_HOST_MEMORY;
      printf("could not allocate slot list: 0x%08lx\n",rv);
      return rv;
    }
  
  rv = (pFunctionList->C_GetSlotList)(TRUE,pSlotList,&ulSlotCount);
  if(rv != CKR_OK)
    {
      printf("FAIL: could not get slot List: 0x%08lx\n",rv);
      return rv;
    }
  
  for(i=0;i<ulSlotCount;i++)
    {
      rv = (pFunctionList->C_GetMechanismInfo)(pSlotList[i],CKM_RSA_PKCS, &info);
      switch(rv)
	{
	case CKR_MECHANISM_INVALID:
	  continue;
	  break;
	case CKR_OK:
	  printf("found a token that does CKM_RSA_PKCS, flags: 0x%lx\n",
		 info.flags);
	  if(info.flags & CKF_VERIFY)
	    {
	      *p_slot = pSlotList[i];
	      return CKR_OK;
	    }
	  break;
	default:
	  printf("FAIL: could not get mechanism info: 0x%08lx\n",rv);
	  return rv;
	}	
    }
  
  return CKR_MECHANISM_INVALID;
}
/* }}} */

/* {{{ CK_BBOOL user_loged_in(CK_SESSION_HANDLE sess); */
CK_BBOOL user_loged_in(CK_SESSION_HANDLE sess)
{
  CK_SESSION_INFO sinfo;
  CK_RV rv = CKR_OK;
  
  rv = (pFunctionList->C_GetSessionInfo)(sess,&sinfo);
  if(rv != CKR_OK)
    { 
      printf("FAIL: could not get session info for session %ld: 0x%08lx\n",
	     sess, rv);
      return rv;
    }
  
  if((sinfo.state == CKS_RO_USER_FUNCTIONS) ||
     (sinfo.state == CKS_RW_USER_FUNCTIONS) )
    return TRUE;
  else
    return FALSE;
}
/* }}} */

CK_RV sign_and_verify(CK_SESSION_HANDLE sign_sess, CK_SESSION_HANDLE verify_sess,
		      CK_CHAR_PTR clear_text,
		      CK_OBJECT_HANDLE priv_handle, CK_OBJECT_HANDLE pub_handle,
		      char* user_pin)
{
  CK_RV rv = CKR_OK;
  CK_ULONG cipher_len;
  CK_CHAR_PTR cipher_text=NULL_PTR;
  CK_MECHANISM mechanism = { CKM_RSA_PKCS ,NULL_PTR, 0};
  
  /* log in before using the private key */
  rv = (pFunctionList->C_Login)(sign_sess,
				CKU_USER,
				user_pin,strlen(user_pin));
  if(rv != CKR_OK)
    {
      printf("FAIL: C_Login failed in session %ld: 0x%08lx\n",
	     sign_sess,rv);
      return rv;
    }
  
  rv = (pFunctionList->C_SignInit)(sign_sess,
				   &mechanism,
				   priv_handle);
  if(rv != CKR_OK)
    {
      printf("FAIL: C_SignInit failed in session %ld: 0x%08lx\n",
	     sign_sess,rv);
      return rv;
    }
  
  rv = (pFunctionList->C_Sign)(sign_sess,
			       clear_text,strlen(clear_text),
			       NULL_PTR, &cipher_len);
  if(rv != CKR_OK)
    {
      printf("FAIL: C_Sign I failed in session %ld: 0x%08lx\n",
	     sign_sess,rv);
      return rv;
    }

  cipher_text = realloc(cipher_text, cipher_len);
  if(cipher_text == NULL_PTR)
    {
      printf("FAIL:failed to allocate memory for cipher_text\n");
      return rv;
    }

  rv = (pFunctionList->C_Sign)(sign_sess,
			       clear_text,strlen(clear_text),
			       cipher_text, &cipher_len);
  if(rv != CKR_OK)
    {
      free(cipher_text);
      printf("FAIL: C_Sign II failed in session %ld: 0x%08lx\n",
	     sign_sess,rv);
      return rv;
    }
  
  /* verify test vector */
  rv = verify_vector(verify_sess, pub_handle,
		     cipher_text, cipher_len,
		     clear_text, strlen(clear_text));
  
  free(cipher_text);
  return rv;
}
/* }}} */
/*
 * Local variables:
 * folded-file: t
 * end:
 */
