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
 * NAME:        t_session_obj_delete2.c
 * SYNOPSIS:    -
 * DESCRIPTION: -
 * FILES:       -
 * SEE/ALSO:    -
 * AUTHOR:      lbe
 * BUGS:        -
 */
/*
 * check that the creation and deletion of session objects works 
 * correctly:
 *
 * - open sessions A,B
 * - create object in A
 * - close session A
 * - try to manipulate/destroy object in B; both must fail as A 
 *   does not exist anymore
 *
 * all this must work in an RO as RW session, since only 
 * session objects are created
 */ 

static char RCSID[]="$Id$";
const char* Version_C_SetPin_c(){return RCSID;}

#include "cryptoki.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void free_template(CK_ATTRIBUTE_PTR template, CK_ULONG lenght);

/* {{{ Key Templates */

CK_CHAR CK_Tcsc_empty_str[] = "";
CK_BYTE CK_Tcsc_empty_bytes[] = "";
CK_BBOOL CK_Tcsc_true = TRUE;
CK_BBOOL CK_Tcsc_false = FALSE;
CK_ULONG CK_Tcsc_ulEmpty = 0;

static CK_OBJECT_CLASS CK_I_data_object_class = CKO_DATA;

/* Data Object Template */

#define CK_I_object_count 3

static CK_ATTRIBUTE CK_I_object_template[CK_I_object_count] ={
  {CKA_CLASS, &CK_I_data_object_class, sizeof(CK_I_data_object_class)},
  {CKA_PRIVATE, &CK_Tcsc_false, sizeof(CK_Tcsc_false)},
  {CKA_TOKEN, &CK_Tcsc_false, sizeof(CK_Tcsc_false)}
};

/* }}} */

/* {{{ int main(int argc, char** argv) */

CK_FUNCTION_LIST_PTR pFunctionList;

int main(int argc, char** argv, char** envp)
{
  extern char *optarg;
  extern int optind;
  CK_RV rv = CKR_OK;
  CK_ULONG ulSlotCount;
  CK_SLOT_ID_PTR pSlotList;
  int i;
  
  rv = C_GetFunctionList(&pFunctionList);
  if(rv != CKR_OK)
    {
      printf("could not get function pointer list: %ld\n",rv);
      exit(1);
    }
  
  rv = (pFunctionList->C_Initialize)(NULL_PTR);
  if(rv != CKR_OK)
    {
      printf("could not initialize: %ld\n",rv);
      exit(1);
    }
  
  /* get the slot list with token. this is not a test of C_OpenSession, 
   * thus only open sessions on token and not on slots 
   */	
  
  rv = (pFunctionList->C_GetSlotList)(TRUE,NULL_PTR,&ulSlotCount);
  if(rv != CKR_OK)
    {
      printf("FAIL: could not get slot count: %ld\n",rv);
      exit(1);
    }
  /* no token is a failure as well */
  if(ulSlotCount == 0)
    {
      printf("FAIL: no token found\n");
      exit(1);
    }
  else
    printf("%ld slots with token found\n",ulSlotCount);
  
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
  
  for(i=0;i<ulSlotCount;i++)
    {
      CK_SESSION_HANDLE sess_A, sess_B;
      CK_OBJECT_HANDLE obj_handle;
      
      printf("starting with token on slot %ld\n", pSlotList[i]);
      
      /* open session A */
	rv = (pFunctionList->C_OpenSession)(pSlotList[i],
					    CKF_SERIAL_SESSION,
					    NULL,NULL,&sess_A);
      if(rv != CKR_OK)
	{
	  printf("FAIL: C_OpenSession for Session A failed on slot %ld: %ld\n",
		 pSlotList[i],rv);
	  continue;
	}
      
      rv = (pFunctionList->C_OpenSession)(pSlotList[i],
					  CKF_SERIAL_SESSION,
					  NULL,NULL,&sess_B);
      if(rv != CKR_OK)
	{
	  printf("FAIL: C_OpenSession for Session B failed on slot %ld: %ld\n",
		 pSlotList[i],rv);
	  continue;
	}
      
      /* open object in A */
      rv = (pFunctionList->C_CreateObject)(sess_A, CK_I_object_template, 
					   CK_I_object_count, &obj_handle);
      switch(rv)
      {
	  case CKR_OK:
	      /* this is just a get away case */
	      break;
	  case CKR_FUNCTION_NOT_SUPPORTED:
	      printf("XFAIL: function C_CreateObject not supported in token on slot %ld\n",
		     pSlotList[i]);
	      continue;
	      break;
	  default:
	      printf("FAIL: C_CreateObject failed on slot %ld: %ld\n",
		     pSlotList[i],
		     rv);
	      continue;
      }

      /* close session A */
      rv = (pFunctionList->C_CloseSession)(sess_A);
      if(rv != CKR_OK)
	{
	  printf("FAIL: C_CloseSession for Session A failed on slot %ld: %ld\n",
		 pSlotList[i],rv);
	  continue;
	}

      /* 
       * destroy object in B. This should fail as session A does not exist
       * anymore. (which is no reported to DejaGNU as no news is good news)
       */
      rv = (pFunctionList->C_DestroyObject)(sess_B,obj_handle);
      switch(rv)
      {
	  case CKR_OK:
	      /* this should not have been possible */
	      printf("FAIL: C_DestroyObject allowed for Session Object of closed session in token in slot %ld\n", pSlotList[i]);
	      continue;
	      break;
	  case CKR_FUNCTION_NOT_SUPPORTED:
	      printf("XFAIL: function C_DestroyObject not supported in token on slot %ld\n",
		     pSlotList[i]);
	      continue;
	      break;
	  case CKR_OBJECT_HANDLE_INVALID:
	      /* all went fine */
	      break;
	  default:
	      printf("FAIL: C_DesrtroyObject failed on slot %ld: %ld\n",
		     pSlotList[i],
		     rv);
	      continue;
      }
	
      /* close session B */
      rv = (pFunctionList->C_CloseSession)(sess_B);
      if(rv != CKR_OK)
	{
	  printf("FAIL: C_CloseSession in session B (%ld): %ld\n",sess_B,rv);
	  continue;
	}
      
      printf("slot %ld done\n", pSlotList[i]);
            
    } /* for each slot */
  free(pSlotList);
  
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

/* {{{ encrypt_vector */
CK_RV encrypt_vector(CK_SESSION_HANDLE sess, CK_OBJECT_HANDLE pub_key,
				CK_CHAR_PTR clear_text, CK_ULONG clear_len,
				CK_CHAR_PTR CK_PTR p_ciphertext, CK_ULONG_PTR p_cipher_len)
 {
   CK_MECHANISM mechanism = { CKM_RSA_PKCS ,NULL_PTR, 0};
   CK_RV rv = CKR_OK;

   rv = (pFunctionList->C_EncryptInit)(sess,
				       &mechanism,
				       pub_key);
   if(rv != CKR_OK)
     {
       printf("FAIL: C_EncryptInit failed in session %ld: 0x%08lx\n",
	      sess,rv);
       return rv;
     }
   rv = (pFunctionList->C_Encrypt)(sess,
				   clear_text,
				   clear_len,
				   NULL_PTR, p_cipher_len);
   if(rv != CKR_OK)
     {
       printf("FAIL: C_Encrypt I failed in session %ld: %ld\n",
	      sess,rv);
       return rv;
     }
   *p_ciphertext = malloc(*p_cipher_len);
   if(*p_ciphertext == NULL_PTR)
     {
       printf("FAIL:failed to allocate memory\n");
       return CKR_HOST_MEMORY;
     }
   
   rv = (pFunctionList->C_Encrypt)(sess,
				   clear_text,
				   clear_len,
				   *p_ciphertext, p_cipher_len);
   if(rv != CKR_OK)
     {
       printf("FAIL: C_Encrypt II failed in session %ld: 0x%08lx\n",
	      sess,rv);
       return rv;
     }

   return rv;
 }
/* }}} */

/* {{{ find_rsa_encrypt */
CK_RV find_rsa_encrypt(CK_FUNCTION_LIST_PTR pFunctionList, CK_SLOT_ID CK_PTR p_slot)
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
      printf("FAIL: could not get slot count: %ld\n",rv);
      return rv;
    }
  
  pSlotList = malloc(sizeof(CK_SLOT_ID)*ulSlotCount);
  if(pSlotList == NULL)
    {
      printf("could not allocate slot list: %d\n",CKR_HOST_MEMORY);
      return rv;
    }
  
  rv = (pFunctionList->C_GetSlotList)(TRUE,pSlotList,&ulSlotCount);
  if(rv != CKR_OK)
    {
      printf("FAIL: could not get slot List: %ld\n",rv);
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
	  if(info.flags & CKF_ENCRYPT)
	    {
	      *p_slot = pSlotList[i];
	      return CKR_OK;
	    }
	  break;
	default:
	  printf("FAIL: could not get mechanism info: %ld\n",rv);
	  return rv;
	}	
    }
  
  return CKR_MECHANISM_INVALID;
}
/* }}} */

/*
 * Local variables:
 * folded-file: t
 * end:
 */


