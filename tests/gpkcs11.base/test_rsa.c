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
 * HISTORY:     Revision 1.1  2000/03/15 19:37:08  lbe
 * HISTORY:     adding missing files
 * HISTORY:
 * HISTORY:     Revision 1.1  2000/01/31 18:09:07  lbe
 * HISTORY:     lockdown prior to win_gdbm change
 * HISTORY:
 */
/*
 * 
 */ 

static char RCSID[]="$Id$";
const char* Version_C_SetPin_c(){return RCSID;}

#include "cryptoki.h"
#include <stdio.h>
#include <stdlib.h>

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

/* Template of default object (that are not global defaults) */
CK_CHAR CK_I_rsa_public_label[] = "An RSA public key object";

/* empty key with the proper defaults and correct number of entries 
 * for a rsa key object 
 */

#define CK_I_rsa_public_key_count 14

static CK_ULONG modulusBits = 1024;
static CK_BYTE publicExponent[] = { 3 };

static CK_ATTRIBUTE CK_I_rsa_public_key_template[CK_I_rsa_public_key_count] ={
  {CKA_CLASS, &CK_I_public_key_class, sizeof(CK_I_public_key_class)},
  {CKA_TOKEN, &CK_Tcsc_true, sizeof(CK_Tcsc_true)},
  {CKA_MODIFIABLE, &CK_Tcsc_false, sizeof(CK_Tcsc_false)},
  {CKA_LABEL, CK_I_rsa_public_label, sizeof(CK_I_rsa_public_label)},
  {CKA_KEY_TYPE, &CK_I_rsa_keyType, sizeof(CK_I_rsa_keyType)},
  {CKA_DERIVE, &CK_Tcsc_false, sizeof(CK_Tcsc_false)},
  {CKA_LOCAL, &CK_Tcsc_true, sizeof(CK_Tcsc_true)},
  {CKA_ENCRYPT, &CK_Tcsc_true, sizeof(CK_Tcsc_true)},
  {CKA_VERIFY, &CK_Tcsc_true, sizeof(CK_Tcsc_true)},
  {CKA_VERIFY_RECOVER, &CK_Tcsc_true, sizeof(CK_Tcsc_true)},
  {CKA_WRAP, &CK_Tcsc_true, sizeof(CK_Tcsc_true)},
  {CKA_EXTRACTABLE, &CK_Tcsc_true, sizeof(CK_Tcsc_true)},
  {CKA_MODULUS_BITS, &modulusBits, sizeof(modulusBits)},
  {CKA_PUBLIC_EXPONENT, publicExponent, sizeof(publicExponent)},  
};

/* }}} */

/* {{{ RSA private Template */

/* Template of default object (that are not global defaults) */
CK_CHAR CK_I_rsa_private_label[] = "An RSA private key object";

/* empty key with the proper defaults and correct number of entries 
 * for a rsa key object 
 */

#define CK_I_rsa_private_key_count 16

static CK_ATTRIBUTE CK_I_rsa_private_key_template[CK_I_rsa_private_key_count] ={
  {CKA_CLASS, &CK_I_private_key_class, sizeof(CK_I_private_key_class)},
  {CKA_TOKEN, &CK_Tcsc_true, sizeof(CK_Tcsc_true)},
  {CKA_PRIVATE, &CK_Tcsc_true, sizeof(CK_Tcsc_true)},
  {CKA_MODIFIABLE, &CK_Tcsc_false, sizeof(CK_Tcsc_false)},
  {CKA_LABEL, CK_I_rsa_private_label, sizeof(CK_I_rsa_private_label)},
  {CKA_KEY_TYPE, &CK_I_rsa_keyType, sizeof(CK_I_rsa_keyType)},
  {CKA_DERIVE, &CK_Tcsc_false, sizeof(CK_Tcsc_false)},
  {CKA_LOCAL, &CK_Tcsc_true, sizeof(CK_Tcsc_true)},
  {CKA_SENSITIVE, &CK_Tcsc_true, sizeof(CK_Tcsc_true)},
  {CKA_DECRYPT, &CK_Tcsc_false, sizeof(CK_Tcsc_false)},
  {CKA_SIGN, &CK_Tcsc_false, sizeof(CK_Tcsc_true)},
  {CKA_SIGN_RECOVER, &CK_Tcsc_false, sizeof(CK_Tcsc_false)},
  {CKA_UNWRAP, &CK_Tcsc_true, sizeof(CK_Tcsc_true)},
  {CKA_EXTRACTABLE, &CK_Tcsc_false, sizeof(CK_Tcsc_false)},
  {CKA_ALWAYS_SENSITIVE, &CK_Tcsc_true, sizeof(CK_Tcsc_true)},
  {CKA_NEVER_EXTRACTABLE, &CK_Tcsc_true, sizeof(CK_Tcsc_true)},
};
/* }}} */

/* }}} */


int main(int argc, char** argv)
{
  extern char *optarg;
  extern int optind;
  CK_RV rv = CKR_OK;
  CK_FUNCTION_LIST_PTR pFunctionList;
  
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
    
    for(i=0;i<ulSlotCount;i++)
      {
	CK_SESSION_HANDLE sess;
	CK_ULONG mech_count;
	CK_MECHANISM_TYPE_PTR mech_list;
	CK_ULONG j;
	CK_BBOOL do_token;
	CK_OBJECT_HANDLE public_key_handle, private_key_handle;
	CK_MECHANISM mechanism = { CKM_RSA_PKCS_KEY_PAIR_GEN ,NULL_PTR, 0};
	printf("starting with token on slot %ld\n", pSlotList[i]);

	/* check that the token supports RSA key gen */
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
	
	/* look for the key gen */
	for(j=0,do_token=FALSE;j<mech_count;j++)
	  if(mech_list[j] == CKM_RSA_PKCS_KEY_PAIR_GEN) do_token = TRUE;

	if(!do_token)
	  {
	    printf("FAIL: no RSA key gen on slot %lu\n",pSlotList[i]);
	    continue;
	  }


	/* open session */
	rv = (pFunctionList->C_OpenSession)(pSlotList[i],
					    CKF_SERIAL_SESSION|CKF_RW_SESSION,
					    NULL,NULL,&sess);
	if(rv != CKR_OK)
	  {
	    printf("FAIL: C_OpenSession failed on slot %ld: %ld\n",pSlotList[i],rv);
	    continue;
	  }
	

	/* generate key */
	rv = (pFunctionList->C_GenerateKeyPair)(sess,
						&mechanism,
						CK_I_rsa_public_key_template,
						CK_I_rsa_public_key_count,
						CK_I_rsa_private_key_template,
						CK_I_rsa_private_key_count,
						&public_key_handle,
						&private_key_handle);
	if(rv != CKR_OK)
	  {
	    printf("FAIL: C_GenerateKeyPair failed in session %ld\n: %ld\n",
		   sess,rv);
	    continue;
	  }

	/* close session */
	rv = (pFunctionList->C_CloseSession)(sess);
	if(rv != CKR_OK)
	  {
	    printf("FAIL: C_CloseSession in session %ld: %ld\n",sess,rv);
	    continue;
	  }

	printf("slot %ld done\n", pSlotList[i]);


      }
    free(pSlotList);
  }
  
  (pFunctionList->C_Finalize)(NULL);

  return 0;
}

 
/*
 * Local variables:
 * folded-file: t
 * end:
 */


