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
 * State:	$State$ $Locker$
 * NAME:	pkcs11_guile.c
 * SYNOPSIS:	-
 * DESCRIPTION: main cryptsh code, implements the additional scheme functions
 * FILES:	-
 * SEE/ALSO:	-
 * AUTHOR:	lbe
 * BUGS:  	-
 */

static char RCSID[]="$Id$";
const char* Version_pkcs11_guile_c(){return RCSID;}

char *dll_name;

#define DO_FKT( _name , _params )           \
 do                                         \
  {                                         \
  if( (rv = pkcs11_fkt_list->_name  _params ) != CKR_OK)      \
    {                                       \
      printf("pkcs11_guile:" #_name " failed (%li)\n", rv);    \
    } }while(0)

#ifndef WIN32
#include "conf.h"
#else
#include "conf.h.win32"
#endif /* WIN32 */


#ifdef HAVE_SC_OPENSSL
#undef NO_OPENSSL_CODE
#else /* !HAVE_SC_OPNESSL */
#define NO_OPENSSL_CODE 1 
#endif /* !HAVE_SC_OPENSSL */

#include <stdio.h>
#include <guile/gh.h>
#include <dlfcn.h>
#include <ctype.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "cryptoki.h"
#include "pkcs11_guile.h"

#ifndef NO_OPENSSL_CODE
#include <openssl/bn.h>
#include <openssl/pem.h>
#include <openssl/buffer.h>

#include <openssl/evp_pkcs11.h>
#include "request.h"
#endif /* NO_OPENSSL_CODE */



CK_FUNCTION_LIST_PTR pkcs11_fkt_list = NULL_PTR;
void* dll_handle = NULL_PTR;
char *run_script = NULL;

static void main_prog(int argc, char **argv);
void read_pkcs_fkts();

#ifndef NO_OPENSSL_CODE
static int crypto_library_init(void);
#endif

/* may be extended later on */
char* usual_args[] = {"cryptsh"};

/* {{{ int main(int argc, char *argv[]) */
int main(int argc, char *argv[])
{
  int c;
  int errflg = 0;

#ifndef NO_OPENSSL_CODE
  SSLeay_add_all_algorithms();
#endif

  /* parse the parameters */

  while ((c = getopt(argc, argv, "f:l:")) != EOF)
    switch (c) {
    case 'f':
      run_script = optarg;
      printf("executing %s\n", run_script);
      break;
    case 'l':
      dll_name = optarg;
      printf("using library %s\n", dll_name);
      break;
    case '?':
      errflg++;
    }
  if (errflg) goto error;

#if !defined(NO_GCC_KLUDGE) && !defined(NO_OPENSSL_CODE)
  /* this ugly thing is only nessecary to force gcc to link some stuff
   * into this file.
   */
  {
    BIGNUM* a;
    BN_ULONG w=1;
    a=BN_new();
    
    BN_mod_word(a, w);
    BN_div_word(a, w);
    BN_add_word(a, w);
    BN_sub_word(a, w);
    BN_mul_word(a, w);
    
    BN_free(a);
  }
#endif /* !defined(NO_GCC_KLUDGE) && !defined(NO_OPENSSL_CODE) */

  gh_enter(1, usual_args, main_prog);
  exit(0);

error:
    fprintf(stderr, "usage: %s [-f <file>] -l <library>\n", argv[0]);
    exit (2);
}
/* }}} */
/* {{{ static void main_prog(int argc, char *argv[]) */
static void main_prog(int argc, char *argv[])
{
#ifndef BUILD_STATIC
  char *filename = NULL_PTR;
  CK_C_GetFunctionList gfl_handle = NULL_PTR;

  filename = dll_name;
  
  /* load the library */
  if((dll_handle = dlopen(filename, RTLD_LAZY|RTLD_GLOBAL))== NULL_PTR)
    {
      fprintf(stderr, "Opening Dynamic Library '%s' failed: %s\n", filename, dlerror());
      exit(1);
    }

  /* get fkt-pointer table */
  gfl_handle= ( CK_C_GetFunctionList )(dlsym(dll_handle, "C_GetFunctionList"));
  if(gfl_handle == NULL_PTR)
    {
      fprintf(stderr, "could not get pointer for function table: %s\n",dlerror());
      exit(1);
    }
  /* get the function list */
  gfl_handle(&pkcs11_fkt_list);
  fprintf(stderr, "fkt pointer set\n");
  
#else
  C_GetFunctionList(&pkcs11_fkt_list);
  fprintf(stderr, "fkt pointer set from static functions\n");
  
#endif
  /* set the c-functions */
  read_pkcs_fkts();

  /* if this is just to run some script call it here */
  /* TODO: some checks on the existence of the file */
  if(run_script)
  gh_eval_file(run_script);

  fprintf(stderr, "starting TC pkcs11 shell\n");
  gh_repl(argc, argv);

}
/* }}} */
/* {{{ void read_pkcs_fkts() */
typedef struct pg_fkt_info {
  char* symbol;
  SCM (*fn)();
  int n_required_args;
  int n_optional_args;
  int varp;
}pg_fkt_info;

/* Parameters: 1: Name of function
 *             2: num of required params
 *             3: num of optional params
 *             4: TRUE for arbitr. num of add params. (FALSE for none)
 */
static pg_fkt_info func_defs[] = {
  {"simple-test",           ci_simple_test,           0,0, FALSE},
  {"ci-parse-byte-stream",  ci_parse_byte_stream,     1,0, FALSE},
  {"ci-unparse-string",     ci_unparse_string,        1,0, FALSE},
  {"C-Initialize",          ck_initialize,            0,0, FALSE},
  {"C-Finalize",            ck_finalize,            0,0, FALSE},
  {"C-GetInfo",             ck_get_info,              0,0, FALSE},
  {"C-GetSlotList",         ck_get_slot_list,         1,0, FALSE},
  {"C-GetSlotInfo",         ck_get_slot_info,         1,0, FALSE},
  {"C-GetTokenInfo",        ck_get_token_info,        1,0, FALSE},
  {"C-GetMechanismList",    ck_get_mechanism_list,    1,0, FALSE},
  {"C-GetMechanismInfo",    ck_get_mechanism_info,    2,0, FALSE},
  {"C-OpenSession",         ck_open_session,          2,0, FALSE},
  {"C-CloseSession",        ck_close_session,         1,0, FALSE},
  {"C-FindObjectsInit",     ck_find_objects_init,     2,0, FALSE},
  {"C-FindObjects",         ck_find_objects,          1,0, FALSE},
  {"C-FindObjectsFinal",    ck_find_objects_final,    1,0, FALSE},
  {"C-CreateObject",        ck_create_object,         2,0, FALSE},
  {"C-DestroyObject",       ck_destroy_object,        2,0, FALSE},
  {"C-EncryptInit",         ck_encrypt_init,          3,0, FALSE},
  {"C-Encrypt",             ck_encrypt,               2,1, FALSE},
  {"C-EncryptUpdate",       ck_encrypt_update,        2,1, FALSE},
  {"C-EncryptFinal",        ck_encrypt_final,         1,1, FALSE},
  {"C-DecryptInit",         ck_decrypt_init,          3,0, FALSE},
  {"C-Decrypt",             ck_decrypt,               2,1, FALSE},
  {"C-DecryptUpdate",       ck_decrypt_update,        2,1, FALSE},
  {"C-DecryptFinal",        ck_decrypt_final,         1,1, FALSE},
  {"C-DigestInit",          ck_digest_init,           2,0, FALSE},
  {"C-Digest",              ck_digest,                2,1, FALSE},
  {"C-DigestUpdate",        ck_digest_update,         2,0, FALSE},
  {"C-DigestKey",           ck_digest_key,            2,0, FALSE},
  {"C-DigestFinal",         ck_digest_final,          1,1, FALSE},
  {"C-SignInit",            ck_sign_init,             2,0, FALSE},
  {"C-Sign",                ck_sign,                  2,1, FALSE},
  {"C-SignUpdate",          ck_sign_update,           2,0, FALSE},
  {"C-SignFinal",           ck_sign_final,            1,1, FALSE},
  {"C-SignRecoverInit",     ck_sign_recover_init,     2,0, FALSE},
  {"C-SignRecover",         ck_sign_recover,          2,1, FALSE},
  {"C-GenerateKey",         ck_generate_key,          3,0, FALSE},
  {"C-GenerateKeyPair",     ck_generate_key_pair,     4,0, FALSE}, 
  {"C-Login",               ck_login,                 3,0, FALSE},
  {"C-Logout",              ck_logout,                1,0, FALSE},
  {"C-InitPIN",             ck_init_pin,              2,0, FALSE},
  {"C-SetPIN",              ck_set_pin,               3,0, FALSE},
  {"C-CloseAllSessions",    ck_close_all_sessions,    1,0, FALSE},
  {"C-GetSessionInfo",      ck_get_session_info,      1,0, FALSE},
  {"C-CopyObject",          ck_copy_object,           3,0, FALSE},
  {"C-VerifyInit",          ck_verify_init,           3,0, FALSE},
  {"C-Verify",              ck_verify,                3,0, FALSE},
  {"C-VerifyUpdate",        ck_verify_update,         2,0, FALSE},
  {"C-VerifyFinal",         ck_verify_final,          2,0, FALSE},
  {"C-VerifyRecoverInit",   ck_verify_recover_init,   3,0, FALSE},
  {"C-VerifyRecover",       ck_verify_recover,        3,0, FALSE},
  {"C-InitToken",           ck_init_token,            3,0, FALSE},
  {"C-SeedRandom",          ck_seed_random,           2,0, FALSE},
  {"C-GenerateRandom",      ck_generate_random,       2,0, FALSE},
  {"C-GetObjectSize",       ck_get_object_size,       2,0, FALSE},
  {"C-GetAttributeValue",   ck_get_attribute_value,   3,0, FALSE},
  {"C-SetAttributeValue",   ck_set_attribute_value,   3,0, FALSE},
  {"C-GetOperationState",   ck_get_operation_state,   1,1, FALSE},
  {"C-SetOperationState",   ck_set_operation_state,   4,0, FALSE},
  {"C-DigestEncryptUpdate", ck_digest_encrypt_update, 2,1, FALSE},
  {"C-DecryptDigestUpdate", ck_decrypt_digest_update, 2,1, FALSE},
  {"C-SignEncryptUpdate",   ck_sign_encrypt_update,   2,1, FALSE},
  {"C-DecryptVerifyUpdate", ck_decrypt_verify_update, 2,1, FALSE},
  {"C-WrapKey",             ck_wrap_key,              4,1, FALSE},
  {"C-UnwrapKey",           ck_unwrap_key,            5,0, FALSE},
  {"C-DeriveKey",           ck_derive_key,            4,0, FALSE},
  {"C-GetFunctionStatus",   ck_get_function_status,   1,0, FALSE},
  {"C-CancelFunction",      ck_cancel_function,       1,0, FALSE},
  {"C-WaitForSlotEvent",    ck_wait_for_slot_event,   1,0, FALSE},

#ifndef NO_OPENSSL_CODE
  {"create-cert-req",        ch_create_cert_req,      5,0, FALSE},
#endif

  {NULL_PTR,                NULL_PTR,                 0,0, FALSE}
};

/*
  */

void read_pkcs_fkts()
{
  int i;

  for(i=0; func_defs[i].symbol != NULL_PTR; i++)
    gh_new_procedure(func_defs[i].symbol, 
		     func_defs[i].fn, 
		     func_defs[i].n_required_args, 
		     func_defs[i].n_optional_args, 
		     func_defs[i].varp);

  /* plus some scheme init's */
  if(getenv("CRYPTSH_INIT") == NULL)
    gh_eval_file("pkcs11_init.scm");
  else
    gh_eval_file(getenv("CRYPTSH_INIT"));
}
/* }}} */

/*********************************************************************
 *                        pkcs #11 dependent stuff                   *
 *********************************************************************/
/* {{{ CK_ATTRIBUTE_PTR ci_list2template(SCM list, CK_ULONG CK_PTR count) */
/* TODO: this deserves a whole lot of error checking once I have found out 
 * how to raise errors in clean fashion */
CK_ATTRIBUTE_PTR ci_list2template(SCM list, CK_ULONG CK_PTR count)
{
  CK_ATTRIBUTE_PTR pTemplate;
  CK_ULONG i;
  SCM tuple;
  int len;

  /* check that this is a list at all */
  if(!gh_list_p(list))
    {
      *count = 0;
      return NULL_PTR;
    }

  *count= gh_length(list);

  pTemplate = malloc(sizeof(CK_ATTRIBUTE)*(*count));
  if(pTemplate == NULL_PTR)
    {
      *count =0;
      return NULL_PTR;
    }

  for(i=0;i<(*count);i++,list = gh_cdr(list))
    {
      tuple = gh_car(list);
      /* if the tuple is not a list itself, we cannot get the parts */
      if(!gh_list_p(tuple)) continue;
      pTemplate[i].type = gh_scm2ulong(gh_car(tuple));
      pTemplate[i].pValue = gh_scm2newstr(ci_parse_byte_stream(gh_cadr(tuple)),
					    &len);
      pTemplate[i].ulValueLen = len;
    }

  return pTemplate;
}
/* }}} */
/* {{{ void ci_template_delete(CK_ATTRIBUTE_PTR template, CK_ULONG ulCount) */
void ci_template_delete(CK_ATTRIBUTE_PTR template, CK_ULONG ulCount)
{
  CK_ULONG i;
  for (i=0; i<ulCount; i++)
    {
      free(template[i].pValue);
    }

  free(template);

  return;
}
/* }}} */
/* {{{ SCM ci_template2list(CK_ATTRIBUTE_PTR template, CK_ULONG ulCount) */
SCM ci_template2list(CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
  SCM retval;
  CK_ULONG i;

  retval = SCM_EOL;
  for(i=0; i<ulCount; i++)
    retval = gh_cons(gh_list(gh_ulong2scm(pTemplate[i].type),
			     gh_str2scm(pTemplate[i].pValue,pTemplate[i].ulValueLen),
			     SCM_UNDEFINED),
		     retval);
  return retval;
}
/* }}} */
/* {{{ SCM ci_simple_test() */
SCM ci_simple_test()
{
    return gh_cons(gh_ulong2scm(400),
		   SCM_BOOL_F);
}
/* }}} */
/* {{{ SCM ci_parse_byte_stream(SCM byte_string) */
static unsigned char byte_xlate[256] = {
   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 0   */
   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 16  */
   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 32  */
   0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 0, 0, 0, 0, 0, /* 48 numbers */
   0,10,11,12,13,14,15, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 64 capitals */
   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 80  */
   0,10,11,12,13,14,15, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 96 lowers */
   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 112 */
   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 128 */
   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 144 */
   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 160 */
   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 176 */
   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 192 */
   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 208 */
   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 224 */
   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};/* 240 */

SCM ci_parse_byte_stream(SCM byte_string)
{
  CK_ULONG outlen, i;
  unsigned char* new_string;
  SCM retval;
  int inlen;

  if(!gh_string_p(byte_string))
    {
      return gh_str2scm("",0);
    }
  
  new_string = gh_scm2newstr(byte_string,&inlen);

  for(i=0,outlen=0; i<inlen; i+=3,outlen++)
    {
      /* check that all characters are correct */
      if( !isxdigit(new_string[i]) ||
	  !isxdigit(new_string[i+1]) ||
	  (new_string[i+2] != ':'))
	return gh_str2scm("",0);

      new_string[outlen] = (byte_xlate[new_string[i]]*16+
			    byte_xlate[new_string[i+1]]);
    }

  /* TODO: this is under the assumption that the function copies the data */
  retval = gh_str2scm(new_string,outlen);
  free(new_string);

  return retval;
}
/* }}} */
/* {{{ SCM ci_unparse_string(SCM byte_string) */
static unsigned char char_xlate[16] = {
  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

SCM ci_unparse_string(SCM char_string)
{
  CK_ULONG outlen, i;
  unsigned char* in_string, *out_string;
  SCM retval;
  int inlen;

  if(!gh_string_p(char_string))
    {
      return gh_str2scm("",0);
    }
  
  in_string = gh_scm2newstr(char_string,&inlen);
  out_string = malloc(sizeof(CK_BYTE)*inlen*3);
  outlen = inlen*3;

  /* TODO: make this in-place as well ( from the back ) */
  for(i=0,outlen=0; i<inlen; i++,outlen+=3)
    {
      out_string[outlen] = char_xlate[in_string[i]/16];
      out_string[outlen+1] = char_xlate[in_string[i]%16];
      out_string[outlen+2] = ':';
    }

  /* TODO: this is under the assumption that the function copies the data */
  retval = gh_str2scm(out_string,outlen);

  free(in_string);
  free(out_string);
  return retval;
}
/* }}} */
/* {{{ CK_MECHANISM_PTR ci_list2mechanism(SCM mechanism_list) */
CK_MECHANISM_PTR ci_list2mechanism(SCM mechanism_list)
{
  CK_MECHANISM_PTR retval = NULL_PTR;
  int mech_len;

  if(!gh_list_p(mechanism_list))
    return NULL_PTR;

  retval= malloc(sizeof(CK_MECHANISM));
  if(retval == NULL_PTR)
    return NULL_PTR;

  retval->mechanism = gh_scm2ulong(gh_car(mechanism_list));
  retval->pParameter = gh_scm2newstr(gh_cadr(mechanism_list),&mech_len);
  retval->ulParameterLen = mech_len;
  return retval;
}
/* }}} */
/* {{{ void ci_mechanism_delete(CK_MECHANISM_PTR) */ 
void ci_mechanism_delete(CK_MECHANISM_PTR mech)
{
  if(mech != NULL_PTR)
    {
      if(mech->pParameter != NULL_PTR)
	free(mech->pParameter);
      free(mech);
    }
}
/* }}} */

/* {{{ SCM ck_initialize() */
SCM ck_initialize()
{
  CK_RV rv = CKR_OK;

  DO_FKT(C_Initialize, (NULL_PTR));

  return gh_ulong2scm(rv);
}
/* }}} */
/* {{{ SCM ck_finalize() */
SCM ck_finalize()
{
  CK_RV rv = CKR_OK;

  DO_FKT(C_Finalize, (NULL_PTR));

  return gh_ulong2scm(rv);
}
/* }}} */
/* {{{ SCM ck_get_info() */
SCM ck_get_info()
{
  CK_RV rv = CKR_OK;
  CK_INFO pInfo;

  DO_FKT(C_GetInfo, (&pInfo));
  if(rv != CKR_OK)
    return gh_cons(gh_ulong2scm(rv),
		   SCM_BOOL_F);
  
  return gh_cons(gh_ulong2scm(rv),
		 gh_list(gh_cons(gh_int2scm(pInfo.cryptokiVersion.major),
				 gh_int2scm(pInfo.cryptokiVersion.minor)),
			 gh_str2scm(pInfo.manufacturerID,32),
			 gh_ulong2scm(pInfo.flags),
			 gh_str2scm(pInfo.libraryDescription,32),
			 gh_cons(gh_int2scm(pInfo.libraryVersion.major),
				 gh_int2scm(pInfo.libraryVersion.minor)),
			 SCM_UNDEFINED));
}
/* }}} */
/* {{{ SCM ck_get_slot_list(SCM tokenp_bool) */
SCM ck_get_slot_list(SCM tokenp_bool)
{
  CK_RV rv = CKR_OK;
  CK_BBOOL tokenp = gh_scm2bool(tokenp_bool);
  CK_SLOT_ID_PTR pSlotList = NULL_PTR;
  CK_ULONG ulSlots =0;
  SCM retlist;
  unsigned int i;

  /* then do the dry run */
  DO_FKT(C_GetSlotList, (tokenp, NULL_PTR, &ulSlots));
  /*    failure */
  if((rv != CKR_OK)||
     /* no list to build, but no failure */
     (ulSlots == 0))
    return gh_cons(gh_ulong2scm(rv),SCM_EOL); 

  pSlotList = malloc(sizeof(CK_SLOT_ID)*ulSlots);
  if(pSlotList == NULL_PTR)
    return gh_cons(gh_ulong2scm(CKR_HOST_MEMORY),SCM_EOL); 

  DO_FKT(C_GetSlotList, (tokenp, pSlotList, &ulSlots));
  if(rv != CKR_OK)
    return gh_cons(gh_ulong2scm(rv),SCM_EOL); 

  /* turn the array into a list */
  for(retlist = SCM_EOL,i = 1;i<=ulSlots;i++)
    retlist = gh_cons(gh_ulong2scm(pSlotList[ulSlots-i]),retlist);
  
  free(pSlotList);

  return gh_cons(gh_ulong2scm(rv),retlist); 
}
/* }}} */
/* {{{ SCM ck_get_slot_info(SCM slot_int) */
SCM ck_get_slot_info(SCM slot_int)
{
  CK_RV rv = CKR_OK;
  CK_SLOT_INFO slot_info;
  CK_ULONG slotID;

  slotID = gh_scm2ulong(slot_int);

  DO_FKT(C_GetSlotInfo, (slotID, &slot_info));
  if(rv != CKR_OK)
    return gh_cons(gh_ulong2scm(rv),SCM_BOOL_F);

  return gh_cons(gh_ulong2scm(rv),
		 gh_list(gh_str2scm(slot_info.slotDescription,64),
			 gh_str2scm(slot_info.manufacturerID,32),
			 gh_ulong2scm(slot_info.flags),
			 gh_cons(gh_int2scm(slot_info.hardwareVersion.major),
				 gh_int2scm(slot_info.hardwareVersion.minor)),
			 gh_cons(gh_int2scm(slot_info.firmwareVersion.major),
				 gh_int2scm(slot_info.firmwareVersion.minor)),
			 SCM_UNDEFINED));
}
/* }}} */
/* {{{ SCM ck_get_token_info(SCM slot_int) */
SCM ck_get_token_info(SCM slot_int)
{
  CK_RV rv = CKR_OK;
  CK_ULONG slotID;
  CK_TOKEN_INFO token_info;

  slotID = gh_scm2ulong(slot_int);

  DO_FKT(C_GetTokenInfo, (slotID, &token_info));
  if(rv != CKR_OK)
    return gh_cons(gh_ulong2scm(rv),SCM_BOOL_F);

  return gh_cons(gh_ulong2scm(rv),
		 gh_list(gh_str2scm(token_info.label,32),
			 gh_str2scm(token_info.manufacturerID,32),
			 gh_str2scm(token_info.model,16),
			 gh_str2scm(token_info.serialNumber,16),
			 gh_ulong2scm(token_info.flags),
			 gh_ulong2scm(token_info.ulMaxSessionCount),
			 gh_ulong2scm(token_info.ulSessionCount),
			 gh_ulong2scm(token_info.ulMaxRwSessionCount),
			 gh_ulong2scm(token_info.ulRwSessionCount),
			 gh_ulong2scm(token_info.ulMaxPinLen),
			 gh_ulong2scm(token_info.ulMinPinLen),
			 gh_ulong2scm(token_info.ulTotalPublicMemory),
			 gh_ulong2scm(token_info.ulFreePublicMemory),
			 gh_ulong2scm(token_info.ulTotalPrivateMemory),
			 gh_ulong2scm(token_info.ulFreePrivateMemory),
			 gh_cons(gh_int2scm(token_info.hardwareVersion.major),
				 gh_int2scm(token_info.hardwareVersion.minor)),
			 gh_cons(gh_int2scm(token_info.firmwareVersion.major),
				 gh_int2scm(token_info.firmwareVersion.minor)),
			 gh_str2scm(token_info.utcTime,16),
			 SCM_UNDEFINED));
}
/* }}} */
/* {{{ SCM ck_get_mechanism_list(SCM slot_ulong) */
SCM ck_get_mechanism_list(SCM slot_ulong)
{
  CK_RV rv = CKR_OK;
  CK_ULONG slotID = gh_scm2ulong(slot_ulong);
  CK_ULONG ulMechanisms = 0;
  CK_MECHANISM_TYPE_PTR pMechanismList = NULL_PTR;
  SCM retlist;
  unsigned int i;

  /* then do the dry run */
  DO_FKT(C_GetMechanismList, (slotID, NULL_PTR, &ulMechanisms));
  if(rv != CKR_OK)
    return gh_cons(gh_ulong2scm(rv),SCM_EOL); 

  /* no list to build, but no failure */
  if(ulMechanisms == 0)
    return gh_cons(gh_ulong2scm(rv),SCM_EOL); 

  pMechanismList = malloc(sizeof(CK_MECHANISM_TYPE)*ulMechanisms);
  if(pMechanismList == NULL_PTR)
    return gh_cons(gh_ulong2scm(CKR_HOST_MEMORY),SCM_BOOL_F); 

  DO_FKT(C_GetMechanismList, (slotID, pMechanismList, &ulMechanisms));
  if(rv != CKR_OK)
    return gh_cons(gh_ulong2scm(rv),SCM_BOOL_F); 

  /* turn the array into a list */
  for(retlist = SCM_EOL,i = 1;i<=ulMechanisms;i++)
      retlist = gh_cons(gh_ulong2scm(pMechanismList[ulMechanisms-i]),retlist);

  free(pMechanismList);

  return gh_cons(gh_ulong2scm(rv),retlist); 
}
/* }}} */
/* {{{ SCM ck_get_mechanism_info(SCM slot_ulong, SCM mech_type_ulong) */
SCM ck_get_mechanism_info(SCM slot_ulong, SCM mech_type_ulong)
{
  CK_RV rv = CKR_OK;
  CK_MECHANISM_INFO pInfo;
  CK_SLOT_ID slotID;
  CK_MECHANISM_TYPE type;

  slotID = gh_scm2ulong(slot_ulong);
  type = gh_scm2ulong(mech_type_ulong);

  DO_FKT(C_GetMechanismInfo, (slotID,type,&pInfo));
  if(rv != CKR_OK)
    return gh_cons(gh_ulong2scm(rv), SCM_EOL);

  return gh_cons(gh_ulong2scm(rv),
		 gh_list(gh_ulong2scm(pInfo.ulMinKeySize),
			 gh_ulong2scm(pInfo.ulMaxKeySize),
			 gh_ulong2scm(pInfo.flags),
			 SCM_UNDEFINED));
}
/* }}} */
/* {{{ SCM ck_open_session(SCM slot_ulong, SCM flags) */
SCM ck_open_session(SCM slot_ulong, SCM flags_ulong)
{
  CK_RV rv = CKR_OK;
  CK_SLOT_ID slotID = gh_scm2ulong(slot_ulong);
  CK_SLOT_ID flags = gh_scm2ulong(flags_ulong);
  CK_SESSION_HANDLE session_handle;

  DO_FKT(C_OpenSession, (slotID,flags,NULL_PTR,NULL_PTR,&session_handle));

  return gh_cons(gh_ulong2scm(rv),gh_ulong2scm(session_handle));
}
/* }}} */
/* {{{ SCM ck_close_session(SCM handle_ulong) */
SCM ck_close_session(SCM handle_ulong)
{
  CK_RV rv = CKR_OK;
  CK_SESSION_HANDLE  session_handle = gh_scm2ulong(handle_ulong);

  DO_FKT(C_CloseSession, (session_handle));

  return gh_ulong2scm(rv);
}
/* }}} */
/* {{{ SCM ck_find_objects_init(SCM session_ulong, SCM attribs_list) */
SCM ck_find_objects_init(SCM session_ulong, SCM attribs_list) 
{
  CK_RV rv = CKR_OK;
  CK_ATTRIBUTE_PTR pTemplate = NULL_PTR;
  CK_SESSION_HANDLE session_handle = gh_scm2ulong(session_ulong);
  CK_ULONG ulCount;

  pTemplate = ci_list2template(attribs_list, &ulCount);

  DO_FKT(C_FindObjectsInit, (session_handle, pTemplate, ulCount));
  ci_template_delete(pTemplate, ulCount);

  return gh_ulong2scm(rv);
}
/* }}} */
/* {{{ SCM ck_find_objects(SCM session_ulong) */
SCM ck_find_objects(SCM session_ulong)
{
  CK_SESSION_HANDLE hSession;          
  CK_OBJECT_HANDLE phObject[1];      
  CK_ULONG ulObjectCount;    
  CK_RV rv = CKR_OK;
  SCM retval = SCM_EOL;

  hSession = gh_scm2ulong(session_ulong);

  while(1)
    {
      DO_FKT(C_FindObjects, (hSession,phObject,1,&ulObjectCount));

      if((rv != CKR_OK) ||
	 (ulObjectCount != 1)) break;
      
      /* verdreht zwar die reihenfolge, aber egal */
      retval= gh_cons(gh_ulong2scm(phObject[0]),retval);
    }
  if(rv != CKR_OK)
    return gh_cons(gh_ulong2scm(rv),SCM_EOL);
  else
    return gh_cons(gh_ulong2scm(rv),retval);
}
/* }}} */
/* {{{ SCM ck_find_objects_final(SCM session_ulong) */
SCM ck_find_objects_final(SCM session_ulong)
{
  CK_RV rv = CKR_OK;
  CK_ULONG session_handle;

  session_handle = gh_scm2ulong(session_ulong);
  DO_FKT(C_FindObjectsFinal, (session_handle));

  return gh_ulong2scm(rv);
}
/* }}} */
/* {{{ SCM ck_create_object(SCM session_ulong, SCM attribs_list) */
SCM ck_create_object(SCM session_ulong, SCM attribs_list)
{
  CK_RV rv = CKR_OK;
  CK_ATTRIBUTE_PTR template = NULL_PTR;
  CK_SESSION_HANDLE session_handle = gh_scm2ulong(session_ulong);
  CK_ULONG template_len;
  CK_ULONG retval;

  template =  ci_list2template(attribs_list, &template_len);

  DO_FKT(C_CreateObject, (session_handle, template, template_len, &retval));
  ci_template_delete(template, template_len);

  if(rv != CKR_OK)
    return gh_cons(gh_ulong2scm(rv),SCM_BOOL_F);
  else
    return gh_cons(gh_ulong2scm(rv),gh_ulong2scm(retval));
}
/* }}} */
/* {{{ SCM ck_destroy_object(SCM session_ulong, SCM object_ulong) */
SCM ck_destroy_object(SCM session_ulong, SCM object_ulong)
{
  CK_RV rv = CKR_OK;
  CK_SESSION_HANDLE session = gh_scm2ulong(session_ulong);
  CK_OBJECT_HANDLE object = gh_scm2ulong(object_ulong);

  DO_FKT(C_DestroyObject, (session, object));

  return gh_ulong2scm(rv);
}
/* }}} */
/* {{{ SCM ck_encrypt_init(SCM session_ulong, SCM mechanism_list, SCM key_ulong) */
SCM ck_encrypt_init(SCM session_ulong, SCM mechanism_list, SCM key_ulong)
{
  CK_RV rv = CKR_OK;
  CK_SESSION_HANDLE session = gh_scm2ulong(session_ulong);
  CK_OBJECT_HANDLE key = gh_scm2ulong(key_ulong);
  CK_MECHANISM_PTR mechanism = ci_list2mechanism(mechanism_list);

  if(mechanism == NULL_PTR)
    return gh_ulong2scm(CKR_GENERAL_ERROR);

  DO_FKT(C_EncryptInit, (session, mechanism, key));

  ci_mechanism_delete(mechanism);

  return gh_ulong2scm(rv);
}
/* }}} */
/* {{{ SCM ck_encrypt(SCM session_ulong, SCM data_string, SCM null_data) */
SCM ck_encrypt(SCM session_ulong, SCM data_string, SCM null_data)
{
  CK_RV rv = CKR_OK;
  CK_SESSION_HANDLE session = gh_scm2ulong(session_ulong);
  int tmp_len;
  CK_ULONG data_len;
  CK_BYTE_PTR data;
  CK_ULONG encrypt_len;
  CK_BYTE_PTR encrypt = NULL_PTR;
  SCM retval;

  data = gh_scm2newstr(data_string, &tmp_len);
  data_len = tmp_len;

  DO_FKT(C_Encrypt, (session,data,data_len,NULL_PTR,&encrypt_len));
  if(rv != CKR_OK)
    return gh_cons(gh_ulong2scm(rv),SCM_BOOL_F);

  encrypt = malloc(encrypt_len);
  if(encrypt == NULL_PTR)
    return gh_cons(gh_ulong2scm(CKR_HOST_MEMORY),SCM_BOOL_F);
  memset(encrypt,' ',encrypt_len);

  if(null_data != SCM_BOOL_F)
    DO_FKT(C_Encrypt, (session,data,data_len,encrypt,&encrypt_len));
  
  retval = gh_str2scm(encrypt,encrypt_len);
  
  free(encrypt);
  free(data);

  return gh_cons(gh_ulong2scm(rv),retval);
}
/* }}} */
/* {{{ SCM ck_encrypt_update(SCM session_ulong, SCM data_string, SCM null_data) */
SCM ck_encrypt_update(SCM session_ulong, SCM data_string, SCM null_data)
{
  CK_RV rv = CKR_OK;
  CK_SESSION_HANDLE session = gh_scm2ulong(session_ulong);
  int tmp_len;
  CK_ULONG data_len;
  CK_BYTE_PTR data;
  CK_ULONG encrypt_len = 0;
  CK_BYTE_PTR encrypt = NULL_PTR;
  SCM retval;

  data = gh_scm2newstr(data_string, &tmp_len);
  data_len = tmp_len;

  DO_FKT(C_EncryptUpdate, (session,data,data_len,NULL_PTR,&encrypt_len));
  if(rv != CKR_OK)
    return gh_cons(gh_ulong2scm(rv),SCM_BOOL_F);

  encrypt = malloc(encrypt_len);
  if(encrypt == NULL_PTR)
    return gh_cons(gh_ulong2scm(CKR_HOST_MEMORY),SCM_BOOL_F);

  /* DEBUG: set to something recognizable */
  memset(encrypt,0xfa,encrypt_len);
  
  if(null_data != SCM_BOOL_F)
    DO_FKT(C_EncryptUpdate, (session,data,data_len,encrypt,&encrypt_len));

  retval = gh_str2scm(encrypt,encrypt_len);
  
  free(encrypt);
  free(data);

  return gh_cons(gh_ulong2scm(rv),retval);
}
/* }}} */
/* {{{ SCM ck_encrypt_final(SCM session_ulong, SCM null_data) */
SCM ck_encrypt_final(SCM session_ulong, SCM null_data)
{
  CK_RV rv = CKR_OK;
  CK_SESSION_HANDLE session = gh_scm2ulong(session_ulong);
  CK_ULONG encrypt_len;
  CK_BYTE_PTR encrypt = NULL_PTR;
  SCM retval;

  DO_FKT(C_EncryptFinal, (session,NULL_PTR,&encrypt_len));
  if(rv != CKR_OK)
    return gh_cons(gh_ulong2scm(rv),SCM_BOOL_F);

  encrypt = malloc(encrypt_len);
  if(encrypt == NULL_PTR)
    return gh_cons(gh_ulong2scm(CKR_HOST_MEMORY),SCM_BOOL_F);
  
  if(null_data != SCM_BOOL_F)
    DO_FKT(C_EncryptFinal, (session,encrypt,&encrypt_len));
  
  retval = gh_str2scm(encrypt,encrypt_len);
  
  free(encrypt);

  return gh_cons(gh_ulong2scm(rv),retval);
}
/* }}} */
/* {{{ SCM ck_decrypt_init(SCM session_ulong, SCM mechanism_list, SCM key_ulong) */
SCM ck_decrypt_init(SCM session_ulong, SCM mechanism_list, SCM key_ulong)
{
  CK_RV rv = CKR_OK;
  CK_SESSION_HANDLE session = gh_scm2ulong(session_ulong);
  CK_OBJECT_HANDLE key = gh_scm2ulong(key_ulong);
  CK_MECHANISM_PTR mechanism = ci_list2mechanism(mechanism_list);

  if(mechanism == NULL_PTR)
    return gh_ulong2scm(CKR_GENERAL_ERROR);

  DO_FKT(C_DecryptInit, (session, mechanism, key));

  ci_mechanism_delete(mechanism);

  return gh_ulong2scm(rv);
}
/* }}} */
/* {{{ SCM ck_decrypt(SCM session_ulong, SCM data_string, SCM null_data) */
SCM ck_decrypt(SCM session_ulong, SCM data_string, SCM null_data)
{
  CK_RV rv = CKR_OK;
  CK_SESSION_HANDLE session = gh_scm2ulong(session_ulong);
  int tmp_len;
  CK_ULONG data_len;
  CK_BYTE_PTR data;
  CK_ULONG decrypt_len;
  CK_BYTE_PTR decrypt = NULL_PTR;
  SCM retval;

  data = gh_scm2newstr(data_string, &tmp_len);
  data_len = tmp_len;

  DO_FKT(C_Decrypt, (session,data,data_len,NULL_PTR,&decrypt_len));
  if(rv != CKR_OK)
    return gh_cons(gh_ulong2scm(rv),SCM_BOOL_F);

  decrypt = malloc(decrypt_len);
  if(decrypt == NULL_PTR)
    return gh_cons(gh_ulong2scm(CKR_HOST_MEMORY),SCM_BOOL_F);
  
  if(null_data != SCM_BOOL_F)
    DO_FKT(C_Decrypt, (session,data,data_len,decrypt,&decrypt_len));
  
  retval = gh_str2scm(decrypt,decrypt_len);
  
  free(decrypt);
  free(data);

  return gh_cons(gh_ulong2scm(rv),retval);
}
/* }}} */
/* {{{ SCM ck_decrypt_update(SCM session_ulong, SCM data_string, SCM null_data) */
SCM ck_decrypt_update(SCM session_ulong, SCM data_string, SCM null_data)
{
  CK_RV rv = CKR_OK;
  CK_SESSION_HANDLE session = gh_scm2ulong(session_ulong);
  int tmp_len;
  CK_ULONG data_len;
  CK_BYTE_PTR data;
  CK_ULONG decrypt_len;
  CK_BYTE_PTR decrypt = NULL_PTR;
  SCM retval;

  data = gh_scm2newstr(data_string, &tmp_len);
  data_len = tmp_len;

  DO_FKT(C_DecryptUpdate, (session,data,data_len,NULL_PTR,&decrypt_len));
  if(rv != CKR_OK)
    return gh_cons(gh_ulong2scm(rv),SCM_BOOL_F);

  decrypt = malloc(decrypt_len);
  if(decrypt == NULL_PTR)
    return gh_cons(gh_ulong2scm(CKR_HOST_MEMORY),SCM_BOOL_F);

  /* DEBUG: set to something recognizable */
  memset(decrypt,0xfa,decrypt_len);
  
  if(null_data != SCM_BOOL_F)
    DO_FKT(C_DecryptUpdate, (session,data,data_len,decrypt,&decrypt_len));

  retval = gh_str2scm(decrypt,decrypt_len);
  
  free(decrypt);
  free(data);

  return gh_cons(gh_ulong2scm(rv),retval);
}
/* }}} */
/* {{{ SCM ck_decrypt_final(SCM session_ulong, SCM null_data) */
SCM ck_decrypt_final(SCM session_ulong, SCM null_data)
{
  CK_RV rv = CKR_OK;
  CK_SESSION_HANDLE session = gh_scm2ulong(session_ulong);
  CK_ULONG decrypt_len;
  CK_BYTE_PTR decrypt = NULL_PTR;
  SCM retval;

  DO_FKT(C_DecryptFinal, (session,NULL_PTR,&decrypt_len));
  if(rv != CKR_OK)
    return gh_cons(gh_ulong2scm(rv),SCM_BOOL_F);

  decrypt = malloc(decrypt_len);
  if(decrypt == NULL_PTR)
    return gh_cons(gh_ulong2scm(CKR_HOST_MEMORY),SCM_BOOL_F);
  
  if(null_data != SCM_BOOL_F)
    DO_FKT(C_DecryptFinal, (session,decrypt,&decrypt_len));
  
  retval = gh_str2scm(decrypt,decrypt_len);
  
  free(decrypt);

  return gh_cons(gh_ulong2scm(rv),retval);
}
/* }}} */
/* {{{ SCM ck_digest_init(SCM session_ulong, SCM mechansim_list) */
SCM ck_digest_init(SCM session_ulong, SCM mechanism_list)
{
  CK_RV rv = CKR_OK;
  CK_SESSION_HANDLE hSession = gh_scm2ulong(session_ulong);
  CK_MECHANISM_PTR pMechanism = ci_list2mechanism(mechanism_list);

  if(pMechanism == NULL_PTR)
    return gh_ulong2scm(CKR_GENERAL_ERROR);

  DO_FKT(C_DigestInit, (hSession, pMechanism));

  return gh_ulong2scm(rv);
}
/* }}} */
/* {{{ SCM ck_digest(SCM session_ulong, SCM data_string, SCM null_data) */
SCM ck_digest(SCM session_ulong, SCM data_string, SCM null_data)
{
  CK_RV rv = CKR_OK;
  CK_SESSION_HANDLE session = gh_scm2ulong(session_ulong);
  int tmp_len;
  CK_ULONG data_len;
  CK_BYTE_PTR data;
  CK_ULONG digest_len;
  CK_BYTE_PTR digest = NULL_PTR;
  SCM retval;

  data = gh_scm2newstr(data_string, &tmp_len);
  data_len = tmp_len;

  DO_FKT(C_Digest, (session,data,data_len,NULL_PTR,&digest_len));
  if(rv != CKR_OK)
    return gh_cons(gh_ulong2scm(rv),SCM_BOOL_F);

  digest = malloc(digest_len);
  if(digest == NULL_PTR)
    return gh_cons(gh_ulong2scm(CKR_HOST_MEMORY),SCM_BOOL_F);
  
  if(null_data != SCM_BOOL_F)
    DO_FKT(C_Digest, (session,data,data_len,digest,&digest_len));
  
  retval = gh_str2scm(digest,digest_len);
  
  free(digest);
  free(data);

  return gh_cons(gh_ulong2scm(rv),retval);
}
/* }}} */
/* {{{ SCM ck_digest_update(SCM session_ulong, SCM data_string) */
SCM ck_digest_update(SCM session_ulong, SCM data_string)
{
  CK_RV rv = CKR_OK;
  CK_SESSION_HANDLE session = gh_scm2ulong(session_ulong);
  int tmp_len;
  CK_BYTE_PTR data;
  CK_ULONG data_len;

  data = gh_scm2newstr(data_string, &tmp_len);
  data_len = tmp_len;

  DO_FKT(C_DigestUpdate, (session,data,data_len));

  free(data);

  return gh_ulong2scm(rv);
}
/* }}} */
/* {{{ SCM ck_digest_key(SCM session_ulong, SCM key_ulong) */
SCM ck_digest_key(SCM session_ulong, SCM key_ulong)
{
  CK_RV rv = CKR_OK;
  CK_SESSION_HANDLE session = gh_scm2ulong(session_ulong);
  CK_OBJECT_HANDLE hKey = gh_scm2ulong(key_ulong);

  DO_FKT(C_DigestKey, (session,hKey));

  return gh_ulong2scm(rv);
}
/* }}} */
/* {{{ SCM ck_digest_final(SCM session_ulong, SCM null_data) */
SCM ck_digest_final(SCM session_ulong, SCM null_data)
{
  CK_RV rv = CKR_OK;
  CK_SESSION_HANDLE session = gh_scm2ulong(session_ulong);
  CK_ULONG digest_len;
  CK_BYTE_PTR digest = NULL_PTR;
  SCM retval;

  DO_FKT(C_DigestFinal, (session,NULL_PTR,&digest_len));
  if(rv != CKR_OK)
    return gh_cons(gh_ulong2scm(rv),SCM_BOOL_F);

  digest = malloc(digest_len);
  if(digest == NULL_PTR)
    return gh_cons(gh_ulong2scm(CKR_HOST_MEMORY),SCM_BOOL_F);
  
  if(null_data != SCM_BOOL_F)
    DO_FKT(C_DigestFinal, (session,digest,&digest_len));
  
  retval = gh_str2scm(digest,digest_len);
  
  free(digest);

  return gh_cons(gh_ulong2scm(rv),retval);
}
/* }}} */
/* {{{ SCM ck_sign_init(SCM session_ulong, SCM mechanism_list, SCM key_ulong) */
SCM ck_sign_init(SCM session_ulong, SCM mechanism_list, SCM key_ulong)
{
  CK_RV rv = CKR_OK;
  CK_SESSION_HANDLE session = gh_scm2ulong(session_ulong);
  CK_OBJECT_HANDLE key = gh_scm2ulong(key_ulong);
  CK_MECHANISM_PTR mechanism = ci_list2mechanism(mechanism_list);

  if(mechanism == NULL_PTR)
    return gh_ulong2scm(CKR_GENERAL_ERROR);

  DO_FKT(C_SignInit, (session, mechanism, key));

  ci_mechanism_delete(mechanism);

  return gh_ulong2scm(rv);
}
/* }}} */
/* {{{ SCM ck_sign(SCM session_ulong, SCM data_string, SCM null_data) */
SCM ck_sign(SCM session_ulong, SCM data_string, SCM null_data)
{
  CK_RV rv = CKR_OK;
  CK_SESSION_HANDLE hSession = gh_scm2ulong(session_ulong);
  int tmp_len;
  CK_BYTE_PTR pData;
  CK_ULONG ulDataLen;
  CK_BYTE_PTR pSignature;
  CK_ULONG ulSignatureLen =0;
  SCM retval;

  pData = gh_scm2newstr(data_string, &tmp_len);
  ulDataLen = tmp_len;
    
  DO_FKT(C_Sign, (hSession, pData, ulDataLen, NULL_PTR, &ulSignatureLen));
  if( rv != CKR_OK) return rv;

  pSignature = malloc(ulSignatureLen);
  if(pSignature == NULL_PTR) return CKR_HOST_MEMORY;

  if(null_data != SCM_BOOL_T)
    {
      DO_FKT(C_Sign, (hSession, pData, ulDataLen, pSignature, &ulSignatureLen));
      if( rv != CKR_OK) 
	{
	  free(pSignature);
	  return rv;
	}
    }

  retval = gh_cons(gh_ulong2scm(rv),gh_str2scm(pSignature,ulSignatureLen));
  free(pSignature);

  return retval;
}
/* }}} */
/* {{{ SCM ck_sign_update(SCM session_ulong, SCM data_string) */
SCM ck_sign_update(SCM session_ulong, SCM data_string)
{
  CK_RV rv = CKR_OK;
  CK_SESSION_HANDLE session = gh_scm2ulong(session_ulong);
  int tmp_len;
  CK_ULONG sign_len;
  CK_BYTE_PTR sign = NULL_PTR;

  sign = gh_scm2newstr(data_string, &tmp_len);
  sign_len = tmp_len;

  DO_FKT(C_SignUpdate, (session,sign,sign_len));

  free(sign);

  return gh_ulong2scm(rv);
}
/* }}} */
/* {{{ SCM ck_sign_final(SCM session_ulong, SCM null_data) */
SCM ck_sign_final(SCM session_ulong, SCM null_data)
{
  CK_RV rv = CKR_OK;
  CK_SESSION_HANDLE session = gh_scm2ulong(session_ulong);
  CK_ULONG sign_len;
  CK_BYTE_PTR sign = NULL_PTR;
  SCM retval;

  DO_FKT(C_SignFinal, (session,NULL_PTR,&sign_len));
  if(rv != CKR_OK)
    return gh_cons(gh_ulong2scm(rv),SCM_BOOL_F);

  sign = malloc(sign_len);
  if(sign == NULL_PTR)
    return gh_cons(gh_ulong2scm(CKR_HOST_MEMORY),SCM_BOOL_F);
  
  if(null_data != SCM_BOOL_F)
    DO_FKT(C_SignFinal, (session,sign,&sign_len));
  
  retval = gh_str2scm(sign,sign_len);
  
  free(sign);

  return gh_cons(gh_ulong2scm(rv),retval);
}
/* }}} */
/* {{{ SCM ck_sign_recover_init(SCM session_ulong, SCM mechanism_list, SCM key_ulong) */
SCM ck_sign_recover_init(SCM session_ulong, SCM mechanism_list, SCM key_ulong)
{
  CK_RV rv = CKR_OK;
  CK_SESSION_HANDLE session = gh_scm2ulong(session_ulong);
  CK_OBJECT_HANDLE key = gh_scm2ulong(key_ulong);
  CK_MECHANISM_PTR mechanism = ci_list2mechanism(mechanism_list);

  if(mechanism == NULL_PTR)
    return gh_ulong2scm(CKR_GENERAL_ERROR);

  DO_FKT(C_SignRecoverInit, (session, mechanism, key));

  ci_mechanism_delete(mechanism);

  return gh_ulong2scm(rv);
}
/* }}} */
/* {{{ SCM ck_sign_recover(SCM session_ulong, SCM data_string, SCM null_data) */
SCM ck_sign_recover(SCM session_ulong, SCM data_string, SCM null_data)
{
  CK_RV rv = CKR_OK;
  CK_SESSION_HANDLE hSession = gh_scm2ulong(session_ulong);
  int tmp_len;
  CK_BYTE_PTR pData;
  CK_ULONG ulDataLen;
  CK_BYTE_PTR pSignature;
  CK_ULONG ulSignatureLen =0;
  SCM retval;

  pData = gh_scm2newstr(data_string, &tmp_len);
  ulDataLen = tmp_len;
    
  DO_FKT(C_SignRecover, (hSession, pData, ulDataLen, NULL_PTR, &ulSignatureLen));
  if( rv != CKR_OK) return rv;

  pSignature = malloc(ulSignatureLen);
  if(pSignature == NULL_PTR) return CKR_HOST_MEMORY;

  if(null_data != SCM_BOOL_T)
    {
      DO_FKT(C_SignRecover, (hSession, pData, ulDataLen, pSignature, &ulSignatureLen));
      if( rv != CKR_OK) 
	{
	  free(pSignature);
	  return rv;
	}
    }

  retval = gh_cons(gh_ulong2scm(rv),gh_str2scm(pSignature,ulSignatureLen));
  free(pSignature);

  return retval;
}
/* }}} */
/* {{{ SCM ck_generate_key(SCM session_ulong, SCM mechanism_list, SCM template_list) */
SCM ck_generate_key(SCM session_ulong, SCM mechanism_list, SCM template_list)
{
  CK_RV rv = CKR_OK;
  CK_SESSION_HANDLE    hSession;
  CK_MECHANISM_PTR     pMechanism;
  CK_ATTRIBUTE_PTR     pTemplate;
  CK_ULONG             ulCount;
  CK_OBJECT_HANDLE     hKey=0;
  
  hSession = gh_scm2ulong(session_ulong);
  pMechanism = ci_list2mechanism(mechanism_list);
  pTemplate = ci_list2template(template_list, &ulCount);

  DO_FKT(C_GenerateKey, (hSession,pMechanism,pTemplate,ulCount,&hKey));
  ci_template_delete(pTemplate, ulCount);

  return gh_cons(gh_ulong2scm(rv),gh_ulong2scm(hKey));
}
/* }}} */
/* {{{ SCM ck_generate_key_pair(SCM, SCM, SCM, SCM) */
SCM ck_generate_key_pair(SCM session, SCM mechanism, SCM public_template, SCM private_template)
{
  CK_RV rv = CKR_OK;
  CK_SESSION_HANDLE    hSession;
  CK_MECHANISM_PTR     pMechanism;
  CK_ATTRIBUTE_PTR     pPublicKeyTemplate;
  CK_ULONG             ulPublicKeyAttributeCount;
  CK_ATTRIBUTE_PTR     pPrivateKeyTemplate;
  CK_ULONG             ulPrivateKeyAttributeCount;
  CK_OBJECT_HANDLE     hPublicKey=0;
  CK_OBJECT_HANDLE     hPrivateKey=0;

  hSession = gh_scm2ulong(session);
  pMechanism = ci_list2mechanism(mechanism);
  pPublicKeyTemplate = ci_list2template(public_template, &ulPublicKeyAttributeCount);
  pPrivateKeyTemplate = ci_list2template(private_template, &ulPrivateKeyAttributeCount);

  /* nicht umbrechen! ist ein Makro! */
  DO_FKT(C_GenerateKeyPair, (hSession, pMechanism, pPublicKeyTemplate, ulPublicKeyAttributeCount, pPrivateKeyTemplate, ulPrivateKeyAttributeCount, &hPublicKey, &hPrivateKey));

  return gh_cons(gh_ulong2scm(rv),gh_list(gh_ulong2scm(hPublicKey),
					  gh_ulong2scm(hPrivateKey),
					  SCM_UNDEFINED));
}
/* }}} */
/* {{{ SCM ck_login(SCM session_ulong, SCM user_ulong, SCM pin_string) */
SCM ck_login(SCM session_ulong, SCM user_ulong, SCM pin_string)
{
  CK_RV rv = CKR_OK;
  CK_SESSION_HANDLE hSession;
  CK_USER_TYPE      userType;
  CK_CHAR_PTR       pPin;
  CK_ULONG          ulPinLen;
  int tmp_len;
  hSession = gh_scm2ulong(session_ulong);
  userType = gh_scm2ulong(user_ulong);
  pPin = gh_scm2newstr(pin_string, &tmp_len);
  ulPinLen=tmp_len;

  /* we assume that if the len of the pin is 0 it should be NULL */
  if(ulPinLen == 0) 
    {
      free(pPin);
      pPin=NULL;
    }

  DO_FKT(C_Login, (hSession, userType, pPin, ulPinLen));

  /* if it is NULL free won't do anything anyway */
  free(pPin);
  
  return gh_ulong2scm(rv);
}
/* }}} */
/* {{{ SCM ck_logout(SCM session_ulong) */
SCM ck_logout(SCM session_ulong)
{
  CK_RV rv = CKR_OK;
  CK_SESSION_HANDLE hSession;

  hSession = gh_scm2ulong(session_ulong);

  DO_FKT(C_Logout, (hSession));

  return gh_ulong2scm(rv);
}
/* }}} */
/* {{{ SCM ck_init_pin(SCM session_ulong, SCM pin_string) */
SCM ck_init_pin(SCM session_ulong, SCM pin_string)
{
  CK_RV rv = CKR_OK;
  CK_SESSION_HANDLE hSession;
  CK_CHAR_PTR       pPin;
  CK_ULONG          ulPinLen;
  int tmp_len;

  hSession = gh_scm2ulong(session_ulong);
  pPin = gh_scm2newstr(pin_string, &tmp_len);
  ulPinLen = tmp_len;

  DO_FKT(C_InitPIN, (hSession, pPin, ulPinLen));

  return gh_ulong2scm(rv);
}
/* }}} */
/* {{{ SCM ck_set_pin(SCM session_ulong, SCM oldpin_string, SCM newpin_string) */
SCM ck_set_pin(SCM session_ulong, SCM oldpin_string, SCM newpin_string)
{
  CK_RV rv = CKR_OK;
  CK_SESSION_HANDLE hSession;
  CK_CHAR_PTR       pOldPin;
  CK_ULONG          ulOldLen;
  CK_CHAR_PTR       pNewPin;
  CK_ULONG          ulNewLen;
  int tmp_len;

  hSession = gh_scm2ulong(session_ulong);
  pOldPin = gh_scm2newstr(oldpin_string, &tmp_len);
  ulOldLen = tmp_len;
  pNewPin = gh_scm2newstr(newpin_string, &tmp_len);
  ulNewLen = tmp_len;

  DO_FKT(C_SetPIN, (hSession, pOldPin, ulOldLen, pNewPin, ulNewLen));

  return gh_ulong2scm(rv);
}
/* }}} */
/* {{{ SCM ck_close_all_sessions(SCM slot_ulong) */
SCM ck_close_all_sessions(SCM slot_ulong)
{
  CK_RV rv = CKR_OK;
  CK_ULONG slotID;

  slotID = gh_scm2ulong(slot_ulong);

  DO_FKT(C_CloseAllSessions, (slotID));

  return gh_ulong2scm(rv);
}
/* }}} */
/* {{{ SCM ck_get_session_info(SCM session_ulong) */
SCM ck_get_session_info(SCM session_ulong)
{
  CK_RV rv = CKR_OK;
  CK_SESSION_HANDLE hSession;
  CK_SESSION_INFO Info;

  hSession = gh_scm2ulong(session_ulong);

  DO_FKT(C_GetSessionInfo, (hSession,&Info));
  if(rv != CKR_OK)
    return gh_cons(gh_ulong2scm(rv),SCM_BOOL_F);
    
  
  return gh_cons(gh_ulong2scm(rv),
		 gh_list(gh_ulong2scm(Info.slotID),
			 gh_ulong2scm(Info.state),
			 gh_ulong2scm(Info.flags),
			 gh_ulong2scm(Info.ulDeviceError),
			 SCM_UNDEFINED));
}
/* }}} */
/* {{{ SCM ck_copy_object(SCM session_ulong, SCM object_ulong, SCM template_list) */
SCM ck_copy_object(SCM session_ulong, SCM object_ulong, SCM template_list)
{
  CK_RV rv = CKR_OK;
  CK_SESSION_HANDLE    hSession;
  CK_OBJECT_HANDLE     hObject;
  CK_ATTRIBUTE_PTR     pTemplate;
  CK_ULONG             ulCount;
  CK_OBJECT_HANDLE     hNewObject;

  hSession = gh_scm2ulong(session_ulong);
  pTemplate = ci_list2template(template_list, &ulCount);

  DO_FKT(C_CopyObject, (hSession, hObject, pTemplate, ulCount, &hNewObject));
  ci_template_delete(pTemplate, ulCount);

  return gh_cons(gh_ulong2scm(rv),gh_ulong2scm(hNewObject));
}
/* }}} */
/* {{{ SCM ck_verify_init(SCM session_ulong, SCM mechanism_list, SCM key_ulong) */
SCM ck_verify_init(SCM session_ulong, SCM mechanism_list, SCM key_ulong)
{
  CK_RV rv = CKR_OK;
  CK_SESSION_HANDLE hSession;
  CK_MECHANISM_PTR  pMechanism;
  CK_OBJECT_HANDLE  hKey;

  hSession = gh_scm2ulong(session_ulong);
  pMechanism = ci_list2mechanism(mechanism_list);
  hKey = gh_scm2ulong(key_ulong);

  DO_FKT(C_VerifyInit, (hSession, pMechanism, hKey));
  ci_mechanism_delete(pMechanism);

  return gh_ulong2scm(rv);
}
/* }}} */
/* {{{ SCM ck_verify(SCM session_ulong, SCM data_string, SCM signature_string) */
SCM ck_verify(SCM session, SCM data_string, SCM signature_string)
{
  CK_RV rv = CKR_OK;
  CK_SESSION_HANDLE hSession;
  CK_BYTE_PTR       pData;
  CK_ULONG          ulDataLen;
  CK_BYTE_PTR       pSignature;
  CK_ULONG          ulSignatureLen;
  int tmp_len;

  hSession = gh_scm2ulong(session);
  pData = gh_scm2newstr(data_string, &tmp_len);
  ulDataLen = tmp_len;

  pSignature = gh_scm2newstr(signature_string,&tmp_len);
  ulSignatureLen = tmp_len;

  DO_FKT(C_Verify, (hSession, pData, ulDataLen, pSignature, ulSignatureLen));
  free(pData);
  free(pSignature);

  return gh_ulong2scm(rv);
}
/* }}} */
/* {{{ SCM ck_verify_update(SCM session_ulong, SCM part_string) */
SCM ck_verify_update(SCM session_ulong, SCM part_string)
{
  CK_RV rv = CKR_OK;
  CK_SESSION_HANDLE hSession;
  CK_BYTE_PTR       pPart;
  CK_ULONG          ulPartLen;
  int tmp_len;

  hSession = gh_scm2ulong(session_ulong);
  pPart = gh_scm2newstr(part_string, &tmp_len);
  ulPartLen = tmp_len;

  DO_FKT(C_VerifyUpdate, (hSession, pPart, ulPartLen));
  free(pPart);

  return gh_ulong2scm(rv);
}
/* }}} */
/* {{{ SCM ck_verify_final(SCM session_ulong, SCM signature_string) */
SCM ck_verify_final(SCM session_ulong, SCM signature_string)
{
  CK_RV rv = CKR_OK;
  CK_SESSION_HANDLE hSession;
  CK_BYTE_PTR       pSignature;
  CK_ULONG          ulSignatureLen;
  int tmp_len;

  hSession = gh_scm2ulong(session_ulong);
  pSignature = gh_scm2newstr(signature_string, &tmp_len);
  ulSignatureLen = tmp_len;

  DO_FKT(C_VerifyFinal, (hSession, pSignature, ulSignatureLen));
  free(pSignature);

  return gh_ulong2scm(rv);
}
/* }}} */
/* {{{ SCM ck_verify_recover_init(SCM session_ulong, SCM mechanism_list, SCM key_ulong) */
SCM ck_verify_recover_init(SCM session_ulong, SCM mechanism_list, SCM key_ulong)
{
  CK_RV rv = CKR_OK;
  CK_SESSION_HANDLE hSession;
  CK_MECHANISM_PTR  pMechanism;
  CK_OBJECT_HANDLE  hKey;

  hSession = gh_scm2ulong(session_ulong);
  pMechanism = ci_list2mechanism(mechanism_list);
  hKey = gh_scm2ulong(key_ulong);

  DO_FKT(C_VerifyRecoverInit, (hSession, pMechanism, hKey));
  ci_mechanism_delete(pMechanism);

  return gh_ulong2scm(rv);
}
/* }}} */
/* {{{ SCM ck_verify_recover(SCM session_ulong, SCM signature_string, SCM null_data) */
SCM ck_verify_recover(SCM session_ulong, SCM signature_string, SCM null_data)
{
  SCM retval;
  CK_RV rv = CKR_OK;
  CK_SESSION_HANDLE hSession;
  CK_BYTE_PTR       pSignature;
  CK_ULONG          ulSignatureLen;
  CK_BYTE_PTR       pData;
  CK_ULONG          ulDataLen;
  int tmp_len;

  hSession = gh_scm2ulong(session_ulong);
  pSignature = gh_scm2newstr(signature_string, &tmp_len);
  ulSignatureLen = tmp_len;

  DO_FKT(C_VerifyRecover, (hSession, pSignature, ulSignatureLen, NULL_PTR, &ulDataLen));

  pData = malloc(ulDataLen*sizeof(CK_BYTE));
  if(pData == NULL_PTR) 
    {
      free(pSignature);
      return gh_cons(gh_ulong2scm(rv),SCM_BOOL_F);
    }

  if(null_data != SCM_BOOL_F)
    DO_FKT(C_VerifyRecover, (hSession, pSignature, ulSignatureLen, pData, &ulDataLen));


  free(pSignature);

  retval = gh_cons(gh_ulong2scm(rv),
		   (rv == CKR_OK)? gh_str2scm(pData, ulDataLen): SCM_BOOL_F);
  
  free(pData);
  
  return retval;
}
/* }}} */
/* {{{ SCM ck_init_token(SCM slot_ulong, SCM pin_string, SCM labe_string) */
SCM ck_init_token(SCM slot_ulong, SCM pin_string, SCM label_string)
{
  CK_RV          rv = CKR_OK;
  CK_SLOT_ID     slotID;
  CK_CHAR_PTR    pPin;
  CK_ULONG       ulPinLen;
  CK_CHAR        pLabel[32];
  CK_CHAR_PTR    tmp_str;
  int            label_len,tmp_len;

  slotID = gh_scm2ulong(slot_ulong);

  memset(pLabel,' ', 32);
  tmp_str=gh_scm2newstr(label_string,&label_len);
  memcpy(pLabel, tmp_str, (label_len>32)? 32 : label_len);
  
  pPin = gh_scm2newstr(pin_string, &tmp_len);
  ulPinLen = tmp_len;

  DO_FKT(C_InitToken, (slotID, pPin, ulPinLen, pLabel));

  return gh_ulong2scm(rv);
}
/* }}} */
/* {{{ SCM ck_seed_random(SCM session_ulong, SCM seed_string) */
SCM ck_seed_random(SCM session_ulong, SCM seed_string)
{
  CK_RV rv = CKR_OK;
  CK_SESSION_HANDLE hSession;
  CK_BYTE_PTR       pSeed;
  CK_ULONG          ulSeedLen;
  int tmp_len;
  
  hSession = gh_scm2ulong(session_ulong);
  pSeed = gh_scm2newstr(seed_string, &tmp_len);
  ulSeedLen = tmp_len;

  DO_FKT(C_SeedRandom, (hSession, pSeed, ulSeedLen));

  return gh_ulong2scm(rv);
}
/* }}} */
/* {{{ SCM ck_generate_random(SCM session_ulong, SCM len_ulong) */
SCM ck_generate_random(SCM session_ulong, SCM len_ulong)
{
  CK_RV rv = CKR_OK;
  CK_SESSION_HANDLE hSession;
  CK_BYTE_PTR       RandomData;
  CK_ULONG          ulRandomLen;
  SCM retval;

  hSession = gh_scm2ulong(session_ulong);
  ulRandomLen = gh_scm2ulong(len_ulong);

  RandomData = malloc(ulRandomLen);
  if(RandomData == NULL_PTR)
  return gh_cons(gh_ulong2scm(CKR_HOST_MEMORY),
		 SCM_BOOL_F);

  DO_FKT(C_GenerateRandom, (hSession, RandomData, ulRandomLen));
  
  retval = gh_cons(gh_ulong2scm(rv),
		 gh_str2scm(RandomData, ulRandomLen));
  free(RandomData);

  return retval;
}
/* }}} */
/* {{{ SCM ck_get_object_size(SCM session_ulong, SCM object_ulong) */
SCM ck_get_object_size(SCM session_ulong, SCM object_ulong)
{
  CK_RV rv = CKR_OK;
  CK_SESSION_HANDLE hSession;
  CK_OBJECT_HANDLE  hObject;
  CK_ULONG          ulSize;

  hSession = gh_scm2ulong(session_ulong);
  hObject = gh_scm2ulong(object_ulong);

  DO_FKT(C_GetObjectSize, (hSession, hObject, &ulSize));

  return gh_cons(gh_ulong2scm(rv),
		  gh_ulong2scm(ulSize));
}
/* }}} */
/* {{{ SCM ck_get_attribute_value(SCM session_ulong, SCM object_ulong, SCM template_list) */
SCM ck_get_attribute_value(SCM session_ulong, SCM object_ulong, SCM template_list)
{
  CK_RV rv = CKR_OK;
  CK_SESSION_HANDLE hSession;
  CK_OBJECT_HANDLE  hObject;
  CK_ATTRIBUTE_PTR  pTemplate;
  CK_ULONG          ulCount;
  SCM retval;
  int i;

  hSession = gh_scm2ulong(session_ulong);
  hObject = gh_scm2ulong(object_ulong);

  ulCount = gh_length(template_list);
  pTemplate = malloc(ulCount*sizeof(CK_ATTRIBUTE));
  if(pTemplate == NULL_PTR)
    {
      retval = gh_cons(gh_ulong2scm(rv),
		       SCM_EOL);
    }

  for(i=0;i<ulCount;i++,template_list = gh_cdr(template_list))
    {
      /* TODO: ensure that we got a ulong and not something else */
      pTemplate[i].type = gh_scm2ulong(gh_car(template_list));
      pTemplate[i].pValue = NULL_PTR;
      pTemplate[i].ulValueLen = 0;
    }

  DO_FKT(C_GetAttributeValue, (hSession, hObject, pTemplate, ulCount));
  if(rv != CKR_OK)
    return gh_cons(gh_ulong2scm(rv), SCM_EOL);
  
  /* malloc the memory to be filled with the actual values */
  for(i=0;i<ulCount;i++)
    {
      pTemplate[i].pValue = malloc(pTemplate[i].ulValueLen);
      if(pTemplate[i].pValue == NULL_PTR) break;
    }
  if(i<ulCount) 
    {
      retval = gh_cons(gh_ulong2scm(CKR_HOST_MEMORY), SCM_EOL);
      goto get_attribute_value_error;
    }
  
  DO_FKT(C_GetAttributeValue, (hSession, hObject, pTemplate, ulCount));
  if(rv != CKR_OK)
    retval = gh_cons(gh_ulong2scm(rv), SCM_EOL);
  else
    retval = gh_cons(gh_ulong2scm(rv),
		     ci_template2list(pTemplate, ulCount));
  
 get_attribute_value_error:
  ci_template_delete(pTemplate,ulCount);
  
  return retval;
}
/* }}} */
/* {{{ SCM ck_set_attribute_value(SCM session_ulong, SCM object_ulong, SCM template_list) */
SCM ck_set_attribute_value(SCM session_ulong, SCM object_ulong, SCM template_list)
{
  CK_RV rv = CKR_OK;
  CK_SESSION_HANDLE hSession;
  CK_OBJECT_HANDLE  hObject;
  CK_ATTRIBUTE_PTR  pTemplate;
  CK_ULONG          ulCount;

  hSession = gh_scm2ulong(session_ulong);
  hObject = gh_scm2ulong(object_ulong);
  pTemplate = ci_list2template(template_list, &ulCount);

  DO_FKT(C_SetAttributeValue, (hSession, hObject, pTemplate, ulCount));

  ci_template_delete(pTemplate, ulCount);
  
  return gh_ulong2scm(rv);
}
/* }}} */
/* {{{ SCM ck_get_operation_state(SCM session_ulong) */
SCM ck_get_operation_state(SCM session_ulong, SCM null_data)
{
  CK_RV rv = CKR_OK;
  CK_SESSION_HANDLE hSession;
  CK_BYTE_PTR       pOperationState;
  CK_ULONG          ulOperationStateLen;
  SCM retval;

  hSession = gh_scm2ulong(session_ulong);
  ulOperationStateLen =0;

  DO_FKT(C_GetOperationState, (hSession, NULL_PTR, &ulOperationStateLen));
  if(rv != CKR_OK)
    return gh_cons(gh_ulong2scm(rv),SCM_BOOL_F);
  
  pOperationState = malloc(ulOperationStateLen);
  if(pOperationState == NULL_PTR)
    return gh_cons(gh_ulong2scm(CKR_HOST_MEMORY),SCM_BOOL_F);

  if(null_data != SCM_BOOL_T)
    DO_FKT(C_GetOperationState, (hSession, pOperationState, &ulOperationStateLen));

  if(rv != CKR_OK)
    retval = gh_cons(gh_ulong2scm(rv),SCM_BOOL_F);
  else
    retval = gh_cons(gh_ulong2scm(rv),
		     gh_str2scm(pOperationState, ulOperationStateLen));
  
  free(pOperationState);
  
  return retval;
}
/* }}} */
/* {{{ SCM ck_set_operation_state(SCM session, SCM state, SCM enc_key, SCM auth_key) */
SCM ck_set_operation_state(SCM session, SCM state, SCM enc_key, SCM auth_key)
{
  CK_RV rv = CKR_OK;
  CK_SESSION_HANDLE hSession;
  CK_BYTE_PTR      pOperationState;
  CK_ULONG         ulOperationStateLen;
  CK_OBJECT_HANDLE hEncryptionKey;
  CK_OBJECT_HANDLE hAuthenticationKey;
  int tmp_len;

  hSession = gh_scm2ulong(session);
  hEncryptionKey = gh_scm2ulong(enc_key);
  hAuthenticationKey= gh_scm2ulong(auth_key);
  pOperationState = gh_scm2newstr(state, &tmp_len);
  ulOperationStateLen = tmp_len;

  DO_FKT(C_SetOperationState, (hSession,pOperationState,
			       ulOperationStateLen,hEncryptionKey,hAuthenticationKey));

  free(pOperationState);

  return gh_ulong2scm(rv);
}
/* }}} */
/* {{{ SCM ck_digest_encrypt_update(SCM session, SCM part, SCM null_data) */
SCM ck_digest_encrypt_update(SCM session, SCM part, SCM null_data)
{
  CK_RV rv = CKR_OK;
  CK_SESSION_HANDLE hSession;
  CK_BYTE_PTR       pPart;
  CK_ULONG          ulPartLen;
  CK_BYTE_PTR       pEncryptedPart;
  CK_ULONG          ulEncryptedPartLen;
  SCM retval;
  int tmp_len;

  hSession = gh_scm2ulong(session);
  pPart = gh_scm2newstr(part, &tmp_len);
  ulPartLen = tmp_len;

  DO_FKT(C_DigestEncryptUpdate, (hSession,pPart,ulPartLen,NULL_PTR,&ulEncryptedPartLen));

  pEncryptedPart = malloc(ulEncryptedPartLen);
  if(pEncryptedPart == NULL_PTR)
    return gh_cons(gh_ulong2scm(CKR_HOST_MEMORY),
		   SCM_BOOL_F);

  if(null_data != SCM_BOOL_T)
    DO_FKT(C_DigestEncryptUpdate, (hSession,pPart,ulPartLen,pEncryptedPart,&ulEncryptedPartLen));

  if(rv == CKR_OK)
  retval = gh_cons(gh_ulong2scm(rv),
		   gh_str2scm(pEncryptedPart, ulEncryptedPartLen));
  else
    retval = gh_cons(gh_ulong2scm(rv),
		     SCM_BOOL_F);

  free(pEncryptedPart);

  return retval;
}
/* }}} */
/* {{{ SCM ck_decrypt_digest_update(SCM session, SCM enc_part, SCM null_data) */
SCM ck_decrypt_digest_update(SCM session, SCM enc_part, SCM null_data)
{
  CK_RV rv = CKR_OK;
  CK_SESSION_HANDLE hSession;
  CK_BYTE_PTR       pEncryptedPart;
  CK_ULONG          ulEncryptedPartLen;
  CK_BYTE_PTR       pPart;
  CK_ULONG          ulPartLen;
  SCM retval;
  int tmp_len;

  hSession = gh_scm2ulong(session);
  pEncryptedPart = gh_scm2newstr(enc_part, &tmp_len);
  ulEncryptedPartLen = tmp_len;

  DO_FKT(C_DecryptDigestUpdate, (hSession,pEncryptedPart,ulEncryptedPartLen,NULL_PTR,&ulPartLen));

  pPart = malloc(ulPartLen);
  if(pPart == NULL_PTR)
    return gh_cons(gh_ulong2scm(CKR_HOST_MEMORY),
		   SCM_BOOL_F);

  if(null_data != SCM_BOOL_T)
    DO_FKT(C_DecryptDigestUpdate, (hSession,pEncryptedPart,ulEncryptedPartLen,pPart,&ulPartLen));

  if(rv == CKR_OK)
  retval = gh_cons(gh_ulong2scm(rv),
		   gh_str2scm(pPart, ulPartLen));
  else
    retval = gh_cons(gh_ulong2scm(rv),
		     SCM_BOOL_F);

  free(pPart);

  return retval;
}
/* }}} */
/* {{{ SCM ck_sign_encrypt_update(SCM session, SCM part, SCM null_data) */
SCM ck_sign_encrypt_update(SCM session, SCM part, SCM null_data)
{
  CK_RV rv = CKR_OK;
  CK_SESSION_HANDLE hSession;
  CK_BYTE_PTR       pPart;
  CK_ULONG          ulPartLen;
  CK_BYTE_PTR       pEncryptedPart;
  CK_ULONG          ulEncryptedPartLen;
  SCM retval;
  int tmp_len;

  hSession = gh_scm2ulong(session);
  pPart = gh_scm2newstr(part, &tmp_len);
  ulPartLen = tmp_len;

  DO_FKT(C_SignEncryptUpdate, (hSession,pPart,ulPartLen,NULL_PTR,&ulEncryptedPartLen));

  pEncryptedPart = malloc(ulEncryptedPartLen);
  if(pEncryptedPart == NULL_PTR)
    return gh_cons(gh_ulong2scm(CKR_HOST_MEMORY),
		   SCM_BOOL_F);

  if(null_data != SCM_BOOL_T)
    DO_FKT(C_SignEncryptUpdate, (hSession,pPart,ulPartLen,pEncryptedPart,&ulEncryptedPartLen));

  if(rv == CKR_OK)
  retval = gh_cons(gh_ulong2scm(rv),
		   gh_str2scm(pEncryptedPart, ulEncryptedPartLen));
  else
    retval = gh_cons(gh_ulong2scm(rv),
		     SCM_BOOL_F);

  free(pEncryptedPart);

  return retval;
}
/* }}} */
/* {{{ SCM ck_decrypt_verify_update(SCM session, SCM enc_part, SCM null_data) */
SCM ck_decrypt_verify_update(SCM session, SCM enc_part, SCM null_data)
{
  CK_RV rv = CKR_OK;
  CK_SESSION_HANDLE hSession;
  CK_BYTE_PTR       pEncryptedPart;
  CK_ULONG          ulEncryptedPartLen;
  CK_BYTE_PTR       pPart;
  CK_ULONG          ulPartLen;
  SCM retval;
  int tmp_len;

  hSession = gh_scm2ulong(session);
  pEncryptedPart = gh_scm2newstr(enc_part, &tmp_len);
  ulEncryptedPartLen = tmp_len;

  DO_FKT(C_DecryptVerifyUpdate, (hSession,pEncryptedPart,ulEncryptedPartLen,NULL_PTR,&ulPartLen));

  pPart = malloc(ulPartLen);
  if(pPart == NULL_PTR)
    return gh_cons(gh_ulong2scm(CKR_HOST_MEMORY),
		   SCM_BOOL_F);

  if(null_data != SCM_BOOL_T)
    DO_FKT(C_DecryptVerifyUpdate, (hSession,pEncryptedPart,ulEncryptedPartLen,pPart,&ulPartLen));

  if(rv == CKR_OK)
  retval = gh_cons(gh_ulong2scm(rv),
		   gh_str2scm(pPart, ulPartLen));
  else
    retval = gh_cons(gh_ulong2scm(rv),
		     SCM_BOOL_F);

  free(pPart);

  return retval;
}
/* }}} */
/* {{{ SCM ck_wrap_key(SCM session, SCM mech_list, SCM wrapper, SCM wrappee, SCM null_data) */
SCM ck_wrap_key(SCM session, SCM mech_list, SCM wrapper, SCM wrappee, SCM null_data)
{
  CK_RV rv = CKR_OK;
  CK_SESSION_HANDLE hSession;
  CK_MECHANISM_PTR  pMechanism;
  CK_OBJECT_HANDLE  hWrappingKey;
  CK_OBJECT_HANDLE  hKey;
  CK_BYTE_PTR       pWrappedKey;
  CK_ULONG          ulWrappedKeyLen;
  SCM retval;

  hSession = gh_scm2ulong(session);
  pMechanism = ci_list2mechanism(mech_list);
  hWrappingKey = gh_scm2ulong(wrapper);
  hKey = gh_scm2ulong(wrappee);

  
  DO_FKT(C_WrapKey, (hSession, pMechanism, hWrappingKey, hKey, NULL_PTR, &ulWrappedKeyLen));
  if(rv != CKR_OK)
    return gh_cons(gh_ulong2scm(rv), SCM_BOOL_F);

  pWrappedKey = malloc(ulWrappedKeyLen);
  if(pWrappedKey == NULL_PTR)
    return gh_cons(gh_ulong2scm(CKR_HOST_MEMORY), SCM_BOOL_F);
  
  if(null_data != SCM_BOOL_T)
    DO_FKT(C_WrapKey, (hSession, pMechanism, hWrappingKey, hKey, pWrappedKey, &ulWrappedKeyLen));

  if(rv != CKR_OK)
    retval = gh_cons(gh_ulong2scm(rv), SCM_BOOL_F);    
  else 
    retval = gh_cons(gh_ulong2scm(rv), gh_str2scm(pWrappedKey,ulWrappedKeyLen));
  
  free(pWrappedKey);

  return retval;
}
/* }}} */
/* {{{ SCM ck_unwrap_key(SCM session, SCM mechanism, SCM unwrapper, SCM wrapped, SCM template) */
SCM ck_unwrap_key(SCM session, SCM mechanism, SCM unwrapper, SCM wrapped, SCM template)
{
  CK_RV rv = CKR_OK;
  CK_SESSION_HANDLE hSession;
  CK_MECHANISM_PTR  pMechanism;
  CK_OBJECT_HANDLE  hUnwrappingKey;
  CK_BYTE_PTR       pWrappedKey;
  CK_ULONG          ulWrappedKeyLen;
  CK_ATTRIBUTE_PTR  pTemplate;
  CK_ULONG          ulAttributeCount;
  CK_OBJECT_HANDLE  hKey=0;
  int tmp_len;

  hSession = gh_scm2ulong(session);
  pMechanism = ci_list2mechanism(mechanism);
  hUnwrappingKey = gh_scm2ulong(unwrapper);
  pWrappedKey = gh_scm2newstr(wrapped,&tmp_len);
  ulWrappedKeyLen = tmp_len;
  pTemplate = ci_list2template(template,&ulAttributeCount);

  DO_FKT(C_UnwrapKey, (hSession, pMechanism, hUnwrappingKey, 
		       pWrappedKey, ulWrappedKeyLen, 
		       pTemplate, ulAttributeCount, &hKey));
  
  ci_template_delete(pTemplate, ulAttributeCount);
  ci_mechanism_delete(pMechanism);

  return gh_cons(gh_ulong2scm(rv),gh_ulong2scm(hKey));
}
/* }}} */
/* {{{ SCM ck_derive_key(SCM session, SCM mechanism, SCM base_key, SCM template) */
SCM ck_derive_key(SCM session, SCM mechanism, SCM base_key, SCM template)
{
  CK_RV rv = CKR_OK;
  CK_SESSION_HANDLE hSession;
  CK_MECHANISM_PTR  pMechanism;
  CK_OBJECT_HANDLE  hBaseKey;
  CK_ATTRIBUTE_PTR  pTemplate;
  CK_ULONG          ulAttributeCount;
  CK_OBJECT_HANDLE  hKey=0;

  hSession = gh_scm2ulong(session);
  pMechanism = ci_list2mechanism(mechanism);
  pTemplate = ci_list2template(template,&ulAttributeCount);
  hBaseKey = gh_scm2ulong(base_key);
  
  DO_FKT(C_DeriveKey, (hSession,pMechanism,hBaseKey,pTemplate,ulAttributeCount,&hKey));

  ci_template_delete(pTemplate, ulAttributeCount);
  ci_mechanism_delete(pMechanism);

  return gh_cons(gh_ulong2scm(rv),gh_ulong2scm(hKey));
}
/* }}} */
/* {{{ SCM ck_get_function_status(SCM session) */
SCM ck_get_function_status(SCM session)
{
  CK_RV rv = CKR_OK;
  CK_SESSION_HANDLE hSession;

  hSession = gh_scm2ulong(session);

  DO_FKT(C_GetFunctionStatus, (hSession));

  return gh_ulong2scm(rv);
}
/* }}} */
/* {{{ SCM ck_cancel_function(SCM session) */
SCM ck_cancel_function(SCM session)
{
  CK_RV rv = CKR_OK;
  CK_SESSION_HANDLE hSession;

  hSession = gh_scm2ulong(session);

  DO_FKT(C_CancelFunction, (hSession));

  return gh_ulong2scm(rv);
}
/* }}} */
/* {{{ SCM ck_wait_for_slot_event(SCM flags_ulong) */
SCM ck_wait_for_slot_event(SCM flags_ulong)
{
  CK_RV rv = CKR_OK;
  CK_FLAGS flags;
  CK_SLOT_ID Slot;

  flags = gh_scm2ulong(flags_ulong);

  DO_FKT(C_WaitForSlotEvent, (flags,&Slot,NULL_PTR));

  return gh_cons(gh_ulong2scm(rv),gh_ulong2scm(Slot));
}
/* }}} */

#ifndef NO_OPENSSL_CODE
/* {{{ X509_NAME* ci_list2X509_NAME(SCM list, X509_NAME *name) */
typedef struct {
const char* label;
long (*set_function)(X509_NAME*,const char*);
} SubjectMatch;

static SubjectMatch subject_match[] = {
  { "country",      &req_SetName_C },
  { "state",        &req_SetName_SP },
  { "locality",     &req_SetName_L },
  { "organization", &req_SetName_O },
  { "unit",         &req_SetName_OU },
  { "common_name",  &req_SetName_CN },
  { "email",        &req_SetName_EMail },
  { NULL, NULL}
};

static X509_NAME* ci_list2X509_NAME(SCM list, X509_NAME *name)
{
  SCM pair;
  unsigned long l_len;
  unsigned int i;
  unsigned char j;

  /* check that this is a list at all */
  if(!gh_list_p(list))
    {
      return NULL_PTR;
    }

  if(!name) return NULL_PTR;

  l_len= gh_length(list);
  
  for(i=0,j=0;i<l_len;i++,list = gh_cdr(list))
    {
      unsigned int len;
      char* label;
      char* value;
      char wrap=0;

      pair = gh_car(list);
      label = gh_scm2newstr(gh_car(pair),&len);
      value = gh_scm2newstr(gh_cdr(pair),&len);
      
      /* this continuous spin makes looking for a non match rather expensive,
	 but ordered matches will be fastest */
      for(;;j++)
	{
	  if(subject_match[j].label==NULL)
	    { 
	      j=0;
	      if(wrap++ >1)  /* no match */
		break; 
	    }
	  if(strcmp(subject_match[j].label,label) == 0)
	    {
	      (subject_match[j].set_function)(name,value);
	      break;
	    }
	     
	}

    }

  return name;
}
/* }}} */

/* ### these functions are to aid in certificate handling (ch) ### */
/* {{{ SCM ch_create_cert_req(SCM, SCM, SCM, SCM, SCM) */
SCM ch_create_cert_req(SCM session_ulong, SCM priv_key_ulong, SCM pub_key_ulong, SCM subject_list, SCM file_string)
{
  CK_RV rv = CKR_OK;
  CK_SESSION_HANDLE hSession;
  CK_OBJECT_HANDLE hPubKey;
  CK_OBJECT_HANDLE hPrivKey;
  char* filename=NULL;
  int tmp_len,nRetVal;
  BIO *fileBio;
  PKCS11_SESS *session;
  PKCS11_CTX *context;
  PKCS11* pkcs11_priv_key;
  EVP_PKEY_CTX* priv_Key;
  PKCS11* pkcs11_pub_key;
  EVP_PKEY_CTX* pub_Key;
  char* dot_pos;
  X509_REQ *req;

  hSession = gh_scm2ulong(session_ulong);
  hPubKey = gh_scm2ulong(pub_key_ulong);
  hPrivKey = gh_scm2ulong(priv_key_ulong);

  filename = gh_scm2newstr(file_string, &tmp_len);

  /* init and create req */
  printf("init and create req\n");

  if(!(req= X509_REQ_new()))
     goto clean_up;

  /* set the version */
  printf("set the Version\n");
  if (!ASN1_INTEGER_set(req->req_info->version,0L)) goto clean_up; /* version 1 */

  /* set the subject */
  printf("set the subject\n");

  if(!ci_list2X509_NAME(subject_list, req->req_info->subject))
    { rv = CKR_GENERAL_ERROR; goto clean_up;  }

  /* create the context */
  printf("create the context\n");

  context= PKCS11_CTX_new();
  context->dll_handle=dll_handle;
  context->methods=pkcs11_fkt_list;

  /* create the session object */
  printf("create the session object\n");

  session= PKCS11_SESS_new();
  session->ctx=context;
  session->session=hSession;

  /* create the keys */
  printf("create the keys\n");

  if((pkcs11_pub_key = PKCS11_new())== NULL)
     goto clean_up;

  pkcs11_pub_key->ctx = session->ctx;
  pkcs11_pub_key->session = session;
  pkcs11_pub_key->obj_handle = hPubKey;

  if ((pub_Key=EVP_PKEY_CTX_new()) == NULL)
    goto clean_up;
  
  EVP_PKEY_assign_PKCS11(pub_Key,pkcs11_pub_key);

  if((pkcs11_priv_key = PKCS11_new()) == NULL)
    goto clean_up;

  pkcs11_priv_key->ctx = session->ctx;
  pkcs11_priv_key->session = session;
  pkcs11_priv_key->obj_handle = hPrivKey;

  if ((priv_Key=EVP_PKEY_CTX_new()) == NULL)
    goto clean_up;
  
  EVP_PKEY_assign_PKCS11(priv_Key,pkcs11_priv_key);

  /* set the key */
  printf("set the key\n");

  if (X509_REQ_set_pubkey(req,pub_Key)<=0)
    { rv = CKR_GENERAL_ERROR; goto clean_up;  }

  /* sign the thing */
  printf("sign the thing\n");

  if (X509_REQ_sign(req,priv_Key,CERT_HASH_ALLG)<=0)
    { rv = CKR_GENERAL_ERROR; goto clean_up;  }
  
  /* verify to be sure */
  printf("verify to be sure\n");

  if (X509_REQ_verify(req,pub_Key)<=0)
    { rv = CKR_GENERAL_ERROR; goto clean_up;  }

  /* write to file */
  printf("write to file\n");

  fileBio=BIO_new_file((char *)filename,"wb");
  if (!fileBio)
    {
      rv= CKR_GENERAL_ERROR;
      goto clean_up;
    }

  /* check if this is supposed to be a der or a pem */
  dot_pos = strrchr(filename,'.');
  if(dot_pos == NULL) /* no extension give */
    {
      rv = CKR_GENERAL_ERROR;
      goto clean_up;
    }
  
  if( strcmp(dot_pos,".der") == 0)
    {

      i2d_X509_REQ_bio(fileBio,req);
      
    }
  else if( strcmp(dot_pos,".pem") == 0)
    {
      nRetVal = PEM_write_bio_X509_REQ(fileBio, req);
      if(nRetVal <= 0)
	{
	  rv=CKR_GENERAL_ERROR; 
	  goto clean_up;
	}
    }
  else
    {
      rv=CKR_GENERAL_ERROR; 
      goto clean_up;
    }
  
  if (req_FlushFile(fileBio) <= 0)
    {
      rv = CKR_GENERAL_ERROR;
      goto clean_up;
    }
  
  BIO_free(fileBio);

  /* done */
  printf("done\n");

  /* clean up */
clean_up:
  printf("clean up\n");
  if(req) X509_REQ_free(req);

  if(filename) free(filename);
  return gh_ulong2scm(rv);
}
/* }}} */

/* {{{ static int crypto_library_init(void) */
static int crypto_library_init(void)
{
#ifndef NO_DES
  EVP_add_cipher(EVP_des_cbc);
  EVP_add_cipher(EVP_des_ede3_cbc);
#endif
#ifndef NO_IDEA
  EVP_add_cipher(EVP_idea_cbc);
#endif
#ifndef NO_RC4
  EVP_add_cipher(EVP_rc4);
#endif  
#ifndef NO_RC2
  EVP_add_cipher(EVP_rc2_cbc);
#endif  
  
#ifndef NO_MD2
  EVP_add_digest(EVP_md2);
#endif
#ifndef NO_MD5
  EVP_add_digest(EVP_md5);
  EVP_add_digest_alias(SN_md5,"ssl2-md5");
  EVP_add_digest_alias(SN_md5,"ssl3-md5");
  EVP_add_digest_alias(SN_md5,"RSA-MD5");
#endif
#ifndef NO_SHA
  EVP_add_digest(&EVP_sha1); /* RSA with sha1 */
  EVP_add_digest_alias(SN_sha1,"ssl3-sha1");
#endif
#if !defined(NO_SHA) && !defined(NO_DSA)
  EVP_add_digest(&EVP_dss1); /* DSA with sha1 */
#endif
  
  /* If you want support for phased out ciphers, add the following */
#if 0
  EVP_add_digest(EVP_sha());
  EVP_add_digest(EVP_dss());
#endif
  return(1);
}
/* }}} */
#endif

/*
 * Local variables:
 * folded-file: t
 * end:
 */

