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
 * NAME:        ceay_symbols.c
 * SYNOPSIS:    -
 * DESCRIPTION: init the symbol table.
 * FILES:       -
 * SEE/ALSO:    -
 * AUTHOR:      lbe
 * BUGS:        -
 */

static char RCSID[]="$Id$";
const char* ceay_symbols_c_version(){return RCSID;}

#include "ceay_symbols.h"
#include "init.h"
#include "dll_wrap.h"

#ifdef CK_Win32
# include <windows.h>
# include <winuser.h>
#elif CK_GENERIC
# include <dlfcn.h>
#endif /* !CK_Win32 */

void * CI_Ceay_lib_handle;

CI_CeaySymbolTableType CI_CeaySymbolTable[] ={
  {"RAND_set_rand_method",NULL},   /* 00 */
  {"RAND_get_rand_method",NULL},   /* 01 */
  {"RAND_SSLeay",NULL},            /* 02 */
  {"RAND_cleanup",NULL},           /* 03 */
  {"RAND_bytes",NULL},             /* 04 */
  {"RAND_seed",NULL},              /* 05 */
  {"RAND_load_file",NULL},         /* 06 */
  {"RAND_write_file",NULL},        /* 07 */
  {"RAND_file_name",NULL},         /* 08 */
  {"RAND_screen",NULL},            /* 09 */
  {"SHA1_Init",NULL},              /* 10 */
  {"SHA1_Update",NULL},            /* 11 */
  {"SHA1_Final",NULL},             /* 12 */
  {"SHA1",NULL},                   /* 13 */
  {"SHA1_Transform",NULL},         /* 14 */
  {"RSA_new",NULL},                /* 15 */
  {"RSA_new_method",NULL},         /* 16 */
  {"RSA_size",NULL},               /* 17 */
  {"RSA_generate_key",NULL},       /* 18 */
  {"RSA_check_key",NULL},          /* 19 */
  {"RSA_public_encrypt",NULL},     /* 20 */
  {"RSA_private_encrypt",NULL},    /* 21 */
  {"RSA_public_decrypt",NULL},     /* 22 */
  {"RSA_private_decrypt",NULL},    /* 23 */
  {"RSA_free ",NULL},              /* 24 */
  {"RSA_flags",NULL},              /* 25 */
  {"RSA_sign",NULL},               /* 26 */
  {"RSA_verify",NULL},             /* 27 */
  {"BN_bn2bin",NULL},              /* 28 */
  {"BN_bin2bn",NULL},              /* 29 */
  {"BN_CTX_free",NULL},            /* 30 */
  {"BN_CTX_new",NULL},             /* 31 */
  {"BN_cmp",NULL},                 /* 32 */
  {"BN_free",NULL},                /* 33 */
  {"BN_gcd",NULL},                 /* 34 */
  {"BN_generate_prime",NULL},      /* 35 */
  {"BN_get_word",NULL},            /* 36 */
  {"BN_lshift",NULL},              /* 37 */
  {"BN_mod",NULL},                 /* 38 */
  {"BN_mod_inverse",NULL},         /* 39 */
  {"BN_mul",NULL},                 /* 40 */
  {"BN_new",NULL},                 /* 41 */
  {"BN_num_bits",NULL},            /* 42 */
  {"BN_set_word",NULL},            /* 43 */
  {"BN_sub",NULL},                 /* 44 */
  {"BN_value_one",NULL},           /* 45 */
  {"DSA_free",NULL},               /* 46 */
  {"DSA_generate_key",NULL},       /* 47 */
  {"DSA_new",NULL},                /* 48 */
  {"DSA_sign",NULL},               /* 49 */
  {"DSA_verify",NULL},             /* 50 */
  {"EVP_PKEY2PKCS8",NULL},         /* 51 */
  {"EVP_PKEY_assign",NULL},        /* 52 */
  {"EVP_PKEY_free",NULL},          /* 53 */
  {"EVP_PKEY_new",NULL},           /* 54 */
  {"MD2_Final",NULL},              /* 55 */
  {"MD2_Init",NULL},               /* 56 */
  {"MD2_Update",NULL},             /* 57 */
  {"MD5_Final",NULL},              /* 58 */
  {"MD5_Init",NULL},               /* 59 */
  {"MD5_Update",NULL},             /* 60 */
  {"OBJ_obj2nid",NULL},            /* 61 */
  {"RC2_cbc_encrypt",NULL},        /* 62 */
  {"RC2_ecb_encrypt",NULL},        /* 63 */
  {"RC2_set_key",NULL},            /* 64 */
  {"RC4",NULL},                    /* 65 */
  {"RC4_set_key",NULL},            /* 66 */
  {"SHA_Init",NULL},               /* 67 */
  {"d2i_PKCS8_PRIV_KEY_INFO",NULL},/* 68 */
  {"d2i_RSAPrivateKey",NULL},      /* 69 */
  {"d2i_RSAPublicKey",NULL},       /* 70 */
  {"des_ecb3_encrypt",NULL},       /* 71 */
  {"des_ecb_encrypt",NULL},        /* 72 */
  {"des_ede3_cbc_encrypt",NULL},   /* 73 */
  {"des_is_weak_key",NULL},        /* 74 */
  {"des_ncbc_encrypt",NULL},       /* 75 */
  {"des_set_key",NULL},            /* 76 */
  {"des_set_odd_parity",NULL},     /* 77 */
  {"i2d_PKCS8_PRIV_KEY_INFO",NULL},/* 78 */
  {"i2d_RSAPrivateKey",NULL},      /* 79 */
  {"i2d_RSAPublicKey",NULL},       /* 80 */
  {"idea_cbc_encrypt",NULL},       /* 81 */
  {"idea_ecb_encrypt",NULL},       /* 82 */
  {"idea_set_decrypt_key",NULL},   /* 83 */
  {"idea_set_encrypt_key",NULL},   /* 84 */
};

CK_RV CI_CeaySymbolTable_init(char* section_name)
{
  char* libpath=NULL_PTR;
  CKR_RV rv =CKR_OK;
  CK_CHAR_PTR reason = NULL_PTR;
  
  /* get name and path of libcrypt from config */
  rv= CI_GetConfigString(section_name,"CryptoDLL",&libpath);
  if(rv != CKR_OK) return rv;
  
  /* open libcrypt */
#if defined(CK_Win32)
  if((CI_Ceay_lib_handle = LoadLibrary(libpath)) == NULL_PTR)
    {
      rv = CKR_GENERAL_ERROR;
      
      FormatMessage( FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
		     NULL, GetLastError(),
		     MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // Default language
		     (LPTSTR) &reason,
		     0, NULL);
            
#else /* ! defined(CK_Win32) */
  if((CI_Ceay_lib_handle = dlopen(libpath, RTLD_LAZY)) == NULL_PTR)
    {
      
      rv = CKR_GENERAL_ERROR;
      reason = dlerror();
      
#endif /* ! defined(CK_Win32) */
      CI_VarLogEntry("CI_CeaySymbolTable_init", "Opening Dynamic Library '%s' failed: %s", 
		     rv, 0,libpath,reason); 
      
#if defined(CK_Win32)
      LocalFree(reason);
#endif /* defined(CK_Win32) */
      
      return rv;      
    }

  /* read all the symbols */
  for(i=0; i<CI_CEAY_SYMBOL_TABLE_SIZE ; i++)
    if((CI_CeaySymbolTable[i].sym= DREF_DLL(CI_Ceay_lib_handle,void*,CI_CeaySymbolTable[i].name))
       == NULL_PTR)
      {
	rv = CKR_GENERAL_ERROR;
	reason = dlerror();
	CI_VarLogEntry("CI_CeaySymbolTable_init", "Reading Symbol '%s' from libcrypto failed: %s", 
		       rv, 0,CI_CeaySymbolTable[i].name,reason);
	return rv;
      }

  return rv;
}

/*
 * Local variables:
 * folded-file: t
 * end:
 */
