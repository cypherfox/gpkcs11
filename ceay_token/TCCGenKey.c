/* -*- c -*- */
/*
 * This file is part of TC-PKCS11.
 * (c) 1999 TC TrustCenter for Security in DataNetworks GmbH 
 *
 * TC-PKCS11 is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *  
 * TC-PKCS11 is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *  
 * You should have received a copy of the GNU General Public License
 * along with TC-PKCS11; see the file COPYING.  If not, write to the Free
 * Software Foundation, 59 Temple Place - Suite 330, Boston, MA 02111, USA.  
 */
/*
 * RCSID:       $Id$
 * Source:      $Source$
 * Last Delta:  $Date$ $Revision$ $Author$
 * State:       $State$ $Locker$
 * NAME:        TCCGenKey.c
 * SYNOPSIS:    -
 * DESCRIPTION: Generates (RSA) key with additional tests
 * FILES:       -
 * SEE/ALSO:    -
 * AUTHOR:      gbe
 * BUGS: *      -
 * HISTORY:     $Log$
 * HISTORY:     Revision 1.3  1999/11/25 16:46:49  lbe
 * HISTORY:     moved all lib version defines into the conf.h
 * HISTORY:
 * HISTORY:     Revision 1.2  1999/11/02 13:47:14  lbe
 * HISTORY:     change of structures and bug fix in slot.c, add more files for tcsc_token: emptyfuncs and general_data
 * HISTORY:
 * HISTORY:     Revision 1.1  1999/06/04 14:58:36  lbe
 * HISTORY:     change to libtool/automake complete (except for __umoddi prob)
 * HISTORY:
 * HISTORY:     Revision 1.2  1999/01/19 12:19:34  lbe
 * HISTORY:     first release lockdown
 * HISTORY:
 * HISTORY:     Revision 1.1  1999/01/18 13:02:32  lbe
 * HISTORY:     swapped Berkeley DB for gdbm
 * HISTORY:
 * HISTORY:     Revision 1.1  1998/10/28 10:58:41  gbe
 * HISTORY:     Initial revision
 * HISTORY:
 */
 
static char RCSID[]="$Id$";
 
#include <stdio.h>

#include <openssl/crypto.h>
#include <openssl/rsa.h>

#include "TCCGenKey.h"

#include "CI_Ceay.h"


const char *TCC_GenKey_Version(void)
{
   return RCSID;
}

#define GK_HAS_PROP(flags,flag)  (((flags)&(flag))?1:0)
/* erst ab ssleay 0.9.0 gibt es das zusaetzliche Argument fuer
 * callback-Funktionen.
 */

#if SSLEAY_VERSION_NUMBER >= 0x0900
#define CB_ARGS int,int,void* 
#define CB_CUSTOM_ARG ,cb_arg 
#elif SSLEAY_VERSION_NUMBER >= 0x0800
#define CB_ARGS       int,int 
#define CB_CUSTOM_ARG 
#else
#error unknown SSLEAY version
#endif

#define LOW_LIMIT_KEYLEN_DIVISOR  3  /* p,q >
                                        2^(keylen/LOW_LIMIT_KEYLEN_DIVISOR) */
#define CLOSENESS_EXPONENT        0  /* p > q,   p > q*2^CLOSENESS_EXPONENT */
/*
 * Funktion :  TCC_GenKey_generate_rsa_key
 *             generiert ein RSA Keypair
 *
 * Parameter:  bits: keylength in bits
 *             e_value: value of exponent (e.g. RSA_F4)
 *             genkey_properties: combined GK_* property values
 *             callback: function to inform about the generation steps
 *             cb_arg: additional parmeter for callback function
 *
 * Precond  :  -
 * Postcond :  -
 * Return   :  keypair in RSA Format
 * Globals  :  -
 * Fehler   :  -
 */
RSA *TCC_GenKey_generate_rsa_key(unsigned long bits, unsigned long e_value,
                                 unsigned long genkey_properties,
                                 void (*callback)(int,int,char*),
                                 char *cb_arg)
{
 RSA *rsa=NULL;
 BIGNUM *r0=NULL,*r1=NULL,*r2=NULL,*r3=NULL,*tmp, *low_limit=NULL;
 int bitsp,bitsq,ok= -1,n=0;
 BN_CTX *ctx=NULL,*ctx2=NULL;

  ctx=BN_CTX_new();
  if (ctx == NULL) goto err;
  ctx2=BN_CTX_new();
  if (ctx2 == NULL) goto err;
//  r0=&(ctx->bn[0]);
//  r1=&(ctx->bn[1]);
//  r2=&(ctx->bn[2]);
//  r3=&(ctx->bn[3]);
//  ctx->tos+=4;
  BN_CTX_start(ctx);
  r0=BN_CTX_get(ctx);
  r1=BN_CTX_get(ctx);
  r2=BN_CTX_get(ctx);
  r3=BN_CTX_get(ctx);
  if (r0 == NULL || r1 == NULL || r2 == NULL || r3 == NULL)
		goto err;
  
  bitsp=(bits+1+CLOSENESS_EXPONENT)/2;  /* p and q should not be very close */
  bitsq=bits-bitsp;
  rsa=CI_Ceay_RSA_new();
  if (rsa == NULL) goto err;

  low_limit=BN_new(); /* p and q should (must) be bigger than this low_limit */
  BN_lshift( low_limit, BN_value_one(), bits/LOW_LIMIT_KEYLEN_DIVISOR );

  /* set e */ 
  rsa->e=BN_new();
  if (rsa->e == NULL) goto err;
  if (!BN_set_word(rsa->e,e_value)) goto err;

  /* generate p and q */
   /* generate p */
  for (;;)
  { rsa->p=BN_generate_prime(NULL, bitsp,
                             GK_HAS_PROP(genkey_properties,GK_PROP_STRONG),
                             NULL, NULL,
                             (void (*)(CB_ARGS))callback CB_CUSTOM_ARG);
    if (rsa->p == NULL) goto err;
    if (BN_cmp(rsa->p,low_limit) < 0)  /* do not accept any prime smaller
                                          than low_limit */
    { BN_free(rsa->p);
      continue;
    }
    if (!BN_sub(r2,rsa->p,BN_value_one())) goto err;
    if (!BN_gcd(r1,r2,rsa->e,ctx)) goto err;
    if (BN_is_one(r1)) break;
    if (callback != NULL) callback(3,n++,cb_arg);
    BN_free(rsa->p);
  }

  if (callback != NULL) callback(4,0,cb_arg);

   /* generate q */
generate_q:
  for (;;)
  { rsa->q=BN_generate_prime(NULL,bitsq,
                             GK_HAS_PROP(genkey_properties,GK_PROP_STRONG),
                             NULL, NULL,
                             (void (*)(CB_ARGS))callback CB_CUSTOM_ARG);
    if (rsa->q == NULL) goto err;
    if (BN_cmp(rsa->q,low_limit) < 0)  /* do not accept any prime smaller
                                          than low_limit */
    { BN_free(rsa->q);
      continue;
    }
    if (!BN_sub(r2,rsa->q,BN_value_one())) goto err;
    if (!BN_gcd(r1,r2,rsa->e,ctx)) goto err;
    if (BN_is_one(r1) && (BN_cmp(rsa->p,rsa->q) != 0))
      break;
    if (callback != NULL) callback(3,n++,cb_arg);
    BN_free(rsa->q);
  }

  if (callback != NULL) callback(4,1,cb_arg);

  /* p > q soll erfuellt sein  => ggf. umordnen */
  if (BN_cmp(rsa->p,rsa->q) < 0)
  { tmp=rsa->p;
    rsa->p=rsa->q;
    rsa->q=tmp;
  }

  /* check, that p and q are not very close, see also assignment to bitsp and
   * bitsq, because BN_rand is forced to set the left-mnost bit to 1 
   */
  tmp=BN_new();
  if (tmp == NULL) goto err;
  if (!BN_lshift(tmp,rsa->q,CLOSENESS_EXPONENT)) goto err; 
  if (BN_cmp(rsa->p,tmp) < 0)
  { BN_free(tmp);
    BN_free(rsa->q);
    goto generate_q;
  }
  BN_free(tmp);

  if (callback != NULL) callback(4,2,cb_arg);

  /* calculate n */
  rsa->n=BN_new();
  if (rsa->n == NULL) goto err;
  if (!BN_mul(rsa->n,rsa->p,rsa->q,ctx)) goto err;

  /* calculate d */
  if (!BN_sub(r1,rsa->p,BN_value_one())) goto err;        /* p-1 */
  if (!BN_sub(r2,rsa->q,BN_value_one())) goto err;        /* q-1 */
  if (!BN_mul(r0,r1,r2,ctx)) goto err;        /* (p-1)(q-1) */

  rsa->d=(BIGNUM *)BN_mod_inverse(NULL,rsa->e,r0,ctx2);        /* d */
  if (rsa->d == NULL) goto err;

  /* calculate d mod (p-1) */
  rsa->dmp1=BN_new();
  if (rsa->dmp1 == NULL) goto err;
  if (!BN_mod(rsa->dmp1,rsa->d,r1,ctx)) goto err;

  /* calculate d mod (q-1) */
  rsa->dmq1=BN_new();
  if (rsa->dmq1 == NULL) goto err;
  if (!BN_mod(rsa->dmq1,rsa->d,r2,ctx)) goto err;

  /* calculate inverse of q mod p */
  rsa->iqmp=BN_mod_inverse(NULL,rsa->q,rsa->p,ctx2);
  if (rsa->iqmp == NULL) goto err;

  ok=1;

err:
  BN_free(low_limit);
	if (ctx != NULL)
		{
			BN_CTX_end(ctx);
			BN_CTX_free(ctx);
		}
	if (ctx2 != NULL)
		{
			BN_CTX_end(ctx2);
			BN_CTX_free(ctx2);
		}

  if (!ok || (ok==-1))
    { if (rsa != NULL) 
        CI_Ceay_RSA_free(rsa);
     return(NULL);
    }
  else
   return(rsa);
}
