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
 * NAME:        ceay_symbols.h
 * SYNOPSIS:    -
 * DESCRIPTION: declares macros to use the libceay functions via dlsym pointers transparently
 * FILES:       -
 * SEE/ALSO:    -
 * AUTHOR:      lbe
 * BUGS:        -
 */

#ifndef CEAY_SYMBOLS_H
#define CEAY_SYMBOLS_H

#include "internal.h"

typedef struct CI_ceay_SymbolTableType {
  char* name;
  void* sym;
} CI_CeaySymbolTableType;

extern CI_CeaySymbolTableType CI_CeaySymbolTable[];

extern void * CI_Ceay_lib_handle;

int CI_CeaySymbolTable_init(char* section_name);

#define CI_Ceay_RAND_set_rand_method ((void (*) (RAND_METHOD *meth))(CI_CeaySymbolTable[00].sym))
#define CI_Ceay_RAND_get_rand_method ((RAND_METHOD* (*) (void ))(CI_CeaySymbolTable[01].sym))
#define CI_Ceay_RAND_SSLeay          ((RAND_METHOD* (*) (void))(CI_CeaySymbolTable[02].sym))
#define CI_Ceay_RAND_cleanup         ((void (*) (void ))(CI_CeaySymbolTable[03].sym))
#define CI_Ceay_RAND_bytes           ((int (*) (unsigned char *buf,int num))(CI_CeaySymbolTable[04].sym))
#define CI_Ceay_RAND_seed            ((void (*) (const void *buf,int num))(CI_CeaySymbolTable[05].sym))
#define CI_Ceay_RAND_load_file       ((int (*) (const char *file,long max_bytes))(CI_CeaySymbolTable[06].sym))
#define CI_Ceay_RAND_write_file      ((int (*) (const char *file))(CI_CeaySymbolTable[07].sym))
#define CI_Ceay_RAND_file_name       ((const char* (*) (char *file,size_t num))(CI_CeaySymbolTable[08].sym))
#define CI_Ceay_RAND_screen          ((void (*) (void))(CI_CeaySymbolTable[09].sym))
#define CI_Ceay_SHA1_Init            ((void (*) (SHA_CTX *c))(CI_CeaySymbolTable[10].sym))
#define CI_Ceay_SHA1_Update          ((void (*) (SHA_CTX *c, const void *data, unsigned long len))(CI_CeaySymbolTable[11].sym))
#define CI_Ceay_SHA1_Final           ((void (*) (unsigned char *md, SHA_CTX *c))(CI_CeaySymbolTable[12].sym))
#define CI_Ceay_SHA1                 ((unsigned char* (*) (const unsigned char *d, unsigned long n,unsigned char *md))(CI_CeaySymbolTable[13].sym))
#define CI_Ceay_SHA1_Transform       ((void (*) (SHA_CTX *c, const unsigned char *data))(CI_CeaySymbolTable[14].sym))
#define CI_Ceay_RSA_new              ((RSA* (*) (void))(CI_CeaySymbolTable[15].sym))
#define CI_Ceay_RSA_new_method       ((RSA* (*) (RSA_METHOD *method))(CI_CeaySymbolTable[16].sym))
#define CI_Ceay_RSA_size             ((int (*) (RSA *))(CI_CeaySymbolTable[17].sym))
#define CI_Ceay_RSA_generate_key     ((RSA* (*) (int bits, unsigned long e,void (*callback)(int,int,void *),void *cb_arg))(CI_CeaySymbolTable[18].sym))
#define CI_Ceay_RSA_check_key        ((int (*) (RSA *))(CI_CeaySymbolTable[19].sym))
#define CI_Ceay_RSA_public_encrypt   ((int (*) (int flen, unsigned char *from, unsigned char *to, RSA *rsa,int padding))(CI_CeaySymbolTable[20].sym))
#define CI_Ceay_RSA_private_encrypt  ((int (*) (int flen, unsigned char *from, unsigned char *to, RSA *rsa,int padding))(CI_CeaySymbolTable[21].sym))
#define CI_Ceay_RSA_public_decrypt   ((int (*) (int flen, unsigned char *from, unsigned char *to, RSA *rsa,int padding))(CI_CeaySymbolTable[22].sym))
#define CI_Ceay_RSA_private_decrypt  ((int (*) (int flen, unsigned char *from, unsigned char *to, RSA *rsa,int padding))(CI_CeaySymbolTable[23].sym))
#define CI_Ceay_RSA_free             ((void (*) (RSA *r))(CI_CeaySymbolTable[24].sym))
#define CI_Ceay_RSA_flags            ((int (*) (RSA *r))(CI_CeaySymbolTable[25].sym))
#define CI_Ceay_RSA_sign             ((int (*) (int type, unsigned char *m, unsigned int m_len, unsigned char *sigret, unsigned int *siglen, RSA *rsa))(CI_CeaySymbolTable[26].sym))
#define CI_Ceay_RSA_verify           ((int (*) (int type, unsigned char *m, unsigned int m_len, unsigned char *sigbuf, unsigned int siglen, RSA *rsa))(CI_CeaySymbolTable[27].sym))
#define CI_Ceay_BN_bn2bin            ((int (*) (const BIGNUM *a, unsigned char *to))(CI_CeaySymbolTable[28].sym))
#define CI_Ceay_BN_bin2bn            ((BIGNUM* (*) (const unsigned char *s,int len,BIGNUM *ret))(CI_CeaySymbolTable[29].sym))

#define CI_Ceay_BN_CTX_free          ((void (*) (BN_CTX *c))(CI_CeaySymbolTable[30].sym))
#define CI_Ceay_BN_CTX_new           ((BN_CTX* (*) (void))(CI_CeaySymbolTable[31].sym))
#define CI_Ceay_BN_cmp               ((int (*) (const BIGNUM *a, const BIGNUM *b))(CI_CeaySymbolTable[32].sym))
#define CI_Ceay_BN_free              ((void (*) (BIGNUM *a))(CI_CeaySymbolTable[33].sym))
#define CI_Ceay_BN_gcd               ((int (*) (BIGNUM *r,BIGNUM *in_a,BIGNUM *in_b,BN_CTX *ctx))(CI_CeaySymbolTable[34].sym))
#define CI_Ceay_BN_generate_prime    ((BIGNUM* (*) (BIGNUM *ret,int bits,int safe,BIGNUM *add)(CI_CeaySymbolTable[35].sym))
#define CI_Ceay_BN_get_word          ((BN_ULONG (*) (BIGNUM *a))(CI_CeaySymbolTable[36].sym))
#define CI_Ceay_BN_lshift            ((int (*) (BIGNUM *r, const BIGNUM *a, int n))(CI_CeaySymbolTable[37].sym))
#define CI_Ceay_BN_mod               ((int (*) (BIGNUM *rem, const BIGNUM *m, const BIGNUM *d, BN_CTX *ctx))(CI_CeaySymbolTable[38].sym))
#define CI_Ceay_BN_mod_inverse       ((BIGNUM* (*) (BIGNUM *ret,BIGNUM *a, const BIGNUM *n,BN_CTX *ctx))(CI_CeaySymbolTable[39].sym))
#define CI_Ceay_BN_mul               ((int (*) (BIGNUM *r, BIGNUM *a, BIGNUM *b, BN_CTX *ctx))(CI_CeaySymbolTable[40].sym))
#define CI_Ceay_BN_new               ((BIGNUM* (*) (void))(CI_CeaySymbolTable[41].sym))
#define CI_Ceay_BN_num_bits          ((int (*) (const BIGNUM *a))(CI_CeaySymbolTable[42].sym))
#define CI_Ceay_BN_set_word          ((int (*) (BIGNUM *a, BN_ULONG w))(CI_CeaySymbolTable[43].sym))
#define CI_Ceay_BN_sub               ((int (*) (BIGNUM *r, const BIGNUM *a, const BIGNUM *b))(CI_CeaySymbolTable[44].sym))
#define CI_Ceay_BN_value_one         ((BIGNUM* (*) (void))(CI_CeaySymbolTable[45].sym))
#define CI_Ceay_DSA_free             ((void (*) (DSA *r))(CI_CeaySymbolTable[46].sym))
#define CI_Ceay_DSA_generate_key     ((int (*) (DSA *a))(CI_CeaySymbolTable[47].sym))
#define CI_Ceay_DSA_new              ((DSA* (*) (void))(CI_CeaySymbolTable[48].sym))
#define CI_Ceay_DSA_sign             ((int (*) (int type,const unsigned char *dgst,int dlen)(CI_CeaySymbolTable[49].sym))
#define CI_Ceay_DSA_verify           ((int	(*) (int type,const unsigned char *dgst,int dgst_len)(CI_CeaySymbolTable[50].sym))
#define CI_Ceay_EVP_PKEY2PKCS8       ((PKCS8_PRIV_KEY_INFO* (*) (EVP_PKEY *pkey))(CI_CeaySymbolTable[51].sym))
#define CI_Ceay_EVP_PKEY_assign      ((int (*) (EVP_PKEY *pkey,int type,char *key))(CI_CeaySymbolTable[52].sym))
#define CI_Ceay_EVP_PKEY_free        ((void (*) (EVP_PKEY *pkey))(CI_CeaySymbolTable[53].sym))
#define CI_Ceay_EVP_PKEY_new         ((EVP_PKEY* (*) (void))(CI_CeaySymbolTable[54].sym))
#define CI_Ceay_MD2_Final            ((void (*) (unsigned char *md, MD2_CTX *c))(CI_CeaySymbolTable[55].sym))
#define CI_Ceay_MD2_Init             ((void (*) (MD2_CTX *c))(CI_CeaySymbolTable[56].sym))
#define CI_Ceay_MD2_Update           ((void (*) (MD2_CTX *c, const unsigned char *data, unsigned long len))(CI_CeaySymbolTable[57].sym))
#define CI_Ceay_MD5_Final            ((void (*) (unsigned char *md, MD5_CTX *c))(CI_CeaySymbolTable[58].sym))
#define CI_Ceay_MD5_Init             ((void (*) (MD5_CTX *c))(CI_CeaySymbolTable[59].sym))
#define CI_Ceay_MD5_Update           ((void (*) (MD5_CTX *c, const void *data, unsigned long len))(CI_CeaySymbolTable[60].sym))
#define CI_Ceay_OBJ_obj2nid          ((int  (*) (ASN1_OBJECT *o))(CI_CeaySymbolTable[61].sym))
#define CI_Ceay_RC2_cbc_encrypt      ((void (*) (const unsigned char *in, unsigned char *out, long length)(CI_CeaySymbolTable[62].sym))
#define CI_Ceay_RC2_ecb_encrypt      ((void (*) (const unsigned char *in,unsigned char *out,RC2_KEY *key)(CI_CeaySymbolTable[63].sym))
#define CI_Ceay_RC2_set_key          ((void (*) (RC2_KEY *key, int len, const unsigned char *data,int bits))(CI_CeaySymbolTable[64].sym))
#define CI_Ceay_RC4                  ((void (*) (RC4_KEY *key, unsigned long len, const unsigned char *indata)(CI_CeaySymbolTable[65].sym))
#define CI_Ceay_RC4_set_key          ((void (*) (RC4_KEY *key, int len, const unsigned char *data))(CI_CeaySymbolTable[66].sym))
#define CI_Ceay_SHA_Init             ((void (*) (SHA_CTX *c))(CI_CeaySymbolTable[67].sym))
#define CI_Ceay_d2i_PKCS8_PRIV_KEY_INFO ((PKCS8_PRIV_KEY_INFO* (*) (PKCS8_PRIV_KEY_INFO **a,unsigned char **pp, long length))(CI_CeaySymbolTable[68].sym))
#define CI_Ceay_d2i_RSAPrivateKey    ((RSA* (*) (RSA **a, unsigned char **pp, long length))(CI_CeaySymbolTable[69].sym))
#define CI_Ceay_d2i_RSAPublicKey     ((RSA* (*) (RSA **a, unsigned char **pp, long length))(CI_CeaySymbolTable[70].sym))
#define CI_Ceay_des_ecb3_encrypt     ((void (*) (const_des_cblock *input, des_cblock *output,des_key_schedule ks1,des_key_schedule ks2,des_key_schedule ks3, int enc))(CI_CeaySymbolTable[71].sym))
#define CI_Ceay_des_ecb_encrypt      ((void (*) (const_des_cblock *input,des_cblock *output,des_key_schedule ks,int enc))(CI_CeaySymbolTable[72].sym))
#define CI_Ceay_des_ede3_cbc_encrypt ((void (*) (const unsigned char *input,unsigned char *output,long length,des_key_schedule ks1,des_key_schedule ks2,des_key_schedule ks3,des_cblock *ivec,int enc))(CI_CeaySymbolTable[73].sym))
#define CI_Ceay_des_is_weak_key      ((int (*) (const_des_cblock *key))(CI_CeaySymbolTable[74].sym))
#define CI_Ceay_des_ncbc_encrypt     ((void (*) (const unsigned char *input,unsigned char *output,long length,des_key_schedule schedule,des_cblock *ivec,int enc))(CI_CeaySymbolTable[75].sym))
#define CI_Ceay_des_set_key          ((int (*) (const_des_cblock *key,des_key_schedule schedule))(CI_CeaySymbolTable[76].sym))
#define CI_Ceay_des_set_odd_parity   ((void (*) (des_cblock *key))(CI_CeaySymbolTable[77].sym))
#define CI_Ceay_i2d_PKCS8_PRIV_KEY_INFO ((int (*) (PKCS8_PRIV_KEY_INFO *a, unsigned char **pp))(CI_CeaySymbolTable[78].sym))
#define CI_Ceay_i2d_RSAPrivateKey    ((int (*) (RSA *a, unsigned char **pp))(CI_CeaySymbolTable[79].sym))
#define CI_Ceay_i2d_RSAPublicKey     ((int (*) (RSA *a, unsigned char **pp))(CI_CeaySymbolTable[80].sym))
#define CI_Ceay_idea_cbc_encrypt     ((void (*) (const unsigned char *in, unsigned char *out,long length, IDEA_KEY_SCHEDULE *ks, unsigned char *iv,int enc))(CI_CeaySymbolTable[81].sym))
#define CI_Ceay_idea_ecb_encrypt     ((void (*) (const unsigned char *in, unsigned char *out,IDEA_KEY_SCHEDULE *ks))(CI_CeaySymbolTable[82].sym))
#define CI_Ceay_idea_set_decrypt_key ((void (*) (IDEA_KEY_SCHEDULE *ek, IDEA_KEY_SCHEDULE *dk))(CI_CeaySymbolTable[83].sym))
#define CI_Ceay_idea_set_encrypt_key ((void (*) (const unsigned char *key, IDEA_KEY_SCHEDULE *ks))(CI_CeaySymbolTable[84].sym))

#define CI_CEAY_SYMBOL_TABLE_SIZE 85

#endif CEAY_SYMBOLS_H




