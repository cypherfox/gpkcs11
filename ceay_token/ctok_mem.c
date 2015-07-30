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
 * State:	$State$ $Locker$
 * NAME:	ctok_mem.c
 * SYNOPSIS:	-
 * DESCRIPTION: -
 * FILES:	-
 * SEE/ALSO:	-
 * AUTHOR:	lbe
 * BUGS: *	-
 * HISTORY:	$Log$
 * HISTORY:	Revision 1.3  2000/06/26 16:01:35  lbe
 * HISTORY:	update changes for pl 0.7.1
 * HISTORY:	
 * HISTORY:	Revision 1.2  1999/10/06 07:57:19  lbe
 * HISTORY:	solved netscape symbol clash problem
 * HISTORY:	
 * HISTORY:	Revision 1.1  1999/06/04 14:58:37  lbe
 * HISTORY:	change to libtool/automake complete (except for __umoddi prob)
 * HISTORY:	
 * HISTORY:	Revision 1.5  1999/01/19 12:19:38  lbe
 * HISTORY:	first release lockdown
 * HISTORY:
 * HISTORY:	Revision 1.4  1998/12/07 13:19:42  lbe
 * HISTORY:	TC_free von parametern für Zeile und Datei befreit.
 * HISTORY:
 * HISTORY:	Revision 1.3  1998/11/13 10:10:25  lbe
 * HISTORY:	added persistent storage.
 * HISTORY:
 * HISTORY:	Revision 1.2  1998/11/03 16:00:22  lbe
 * HISTORY:	auto-lockdown
 * HISTORY:
 * HISTORY:	Revision 1.1  1998/10/12 10:00:31  lbe
 * HISTORY:	clampdown
 * HISTORY:
 */

static char RCSID[]="$Id$";
const char* ctok_mem_c_version(){return RCSID;}

#ifndef CK_I_library_build
#define CK_I_library_build
#endif

#include "ceay_token.h"
#include "objects.h"
#include "ctok_mem.h"
#include "error.h"

#include <stdlib.h>

#include "CI_Ceay.h"

/* the functions in this file allocate memory for the use in ceay_tok.c */
/* all allocation should take place in this file */

/* {{{ CK_BYTE_PTR CI_ByteStream_new(CK_ULONG len) */
CK_BYTE_PTR CI_ByteStream_new(CK_ULONG len)
{
  return TC_malloc(sizeof(CK_BYTE)*len);
}
/* }}} */
/* {{{ RC4_KEY CK_PTR CI_RC4Key_new() */
RC4_KEY CK_PTR CI_RC4Key_new()
{
  return TC_malloc(sizeof(RC4_KEY));
}
/* }}} */
/* {{{ void CI_RC4Key_delete(RC4_KEY CK_PTR key) */
void CI_RC4Key_delete(RC4_KEY CK_PTR key)
{
  if(key == NULL_PTR)
    return;

  TC_free(key);

  return;
}
/* }}} */
/* {{{ RC2_KEY CK_PTR CI_RC2Key_new() */
RC2_KEY CK_PTR CI_RC2Key_new()
{
  return TC_malloc(sizeof(RC2_KEY));
}
/* }}} */
/* {{{ void CI_RC2Key_delete(RC2_KEY CK_PTR key) */
void CI_RC2Key_delete(RC2_KEY CK_PTR key)
{
  if(key == NULL_PTR)
    return;

  TC_free(key);

  return;
}
/* }}} */
/* {{{ CK_I_CEAY_RC2_INFO_PTR CI_RC2_INFO_new() */
CK_I_CEAY_RC2_INFO_PTR CI_RC2_INFO_new()
{
  CK_I_CEAY_RC2_INFO_PTR retval = NULL_PTR;
  
  retval = TC_calloc(1,sizeof(CK_I_CEAY_RC2_INFO));
  if(retval == NULL_PTR) return retval;

  retval->key = CI_RC2Key_new();
  if(retval->key == NULL_PTR)
    {
      CI_RC2_INFO_delete(retval);
      return NULL_PTR;
    }
  
  return retval;
}
/* }}} */
/* {{{ void CI_RC2_INFO_delete(CK_I_CEAY_RC2_INFO_PTR obj) */
void CI_RC2_INFO_delete(CK_I_CEAY_RC2_INFO_PTR obj)
{
  if(obj == NULL_PTR) return;

  if(obj->key != NULL_PTR) 
    {
      TC_free(obj->key);
    }

  TC_free(obj);
  
  return;
}
/* }}} */
/* {{{ des_cblock CK_PTR CI_des_cblock_new() */
des_cblock CK_PTR CI_des_cblock_new()
{
  return TC_malloc(sizeof(des_cblock));
}
/* }}} */
/* {{{ CK_BYTE_PTR CI_des3_cblock_new(void) */
CK_BYTE_PTR CI_des3_cblock_new(void)
{
  return TC_malloc(sizeof(des_cblock)*3);
}
/* }}} */
/* {{{ CK_I_CEAY_DES_INFO_PTR CI_DES_INFO_new() */
CK_I_CEAY_DES_INFO_PTR CI_DES_INFO_new()
{
  /* the caller will detect if this failed */
  CK_I_CEAY_DES_INFO_PTR retval = TC_malloc(sizeof(CK_I_CEAY_DES_INFO));
  return retval;
}
/* }}} */
/* {{{ void CI_DES_INFO_delete( CK_I_CEAY_DES_INFO_PTR obj) */
void CI_DES_INFO_delete( CK_I_CEAY_DES_INFO_PTR obj)
{
  if(obj == NULL_PTR) return;

  TC_free(obj);

  return;
}
/* }}} */

/* {{{ CK_I_CEAY_IDEA_INFO_PTR CI_IDEA_INFO_new() */
CK_I_CEAY_IDEA_INFO_PTR CI_IDEA_INFO_new()
{
  CK_I_CEAY_IDEA_INFO_PTR retval = TC_malloc(sizeof(CK_I_CEAY_IDEA_INFO));
  if(retval == NULL_PTR) return retval;

  /* sched ist statische variable in der struktur */ 

  retval->ivec = TC_malloc(sizeof(CK_BYTE)*CK_I_IVEC_LEN);
  if(retval->ivec == NULL_PTR)
    {
      CI_IDEA_INFO_delete(retval);
      return NULL_PTR;
    }
  
  return retval;
}
/* }}} */
/* {{{ void CI_IDEA_INFO_delete( CK_I_CEAY_IDEA_INFO_PTR obj) */
void CI_IDEA_INFO_delete( CK_I_CEAY_IDEA_INFO_PTR obj)
{
  if(obj == NULL_PTR) return;

  if(obj->ivec) TC_free(obj->ivec);
  
  TC_free(obj);

  return;
}
/* }}} */

/* {{{ CK_I_CEAY_DES3_INFO_PTR CI_DES3_INFO_new(des_cblock CK_PTR keys) */
CK_I_CEAY_DES3_INFO_PTR CI_DES3_INFO_new(CK_BYTE_PTR keys)
{
  CK_I_CEAY_DES3_INFO_PTR retval = NULL_PTR;
  CK_BYTE_PTR key_start;

  retval = TC_malloc(sizeof(CK_I_CEAY_DES3_INFO));
  if(retval == NULL_PTR) return NULL_PTR;

  key_start = keys;
  des_set_key((des_cblock*)key_start, retval->sched[0]);

  key_start += sizeof(des_cblock);
  des_set_key((des_cblock*)key_start, retval->sched[1]);

  key_start += sizeof(des_cblock);
  des_set_key((des_cblock*)key_start, retval->sched[2]);

  retval->ivec = CI_des_cblock_new();
  if(retval->ivec == NULL_PTR)
    {
      TC_free(retval);
      return NULL_PTR;
    }

  return retval;
}
/* }}} */
/* {{{ void CI_DES3_INFO_delete(CK_I_CEAY_DES3_INFO_PTR obj) */
void CI_DES3_INFO_delete(CK_I_CEAY_DES3_INFO_PTR obj)
{
  if(!obj) return;

  if(obj->ivec) TC_free(obj);

  return;
}
/* }}} */
/* {{{ IDEA_KEY_SCHEDULE CK_PTR CI_IDEA_KEY_SCHEDULE_new() */
IDEA_KEY_SCHEDULE CK_PTR CI_IDEA_KEY_SCHEDULE_new()
{
  return TC_malloc(sizeof(IDEA_KEY_SCHEDULE));
}
/* }}} */
/* {{{ MD5_CTX CK_PTR CI_MD5_CTX_new() */
MD5_CTX CK_PTR CI_MD5_CTX_new()
{
  return TC_malloc(sizeof(MD5_CTX));
}
/* }}} */
/* {{{ MD2_CTX CK_PTR CI_MD2_CTX_new() */
MD2_CTX CK_PTR CI_MD2_CTX_new()
{
  return TC_malloc(sizeof(MD2_CTX));
}
/* }}} */
/* {{{ SHA_CTX CK_PTR CI_SHA_CTX_new() */
SHA_CTX CK_PTR CI_SHA_CTX_new()
{
  return TC_malloc(sizeof(SHA_CTX));
}
/* }}} */
/* {{{ CK_I_MD5_MAC_STATE_PTR CI_MD5_MAC_STATE_new() */
CK_I_MD5_MAC_STATE_PTR CI_MD5_MAC_STATE_new()
{
  CK_I_MD5_MAC_STATE_PTR retval = NULL_PTR;
  retval = TC_malloc(sizeof(CK_I_MD5_MAC_STATE));
  if(retval == NULL_PTR) return retval;

  retval->inner_CTX = TC_malloc(sizeof(MD5_CTX));
  if (retval->inner_CTX == NULL_PTR)
    {
      TC_free(retval);
      return NULL_PTR;
    }
  
  retval->outer_CTX = TC_malloc(sizeof(MD5_CTX));
  if (retval->outer_CTX == NULL_PTR)
    {
      TC_free(retval->inner_CTX);
      TC_free(retval);
      return NULL_PTR;
    }

  MD5_Init(retval->inner_CTX);
  MD5_Init(retval->outer_CTX);

  return retval;
}
/* }}} */
/* {{{ CK_I_SHA_MAC_STATE_PTR CI_SHA_MAC_STATE_new() */
CK_I_SHA_MAC_STATE_PTR CI_SHA_MAC_STATE_new()
{
  CK_I_SHA_MAC_STATE_PTR retval = NULL_PTR;
  retval = TC_malloc(sizeof(CK_I_SHA_MAC_STATE));
  if(retval == NULL_PTR) return retval;

  retval->inner_CTX = TC_malloc(sizeof(SHA_CTX));
  if (retval->inner_CTX == NULL_PTR)
    {
      TC_free(retval);
      return NULL_PTR;
    }
  
  retval->outer_CTX = TC_malloc(sizeof(SHA_CTX));
  if (retval->outer_CTX == NULL_PTR)
    {
      TC_free(retval->inner_CTX);
      TC_free(retval);
      return NULL_PTR;
    }

  CI_Ceay_SHA_Init(retval->inner_CTX);
  CI_Ceay_SHA_Init(retval->outer_CTX);

  return retval;
}
/* }}} */
/* {{{ CK_VERSION CK_PTR CI_VERSION_new() */
CK_VERSION CK_PTR CI_VERSION_new()
{
  return TC_malloc(sizeof(CK_VERSION));
}
/* }}} */
/* {{{ void CK_ATTRIBUTE_delete(CK_ATTRIBUTE_PTR attrib) */
void CK_ATTRIBUTE_delete(CK_ATTRIBUTE_PTR attrib)
{
  if(attrib == NULL_PTR) return;
  if(attrib->pValue != NULL_PTR) TC_free(attrib->pValue);
  TC_free(attrib);
  return;
}
/* }}} */
/*
 * Local variables:
 * folded-file: t
 * end:
 */
