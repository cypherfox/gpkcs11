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
 * NAME:	ctok_mem.h
 * SYNOPSIS:	-
 * DESCRIPTION: -
 * FILES:	-
 * SEE/ALSO:	-
 * AUTHOR:	lbe
 * BUGS: 	-
 */

#ifndef CTOK_MEM_H
#define CTOK_MEM_H

#include <openssl/rc4.h>

/* digesting */
#include <openssl/md5.h>
#include <openssl/md2.h>
#include <openssl/sha.h>

CK_BYTE_PTR CI_ByteStream_new(CK_ULONG len);
RC4_KEY CK_PTR CI_RC4Key_new(void);
void CI_RC4Key_delete(RC4_KEY CK_PTR key);
RC2_KEY CK_PTR CI_RC2Key_new(void);
void CI_RC2Key_delete(RC2_KEY CK_PTR key);
CK_I_CEAY_RC2_INFO_PTR CI_RC2_INFO_new(void);
void CI_RC2_INFO_delete(CK_I_CEAY_RC2_INFO_PTR obj);
des_cblock CK_PTR CI_des_cblock_new(void);
CK_BYTE_PTR CI_des3_cblock_new(void);
CK_I_CEAY_DES_INFO_PTR CI_DES_INFO_new(void);
void CI_DES_INFO_delete( CK_I_CEAY_DES_INFO_PTR obj);
CK_I_CEAY_IDEA_INFO_PTR CI_IDEA_INFO_new(void);
void CI_IDEA_INFO_delete( CK_I_CEAY_IDEA_INFO_PTR obj);
CK_I_CEAY_DES3_INFO_PTR CI_DES3_INFO_new(CK_BYTE_PTR keys);
void CI_DES3_INFO_delete(CK_I_CEAY_DES3_INFO_PTR obj);
IDEA_KEY_SCHEDULE CK_PTR CI_IDEA_KEY_SCHEDULE_new(void);
MD5_CTX CK_PTR CI_MD5_CTX_new(void);
MD2_CTX CK_PTR CI_MD2_CTX_new(void);
SHA_CTX CK_PTR CI_SHA_CTX_new(void);
CK_I_MD5_MAC_STATE_PTR CI_MD5_MAC_STATE_new(void);
CK_I_SHA_MAC_STATE_PTR CI_SHA_MAC_STATE_new(void);
CK_VERSION CK_PTR CI_VERSION_new(void);
void CK_ATTRIBUTE_delete(CK_ATTRIBUTE_PTR attrib);
#endif /* CTOK_MEM_H */
