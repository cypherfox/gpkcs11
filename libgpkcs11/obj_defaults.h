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
 * NAME:        obj_defaults.h
 * SYNOPSIS:    -
 * DESCRIPTION: -
 * FILES:       -
 * SEE/ALSO:    -
 * AUTHOR:      lbe
 * BUGS:        -
 */

#ifndef _OBJ_DEFAULTS_H
#define _OBJ_DEFAULTS_H 1

#ifndef OBJECT_DEFAULT_LOAD
#error obj_defaults.h should only be called from objects.c
#endif /* OBJECT_DEFAULT_LOAD */

#include "objects.h"

CK_ATTRIBUTE CK_I_obj_default_arr[] = {
  {CKA_TOKEN, &CK_I_false, sizeof(CK_I_false)},
  {CKA_PRIVATE, &CK_I_true, sizeof(CK_I_true)},
  {CKA_MODIFIABLE, &CK_I_true, sizeof(CK_I_true)},
  {CKA_LABEL, CK_I_empty_str, sizeof(CK_I_empty_str)},
  {CKA_APPLICATION, CK_I_empty_str, sizeof(CK_I_empty_str)},
  {CKA_VALUE, CK_I_empty_bytes, sizeof(CK_I_empty_bytes)},
  {CKA_ID, CK_I_empty_bytes, sizeof(CK_I_empty_bytes)},
  {CKA_ISSUER, CK_I_empty_bytes, sizeof(CK_I_empty_bytes)},
  {CKA_DERIVE, &CK_I_false, sizeof(CK_I_false)},
  {CKA_SUBJECT, CK_I_empty_bytes, sizeof(CK_I_empty_bytes)},
  {CKA_SENSITIVE, &CK_I_false, sizeof(CK_I_false)},
  {CKA_ALWAYS_SENSITIVE, &CK_I_false, sizeof(CK_I_false)}
};

#define CK_I_OBJ_DEFAULTS_SIZE 12
CK_I_OBJ_PTR CK_I_obj_default = NULL_PTR;

#endif /* _OBJ_DEFAULTS_H */
/*
 * Local variables:
 * folded-file: t
 * end:
 */
