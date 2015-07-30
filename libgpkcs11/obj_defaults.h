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
 * NAME:        obj_defaults.h
 * SYNOPSIS:    -
 * DESCRIPTION: -
 * FILES:       -
 * SEE/ALSO:    -
 * AUTHOR:      lbe
 * BUGS: *      -
 * HISTORY:     $Log$
 * HISTORY:     Revision 1.2  2000/01/31 18:09:02  lbe
 * HISTORY:     lockdown prior to win_gdbm change
 * HISTORY:
 * HISTORY:     Revision 1.1  1999/06/16 09:46:09  lbe
 * HISTORY:     reorder files
 * HISTORY:
 * HISTORY:     Revision 1.5  1999/01/19 12:19:43  lbe
 * HISTORY:     first release lockdown
 * HISTORY:
 * HISTORY:     Revision 1.4  1998/08/05 08:57:29  lbe
 * HISTORY:     *** empty log message ***
 * HISTORY:
 * HISTORY:     Revision 1.3  1998/07/23 15:20:17  lbe
 * HISTORY:     working
 * HISTORY:
 * HISTORY:     Revision 1.2  1998/07/13 15:34:38  lbe
 * HISTORY:     *** empty log message ***
 * HISTORY:
 * HISTORY:     Revision 1.1  1998/07/02 17:19:12  lbe
 * HISTORY:     Initial revision
 * HISTORY:
 */

#ifndef _OBJ_DEFAULTS_H
#define _OBJ_DEFAULTS_H 1

#ifndef OBJECT_DEFAULT_LOAD
#error obj_defaults.h should only be called from objects.c
#endif /* OBJECT_DEFAULT_LOAD */

#include "objects.h"

CK_ATTRIBUTE CK_I_obj_attr_defaults_common[] =
{
  {CKA_TOKEN,       &CK_I_false,    sizeof(CK_I_false)},
  {CKA_PRIVATE,     &CK_I_true,     sizeof(CK_I_true)},          
  {CKA_MODIFIABLE,  &CK_I_true,     sizeof(CK_I_true)},
  {CKA_LABEL,       CK_I_empty_str, sizeof(CK_I_empty_str)}
};
#define CK_I_OBJ_ATTR_DEFAULTS_COMMON_SIZE 4


CK_ATTRIBUTE CK_I_obj_attr_defaults_data[] =
{
  {CKA_APPLICATION, CK_I_empty_str,   sizeof(CK_I_empty_str)},
  {CKA_VALUE,       CK_I_empty_bytes, sizeof(CK_I_empty_bytes)}
};
#define CK_I_OBJ_ATTR_DEFAULTS_DATA_SIZE 2
          

CK_ATTRIBUTE CK_I_obj_attr_defaults_certificate_x509[] =
{
  {CKA_ID,            CK_I_empty_bytes, sizeof(CK_I_empty_bytes)},
  {CKA_ISSUER,        CK_I_empty_bytes, sizeof(CK_I_empty_bytes)},
  {CKA_SERIAL_NUMBER, CK_I_empty_bytes, sizeof(CK_I_empty_bytes)}
};
#define CK_I_OBJ_ATTR_DEFAULTS_CERTIFICATE_X509_SIZE 3


CK_ATTRIBUTE CK_I_obj_attr_defaults_key_common[] =
{
  {CKA_ID,           CK_I_empty_bytes,   sizeof(CK_I_empty_bytes)},
  {CKA_START_DATE,   &CK_I_empty_date,   sizeof(CK_I_empty_date)},
  {CKA_END_DATE,     &CK_I_empty_date,   sizeof(CK_I_empty_date)},
  {CKA_DERIVE,       &CK_I_false,        sizeof(CK_I_false)},
  {CKA_LOCAL,        &CK_I_false,        sizeof(CK_I_false)}
};
#define CK_I_OBJ_ATTR_DEFAULTS_KEY_COMMON_SIZE 5


CK_ATTRIBUTE CK_I_obj_attr_defaults_key_public_common[] =
{
  {CKA_SUBJECT,         CK_I_empty_bytes,   sizeof(CK_I_empty_bytes)},
  {CKA_ENCRYPT,         &CK_I_true,         sizeof(CK_I_true)},
  {CKA_VERIFY,          &CK_I_true,         sizeof(CK_I_true)},
  {CKA_VERIFY_RECOVER,  &CK_I_false,        sizeof(CK_I_false)},
  {CKA_WRAP,            &CK_I_true,         sizeof(CK_I_true)}
};
#define CK_I_OBJ_ATTR_DEFAULTS_KEY_PUBLIC_COMMON_SIZE 5


CK_ATTRIBUTE CK_I_obj_attr_defaults_key_private_common[] =
{
  {CKA_SUBJECT,           CK_I_empty_bytes,   sizeof(CK_I_empty_bytes)},
  {CKA_SENSITIVE,         &CK_I_false,        sizeof(CK_I_false)},
  {CKA_DECRYPT,           &CK_I_true,         sizeof(CK_I_true)},
  {CKA_SIGN,              &CK_I_true,         sizeof(CK_I_true)},
  {CKA_SIGN_RECOVER,      &CK_I_false,        sizeof(CK_I_false)},
  {CKA_UNWRAP,            &CK_I_true,         sizeof(CK_I_true)},
  {CKA_EXTRACTABLE,       &CK_I_true,         sizeof(CK_I_true)}
};
#define CK_I_OBJ_ATTR_DEFAULTS_KEY_PRIVATE_COMMON_SIZE 7


CK_ATTRIBUTE CK_I_obj_attr_defaults_key_secret_common[] =
{
  {CKA_SENSITIVE,         &CK_I_false,        sizeof(CK_I_false)},
  {CKA_ENCRYPT,           &CK_I_true,         sizeof(CK_I_true)},
  {CKA_DECRYPT,           &CK_I_true,         sizeof(CK_I_true)},
  {CKA_SIGN,              &CK_I_true,         sizeof(CK_I_true)},
  {CKA_VERIFY,            &CK_I_true,         sizeof(CK_I_true)},
  {CKA_WRAP,              &CK_I_true,         sizeof(CK_I_true)},
  {CKA_UNWRAP,            &CK_I_true,         sizeof(CK_I_true)},
  {CKA_EXTRACTABLE,       &CK_I_true,         sizeof(CK_I_true)}
};
#define CK_I_OBJ_ATTR_DEFAULTS_KEY_SECRET_COMMON_SIZE 8


#endif /* _OBJ_DEFAULTS_H */
/*
 * Local variables:
 * folded-file: t
 * end:
 */
