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
 * NAME:        cryptdb.h
 * SYNOPSIS:    -
 * DESCRIPTION: -
 * FILES:       -
 * SEE/ALSO:    -
 * AUTHOR:      lbe
 * BUGS:        -
 */
 
#ifndef CRYPTDB_H
#define CRYPTDB_H

#include "cryptoki.h"
#include "objects.h"
#include <gdbm.h>
#include <openssl/des.h>

#define CK_I_CDB_PAGE_SIZE 2048  

#define CK_I_CDB_F_SO_PIN_SET 1
#define CK_I_CDB_F_USER_PIN_SET 2

typedef struct CK_I_CRYPT_DB{
  GDBM_FILE table;
  datum old_key;
  des_key_schedule so_key_sched[3];
  des_key_schedule user_key_sched[3];
  CK_ULONG flags;
}CK_I_CRYPT_DB;

typedef CK_I_CRYPT_DB CK_PTR CK_I_CRYPT_DB_PTR;

CK_I_CRYPT_DB_PTR CDB_Open(CK_CHAR_PTR file_name);
CK_RV CDB_Close(CK_I_CRYPT_DB_PTR cdb);

CK_BBOOL CDB_CheckPin(CK_I_CRYPT_DB_PTR cdb, CK_BBOOL so_pin, CK_CHAR_PTR pin , CK_ULONG pinLen);
CK_RV CDB_SetPin(CK_I_CRYPT_DB_PTR cdb, CK_BBOOL so_pin, CK_CHAR_PTR pin, CK_ULONG pinLen);
CK_RV CDB_NewPin(CK_I_CRYPT_DB_PTR cdb, CK_BBOOL so_pin, CK_CHAR_PTR old_pin, CK_ULONG old_pinLen, 
		 CK_CHAR_PTR new_pin, CK_ULONG new_pinLen);

CK_RV CDB_GetObjectInit(CK_I_CRYPT_DB_PTR cdb);
CK_RV CDB_GetObjectUpdate(CK_I_CRYPT_DB_PTR cdb, CK_I_OBJ_PTR CK_PTR next_obj);
CK_RV CDB_GetObjectFinal(CK_I_CRYPT_DB_PTR cdb);

CK_RV CDB_PutObject(CK_I_CRYPT_DB_PTR cdb, CK_I_OBJ_PTR new_obj);
CK_RV CDB_DeleteObject(CK_I_CRYPT_DB_PTR cdb, CK_I_OBJ_PTR new_obj);
CK_RV CDB_UpdateObject(CK_I_CRYPT_DB_PTR cdb, CK_I_OBJ_PTR new_obj);

CK_RV CDB_DeleteAllObjects(CK_I_CRYPT_DB_PTR cdb);

CK_RV CDB_GetPrivObject(CK_I_CRYPT_DB_PTR cdb, CK_I_OBJ_PTR CK_PTR next_obj);
CK_CHAR_PTR CDB_GetRndPin(CK_I_CRYPT_DB_PTR cdb,CK_CHAR_PTR pin, CK_ULONG pinLen);
CK_RV CDB_RndPin(CK_I_CRYPT_DB_PTR cdb, CK_CHAR_PTR CK_PTR crypt_key, CK_CHAR_PTR pin, CK_ULONG pinLen);
CK_RV CDB_PinExists(CK_I_CRYPT_DB_PTR cdb, CK_BBOOL so_pin);

#endif /* CRYPTDB_H */

