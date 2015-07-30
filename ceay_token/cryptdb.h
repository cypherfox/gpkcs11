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
 * NAME:        cryptdb.h
 * SYNOPSIS:    -
 * DESCRIPTION: -
 * FILES:       -
 * SEE/ALSO:    -
 * AUTHOR:      lbe
 * BUGS: *      -
 * HISTORY:     $Log$
 * HISTORY:     Revision 1.3  2000/02/08 16:12:45  lbe
 * HISTORY:     last changes from beta testers
 * HISTORY:
 * HISTORY:     Revision 1.2  2000/01/31 18:09:00  lbe
 * HISTORY:     lockdown prior to win_gdbm change
 * HISTORY:
 * HISTORY:     Revision 1.1  1999/06/04 14:58:37  lbe
 * HISTORY:     change to libtool/automake complete (except for __umoddi prob)
 * HISTORY:
 * HISTORY:     Revision 1.5  1999/01/22 08:35:32  lbe
 * HISTORY:     full build with new perisistant storage complete
 * HISTORY:
 * HISTORY:     Revision 1.4  1999/01/19 12:19:37  lbe
 * HISTORY:     first release lockdown
 * HISTORY:
 * HISTORY:     Revision 1.3  1999/01/19 10:10:19  lbe
 * HISTORY:     pre package clampdown
 * HISTORY:
 * HISTORY:     Revision 1.2  1999/01/18 13:02:33  lbe
 * HISTORY:     swapped Berkeley DB for gdbm
 * HISTORY:
 * HISTORY:     Revision 1.1  1999/01/13 16:17:31  lbe
 * HISTORY:     Initial revision
 * HISTORY:
 */
 
#ifndef CRYPTDB_H
#define CRYPTDB_H

#include "cryptoki.h"
#include "objects.h"
#include <gdbm.h>
#include <openssl/des.h>

#define CK_I_CDB_PAGE_SIZE 2048  

#define CK_I_CDB_F_SO_PIN_SET   1
#define CK_I_CDB_F_USER_PIN_SET 2

typedef struct CK_I_CRYPT_DB
  {
  GDBM_FILE table;
  datum old_key;
  des_key_schedule so_key_sched[3];
  des_key_schedule user_key_sched[3];
  CK_ULONG flags;
  }
CK_I_CRYPT_DB;

typedef CK_I_CRYPT_DB CK_PTR CK_I_CRYPT_DB_PTR;

/// Creates the database file for a new crypto token.
CK_I_CRYPT_DB_PTR CDB_Create (CK_CHAR_PTR);
/// Opens the existing database file of a crypto token.
CK_I_CRYPT_DB_PTR CDB_Open (CK_CHAR_PTR, int);
/// Closes the database file of a crypto token.
CK_RV             CDB_Close (CK_I_CRYPT_DB_PTR);
/// Checks an existing database file for read-only attribute
CK_BBOOL          CDB_IsFileReadOnly (CK_CHAR_PTR);


CK_CHAR_PTR DefaultPin;    ///< Default so's and user's PIN
CK_ULONG    DefaultPinLen; ///< Length in bytes of the PIN

/// Checks an given PIN against the entry in the database
CK_RV CDB_CheckPin (CK_I_CRYPT_DB_PTR, CK_BBOOL, CK_CHAR_PTR , CK_ULONG);
/// Creates a new PIN and stores it in the database
CK_RV CDB_NewPin (CK_I_CRYPT_DB_PTR, CK_BBOOL, CK_CHAR_PTR, CK_ULONG, CK_CHAR_PTR, CK_ULONG);
/// Checks a given PIN type against the database entrys
CK_RV CDB_PinExists (CK_I_CRYPT_DB_PTR, CK_BBOOL);


/// Generates a key to get encrypt private objects by a PIN
CK_RV CDB_SetPin (CK_I_CRYPT_DB_PTR, CK_BBOOL, CK_CHAR_PTR, CK_ULONG);
/// Generates a key to encrypt private objects by randomize
CK_RV CDB_RndPin (CK_I_CRYPT_DB_PTR, CK_CHAR_PTR CK_PTR, CK_CHAR_PTR, CK_ULONG);
/// Gets the generated key to encrypt private objects
CK_CHAR_PTR CDB_GetRndPin (CK_I_CRYPT_DB_PTR, CK_CHAR_PTR, CK_ULONG);


CK_RV CDB_PutTokenInfo (CK_I_CRYPT_DB_PTR cdb, CK_TOKEN_INFO_PTR pTokenInfo);
CK_RV CDB_GetTokenInfo (CK_I_CRYPT_DB_PTR cdb, CK_TOKEN_INFO_PTR CK_PTR ppTokenInfo);

CK_RV CDB_GetObjectInit(CK_I_CRYPT_DB_PTR cdb);
CK_RV CDB_GetObjectUpdate(CK_I_CRYPT_DB_PTR cdb, CK_I_OBJ_PTR CK_PTR next_obj);
CK_RV CDB_GetObjectFinal(CK_I_CRYPT_DB_PTR cdb);

CK_RV CDB_PutObject(CK_I_CRYPT_DB_PTR cdb, CK_I_OBJ_PTR new_obj);
CK_RV CDB_DeleteObject(CK_I_CRYPT_DB_PTR cdb, CK_I_OBJ_PTR new_obj);
CK_RV CDB_UpdateObject(CK_I_CRYPT_DB_PTR cdb, CK_I_OBJ_PTR new_obj);

/// Deletes all entrys in a database
CK_RV CDB_DeleteAllObjects(CK_I_CRYPT_DB_PTR);

CK_RV CDB_GetPrivObject(CK_I_CRYPT_DB_PTR cdb, CK_I_OBJ_PTR CK_PTR next_obj);

#endif /* CRYPTDB_H */

