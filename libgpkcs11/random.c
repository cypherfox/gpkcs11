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
 * NAME:        random.c
 * SYNOPSIS:    -
 * DESCRIPTION: -
 * FILES:       -
 * SEE/ALSO:    -
 * AUTHOR:      lbe
 * BUGS: *      -
 * HISTORY:     $Log$
 * HISTORY:     Revision 1.4  2000/01/31 18:09:03  lbe
 * HISTORY:     lockdown prior to win_gdbm change
 * HISTORY:
 * HISTORY:     Revision 1.3  1999/11/02 13:47:19  lbe
 * HISTORY:     change of structures and bug fix in slot.c, add more files for tcsc_token: emptyfuncs and general_data
 * HISTORY:
 * HISTORY:     Revision 1.2  1999/10/06 07:57:23  lbe
 * HISTORY:     solved netscape symbol clash problem
 * HISTORY:
 * HISTORY:     Revision 1.1  1999/06/16 09:46:11  lbe
 * HISTORY:     reorder files
 * HISTORY:
 * HISTORY:     Revision 1.5  1999/01/19 12:19:46  lbe
 * HISTORY:     first release lockdown
 * HISTORY:
 * HISTORY:     Revision 1.4  1998/10/12 10:00:11  lbe
 * HISTORY:     clampdown
 * HISTORY:
 * HISTORY:     Revision 1.3  1998/08/05 09:00:20  lbe
 * HISTORY:     *** empty log message ***
 * HISTORY:
 * HISTORY:     Revision 1.2  1998/07/23 15:18:17  lbe
 * HISTORY:     working
 * HISTORY:
 * HISTORY:     Revision 1.1  1998/07/02 17:24:14  lbe
 * HISTORY:     Initial revision
 * HISTORY:
 */
 
static char RCSID[]="$Id$";
const char* Version_random_c(){return RCSID;}

#ifndef CK_I_library_build
#define CK_I_library_build
#endif

#include "internal.h"
#include "error.h"
#include "objects.h"

/* {{{ C_SeedRandom */
CK_DEFINE_FUNCTION(CK_RV, C_SeedRandom)(
        CK_SESSION_HANDLE hSession,
        CK_BYTE_PTR pSeed,
        CK_ULONG ulSeedLen
      )
{
  CK_I_SESSION_DATA_PTR session_data = NULL_PTR;
  CK_RV rv = CKR_OK;

  CI_LogEntry("C_SeedRandom", "starting...", rv, 1);

  /* make sure we are initialized */
  if (!(CK_I_global_flags & CK_IGF_INITIALIZED)) 
    return CKR_CRYPTOKI_NOT_INITIALIZED;

  /* get session info and make sure that this session exists */
  rv = CI_ReturnSession(hSession, &session_data);
  if(rv != CKR_OK)
    {
      CI_VarLogEntry("C_SeedRandom", "retrieve session data (hSession: %lu)", rv, 1,
                     hSession);
      return rv;
    }

  CK_I_CALL_TOKEN_METHOD(rv, SeedRandom, (session_data, pSeed, ulSeedLen));

  CI_LogEntry("C_SeedRandom", "...complete", rv, 1);
  return rv; 
}
/* }}} */

/* {{{ C_GenerateRandom */
CK_DEFINE_FUNCTION(CK_RV, C_GenerateRandom)(
        CK_SESSION_HANDLE hSession,
        CK_BYTE_PTR pRandomData,
        CK_ULONG ulRandomLen
      )
{
  CK_RV rv = CKR_OK;
  CK_I_SESSION_DATA_PTR session_data = NULL_PTR;

  CI_LogEntry("C_GenerateRandom", "starting...", rv, 1);

  /* make sure we are initialized */
  if (!(CK_I_global_flags & CK_IGF_INITIALIZED)) 
    return CKR_CRYPTOKI_NOT_INITIALIZED;

  /* get session info and make sure that this session exists */
  rv = CI_ReturnSession(hSession, &session_data);
  if(rv != CKR_OK)
    {
      CI_VarLogEntry("C_GenerateRandom", "retrieve session data (hSession: %lu)", rv, 1,
                     hSession);
      return rv;
    }

  CK_I_CALL_TOKEN_METHOD(rv, GenerateRandom, (session_data, pRandomData, ulRandomLen));

  CI_LogEntry("C_GenerateRandom", "...complete", rv, 1);

  return rv;
}
/* }}} */
/*
 * Local variables:
 * folded-file: t
 * end:
 */


