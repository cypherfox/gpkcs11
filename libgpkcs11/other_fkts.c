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
 * NAME:        other_fkts.c
 * SYNOPSIS:    -
 * DESCRIPTION: -
 * FILES:       -
 * SEE/ALSO:    -
 * AUTHOR:      lbe
 * BUGS:        -
 */
 
static char RCSID[]="$Id$";
const char* Version_other_fkts_c(){return RCSID;}

#ifndef CK_I_library_build
#define CK_I_library_build
#endif

#include "internal.h"
#include "error.h"

/* Object management */
/* C_GetObjectSize gets the size of an object in bytes. */
CK_DEFINE_FUNCTION(CK_RV, C_GetObjectSize)
(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_OBJECT_HANDLE  hObject,   /* the object's handle */
  CK_ULONG_PTR      pulSize    /* receives size of object */
)
{
  CK_RV rv = CKR_OK;

  CI_LogEntry("C_GetObjectSize", "starting...", rv, 1);

  /* make sure we are initialized */
  if (!(CK_I_global_flags & CK_IGF_INITIALIZED)) 
    return CKR_CRYPTOKI_NOT_INITIALIZED;


  rv = CKR_FUNCTION_NOT_SUPPORTED;
  CI_LogEntry("C_GetObjectSize", "...complete", rv, 1);
  return rv;
}

/* Parallel function management */
/* C_GetFunctionStatus is a legacy function, it obtains an
 * updated status of a function running in parallel with an
 * application. */
CK_DEFINE_FUNCTION(CK_RV, C_GetFunctionStatus)
(
  CK_SESSION_HANDLE hSession  /* the session's handle */
)
{
  CK_RV rv = CKR_OK;

  CI_LogEntry("C_GetFunctionStatus", "starting...", rv, 1);

  /* make sure we are initialized */
  if (!(CK_I_global_flags & CK_IGF_INITIALIZED)) 
    return CKR_CRYPTOKI_NOT_INITIALIZED;


  rv = CKR_FUNCTION_NOT_SUPPORTED;
  CI_LogEntry("C_GetFunctionStatus", "...complete", rv, 1);
  return rv;
}


/* C_CancelFunction is a legacy function,
 * it cancels a function running in parallel. */
CK_DEFINE_FUNCTION(CK_RV, C_CancelFunction)
(
  CK_SESSION_HANDLE hSession  /* the session's handle */
)
{
  CK_RV rv = CKR_OK;

  CI_LogEntry("C_CancelFunction", "starting...", rv, 1);

  /* make sure we are initialized */
  if (!(CK_I_global_flags & CK_IGF_INITIALIZED)) 
    return CKR_CRYPTOKI_NOT_INITIALIZED;

  rv = CKR_FUNCTION_NOT_SUPPORTED;
  CI_LogEntry("C_CancelFunction", "...complete", rv, 1);
  return rv;
}


/*
 * Local variables:
 * folded-file: t
 * end:
 */
