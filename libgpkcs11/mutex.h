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
 * NAME:        mutex.h
 * SYNOPSIS:    -
 * DESCRIPTION: -
 * FILES:       -
 * SEE/ALSO:    -
 * AUTHOR:      lbe
 * BUGS:        -
 */

#ifndef _MUTEX_H_
#define _MUTEX_H_ 1

CK_DECLARE_FUNCTION(CK_RV, I_CreateMutex)(
  CK_VOID_PTR_PTR ppMutex  /* location to receive ptr to mutex */
);

CK_DECLARE_FUNCTION(CK_RV, I_DestroyMutex)(
  CK_VOID_PTR pMutex  /* ptr to mutex */
);

CK_DECLARE_FUNCTION(CK_RV, I_LockMutex)(
  CK_VOID_PTR pMutex  /* ptr to mutex */
);

CK_DECLARE_FUNCTION(CK_RV, I_UnlockMutex)(
  CK_VOID_PTR pMutex  /* ptr to mutex */
);

CK_DECLARE_FUNCTION(CK_RV, CI_CreateMutex)(
  CK_VOID_PTR_PTR ppMutex  /* location to receive ptr to mutex */
);

CK_DECLARE_FUNCTION(CK_RV, CI_DestroyMutex)(
  CK_VOID_PTR pMutex  /* ptr to mutex */
);

CK_DECLARE_FUNCTION(CK_RV, CI_LockMutex)(
  CK_VOID_PTR pMutex  /* ptr to mutex */
);

CK_DECLARE_FUNCTION(CK_RV, CI_UnlockMutex)(
  CK_VOID_PTR pMutex  /* ptr to mutex */
);



/* ### mutex helpers ### */
#ifdef NDEBUG
#define _LOCK(__mutex)       (CI_LockMutex( __mutex ))
#define _UNLOCK(__mutex)     (CI_UnlockMutex( __mutex ))
#else 
#define _LOCK(__mutex)       assert(CI_LockMutex( __mutex ) == CKR_OK)
#define _UNLOCK(__mutex)     assert(CI_UnlockMutex( __mutex ) == CKR_OK)
#endif

#endif /* _MUTEX_H_ */
/*
 * Local variables:
 * folded-file: t
 * end:
 */
