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
 * NAME:        mutex.h
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
 * HISTORY:     Revision 1.5  1999/01/19 12:19:42  lbe
 * HISTORY:     first release lockdown
 * HISTORY:
 * HISTORY:     Revision 1.4  1998/10/12 10:01:08  lbe
 * HISTORY:     clampdown
 * HISTORY:
 * HISTORY:     Revision 1.3  1998/08/05 08:57:27  lbe
 * HISTORY:     *** empty log message ***
 * HISTORY:
 * HISTORY:     Revision 1.2  1998/07/30 15:29:13  lbe
 * HISTORY:     Win32 Port
 * HISTORY:
 * HISTORY:     Revision 1.1  1998/07/02 17:18:43  lbe
 * HISTORY:     Initial revision
 * HISTORY:
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
