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
 * NAME:        mutex.c
 * SYNOPSIS:    -
 * DESCRIPTION: -
 * FILES:       -
 * SEE/ALSO:    -
 * AUTHOR:      lbe
 * BUGS: *      -
 * HISTORY:     $Log$
 * HISTORY:     Revision 1.4  2000/01/31 18:09:02  lbe
 * HISTORY:     lockdown prior to win_gdbm change
 * HISTORY:
 * HISTORY:     Revision 1.3  1999/11/02 13:47:18  lbe
 * HISTORY:     change of structures and bug fix in slot.c, add more files for tcsc_token: emptyfuncs and general_data
 * HISTORY:
 * HISTORY:     Revision 1.2  1999/10/06 07:57:22  lbe
 * HISTORY:     solved netscape symbol clash problem
 * HISTORY:
 * HISTORY:     Revision 1.1  1999/06/16 09:46:09  lbe
 * HISTORY:     reorder files
 * HISTORY:
 * HISTORY:     Revision 1.9  1999/03/01 14:36:44  lbe
 * HISTORY:     merged changes from the weekend
 * HISTORY:
 * HISTORY:     Revision 1.8  1999/01/19 12:19:42  lbe
 * HISTORY:     first release lockdown
 * HISTORY:
 * HISTORY:     Revision 1.7  1998/12/07 13:20:13  lbe
 * HISTORY:     TC_free von parametern für Zeile und Datei befreit.
 * HISTORY:
 * HISTORY:     Revision 1.6  1998/11/13 10:10:14  lbe
 * HISTORY:     added persistent storage.
 * HISTORY:
 * HISTORY:     Revision 1.5  1998/10/12 10:00:10  lbe
 * HISTORY:     clampdown
 * HISTORY:
 * HISTORY:     Revision 1.4  1998/08/05 08:57:26  lbe
 * HISTORY:     *** empty log message ***
 * HISTORY:
 * HISTORY:     Revision 1.3  1998/07/30 15:29:23  lbe
 * HISTORY:     Win32 Port
 * HISTORY:
 * HISTORY:     Revision 1.2  1998/07/23 15:18:12  lbe
 * HISTORY:     working
 * HISTORY:
 * HISTORY:     Revision 1.1  1998/07/02 17:17:56  lbe
 * HISTORY:     Initial revision
 * HISTORY:
 */
 
static char RCSID[]="$Id$";
const char* Version_mutex_c(){return RCSID;}

/* Needed for Win32-isms in cryptoki.h */
#ifndef CK_I_library_build
#define CK_I_library_build
#endif

#include "internal.h"
#include "error.h"
#include "mutex.h"

/* TODO: the mutexes are not working at all at the moment! Fix Me */

/******************************************************************
 *                  Unix Mutex                                    *
 ******************************************************************/
#ifdef CK_GENERIC

#if defined(HAVE_PTHREAD_H)
# include <pthread.h>
#else 
# include <thread.h>
# include <synch.h>
#endif 
#include <stdlib.h>

CK_DEFINE_FUNCTION(CK_RV, I_CreateMutex)(
  CK_VOID_PTR_PTR ppMutex  /* location to receive ptr to mutex */
)
{
#if 0
#if defined(HAVE_PTHREAD_H)
  *ppMutex = TC_calloc(1,sizeof(mutex_t));
#else 
  *ppMutex = TC_calloc(1,sizeof(pthread_mutex_t));
#endif 

  if(*ppMutex == NULL_PTR)
    return CKR_HOST_MEMORY;
  
#if defined(HAVE_PTHREAD_H)
  pthread_mutex_init((pthread_mutex_t CK_PTR)*ppMutex, NULL_PTR);
#else 
  mutex_init((mutex_t CK_PTR)*ppMutex, USYNC_THREAD, NULL_PTR);
#endif 

#else /* !0 */
  *ppMutex= NULL_PTR;
#endif
  
  return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, I_DestroyMutex)(
  CK_VOID_PTR pMutex  /* pointer to mutex */
)
{
#if 0
  mutex_destroy((mutex_t CK_PTR)pMutex);
  TC_free(pMutex);
  
#endif
  return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, I_LockMutex)(
  CK_VOID_PTR pMutex  /* pointer to mutex */
)
{
#if 0
  CK_RV rv;
  rv = mutex_lock((mutex_t CK_PTR)pMutex);
  if( rv != 0 ) return CKR_MUTEX_BAD;
#endif
  return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, I_UnlockMutex)(
  CK_VOID_PTR pMutex  /* pointer to mutex */
)
{
#if 0
  CK_RV rv;
  rv = mutex_unlock((mutex_t CK_PTR)pMutex);
  if( rv != 0 ) return CKR_MUTEX_BAD;
#endif
  return CKR_OK;
}

#elif defined(CK_Win32)
/********************************************************
 *               Win32 Mutex                            *
 ********************************************************/
#include <windows.h>
#include <stdio.h>
static int depth = 0;

CK_DEFINE_FUNCTION(CK_RV, I_CreateMutex)(
  CK_VOID_PTR_PTR ppMutex  /* location to receive ptr to mutex */
)
{
#if 0
  DWORD err_code;
  CK_RV rv = CKR_OK;
  HANDLE CK_PTR mutex_field = NULL_PTR;
  
  if(depth++ >0) 
    {
      FILE* log;
      log = fopen("C:\\mutex.log","a");
      fprintf(log,"CreateMutex(Win32): depth:%i",depth);
      fclose(log);
    }
  
  mutex_field = TC_malloc(sizeof(int));
  if(!mutex_field)
    {
      rv = CKR_HOST_MEMORY;
      CI_LogEntry("I_CreateMutex" ,"mutex creation failed",
		  rv, 0);
      return rv;
    }

  *mutex_field = (CK_VOID_PTR)CreateMutex(NULL_PTR, FALSE, NULL_PTR);

  if(*mutex_field == 0)
    {
      err_code = GetLastError();
      if((err_code == ERROR_NOT_ENOUGH_MEMORY) || ( err_code == ERROR_OUTOFMEMORY ))
	rv = CKR_HOST_MEMORY;
      else 
	rv = CKR_GENERAL_ERROR;
      
      CI_VarLogEntry("I_CreateMutex" ,"mutex creation: GetLastError(): %i",
		     rv, 0, err_code);
    }

  *ppMutex = mutex_field;
  
  return rv;
#else
  *ppMutex = NULL_PTR;
  return CKR_OK;
#endif
}


CK_DEFINE_FUNCTION(CK_RV, I_DestroyMutex)(
  CK_VOID_PTR pMutex  /* mutex itself */
)
{
#if 0
  DWORD err_code;

  CK_RV rv = CKR_OK;

if(--depth >0) 
  {
    FILE* log;
    log = fopen("C:\\mutex.log","a");
    fprintf(log,"DestroyMutex(Win32): depth:%i",depth);
    fclose(log);
  }

  CloseHandle(*((HANDLE CK_PTR)pMutex));
  err_code = GetLastError();

  if(err_code != ERROR_SUCCESS)
    switch(err_code)
      {
      case ERROR_INVALID_HANDLE:
	rv = CKR_MUTEX_BAD;
	break;
      case ERROR_NOT_ENOUGH_MEMORY:
      case ERROR_OUTOFMEMORY:
	rv = CKR_HOST_MEMORY;
	break;
      default:
	rv = CKR_GENERAL_ERROR;
      }

  TC_free(pMutex);

  if(rv != CKR_OK)
    CI_VarLogEntry("I_DestroyMutex" ,"mutex destruction: GetLastError(): %i",
		   rv, 1, err_code);

  return rv;
#else
  return CKR_OK;
#endif
}

CK_DEFINE_FUNCTION(CK_RV, I_LockMutex)(
  CK_VOID_PTR pMutex  /* pointer to mutex */
)
{
#if 0
  CK_RV rv =CKR_OK;
  DWORD err_code;

  if(WAIT_FAILED == WaitForSingleObject((HANDLE)pMutex, INFINITE))
    {
      err_code = GetLastError();
      switch(err_code)
	{
	case ERROR_INVALID_HANDLE:
	rv = CKR_OK; 
	/*	  rv = CKR_MUTEX_BAD; */
	  break;
	case ERROR_NOT_ENOUGH_MEMORY:
	case ERROR_OUTOFMEMORY:
	  rv = CKR_HOST_MEMORY;
	  break;
	default:
	  rv = CKR_GENERAL_ERROR;
	}
    }

  if(rv != CKR_OK)
    CI_VarLogEntry("I_LockMutex" ,"mutex locking: GetLastError(): %i",
		   rv, 1, err_code);

  return rv;
#else
  return CKR_OK;
#endif
}

CK_DEFINE_FUNCTION(CK_RV, I_UnlockMutex)(
  CK_VOID_PTR pMutex  /* pointer to mutex */
)
{
#if 0
    DWORD err_code;

    CK_RV rv = CKR_OK;

  if(!ReleaseMutex((HANDLE)pMutex))
    {
      err_code = GetLastError();
      switch(err_code)
	{
	case ERROR_INVALID_HANDLE:
	rv = CKR_OK; 
	/* rv = CKR_MUTEX_BAD; */
	  break;
	case ERROR_NOT_ENOUGH_MEMORY:
	case ERROR_OUTOFMEMORY:
	  rv = CKR_HOST_MEMORY;
	  break;
	default:
	  rv = CKR_GENERAL_ERROR;
	}
    }
  

  if(rv != CKR_OK)
    CI_VarLogEntry("I_UnlockMutex" ,"mutex unlocking: GetLastError(): %i",
		   rv, 1, err_code);

  return rv;
#else
  return CKR_OK;
#endif
}

#else /* ! Win32 */
#error für diese Architectur sind keine Mutexes implementiert!
#endif

CK_DEFINE_FUNCTION(CK_RV, CI_CreateMutex)(
  CK_VOID_PTR_PTR ppMutex  /* location to receive ptr to mutex */
)
{
  return CK_I_ext_functions._CreateMutex(ppMutex);
}

CK_DEFINE_FUNCTION(CK_RV, CI_DestroyMutex)(
  CK_VOID_PTR pMutex  /* mutex itself */
)
{
  return CK_I_ext_functions._DestroyMutex(pMutex);
}

CK_DEFINE_FUNCTION(CK_RV, CI_LockMutex)(
  CK_VOID_PTR pMutex  /* ptr to mutex */
)
{
  return CK_I_ext_functions._LockMutex(pMutex);
}

CK_DEFINE_FUNCTION(CK_RV, CI_UnlockMutex)(
  CK_VOID_PTR pMutex  /* ptr to mutex */
)
{
  return CK_I_ext_functions._UnlockMutex(pMutex);
}


/*
 * Local variables:
 * folded-file: t
 * end:
 */





