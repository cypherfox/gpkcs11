/*
 * Copyright (c) TC TrustCenter - Projekt TC-PKCS11 - all rights reserved
 * RCSID:       $Id$
 * Source:      $Source$
 * Last Delta:  $Date$ $Revision$ $Author$
 * State:       $State$ $Locker$
 * NAME:        thread.c
 * SYNOPSIS:    -
 * DESCRIPTION: A library to simplify the calls to thread functions under Windows or Unix.
 * FILES:       -
 * SEE/ALSO:    -
 * AUTHOR:      ben
 * BUGS: *      -
 * HISTORY:     $Log$
 * HISTORY:     Revision 1.4  2000/09/19 09:14:55  lbe
 * HISTORY:     write flag for pin change onto SC, support Auth Pin path
 * HISTORY:
 * HISTORY:     Revision 1.3  2000/07/24 15:44:11  lbe
 * HISTORY:     added the files for snacc usage
 * HISTORY:
 * HISTORY:     Revision 1.2  2000/06/05 11:43:43  lbe
 * HISTORY:     tcsc token breakup, return pSlotCount in SlotList, code for event handling deactivated
 * HISTORY:
 * HISTORY:     Revision 1.1  2000/05/16 15:14:08  lbe
 * HISTORY:     new files for thread handling needed for events
 * HISTORY:
 */
 
static char RCSID[]="$Id$";
const char* Version_TCThread_c(){return RCSID;}

#ifdef HAVE_CONFIG_H
# include "conf.h"
#elif  WIN32
# include "conf.h.win32"
#endif

#include <errno.h>
#include "thread.h"
#include "string.h"
#include "stdlib.h"

#ifndef HAVE_MACHDEP_SYS_SENDMSG
/* ACHTUNG: linkage problem, LINUX does not implement the sendmsg and
     recvmsg functions, so we do it, but returns always an error,
     hoping that these functions are called only in a certain case
     while using threads. 
     LBE: Ich kann die Dinger auf Solaris auch nicht finden. 
          Deswegen werden sie von autoconf auch nicht erkannt.
*/
int machdep_sys_sendmsg(int a, char *b, int c){return -1;}
int machdep_sys_recvmsg(int a, char *b, int c){return -1;}
#endif

int TCMutexInit(TC_MUTEX *m, int flags)
{
  int r=TCTHRe_NoError;
  if(m==NULL)
    return TCTHRe_InvArg;

#ifdef TC_THREAD_WINDOWS
  m->attr.nLength = sizeof(SECURITY_ATTRIBUTES);
  m->attr.lpSecurityDescriptor = NULL;
  m->attr.bInheritHandle = ((flags & TCTHREAD_INIT_SHARED) != 0);
  m->mut = CreateMutex(&m->attr, ((flags & TCTHREAD_INIT_OWN) != 0), NULL);
  if(!m->mut)
    return TCTHRe_InvArg;
#endif

#ifdef TC_THREAD_POSIX
  /* this used to be 'LINUX'. changed it to HAVE_MUTEXATTR */
#ifdef HAVE_PTHREAD_MUTEXATTR
  if(pthread_mutexattr_init(&m->attr))
    {r=TCTHRe_InvArg;goto error;}

  if(flags & TCTHREAD_INIT_SHARED)
    pthread_mutexattr_setpshared(&m->attr, PTHREAD_PROCESS_SHARED);
  else
    pthread_mutexattr_setpshared(&m->attr, PTHREAD_PROCESS_PRIVATE);
#endif
  if(pthread_mutex_init(&m->mut, &m->attr))
    {r=TCTHRe_InvArg;goto error;}

  if(flags & TCTHREAD_INIT_OWN)
    r=TCMutexWaitAndLock(m);

error:
  if(r!=TCTHRe_NoError && m)
    TCMutexDestroy(m);
#endif

  return r;
}
  

int TCMutexDestroy(TC_MUTEX *m)
{
  if(m==NULL)
    return TCTHRe_InvArg;

#ifdef TC_THREAD_WINDOWS
  if(!CloseHandle(m->mut))
    return TCTHRe_InvArg;
#endif

#ifdef TC_THREAD_POSIX
  if(pthread_mutex_destroy(&m->mut))
    return TCTHRe_InvArg;
#ifdef HAVE_PTHREAD_MUTEXATTR
  if(pthread_mutexattr_destroy(&m->attr))
    return TCTHRe_InvArg;
#endif
#endif

  return TCTHRe_NoError;
}

int TCMutexWaitAndLock(TC_MUTEX *m)
{
  if(m==NULL)
    return TCTHRe_InvArg;

#ifdef TC_THREAD_WINDOWS
  if(WaitForSingleObject(m->mut, INFINITE) == WAIT_FAILED)
    return TCTHRe_InvArg;
#endif

#ifdef TC_THREAD_POSIX
  if(pthread_mutex_lock(&m->mut))
    return TCTHRe_InvArg;
#endif

  return TCTHRe_NoError;
}

int TCMutexTryLock(TC_MUTEX *m)
{
  int r=TCTHRe_NoError;
  if(m==NULL)
    return TCTHRe_InvArg;

#ifdef TC_THREAD_WINDOWS
  if(WaitForSingleObject(m->mut, 0) == WAIT_FAILED)
    switch(GetLastError())
      {
      case WAIT_OBJECT_0:
      case WAIT_TIMEOUT:
	r = TCTHRe_MutexNotAvailable;
	break;
      default:
	r = TCTHRe_InvArg;
      }
#endif

#ifdef TC_THREAD_POSIX
  switch(pthread_mutex_trylock(&m->mut))
    {
    case EBUSY:
      r=TCTHRe_MutexNotAvailable;
      break;
    case 0:
      r=TCTHRe_NoError;
      break;
    default:
      r=TCTHRe_InvArg;
    }
#endif

  return r;
}

int TCMutexUnlock(TC_MUTEX *m)
{
  if(m==NULL)
    return TCTHRe_InvArg;

#ifdef TC_THREAD_WINDOWS
  if(!ReleaseMutex(m->mut))
    return TCTHRe_InvArg;
#endif

#ifdef TC_THREAD_POSIX
  if(pthread_mutex_unlock(&m->mut))
    return TCTHRe_InvArg;
#endif

  return TCTHRe_NoError;
}

#ifdef TC_THREAD_POSIX
typedef struct
{
  void *arg;
  void (*func)(void *);
} TC_SIMPLE_THREAD_POSIX_ARGS;

void *TCSimpleThreadCreatePOSIXStartup(void *a)
{
  TC_SIMPLE_THREAD_POSIX_ARGS *mya;
  mya=(TC_SIMPLE_THREAD_POSIX_ARGS *)a;
  mya->func(mya->arg);

  return NULL;
}
#endif


DECLSPEC int TCSimpleThreadCreate(TC_SIMPLE_THREAD_FUNCTION_AS_PARAM (*func)(TC_THREAD_FUNCTION_ARGUMENT),
				  TC_THREAD_FUNCTION_ARGUMENT arg, int flags,
				  TC_SIMPLE_THREAD_HANDLE *tha)
{
#ifdef TC_THREAD_WINDOWS
  HANDLE t;
#endif
#ifdef TC_THREAD_POSIX
  TC_SIMPLE_THREAD_POSIX_ARGS a;
#endif

  if(func==NULL)
    return TCTHRe_InvArg;

#ifdef TC_THREAD_WINDOWS
  t=(HANDLE)_beginthread(func, 0, arg);
  if(t==(HANDLE)(-1)) /* I love MS when an unsigned long can have the value -1 */
    switch(errno)
      {
      case EAGAIN: return TCTHRe_TooManyThreads;
      case EINVAL:
      default: return TCTHRe_InvArg;
      }

  if(tha)
    *tha = t;
#endif

#ifdef TC_THREAD_POSIX
  a.arg=arg;
  a.func=func;
  switch(pthread_create(tha, NULL, TCSimpleThreadCreatePOSIXStartup, (void *)(&a)))
    {
    case 0: break;
    case EAGAIN: return TCTHRe_TooManyThreads;
    case ENOMEM: return TCTHRe_Memory;
    case EINVAL:
    default: return TCTHRe_InvArg;
    } 
#endif

  return TCTHRe_NoError;
}

DECLSPEC void TCSimpleThreadExit(void)
{
#ifdef TC_THREAD_WINDOWS
  _endthread();
#endif
#ifdef TC_THREAD_POSIX
  pthread_exit(NULL);
#endif
}







TC_SIMPLE_THREAD_ID TCGetCurrentSimpleThreadID(void)
{
#ifdef TC_THREAD_WINDOWS
  return GetCurrentThreadId();
#endif

#ifdef TC_THREAD_POSIX
  return pthread_self();
#endif
}



/* This section is only necessary for POSIX, cause the thread locale
     variables are handled transparently by WIN32, and as a result
     are defined as macros. */
#ifdef TC_THREAD_POSIX
int TCThreadedPointerInit(TC_THREADED_POINTER_AS_PARAM *tv)
{
  switch(pthread_key_create(tv, NULL))
    {
    case EAGAIN: return TCTHRe_Resource;
    case ENOMEM: return TCTHRe_Memory;
    case 0: break;
    default: return TCTHRe_InvArg;
    }

  return TCTHRe_NoError;
}

int TCThreadedPointerSet(TC_THREADED_POINTER_AS_PARAM tv, void *v)
{
  switch(pthread_setspecific(tv, v))
    {
    case ENOMEM: return TCTHRe_Memory;
    case EINVAL: return TCTHRe_InvArg;
    case 0: break;
    default: return TCTHRe_InvArg;
    }

  return TCTHRe_NoError;
}

int TCThreadedPointerDestroy(TC_THREADED_POINTER_AS_PARAM tv)
{
  switch(pthread_key_delete(tv))
    {
    case EINVAL: return TCTHRe_InvArg;
    case 0: break;
    default: return TCTHRe_InvArg;
    }

  return TCTHRe_NoError;
}
#endif

/************************************************************************
 *                            Named mutexes                             *
 ************************************************************************/


int TCNamedMutexInit(TC_NAMED_MUTEX *pMutex, char* name, int flags)
{
  pMutex->name = strdup(name);
  if(pMutex->name == NULL) 
    return TCTHRe_Memory;
  
#ifdef TC_THREAD_WINDOWS
  pMutex->attr.nLength = sizeof(SECURITY_ATTRIBUTES);
  pMutex->attr.lpSecurityDescriptor = NULL;
  pMutex->attr.bInheritHandle = ((flags & TCTHREAD_INIT_SHARED) != 0);
  pMutex->mut = CreateMutex(&(pMutex->attr), FALSE, name);
  if(!pMutex->mut)
    {
      free(pMutex->name);
      return TCTHRe_InvArg;
    }
#endif
    
#ifdef TC_THREAD_POSIX
  return TCTHRe_MutexNotAvailable;
#endif

  return TCTHRe_NoError;
}

int TCNamedMutexDestroy(TC_NAMED_MUTEX *pNamedMutex)
{
  if( pNamedMutex == NULL )
    return TCTHRe_InvArg;

  if( pNamedMutex->name != NULL )
    free(pNamedMutex->name);

#ifdef TC_THREAD_WINDOWS
  if(!CloseHandle(pNamedMutex->mut))
    return TCTHRe_InvArg;
#endif

#ifdef TC_THREAD_POSIX
#endif
  return TCTHRe_NoError;
}

int TCNamedMutexWaitAndLock(TC_NAMED_MUTEX *m)
{
  if(m==NULL)
    return TCTHRe_InvArg;

#ifdef TC_THREAD_WINDOWS
  if(WaitForSingleObject(m->mut, INFINITE) == WAIT_FAILED)
    return TCTHRe_InvArg;
#endif

#ifdef TC_THREAD_POSIX
  return TCTHRe_MutexNotAvailable;
#endif

  return TCTHRe_NoError;
}

int TCNamedMutexTryLock(TC_NAMED_MUTEX *m)
{
  int r=TCTHRe_NoError;

  if(m==NULL)
    return TCTHRe_InvArg;

#ifdef TC_THREAD_WINDOWS
  if(WaitForSingleObject(m->mut, 0) == WAIT_FAILED)
    switch(GetLastError())
      {
      case WAIT_OBJECT_0:
      case WAIT_TIMEOUT:
	r = TCTHRe_MutexNotAvailable;
	break;
      default:
	r = TCTHRe_InvArg;
      }
#endif

 #ifdef TC_THREAD_POSIX
  return TCTHRe_MutexNotAvailable;
 #endif

  return r;
}

int TCNamedMutexUnlock(TC_NAMED_MUTEX *m)
{
  if(m==NULL)
    return TCTHRe_InvArg;

 #ifdef TC_THREAD_WINDOWS
  if(!ReleaseMutex(m->mut))
    return TCTHRe_InvArg;
 #endif

 #ifdef TC_THREAD_POSIX
  return TCTHRe_MutexNotAvailable;
 #endif

  return TCTHRe_NoError;
}
