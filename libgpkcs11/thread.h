/*
 * Copyright (c) TC TrustCenter - Projekt TC-PKCS11 - all rights reserved
 * RCSID:       $Id$
 * Source:      $Source$
 * Last Delta:  $Date$ $Revision$ $Author$
 * State:       $State$ $Locker$
 * NAME:        thread.h
 * SYNOPSIS:    -
 * DESCRIPTION: A library to simplify the calls to thread functions under Windows or Unix.
 * FILES:       -
 * SEE/ALSO:    -
 * AUTHOR:      ben
 * BUGS: *      -
 * HISTORY:     $Log$
 * HISTORY:     Revision 1.3  2000/06/23 17:32:18  lbe
 * HISTORY:     release to secude, lockdown for 0_6_2
 * HISTORY:
 * HISTORY:     Revision 1.2  2000/06/05 11:43:43  lbe
 * HISTORY:     tcsc token breakup, return pSlotCount in SlotList, code for event handling deactivated
 * HISTORY:
 * HISTORY:     Revision 1.1  2000/05/16 15:14:08  lbe
 * HISTORY:     new files for thread handling needed for events
 * HISTORY:
 * HISTORY:
 */

#ifndef TCTHREAD_H
#define TCTHREAD_H
 
#ifdef  __cplusplus
extern "C" {
#endif


/* Defines verification */

#if defined(WIN16) || defined(MSDOS)
#error ACHTUNG! Threads are not supported by WIN16 and MSDOS
#endif

#if defined(WIN32) && !defined(_MT)
#error ACHTUNG! TCThread must be compiled with the _MT symbol under WIN32
#endif

#if !defined(WIN32) && !defined(_REENTRANT)
#error ACHTUNG! TCThread must be compiled with the _REENTRANT symbol under Unix
#endif

/* Global defines creation - could change with other systems*/
#if defined(WIN32) && defined(_MT)
#define TC_THREAD_WINDOWS
#endif

#if defined(_REENTRANT) && !defined(TC_THREAD_WINDOWS)
#define TC_THREAD_POSIX
#endif

/* Includes */
#ifdef TC_THREAD_WINDOWS
#include <wtypes.h>
#include <windef.h>
#include <winbase.h>
#include <process.h>
#endif

#ifdef TC_THREAD_POSIX
#include <pthread.h>
#endif


/* TCThread defines */

#define TCTHREAD_INIT_DEFAULT     0 /* This object is created with the default attrs */
#define TCTHREAD_INIT_SHARED      1 /* Shared by several processes (mutex) */
#define TCTHREAD_INIT_OWN         2 /* The current thread owns this obj after init (mutex) */

#define TCTHRe_NoError            0
#define TCTHRe_FirstError         3700
#define TCTHRe_InvArg             (TCTHRe_FirstError +  1)
#define TCTHRe_MutexNotAvailable  (TCTHRe_FirstError +  2)
#define TCTHRe_Memory             (TCTHRe_FirstError +  3)
#define TCTHRe_Resource           (TCTHRe_FirstError +  4)
#define TCTHRe_TooManyThreads     (TCTHRe_FirstError +  5)

#ifdef TC_THREAD_WINDOWS
typedef struct
{
  HANDLE mut;
  SECURITY_ATTRIBUTES attr;
} TC_MUTEX;

typedef HANDLE TC_SIMPLE_THREAD_HANDLE;
typedef DWORD TC_SIMPLE_THREAD_ID;
typedef void * TC_THREADED_POINTER_AS_PARAM;
#define TC_THREADED_POINTER __declspec(thread) TC_THREADED_POINTER_AS_PARAM
typedef DWORD TC_THREAD_RETURN_VALUE;
typedef TC_THREAD_RETURN_VALUE TC_THREAD_FUNCTION_AS_PARAM;
#define TC_THREAD_FUNCTION TC_THREAD_FUNCTION_AS_PARAM WINAPI
typedef void TC_SIMPLE_THREAD_FUNCTION_AS_PARAM;
#define TC_SIMPLE_THREAD_FUNCTION TC_SIMPLE_THREAD_FUNCTION_AS_PARAM WINAPI
typedef LPVOID TC_THREAD_FUNCTION_ARGUMENT;

#define DECLSPEC __declspec(dllexport)
#endif

#ifdef TC_THREAD_POSIX
typedef struct
{
  pthread_mutex_t mut;
  pthread_mutexattr_t attr;
} TC_MUTEX;

typedef pthread_t TC_SIMPLE_THREAD_HANDLE;
typedef pthread_t TC_SIMPLE_THREAD_ID;
typedef pthread_key_t TC_THREADED_POINTER_AS_PARAM;
typedef TC_THREADED_POINTER_AS_PARAM TC_THREADED_POINTER;
typedef void * TC_THREAD_RETURN_VALUE;
typedef TC_THREAD_RETURN_VALUE TC_THREAD_FUNCTION;
typedef TC_THREAD_FUNCTION TC_THREAD_FUNCTION_AS_PARAM;
typedef void TC_SIMPLE_THREAD_FUNCTION;
typedef TC_SIMPLE_THREAD_FUNCTION TC_SIMPLE_THREAD_FUNCTION_AS_PARAM;
typedef void * TC_THREAD_FUNCTION_ARGUMENT;

#define DECLSPEC 
#endif





/*
   Mutex functions, mutexes are 'mutual exclusive' objects. Only one thread
   can lock a mutex at the same time, the other threads can wait until this
   mutex is unlocked, then the order of which thread will have the mutex is
   undefined. 
 */

/** Initialize a mutex object
 * @descr          Init a globally-defined TCMutex object.
 * @param  m       A pointer on the mutex to init
 * @param  flags   An 'ored' combination of TCTHREAD_INIT_* (SHARED and OWN
 *                   are at this time supported).
 * @return         0 if success, otherwise an error number.
 * @remark All the TCMutex functions use a pointer to access the mutex,
 *           because such an object cannot be dupplicate. Furthermore,
 *           if a mutex have to be shared between several processes, it
 *           must be allocated in a shared area of memory, that's why
 *           these functions do not attempt to allocate the mutexes.
 */
int TCMutexInit(TC_MUTEX *m, int flags);

/* TCMutexDestroy
   @descr          Destroy a globally-defined TCMutex object.
   @param  m       A pointer on the mutex to destroy.
   @return         0 if success, otherwise an error number.
*/
int TCMutexDestroy(TC_MUTEX *m);

/* TCMutexWaitAndLock
   @descr          Wait for a mutex and lock it.
   @param  m       A pointer on the mutex to lock.
   @return         0 if success, otherwise an error number.
   @remark If the mutex is already locked by the calling process,
             the behaviour is undefined.
*/
int TCMutexWaitAndLock(TC_MUTEX *m);

/* TCMutexTryLock
   @descr  Try to lock a mutex, do not wait.
   @param  m       A pointer on the mutex to lock.
   @return         0 if success (mutex locked), otherwise an error number.
   @remark If the mutex is already locked by the calling process,
             the behaviour is undefined.
*/
int TCMutexTryLock(TC_MUTEX *m);

/* TCMutexUnlock
   @descr          Unlock a previously locked mutex.
   @param  m       A pointer on the mutex to unlock.
   @return         0 if success, otherwise an error number.
   @remark If the mutex is not currently locked by any process,
             the behaviour is undefined.
*/
int TCMutexUnlock(TC_MUTEX *m);

/************************************************************************
 *                            Named mutexes                             *
 *  These can be shared accross different processes (not just threads)  *
 *  and have the operating system find them for an application          *
 *  that needs them. They do not need the memory in which they reside   *
 *  to be shared mem                                                    *
 ************************************************************************/

#ifdef TC_THREAD_WINDOWS
typedef struct
{
  HANDLE mut;
  SECURITY_ATTRIBUTES attr;
  char* name;
} TC_NAMED_MUTEX;
#endif /* TC_THREAD_WINDOWS */

#ifdef TC_THREAD_POSIX
typedef struct _tc_named_mutex
{
  pthread_key_t sem_key; /* key of the OS semaphore object */
  pthread_mutex_t mut;
  pthread_mutexattr_t attr;
  char* name;
} TC_NAMED_MUTEX;
#endif /* TC_THREAD_POSIX */

/** Initialize a named mutex object.
 * The function will create a unique named mutex object and register the
 * appropriate objects with the operating system. If an object of that
 * name allready exists it will not be recreated, but a reference to the
 * same object will be returned. This allows the usage of the same mutex
 * between different applications.
 * 
 * There may be at most 2^16 key in usage. On UNIX system the name is
 * mapped onto a unique key via a linear testing hash. On Windows systems
 * the operating system performs this task.
 * 
 * While the calls for this mutex are thread safe, it is global for all 
 * threads of a process.
 * 
 * @param  pNewNamedMutex  The mutex that is initialized according to name
 *                         and flags parameter.
 * @param  name    The name that the mutex is to have.
 * @param  flags   An 'ored' combination of TCTHREAD_INIT_* (SHARED and 
 *                 OWN are at this time supported).
 * @return         0 if success, otherwise an error number.
 */ 
int TCNamedMutexInit(TC_NAMED_MUTEX *pNewNamedMutex, char* name, int flags);

/** Destroy a TCNamedMutex object.
 * Unless this is the last object of that name, it will only be destroyed 
 * for the current process. If it is the last object, it will be removed 
 * from the system.
 *  @param  m       A pointer on the mutex to destroy.
 *  @return         0 if success, otherwise an error number.
 */
int TCNamedMutexDestroy(TC_NAMED_MUTEX *m);

/** Wait for a named mutex and lock it.
 * If the mutex is already locked by the calling process,
 * the behaviour is undefined
 *
 * @param  m       A pointer on the mutex to lock.
 * @return         0 if success, otherwise an error number.
 */
int TCNamedMutexWaitAndLock(TC_NAMED_MUTEX *m);

/** Try to lock a mutex, do not wait.
 * If the mutex is already locked by the calling process,
 * the behaviour is undefined.
 *
 * @param  m       A pointer on the mutex to lock.
 * @return         0 if success (mutex locked), otherwise an error number.
 */
int TCNamedMutexTryLock(TC_NAMED_MUTEX *m);

/** Unlock a previously locked mutex.
 * If the mutex is not currently locked by any process,
 * the behaviour is undefined.
 * @param  m       A pointer on the mutex to unlock.
 * @return         0 if success, otherwise an error number.
 */
int TCNamedMutexUnlock(TC_NAMED_MUTEX *m);


/****************************************************************************
 * Simple thread functions, I use the term "simple thread" for any thread   *
 * that doesn't return a value. That makes no big difference with the POSIX *
 * threads, but that does with the threads under Windows. Thus a so-called  *
 * simple thread does not need to be destroyed.                             *
 ****************************************************************************/

/* TCSimpleThreadCreate
   @descr          Create and launch a thread without returned value.
   @param  func    Pointer on the simple thread function to execute.
   @param  arg     Argument to pass to the thread function.
   @param  flags   Creation flags, not supported yet (TCTHREAD_INIT_DEFAULT).
   @param  tha     If not NULL and if the function success, return
                     the created thread's Handle.
   @return         0 if success, otherwise an error number.
   @remark The thread function must be of the form:
             TC_SIMPLE_THREAD_FUNCTION MyFunc(TC_THREAD_ARGUMENT MyArg),
	     where TC_THREAD_ARGUMENT can contains at least a (void *).
*/
int DECLSPEC TCSimpleThreadCreate(TC_SIMPLE_THREAD_FUNCTION_AS_PARAM (*func)(TC_THREAD_FUNCTION_ARGUMENT),
				  TC_THREAD_FUNCTION_ARGUMENT arg, int flags,
				  TC_SIMPLE_THREAD_HANDLE *tha);

/* TCSimpleThreadExit
   @descr          Exit from a thread without returning a value.
   @return         Nothing, by definition.
   @remark This function doesn't return any value readable anywhere else.
*/
DECLSPEC void TCSimpleThreadExit(void);

/* TCGetCurrentSimpleThreadID
   @descr          Return the calling simple thread's ID.
   @return         the Thread's ID.
   @remark Such an ID can only be used to compare thread instances, but at this
             time not to wait for a thread completion.
*/
TC_SIMPLE_THREAD_ID TCGetCurrentSimpleThreadID(void);



/****************************************************************************
 * Threaded pointer functions, threaded pointers are designed to give an    *
 * easy way to use a "local" variable shared by several threads. This means *
 * that each thread owns a value of thi variable.                           *
 ****************************************************************************/

/* TCThreadedPointerInit
   @descr           Init a threaded pointer (void *).
   @param  *tv      The threaded variable to init.
   @return          0 if success, otherwise an error number.
   @remark A TCThreadedPointer must be static. With such a variable, each
            thread can have access to a different value for each one.
*/
#ifdef TC_THREAD_WINDOWS
#define TCThreadedPointerInit(tv) (int)(TCTHRe_NoError)
#endif
#ifdef TC_THREAD_POSIX
int TCThreadedPointerInit(TC_THREADED_POINTER_AS_PARAM *tv);
#endif

/* TCThreadedPointerGet
   @descr           Return the value of a threaded pointer.
   @param  tv       The threaded variable to get.
   @return          the value of the pointer.
   @remark A TCThreadedPointer must be static.
*/
#ifdef TC_THREAD_WINDOWS
#define TCThreadedPointerGet(tv) ((void *)(tv))
#endif
#ifdef TC_THREAD_POSIX
#define TCThreadedPointerGet(tv) ((void *)pthread_getspecific((tv)))
#endif

/* TCThreadedPointerSet
   @descr           Set the value of a threaded pointer.
   @param  tv       The threaded variable to set.
   @param  v        The value to set.
   @return          0 if success, otherwise an error number.
   @remark A TCThreadedPointer must be static.
*/
#ifdef TC_THREAD_WINDOWS
#define TCThreadedPointerSet(tv, v) (((tv)=(v)), (int)TCTHRe_NoError)
#endif
#ifdef TC_THREAD_POSIX
int TCThreadedPointerSet(TC_THREADED_POINTER_AS_PARAM tv, void *v);
#endif

/* TCThreadedPointerDestroy
   @descr           Destroy a previously created threaded pointer.
   @param  tv       The threaded variable to destroy.
   @return          0 if success, otherwise an error number.
   @remark A TCThreadedPointer must be static.
*/
#ifdef TC_THREAD_WINDOWS
#define TCThreadedPointerDestroy(tv) (int)(TCTHRe_NoError)
#endif
#ifdef TC_THREAD_POSIX
int TCThreadedPointerDestroy(TC_THREADED_POINTER_AS_PARAM tv);
#endif





#ifdef  __cplusplus
}
#endif

#endif  /* TCTHREAD_H */












