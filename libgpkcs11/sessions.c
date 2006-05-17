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
 * NAME:        sessions.c
 * SYNOPSIS:    -
 * DESCRIPTION: define the session specific functions of PKCS#11
 * FILES:       -
 * SEE/ALSO:    -
 * AUTHOR:      lbe
 * BUGS:        -
 */
 
static char RCSID[]="$Id$";
const char* Version_sessions_c(){return RCSID;}
 
/* Needed for Win32-isms in cryptoki.h */
#ifndef CK_I_library_build
#define CK_I_library_build
#endif

#include <assert.h>
#include <stdlib.h>

#ifdef EBUG 
#include <stdio.h>
#endif /* EBUG */

#include "internal.h"
#include "objects.h"
#include "pkcs11_error.h"
#include "mutex.h"
#include "slot.h"

/* information about the application.
 * referenced in init.c objects.c sessions.c 
 * defined in internal_def.h
 */
CK_I_APP_DATA CK_I_app_table = {NULL_PTR};

/* {{{ C_OpenSession */
CK_DEFINE_FUNCTION(CK_RV, C_OpenSession)
		(
        CK_SLOT_ID slotID,
        CK_FLAGS flags,
        CK_VOID_PTR pApplication,
        CK_NOTIFY Notify,
        CK_SESSION_HANDLE_PTR phSession
      )
{
  CK_I_TOKEN_DATA_PTR token_data = NULL_PTR;
  CK_I_SLOT_DATA_PTR slot_data = NULL_PTR;
  CK_VOID_PTR mutex = NULL_PTR;
  CK_STATE state = CKS_RO_PUBLIC_SESSION;
  CK_FLAGS session_flags;
  CK_I_SESSION_DATA_PTR new_session = NULL_PTR;
  CK_RV rv = CKR_OK;

  CI_LogEntry("C_OpenSession", "starting...", rv, 1);
  CI_CodeFktEntry("C_OpenSession", "%lu,%x,%p,%p,%p", 
                  slotID,
		  flags,
		  pApplication,
		  Notify,
		  phSession);

  /* make sure we are initialized */
  if (!(CK_I_global_flags & CK_IGF_INITIALIZED)) 
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  
  /* Legacy check. See PKCS#11 Section 10.14 */
  if(!(flags & CKF_SERIAL_SESSION))
    return CKR_SESSION_PARALLEL_NOT_SUPPORTED;

  /* get mutex, there are some synchronized areas in here */
  CI_CreateMutex(&mutex);

  /* get the token data */

  rv = CI_GetSlotData(slotID,&slot_data);
  if(rv != CKR_OK)
    {
      CI_LogEntry("C_OpenSession", "getting slot data", rv, 0);
      CI_DestroyMutex(mutex);
      return rv;
    }

  /* check wether there is a token at all (and it is marked valid).
   * No sense opening a session in the void does now? B-) */
  if(!(slot_data->slot_info->flags & CKF_TOKEN_PRESENT))
    {
      rv = CKR_TOKEN_NOT_PRESENT;
      CI_LogEntry("C_OpenSession", "testing token flags", rv, 0);
      CI_DestroyMutex(mutex);
      return rv;
    }

  token_data=slot_data->token_data;
  if(token_data == NULL_PTR)
    {
      rv = CKR_TOKEN_NOT_PRESENT;
      CI_LogEntry("C_OpenSession", "testing token", rv, 0);
      CI_DestroyMutex(mutex);
      return rv;
    }

  /* Check number of concurrent Sessions */
  _LOCK(mutex);
  if(token_data->token_info->ulSessionCount >= token_data->token_info->ulMaxSessionCount)
    {
      CI_LogEntry("C_OpenSession", "number of avail. sessions exhausted", rv, 0);
      _UNLOCK(mutex);  
      CI_DestroyMutex(mutex);
      return CKR_SESSION_COUNT;
    }

  /* is the hashtable for the sessions already there? */
  if(CK_I_app_table.session_table == NULL_PTR) 
    {
      rv = CI_InitHashtable(&CK_I_app_table.session_table,
			    token_data->token_info->ulMaxSessionCount);
      if(rv != CKR_OK)
	{
	  CI_LogEntry("C_OpenSession", "creating application session list", rv, 0);
	  _UNLOCK(mutex);  
	  CI_DestroyMutex(mutex);
	  return rv; 
	}
    }

  /* If this is to be a RW session... */
  if(flags & CKF_RW_SESSION)
    {
      /* 1. check wether the token is write protected */
      if(token_data->token_info->flags & CKF_WRITE_PROTECTED)
	{
	  _UNLOCK(mutex);  
	  CI_DestroyMutex(mutex);
	  return CKR_TOKEN_WRITE_PROTECTED;
	}

      /* 2. check number of concurrent RW Sessions */
      if(token_data->token_info->ulRwSessionCount >= token_data->token_info->ulMaxRwSessionCount)
	{
	  _UNLOCK(mutex);  
	  CI_DestroyMutex(mutex);
	  return CKR_SESSION_COUNT;
	}
      

      session_flags = CKF_SERIAL_SESSION|CKF_RW_SESSION;

      /*
       * Es darf nur eine RW-SO Session geben. Das Flag wird in CI_Login
       * (Beim Login des SO) gesetzt und hier nur für folgende Sessions
       * getested
       */
            
      if(slot_data->flags & CK_I_SIF_RW_SO_SESSION)
	state = CKS_RW_SO_FUNCTIONS;
      else if(slot_data->flags & CK_I_SIF_USER_SESSION)
	state = CKS_RW_USER_FUNCTIONS;
      else
	state = CKS_RW_PUBLIC_SESSION;
    }
  else /* This is a RO session... */
    {
      session_flags = CKF_SERIAL_SESSION;

      /* make sure that there is not a RW SO session already open */
      if(slot_data->flags & CK_I_SIF_RW_SO_SESSION)
	{
	  _UNLOCK(mutex);  
	  CI_DestroyMutex(mutex);
	  return CKR_SESSION_READ_WRITE_SO_EXISTS;
	}

      /* is there already a logged user session? */
      if(slot_data->flags & CK_I_SIF_USER_SESSION)
	state = CKS_RO_USER_FUNCTIONS; /* Then this becomes a logged in session as well */
      else
	session_flags = CKS_RO_PUBLIC_SESSION; /* this becomes a public RO session */
    } /* RO session */
  
  /* write data to session table */
  new_session = TC_calloc(1,sizeof(CK_I_SESSION_DATA));
  if(new_session == NULL_PTR)
    {
      _UNLOCK(mutex);  
      CI_DestroyMutex(mutex);
      return CKR_HOST_MEMORY;
    }

  new_session->session_info = TC_calloc(1,sizeof(CK_SESSION_INFO));
  if(new_session->session_info == NULL_PTR)
    {
      TC_free(new_session);
      _UNLOCK(mutex);  
      CI_DestroyMutex(mutex);
      return CKR_HOST_MEMORY;
    }

  /* make sure that the object container is initialized */
  if(new_session->object_list == NULL_PTR)
    {
      rv = CI_InitHashtable(&(new_session->object_list),CK_I_OBJ_LIST_SIZE);
      if(rv != CKR_OK)
	{
	  CI_LogEntry("C_OpenSession", "creating session object list", rv, 1);
	  CI_DestroyMutex(mutex);
	  return rv;
	}
    }

  new_session->session_info->slotID = slotID;
  new_session->session_info->flags = session_flags;
  new_session->session_info->state = state;	  

  new_session->pApplication = pApplication;
  new_session->Notify = Notify;

  new_session->slot_data = slot_data;

  /* post creation processing by the token */
  {
    CIP_OpenSession CK_I_Method_P = slot_data->methods->OpenSession;
    if(CK_I_Method_P == NULL_PTR) rv = CKR_OK;
    else rv = CK_I_Method_P (new_session);
  }
  if(rv != CKR_OK) 
    {
       CI_LogEntry("C_OpenSession",
		  "call to token method failed",rv,0);
       
      TC_free(new_session->session_info);
      TC_free(new_session);
      _UNLOCK(mutex);  
      CI_DestroyMutex(mutex);
      return rv;
    }

  /* assign new handle */
  rv= CI_NewHandle(phSession);
  if(rv != CKR_OK)
    {
      TC_free(new_session->session_info);
      TC_free(new_session);
      _UNLOCK(mutex);  
      CI_DestroyMutex(mutex);
      return rv; 
    }

  /* remember for the callback function in rsa_key_gen */
  new_session->session_handle = *phSession;

  ++(token_data->token_info->ulSessionCount);
  if(state >= CKS_RW_PUBLIC_SESSION)
    ++(token_data->token_info->ulRwSessionCount);


  rv = CI_HashPutEntry(CK_I_app_table.session_table,*phSession,(CK_VOID_PTR)new_session);
  if(rv != CKR_OK)
    {
      TC_free(new_session->session_info);
      TC_free(new_session);
      --(token_data->token_info->ulSessionCount);
      if(state >= CKS_RW_PUBLIC_SESSION)
	--(token_data->token_info->ulRwSessionCount);
      _UNLOCK(mutex);  
      CI_DestroyMutex(mutex);
      return rv; 
    }

  CI_VarLogEntry("C_OpenSession", "for Session %lu...complete", rv, 1,*phSession);
  _UNLOCK(mutex);  
  CI_DestroyMutex(mutex);
  return rv;
}


/* }}} */
/* {{{ CI_InternalCloseSession*/
CK_DEFINE_FUNCTION(CK_RV, CI_InternalCloseSession)(
        CK_I_SESSION_DATA_PTR session_data
      )
{
  CK_RV rv = CKR_OK;
  CK_I_HASH_ITERATOR_PTR iter;
  CK_VOID_PTR val = NULL_PTR;
  CK_ULONG key;

  CI_LogEntry("CI_InternalCloseSession","starting...",rv,1);

  /* Free internal state objects */
  CK_I_CALL_TOKEN_METHOD(rv, CloseSession, (session_data) ); 
  if(rv != CKR_OK) 
    {
       CI_LogEntry("CI_InternalCloseSession",
		  "call to token method failed",rv,0);
      return rv;
    }

#ifdef _DEBUG
  /* make sure that the token has deleted all internal objects. */
  if(session_data->digest_state  || session_data->encrypt_state || 
     session_data->decrypt_state || session_data->sign_state    || 
     session_data->verify_state )
    {
      rv = CKR_GENERAL_ERROR;
       CI_LogEntry("CI_InternalCloseSession",
		  "token failed to clear internal states",rv,0);
       if(session_data->digest_state != NULL_PTR) 
	 CI_LogEntry("CI_InternalCloseSession", "\tdigest state not reset",rv,0);
       if(session_data->encrypt_state != NULL_PTR) 
	 CI_LogEntry("CI_InternalCloseSession", "\tencrypt state not reset",rv,0);
       if(session_data->decrypt_state != NULL_PTR) 
	 CI_LogEntry("CI_InternalCloseSession", "\tdecrypt state not reset",rv,0);
       if(session_data->sign_state != NULL_PTR) 
	 CI_LogEntry("CI_InternalCloseSession", "\tsign state not reset",rv,0);
       if(session_data->verify_state != NULL_PTR) 
	 CI_LogEntry("CI_InternalCloseSession", "\tverify state not reset",rv,0);
      return rv;
    }

#endif /* _DEBUG */
  

  /* free memory of remaining objects */
  rv = CI_HashIterateInit(session_data->object_list,&iter);
  if(rv != CKR_OK) 
    {
       CI_LogEntry("CI_InternalCloseSession",
		  "failed to init hash iter",rv,0);
      return rv;
    }

  for ( ; CI_HashIterValid(iter); )
    {
      CI_VarLogEntry("CI_InternalCloseSession","%lu objects left in session obj list",rv,2,
		     session_data->object_list->entries);

      rv = CI_HashIterateDeRef(iter, &key, &val);
      if(rv != CKR_OK) 
	{
	  CI_LogEntry("CI_InternalCloseSession","object remove: iter deref",rv,0);
	  return rv;
	}

      /* free memory of object */
      CI_VarLogEntry("CI_InternalCloseSession","removing object %lu from session",rv,0,key);
      rv = CI_InternalDestroyObject(session_data, key, FALSE);
      if(rv != CKR_OK) 
	{
	  CI_LogEntry("CI_InternalCloseSession","remove object from session",rv,0);
	  return rv;
	}

      /* deleting will invalidate the iterator, so trash it */
      rv = CI_HashIterateDelete(iter);
      if(rv != CKR_OK) 
	{
	  CI_LogEntry("CI_InternalCloseSession","delete iter over object list",rv,0);
	  return rv;
	}
      
      /* start from the beginning */
      rv = CI_HashIterateInit(session_data->object_list,&iter);
      if(rv != CKR_OK) 
	{
	  CI_LogEntry("CI_InternalCloseSession","init iter over session object list",rv,0);
	  return rv;
	}
    }

  /* free memory of the hashtable */
  rv = CI_DestroyHashtable(session_data->object_list);
  if(rv != CKR_OK)
    CI_LogEntry("CI_InternalCloseSession","failed to destroy object list",rv,1);

  --(session_data->slot_data->token_data->token_info->ulSessionCount);
  /* if this a RW session, update the RW-Session counter as well */  
  if(session_data->session_info->state >= CKS_RW_PUBLIC_SESSION)
    --(session_data->slot_data->token_data->token_info->ulRwSessionCount);

  /* if this was the last session on this token reset the login state of the 
   * token to public 
   */
  if(session_data->slot_data->token_data->token_info->ulSessionCount == 0)
    {
      session_data->slot_data->flags &= 
	~(CK_I_SIF_USER_SESSION|CK_I_SIF_RW_SO_SESSION);
    }

  session_data->object_list = NULL_PTR;

  TC_free(session_data->session_info);
  TC_free(session_data);

  CI_LogEntry("CI_InternalCloseSession","...complete",rv,1);

  return CKR_OK;
}
/* }}} */
/* {{{ C_CloseSession */
CK_DEFINE_FUNCTION(CK_RV, C_CloseSession)(
        CK_SESSION_HANDLE hSession
      )
{
  CK_RV rv = CKR_OK;
  CK_VOID_PTR mutex;
  CK_I_SESSION_DATA_PTR session_data = NULL_PTR;

  CI_VarLogEntry("C_CloseSession", "starting...Session: %lu", rv, 1,hSession);
  CI_CodeFktEntry("C_CloseSession", "%lu", 
                  hSession);

  /* get mutex, there are some synchronized areas in here */
  rv = CI_CreateMutex(&mutex);
  if(rv != CKR_OK) return rv;

  _LOCK(mutex);  
  /* make sure we are initialized */
  if (!(CK_I_global_flags & CK_IGF_INITIALIZED)) 
    {
      _UNLOCK(mutex);  
      CI_DestroyMutex(mutex);
      return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

  rv = CI_ReturnSession(hSession, &session_data);
  if(rv != CKR_OK)
    {
      CI_VarLogEntry("C_CloseSession", "retrieve session data (hSession: %lu)", rv, 1,
                     hSession);
      _UNLOCK(mutex);  
      CI_DestroyMutex(mutex);
      return rv;
    }

  /* remove entry from session table */
  if(rv == CKR_OK )
    CI_HashRemoveEntry(CK_I_app_table.session_table,hSession);

  rv = CI_InternalCloseSession(session_data);

  CI_LogEntry("C_CloseSession", "...complete", rv, 1);

  _UNLOCK(mutex);  
  CI_DestroyMutex(mutex);
  return rv; 
}
/* }}} */
/* {{{ C_CloseAllSessions */
/* C_CloseAllSessions closes all sessions with a token. */
CK_DEFINE_FUNCTION(CK_RV, C_CloseAllSessions)
(
  CK_SLOT_ID     slotID  /* the token's slot */
)
{
  CK_RV rv= CKR_OK;
  CK_I_SESSION_DATA_PTR session_data = NULL_PTR;
  CK_ULONG key;
  CK_I_HASH_ITERATOR_PTR iter;

  /* ptr to the token data of the slot */
  CK_I_SLOT_DATA_PTR slot_data = NULL_PTR; 

  CI_LogEntry("C_CloseAllSessions", "starting...", rv, 1);
  CI_CodeFktEntry("C_CloseAllSession", "%lu", 
                  slotID);

  /* make sure we are initialized */
  if (!(CK_I_global_flags & CK_IGF_INITIALIZED)) 
    return CKR_CRYPTOKI_NOT_INITIALIZED;

  /* get ptr to token data of slot */
  rv = CI_GetSlotData(slotID,&slot_data);
  if(rv != CKR_OK)
    {
      CI_LogEntry("C_CloseAlleSessions", "getting token data", rv, 0);
      return rv;
    }

  /* TODO: the token knows about its sessions. use that info to clean up */
  /* go through all sessions in the session table and select those with same token_data */
  
  //if(CK_I_app_table.session_table == NULL_PTR) goto ende;
  if(CK_I_app_table.session_table == NULL_PTR) return rv;

  rv = CI_HashIterateInit(CK_I_app_table.session_table,&iter);
  if(rv != CKR_OK) 
    {
      CI_LogEntry("C_CloseAllSessions", "init session_table iter", rv, 0);
      return rv;
    }

  for ( ; CI_HashIterValid(iter) ; )
    {
      rv = CI_HashIterateDeRef(iter, &key, (CK_VOID_PTR CK_PTR)(&session_data));
      if(rv != CKR_OK) 
	{
	  CI_LogEntry("C_CloseAllSessions", "de-refing iter", rv, 0);
	  goto ende;
	}

      /* are the token of this slot and the session the same? */
      if(session_data->slot_data == slot_data)
	{
	  rv = CI_HashIterateDel(iter);
	  if(rv != CKR_OK) 
	    {
	      CI_LogEntry("C_CloseAllSessions", "deleting iter-ref'ed element", rv, 0);
	      goto ende;
	    }

	  rv = CI_InternalCloseSession(session_data);
	  if(rv != CKR_OK) 
	    {
	      CI_LogEntry("C_CloseAllSessions", "closing internal Session rep", rv, 0);
	      goto ende;
	    }
	}
      else
	CI_HashIterateInc(iter);
    }

 ende:
  CI_HashIterateDelete(iter);

  CI_LogEntry("C_CloseAllSession", "...complete", rv, 1);

  return rv;
}
/* }}} */
/* {{{ C_GetSessionInfo */
CK_DEFINE_FUNCTION(CK_RV, C_GetSessionInfo)(
        CK_SESSION_HANDLE hSession,
        CK_SESSION_INFO_PTR pInfo
      )
{
  CK_I_SESSION_DATA_PTR session_data = NULL_PTR;
  CK_RV rv = CKR_OK;

  CI_LogEntry("C_GetSessionInfo", "starting...", rv, 1);
  CI_CodeFktEntry("C_GetSessionInfo", "%lu,%p", 
                  hSession,
                  pInfo);

  /* make sure we are initialized */
  if (!(CK_I_global_flags & CK_IGF_INITIALIZED)) 
    return CKR_CRYPTOKI_NOT_INITIALIZED;

  rv = CI_ReturnSession(hSession, &session_data);
  if(rv != CKR_OK)
    {
      CI_VarLogEntry("C_GetSessionInfo", "retrieve session data (hSession: %lu)", rv, 1,
                     hSession);
      return rv;
    }

  pInfo->slotID = session_data->session_info->slotID ;
  pInfo->state = session_data->session_info->state ;
  pInfo->flags = session_data->session_info->flags ;
  pInfo->ulDeviceError = session_data->session_info->ulDeviceError ;

  CI_LogEntry("C_GetSessionInfo", "...complete", rv, 1);

  return CKR_OK;
}
/* }}} */
/* {{{ CI_PropagateSessionState */
CK_DEFINE_FUNCTION(CK_RV, CI_PropagateSessionState)(
  CK_I_SESSION_DATA_PTR session_data /* session whose state is to be propagated */
      )
{
  CK_I_HASH_ITERATOR_PTR iter;
  CK_VOID_PTR mutex;
  CK_I_SESSION_DATA_PTR curr_session;
  CK_ULONG dummy_handle;
  CK_RV rv = CKR_OK;

  CI_LogEntry("CI_PropagateSessionState", "starting...", 
	      rv, 1);
  
  rv = CI_CreateMutex(&mutex);
  if(rv != CKR_OK) 
    {
      CI_LogEntry("CI_PropagateSessionState", 
		  "creation of mutex failed", rv, 0);
      return rv;
    }
  
  _LOCK(mutex);
  rv = CI_HashIterateInit(CK_I_app_table.session_table,&iter);
  if(rv != CKR_OK) 
    {
      CI_LogEntry("CI_PropagateSessionState", 
		  "unable to get iterator on session list", 
		  rv, 0);
      _UNLOCK(mutex);
      CI_DestroyMutex(mutex);
      return rv;
    }
  
  while(CI_HashIterValid(iter))
    {
      rv = CI_HashIterateDeRef(iter,&dummy_handle,(CK_VOID_PTR_PTR)&curr_session);
      if(rv != CKR_OK)
	{
	  CI_LogEntry("CI_PropagateSessionState", 
		      "unable to deref iter on session table", 
		      rv, 0);
	  _UNLOCK(mutex);
	  CI_DestroyMutex(mutex);
	  return rv;	    
	}

      if(curr_session->session_info->slotID ==
	 session_data->session_info->slotID)
	{
	  CI_VarLogEntry("CI_PropagateSessionState", 
		      "setting state to %i for session %i", 
		      rv, 0,session_data->session_info->state,dummy_handle);
	  curr_session->session_info->state = 
	    session_data->session_info->state;
	}
      else
	CI_VarLogEntry("CI_PropagateSessionState", 
		       "session %i of slot %i, no state change", 
		       rv, 0,dummy_handle, session_data->session_info->slotID);

      rv=CI_HashIterateInc(iter);
      if(rv != CKR_OK)
	{
	  CI_LogEntry("CI_PropagateSessionState", 
		      "unable to iterate on session list", 
		      rv, 0);
	  _UNLOCK(mutex);
	  CI_DestroyMutex(mutex);
	  return rv;	    
	}
      
    }

  CI_HashIterateDelete(iter);

  _UNLOCK(mutex);
  CI_DestroyMutex(mutex);

  CI_LogEntry("CI_PropagateSessionState", "...done", 
	      rv, 1);

  return rv;
}

/* }}} */
/* {{{ C_Login */
/* C_Login logs a user into a token. */
CK_DEFINE_FUNCTION(CK_RV, C_Login)
(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_USER_TYPE      userType,  /* the user type */
  CK_CHAR_PTR       pPin,      /* the user's PIN */
  CK_ULONG          ulPinLen   /* the length of the PIN */
)
{
  CK_I_SESSION_DATA_PTR session_data = NULL_PTR;
  CK_RV rv = CKR_OK;
#ifdef PRINT_PINS
  CK_CHAR_PTR tmp = NULL_PTR;
#endif /* PRINT_PINS */

  CI_LogEntry("C_Login", "starting...", rv, 1);
  CI_CodeFktEntry("C_Login", "%lu,%x,%s,%lu", 
                  hSession,
		  userType,
#ifndef PRINT_PINS
                  "<opaque PIN>",
		  ulPinLen);
#else /* PRINT_PINS */
                  tmp = CI_ScanableByteStream(pPin,ulPinLen),
		  ulPinLen);
   TC_free(tmp);
#endif /* PRINT_PINS */
  
  /* make sure we are initialized */
  if (!(CK_I_global_flags & CK_IGF_INITIALIZED)) 
    return CKR_CRYPTOKI_NOT_INITIALIZED;

  
  rv = CI_ReturnSession(hSession, &session_data);
  if(rv != CKR_OK)
    {
      CI_VarLogEntry("C_Login", "retrieve session data (hSession: %lu)", rv, 1,
                     hSession);
      return rv;
    }
 
  /* TODO: remaining correctness pre-checks of login */

  if(((session_data->session_info->state==CKS_RO_USER_FUNCTIONS) ||
      (session_data->session_info->state==CKS_RW_USER_FUNCTIONS)) &&
     (userType == CKU_SO))
    {
      rv = CKR_USER_ANOTHER_ALREADY_LOGGED_IN;
      CI_LogEntry("C_Login", "Login pre-check failed", rv, 0);
      return rv;
    }

  if((session_data->session_info->state==CKS_RO_USER_FUNCTIONS) ||
     (session_data->session_info->state==CKS_RW_USER_FUNCTIONS) ||
     (session_data->session_info->state==CKS_RW_SO_FUNCTIONS))
    {
      rv = CKR_USER_ALREADY_LOGGED_IN;
      CI_LogEntry("C_Login", "Login pre-check failed", rv, 0);
      return rv;
    }

  CK_I_CALL_TOKEN_METHOD(rv, Login, (session_data, userType, pPin, ulPinLen));
  if(rv != CKR_OK)
    {
      CI_LogEntry("C_Login", "token call of Login failed", rv, 0);
      return rv;
    }

  /* actually set the new state */
  if(userType == CKU_SO)
    {
      session_data->session_info->state= CKS_RW_SO_FUNCTIONS; 
      session_data->slot_data->flags |= CK_I_SIF_RW_SO_SESSION;
    }
  else
    {
      session_data->slot_data->flags |= CK_I_SIF_USER_SESSION;
      if(session_data->session_info->state== CKS_RW_PUBLIC_SESSION)
	session_data->session_info->state=CKS_RW_USER_FUNCTIONS;
      else
	session_data->session_info->state=CKS_RO_USER_FUNCTIONS;
    }

  /* now propagate this accross all sessions (see 6.6.4) */
  CI_PropagateSessionState(session_data);

  /* set the value in the slot_data for new sessions to be opened 
   * on this slot */

  CI_LogEntry("C_Login", "...complete", rv, 1);

  return rv;
}
/* }}} */
/* {{{ C_Logout */
/* C_Logout logs a user out from a token. */
CK_DEFINE_FUNCTION(CK_RV, C_Logout)(
  CK_SESSION_HANDLE hSession  /* the session's handle */
)
{
  CK_I_SESSION_DATA_PTR session_data = NULL_PTR;
  CK_RV rv = CKR_OK;

  CI_LogEntry("C_Logout", "starting...", rv, 1);
  CI_CodeFktEntry("C_Logout", "%lu", 
                  hSession);

  /* make sure we are initialized */
  if (!(CK_I_global_flags & CK_IGF_INITIALIZED)) 
    return CKR_CRYPTOKI_NOT_INITIALIZED;

  
  /* make sure that this session exists */
  rv = CI_ReturnSession(hSession, &session_data);
  if(rv != CKR_OK)
    {
      CI_VarLogEntry("C_Logout", 
		     "retrieve session data (hSession: %lu)", rv, 1,
                     hSession);
      return rv;
    }
 
  CK_I_CALL_TOKEN_METHOD(rv, Logout, (session_data));
  if(rv != CKR_OK)
    {
      CI_LogEntry("C_Logout", "call to token failed", rv, 0);
      return rv;
    }

  /* actually set the new state */
  if((session_data->session_info->state== CKS_RW_SO_FUNCTIONS) ||
     (session_data->session_info->state=CKS_RW_USER_FUNCTIONS))
    session_data->session_info->state= CKS_RW_PUBLIC_SESSION; 
  else 
    session_data->session_info->state=CKS_RO_USER_FUNCTIONS;

  /* reset for slot for future sessions */
  session_data->slot_data->flags &= 
    ~(CK_I_SIF_USER_SESSION|CK_I_SIF_RW_SO_SESSION);
  
  /* now propagate this accross all sessions (see 6.6.4) */
  CI_PropagateSessionState(session_data);

  CI_LogEntry("C_Logout", "...complete", rv, 1);

  return rv;
}
/* }}} */
/* {{{ C_GetOperationState */
/* C_GetOperationState obtains the state of the cryptographic operation
 * in a session. */
CK_DEFINE_FUNCTION(CK_RV, C_GetOperationState)
(
  CK_SESSION_HANDLE hSession,             /* session's handle */
  CK_BYTE_PTR       pOperationState,      /* gets state */
  CK_ULONG_PTR      pulOperationStateLen  /* gets state length */
)
{
  CK_RV rv = CKR_OK;
  CK_I_SESSION_DATA_PTR session_data = NULL_PTR;

  CI_LogEntry("C_GetOperationState", "starting...", rv, 1);

  /* make sure we are initialized */
  if (!(CK_I_global_flags & CK_IGF_INITIALIZED)) 
    return CKR_CRYPTOKI_NOT_INITIALIZED;

  rv = CI_ReturnSession(hSession, &session_data);
  if(rv != CKR_OK)
    {
      CI_VarLogEntry("C_CreateObject", "retrieve session data (hSession: %lu)", rv, 1,
                     hSession);
      return rv;
    }

  CK_I_CALL_TOKEN_METHOD(rv, GetOperationState, (session_data, pOperationState, pulOperationStateLen));

  CI_LogEntry("C_GetOperationState", "...complete", rv, 1);

  return rv;
}
/* }}} */
/* {{{ C_SetOperationState */
/* C_SetOperationState restores the state of the cryptographic
 * operation in a session. */
CK_DEFINE_FUNCTION(CK_RV, C_SetOperationState)
(
  CK_SESSION_HANDLE hSession,            /* session's handle */
  CK_BYTE_PTR      pOperationState,      /* holds state */
  CK_ULONG         ulOperationStateLen,  /* holds state length */
  CK_OBJECT_HANDLE hEncryptionKey,       /* en/decryption key */
  CK_OBJECT_HANDLE hAuthenticationKey    /* sign/verify key */
)
{
  CK_RV rv = CKR_OK;
  CK_I_OBJ_PTR enc_key = NULL_PTR;  /* key for encryption */
  CK_I_OBJ_PTR auth_key = NULL_PTR;  /* key for authentication */
  CK_I_SESSION_DATA_PTR session_data = NULL_PTR;

  CI_LogEntry("C_SetOperationState", "starting...", rv, 1);

  /* make sure we are initialized */
  if (!(CK_I_global_flags & CK_IGF_INITIALIZED)) 
    return CKR_CRYPTOKI_NOT_INITIALIZED;

  rv = CI_ReturnSession(hSession, &session_data);
  if(rv != CKR_OK)
    {
      CI_VarLogEntry("C_SetOperationState", "retrieve session data (hSession: %lu)", rv, 1,
                     hSession);
      return rv;
    }

  /* TODO: do some tests that keys allow enc/decryption and sign/verify respectivly */
  rv = CI_ReturnObj(session_data,hEncryptionKey, &enc_key);
  if(rv != CKR_OK)
    {
      CI_VarLogEntry("C_SetOperationState", "retrieve object list (hSession: %lu, hKey: %lu)", rv, 1,
                     hSession, hEncryptionKey);
      return rv;
    }
  
  rv = CI_ReturnObj(session_data,hAuthenticationKey, &auth_key);
  if(rv != CKR_OK)
    {
      CI_VarLogEntry("C_SetOperationState", "retrieve object list (hSession: %lu, hKey: %lu)", rv, 1,
                     hSession, hAuthenticationKey);
      return rv;
    }

  CK_I_CALL_TOKEN_METHOD(rv, SetOperationState, (session_data, pOperationState, ulOperationStateLen, enc_key, auth_key));

  CI_LogEntry("C_SetOperationState", "...complete", rv, 1);

  return rv;
}
/* }}} */
/*
 * Local variables:
 * folded-file: t
 * end:
 */


