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
 * NAME:        slot.c
 * SYNOPSIS:    -
 * DESCRIPTION: -
 * FILES:       -
 * SEE/ALSO:    -
 * AUTHOR:      lbe
 * BUGS: *      -
 * HISTORY:     $Log$
 * HISTORY:     Revision 1.14  2000/09/19 09:14:55  lbe
 * HISTORY:     write flag for pin change onto SC, support Auth Pin path
 * HISTORY:
 * HISTORY:     Revision 1.13  2000/06/05 11:43:43  lbe
 * HISTORY:     tcsc token breakup, return pSlotCount in SlotList, code for event handling deactivated
 * HISTORY:
 * HISTORY:     Revision 1.12  2000/05/16 09:54:14  lbe
 * HISTORY:     checkin to test bonsai
 * HISTORY:
 * HISTORY:     Revision 1.11  2000/05/12 13:13:15  lbe
 * HISTORY:     zwischen durchmal B-)
 * HISTORY:
 * HISTORY:     Revision 1.10  2000/01/31 18:09:03  lbe
 * HISTORY:     lockdown prior to win_gdbm change
 * HISTORY:
 * HISTORY:     Revision 1.9  2000/01/12 23:06:45  lbe
 * HISTORY:     changes for 0.5.7: detect missing card
 * HISTORY:
 * HISTORY:     Revision 1.8  2000/01/07 10:24:44  lbe
 * HISTORY:     introduce changes for release
 * HISTORY:
 * HISTORY:     Revision 1.7  1999/12/02 14:16:27  lbe
 * HISTORY:     tons of small bug fixes and bullet proofing of libgpkcs11 and cryptsh
 * HISTORY:
 * HISTORY:     Revision 1.6  1999/11/25 16:46:52  lbe
 * HISTORY:     moved all lib version defines into the conf.h
 * HISTORY:
 * HISTORY:     Revision 1.5  1999/11/02 13:47:19  lbe
 * HISTORY:     change of structures and bug fix in slot.c, add more files for tcsc_token: emptyfuncs and general_data
 * HISTORY:
 * HISTORY:     Revision 1.4  1999/10/08 13:00:13  lbe
 * HISTORY:     release version 0.5.5
 * HISTORY:
 * HISTORY:     Revision 1.3  1999/10/06 07:57:23  lbe
 * HISTORY:     solved netscape symbol clash problem
 * HISTORY:
 * HISTORY:     Revision 1.2  1999/07/20 17:40:01  lbe
 * HISTORY:     fix bug in gdbm Makefile: there is not allways an 'install' around
 * HISTORY:
 * HISTORY:     Revision 1.1  1999/06/16 09:46:11  lbe
 * HISTORY:     reorder files
 * HISTORY:
 * HISTORY:     Revision 1.9  1999/01/26 08:11:34  lbe
 * HISTORY:     test system in first form
 * HISTORY:
 * HISTORY:     Revision 1.8  1999/01/19 12:19:47  lbe
 * HISTORY:     first release lockdown
 * HISTORY:
 * HISTORY:     Revision 1.7  1999/01/13 16:16:40  lbe
 * HISTORY:     clampdown for persistent storage complete.
 * HISTORY:
 * HISTORY:     Revision 1.6  1998/11/04 17:12:34  lbe
 * HISTORY:     debug-lockdown
 * HISTORY:
 * HISTORY:     Revision 1.5  1998/10/14 15:57:40  lbe
 * HISTORY:     *** empty log message ***
 * HISTORY:
 * HISTORY:     Revision 1.4  1998/10/12 10:00:10  lbe
 * HISTORY:     clampdown
 * HISTORY:
 * HISTORY:     Revision 1.3  1998/08/05 09:00:27  lbe
 * HISTORY:     *** empty log message ***
 * HISTORY:
 * HISTORY:     Revision 1.2  1998/07/23 15:18:19  lbe
 * HISTORY:     working
 * HISTORY:
 * HISTORY:     Revision 1.1  1998/07/02 17:25:43  lbe
 * HISTORY:     Initial revision
 * HISTORY:
 */
 
static char RCSID[]="$Id$";
const char* Version_slot_c(){return RCSID;}

#ifndef CK_I_library_build
#define CK_I_library_build
#endif

#include <string.h>
#include <assert.h>
#include <stdlib.h>

#include "internal.h"
#include "error.h"
#include "objects.h"
#include "slot.h"

/* {{{ Data Structures */
/* the table containing the references to the slot data informations
 * is dynamically allocated in CI_RegisterToken, each time a slot registers
 * CK_I_SLOT_ANZ counts the number of slots loaded in the library
 * TODO : put the table and the counter in a private structure
 */
static CK_I_SLOT_DATA **CK_I_slot_info_table = NULL_PTR;
static CK_ULONG CK_I_SLOT_ANZ = 0;
/* }}} */
/* {{{ C_GetSlotList */
CK_DEFINE_FUNCTION(CK_RV, C_GetSlotList)(
        CK_BBOOL tokenPresent,
        CK_SLOT_ID_PTR pSlotList,
        CK_ULONG_PTR pulCount
      )
{
  CK_ULONG i,count = 0;
  CK_RV rv = CKR_OK;

  CI_LogEntry("C_GetSlotList", "starting...", rv, 1);
  if(tokenPresent) 
    CI_LogEntry("C_GetSlotList", "Listing only slots with present tokens", rv, 1);
  else 
    CI_LogEntry("C_GetSlotList", "Listing all slots", rv, 1);
  CI_CodeFktEntry("C_GetSlotList", "%s,%p,%p", 
                  (tokenPresent == TRUE)?"TRUE":"FALSE",
                  pSlotList,
		  pulCount);
  if(pSlotList != NULL_PTR)
    CI_VarLogEntry("C_GetSlotList", "*pulCount: %i", rv, 1, *pulCount);
 
    /* make sure we are initialized */
  if (!(CK_I_global_flags & CK_IGF_INITIALIZED)) 
    return CKR_CRYPTOKI_NOT_INITIALIZED;

  /* the slots are loaded dynamically at initialization
   * the slot_info_table records now contain NULL_PTR if the slot 
   *  is not loaded
   * to test whether a token is present or not, use flag CKF_TOKEN_PRESENT
   */
  for (i = 0; i< CK_I_SLOT_ANZ; i++)
    if (CK_I_slot_info_table[i] != NULL_PTR)
      {
	if(CK_I_slot_info_table[i]->slot_info == NULL_PTR)
	  {
	    rv = CKR_GENERAL_ERROR;
	    CI_LogEntry("C_GetSlotList", "No slot_info set in slot_data", rv, 1);
	  }
	if ( ( tokenPresent == FALSE )
	    || (CK_I_slot_info_table[i]->slot_info->flags & CKF_TOKEN_PRESENT) )
	  count++;
      }
  if(pSlotList == NULL_PTR) /* only query the number of slots */
    {
      rv = CKR_OK;
      CI_LogEntry("C_GetSlotList", "computing needed size of List-Array", rv, 1);
      *pulCount= count;
      CI_VarLogEntry("C_GetSlotList", "*pulCount: %i", rv, 1, *pulCount);

      return rv;
    }

  /* Ok this is the real thing: return the list of slots */
  /* first check that the size of buffer is sufficient for the availiable slots */
  /* number of slot was computed in count ; comparing with pulCount */
  if (*pulCount < count)
    {
      rv = CKR_BUFFER_TOO_SMALL;
      CI_LogEntry("C_GetSlotList", "checking size of list buffer", rv, 1);
      return rv ;
    }

  /* copy the slot number into the list */
  count = 0;
  for(i = 0; i< CK_I_SLOT_ANZ; i++)
    /* be sure that the slot_info_table record isn't NULL_PTR */
    if (CK_I_slot_info_table[i] != NULL_PTR)
      if ( (tokenPresent == FALSE)
	   || (CK_I_slot_info_table[i]->slot_info->flags & CKF_TOKEN_PRESENT) )
	pSlotList[count++] = i;
  
  *pulCount= count;
  CI_VarLogEntry("C_GetSlotList", "returning *pulCount: %i", rv, 1, *pulCount);

  CI_LogEntry("C_GetSlotList", "...complete", rv, 1);

  return CKR_OK;  
}
/* }}} */
/* {{{ C_GetSlotInfo */
CK_DEFINE_FUNCTION(CK_RV, C_GetSlotInfo)(
        CK_SLOT_ID slotID,
        CK_SLOT_INFO_PTR pInfo
      )
{
  CK_I_SLOT_DATA_PTR slot_data = NULL_PTR;
  CK_RV rv = CKR_OK;

  CI_LogEntry("C_GetSlotInfo", "starting...", rv, 1);
  CI_CodeFktEntry("C_GetSlotInfo", "%i,%p", 
                  slotID,
                  pInfo);

  /* make sure we are initialized */
  if (!(CK_I_global_flags & CK_IGF_INITIALIZED)) 
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  
  /* TODO: get information wether the token is removable / hardware */
  pInfo->flags = 0;

  rv = CI_GetSlotData(slotID, &slot_data);
  if(rv != CKR_OK)
    {
      CI_LogEntry("C_GetSlotInfo", "getting slot data", rv, 1);
      return rv;
    }  

  strncpy((char*)pInfo->slotDescription,
	  (char*)slot_data->slot_info->slotDescription, 64);
  strncpy((char*)pInfo->manufacturerID,
	  (char*)slot_data->slot_info->manufacturerID, 32);
  
  if(CK_I_slot_info_table[slotID]->token_data != NULL_PTR)
    {
      CI_LogEntry("C_GetSlotInfo", "token present", rv, 1);
      pInfo->flags |= CKF_TOKEN_PRESENT;
    }
  else
    CI_LogEntry("C_GetSlotInfo", "token not present", rv, 1);

  pInfo->hardwareVersion.major = slot_data->slot_info->hardwareVersion.major;
  pInfo->hardwareVersion.minor = slot_data->slot_info->hardwareVersion.minor;
  pInfo->firmwareVersion.major = slot_data->slot_info->firmwareVersion.major;
  pInfo->firmwareVersion.minor = slot_data->slot_info->firmwareVersion.minor;

  CI_LogEntry("C_GetSlotInfo", "...complete", rv, 1);

  return rv;
}
/* }}} */
/* {{{ C_GetTokenInfo */
CK_DEFINE_FUNCTION(CK_RV, C_GetTokenInfo)(
        CK_SLOT_ID slotID,
        CK_TOKEN_INFO_PTR pInfo
      )
{
  CK_I_TOKEN_DATA_PTR token_data = NULL_PTR;
  CK_I_SLOT_DATA_PTR slot_data = NULL_PTR;
  CK_RV rv = CKR_OK;

  CI_LogEntry("C_GetTokenInfo", "starting...", rv, 1);
  CI_CodeFktEntry("C_GetTokenInfo", "%i,%p", 
                  slotID,
                  pInfo);

    /* make sure we are initialized */
  if (!(CK_I_global_flags & CK_IGF_INITIALIZED)) 
    return CKR_CRYPTOKI_NOT_INITIALIZED;

  rv = CI_GetSlotData(slotID, &slot_data);
  if(rv != CKR_OK)
    {
      CI_LogEntry("C_GetTokenInfo", "getting slot data", rv, 1);
      return rv;
    }

  /* check for slot existence */
  if(!(slot_data->slot_info->flags & CKF_TOKEN_PRESENT))
    {
      rv = CKR_TOKEN_NOT_PRESENT;
      CI_LogEntry("C_GetTokenInfo", "checking token flags", rv, 1);
      return rv;
    }
  if(slot_data->token_data == NULL_PTR)
    {
      rv = CKR_TOKEN_NOT_PRESENT;
      CI_LogEntry("C_GetTokenInfo", "getting token data", rv, 1);
      return rv;
    }
  token_data = slot_data->token_data;

  pInfo->flags                 = token_data->token_info->flags;  
  pInfo->ulMaxSessionCount     = token_data->token_info->ulMaxSessionCount;
  pInfo->ulSessionCount        = token_data->token_info->ulSessionCount;
  pInfo->ulMaxRwSessionCount   = token_data->token_info->ulMaxRwSessionCount;  
  pInfo->ulRwSessionCount      = token_data->token_info->ulRwSessionCount;
  pInfo->ulMaxPinLen           = token_data->token_info->ulMaxPinLen;
  pInfo->ulMinPinLen           = token_data->token_info->ulMinPinLen;
  pInfo->ulTotalPublicMemory   = token_data->token_info->ulTotalPublicMemory;
  pInfo->ulFreePublicMemory    = token_data->token_info->ulFreePublicMemory;
  pInfo->ulTotalPrivateMemory  = token_data->token_info->ulTotalPrivateMemory;
  pInfo->ulFreePrivateMemory   = token_data->token_info->ulFreePrivateMemory;
  pInfo->hardwareVersion.major = token_data->token_info->hardwareVersion.major;
  pInfo->hardwareVersion.minor = token_data->token_info->hardwareVersion.minor;
  pInfo->firmwareVersion.major = token_data->token_info->firmwareVersion.major;
  pInfo->firmwareVersion.minor = token_data->token_info->firmwareVersion.minor;

  strncpy((char*)pInfo->manufacturerID,  (char*)token_data->token_info->manufacturerID, 32);
  strncpy((char*)pInfo->model,           (char*)token_data->token_info->model, 16);
  
  if(slot_data->token_data->token_info->flags & CKF_TOKEN_INITIALIZED == 0)
    {
      CI_LogEntry("C_GetTokenInfo", "getting token data", rv, 1);
      return rv;
    }

  strncpy((char*)pInfo->label,           (char*)token_data->token_info->label, 32);
  strncpy((char*)pInfo->serialNumber,    (char*)token_data->token_info->serialNumber, 16);   

  /* call the method for special or dynamic values */
  if(slot_data->methods->GetTokenInfo != NULL_PTR)
    rv = (slot_data->methods->GetTokenInfo)(CK_I_slot_info_table[slotID], pInfo);

  CI_LogEntry("C_GetTokenInfo", "...complete", rv, 1);
  
  return rv;
}
/* }}} */
/* {{{ C_GetMechanismList */
CK_DEFINE_FUNCTION(CK_RV, C_GetMechanismList)(
        CK_SLOT_ID slotID,
        CK_MECHANISM_TYPE_PTR pMechanismList,
        CK_ULONG_PTR pulCount
      )
{
  CK_I_SLOT_DATA_PTR slot_data = NULL_PTR;
  CK_RV rv = CKR_OK;

  CI_LogEntry("C_GetMechanismList", "starting...", rv, 1);
  CI_CodeFktEntry("C_GetMechanismList", "%i,%p,%p", 
                  slotID,
                  pMechanismList,
		  pulCount);
  if(pMechanismList != NULL_PTR)
  CI_VarLogEntry("C_GetMechanismList", "*pulCount: %i", rv, 1,*pulCount);

    /* make sure we are initialized */
  if (!(CK_I_global_flags & CK_IGF_INITIALIZED)) 
    return CKR_CRYPTOKI_NOT_INITIALIZED;

  /* make sure that the slot is valid */
  if(slotID >= CK_I_SLOT_ANZ)
    {
      rv = CKR_SLOT_ID_INVALID;
      CI_VarLogEntry("C_GetMechanismList", "Invalid SlotID %ul, library only contains %ul slots", rv, 0, slotID, CK_I_SLOT_ANZ);
      return rv;
    }

  rv = CI_GetSlotData(slotID,&slot_data);
  if(rv != CKR_OK)
    {
      CI_LogEntry("C_GetMechanismList", "getting token data", rv, 1);
      return rv;
    }

  rv = (slot_data->methods->GetMechanismList)(pMechanismList, pulCount);
  CI_LogEntry("C_GetMechanismList", "...complete", rv, 1);

  return rv;
}
/* }}} */
/* {{{ C_GetMechanismInfo */
CK_DEFINE_FUNCTION(CK_RV, C_GetMechanismInfo)(
        CK_SLOT_ID slotID,
        CK_MECHANISM_TYPE type,
        CK_MECHANISM_INFO_PTR pInfo
      )
{
  CK_I_SLOT_DATA_PTR slot_data = NULL_PTR;
  CK_RV rv=CKR_OK;

  CI_LogEntry("C_GetMechanismInfo", "starting...", rv, 1);
  CI_CodeFktEntry("C_GetMechanismInfo", "%i,%x,%p", 
                  slotID,
                  CI_MechanismStr(type),
		  pInfo);

    /* make sure we are initialized */
  if (!(CK_I_global_flags & CK_IGF_INITIALIZED)) 
    return CKR_CRYPTOKI_NOT_INITIALIZED;

  rv = CI_GetSlotData(slotID,&slot_data);
  if(rv != CKR_OK)
    {
      CI_LogEntry("C_GetMechanismInfo", "getting slot data", rv, 1);
      return rv;
    }

  rv = (slot_data->methods->GetMechanismInfo)(type, pInfo);
  CI_LogEntry("C_GetMechanismInfo", "...complete", rv, 1);

  return rv;
}
/* }}} */

/**
C_InitPIN() initializes the normal user's PIN.

It checks
<ul>
  <li>that Cryptoki is initialized
  <li>that C_OpenSession() was previously called with CKS_RW_SO_FUNCTIONS
  <li>
</ul>
*/

/* {{{ C_InitPIN */
CK_DEFINE_FUNCTION(CK_RV, C_InitPIN)
(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_CHAR_PTR       pPin,      /* the normal user's PIN */
  CK_ULONG          ulPinLen   /* length in bytes of the PIN */
)
{
  CK_I_SESSION_DATA_PTR session_data = NULL_PTR;
  CK_RV rv = CKR_OK;

  CI_LogEntry("C_InitPIN", "starting...", rv, 1);

  /* make sure we are initialized */
  if (!(CK_I_global_flags & CK_IGF_INITIALIZED)) 
    return CKR_CRYPTOKI_NOT_INITIALIZED;

  
  /* make sure that this session exists */
  rv = CI_ReturnSession(hSession, &session_data);
  if(rv != CKR_OK)
    {
      CI_VarLogEntry("C_InitPIN", "retrieve session data (hSession: %lu)", rv, 0,
                     hSession);
      return rv;
    }

  /* check the status of the session */
  if(session_data->session_info->state != CKS_RW_SO_FUNCTIONS) 
    {
      CI_LogEntry("C_InitPIN", "Function may only be called by the SO", rv, 0);
      return CKR_USER_NOT_LOGGED_IN;
    }

  CK_I_CALL_TOKEN_METHOD(rv, InitPIN, (session_data, pPin, ulPinLen));

  CI_LogEntry("C_InitPIN", "...complete", rv, 1);

  return rv;
}
/* }}} */
/* {{{ C_SetPIN */
/* C_SetPIN modifies the PIN of the user who is logged in. */
CK_DEFINE_FUNCTION(CK_RV, C_SetPIN)
(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_CHAR_PTR       pOldPin,   /* the old PIN */
  CK_ULONG          ulOldLen,  /* length of the old PIN */
  CK_CHAR_PTR       pNewPin,   /* the new PIN */
  CK_ULONG          ulNewLen   /* length of the new PIN */
)
{
  CK_I_SESSION_DATA_PTR session_data = NULL_PTR;
  CK_RV rv = CKR_OK;

  CI_LogEntry("C_SetPIN", "starting...", rv, 1);
  
#ifndef PRINT_PINS
  CI_CodeFktEntry("C_SetPIN", "%i,%s", 
  hSession,
  "<opaque old PIN>");
#else /* PRINT_PINS */
#ifndef NO_LOGGING
  {
    CK_CHAR_PTR tmp = NULL;
    CK_CHAR_PTR tmp2 = NULL;
    CI_CodeFktEntry("C_SetPIN", "%i,%s", 
      hSession,
		  tmp = CI_ScanableByteStream(pOldPin,ulOldLen),
      ulOldLen
      tmp2 = CI_ScanableByteStream(pNewPin,ulNewLen),
      ulNewLen);
    TC_free(tmp);
    TC_free(tmp2);
  }
#endif // NO_LOGGING
#endif /* PRINT_PINS */

  /* make sure we are initialized */
  if (!(CK_I_global_flags & CK_IGF_INITIALIZED)) 
    return CKR_CRYPTOKI_NOT_INITIALIZED;

  /* make sure that this session exists */
  rv = CI_ReturnSession(hSession, &session_data);
  if(rv != CKR_OK)
    {
      CI_VarLogEntry("C_SetPin", "retrieve session data (hSession: %lu)", rv, 1,
                     hSession);
      return rv;
    }
 
  /* check the state of the session */
  if((session_data->session_info->state != CKS_RW_PUBLIC_SESSION) &&
     (session_data->session_info->state != CKS_RW_USER_FUNCTIONS) &&
     (session_data->session_info->state != CKS_RW_SO_FUNCTIONS))
    {
      rv =  CKR_SESSION_READ_ONLY;
      CI_VarLogEntry("C_SetPIN", 
		     "session is %i. Function may only be called in a user-RW or SO-RW session state", 
		  rv, 0,session_data->session_info->state);
      return rv;
    }

  CK_I_CALL_TOKEN_METHOD(rv, SetPIN, (session_data, pOldPin, ulOldLen, pNewPin, ulNewLen));

  CI_LogEntry("C_SetPin", "...complete", rv, 1);

  return rv;
}
/* }}} */
/* {{{ CI_RegisterSlot */
/** called by init to make the token known to the library.
 * the function actually registers a slot, and not a token
 * The data structure CK_I_SLOT_DATA is then defined in the so-called 
 * token implementation.
 */
CK_DEFINE_FUNCTION(CK_RV, CI_RegisterSlot)(
 CK_ULONG slotID,
 /* the variable allocated here is freed in C_Finalize */
 CK_I_SLOT_DATA_PTR slot_data
)
{
  CK_RV rv = CKR_OK;
  
  CI_LogEntry("CI_RegisterToken", "starting...", CKR_OK, 1);

  /* tell the token which slot holds it */
  slot_data->token_data->slot = slotID;

  /* update the table of slots */
  CK_I_slot_info_table = 
    (CK_I_SLOT_DATA_PTR CK_PTR)realloc(CK_I_slot_info_table,
				       (CK_I_SLOT_ANZ+1)
				       * sizeof(CK_I_SLOT_DATA_PTR));
  if (CK_I_slot_info_table == NULL_PTR) {
    rv = CKR_HOST_MEMORY;
    CI_LogEntry("CI_RegisterToken", "unable to allocate slot info table", CKR_HOST_MEMORY, 1);
    return rv;
  }
  
  CK_I_slot_info_table[CK_I_SLOT_ANZ] = slot_data;
  /* increment the slot counter */
  CK_I_SLOT_ANZ++;

  /* *** do some housekeeping on the new token ** */
  /* alloc the token object list  (the define for the lenght is set in internal.h) */
  rv = CI_InitHashtable(&(slot_data->token_data->object_list),
			CK_I_object_list_size);
  if(rv != CKR_OK)
    {
      CI_LogEntry("CI_RegisterToken", "failure to init token object list", CKR_HOST_MEMORY, 1);
      return rv;
    }

  CI_LogEntry("CI_RegisterToken", "...complete", CKR_OK, 1);

  return rv;
}
/* }}} */
/* {{{ CI_UnregisterSlot */
CK_DEFINE_FUNCTION(CK_RV, CI_UnregisterSlot)(
 CK_ULONG ulSlotID
) {
  CK_ULONG ulSlotCount;
  CK_RV rv;

  if (ulSlotID >= CK_I_SLOT_ANZ)
    return CKR_SLOT_ID_INVALID;

  if (CK_I_slot_info_table[ulSlotID] == NULL_PTR)
    return CKR_SLOT_ID_INVALID;

  CK_I_slot_info_table[ulSlotID] = NULL_PTR;

  /* free the allocated table of dynamically loaded slots */
  ulSlotCount = 0;
  rv = C_GetSlotList(FALSE, NULL_PTR, &ulSlotCount);
  if ( (rv == CKR_OK) && (ulSlotCount == 0) ) {
    free(CK_I_slot_info_table);
    CK_I_slot_info_table = NULL_PTR; /* reinitialize global table */
    CK_I_SLOT_ANZ = 0;               /* reinitialize counter */
  }
  return CKR_OK;
}
/* }}} */
/* {{{ CI_RemoveToken */
/* removal of token from library */
CK_DEFINE_FUNCTION(CK_RV, CI_RemoveToken)(
 CK_ULONG slotID
)
{
  CK_RV rv = CKR_OK;
  CK_I_SLOT_DATA_PTR slot_data = NULL_PTR;

  /* make sure we are initialized */
  if (!(CK_I_global_flags & CK_IGF_INITIALIZED)) 
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  
  rv = CI_GetSlotData(slotID,&slot_data);
  if(rv != CKR_OK)
    {
      CI_LogEntry("CI_RemoveToken", "getting slot data", rv, 1);
      return rv;
    }

  /* free the memory for the token object list */
  rv = CI_DestroyHashtable(slot_data->token_data->object_list);
  if(rv != CKR_OK)
    {
      CI_LogEntry("CI_RemoveToken", "freeing token object list", rv, 1);
      return rv;
    }
  
  /* finalize token */
  if( (slot_data->methods->FinalizeToken != NULL_PTR))
    (slot_data->methods->FinalizeToken)(slot_data);

#if 0 
  /* TODO: Separate RemoveSlot and RemoveToken */
  /* set the flags */
  slot_data->slot_info->flags &= ~CKF_TOKEN_PRESENT;
#endif

  rv = CI_UnregisterSlot(slotID);
  if (rv != CKR_OK) 
    {
      CI_LogEntry("CI_RemoveToken", "unregistering slot", rv, 1);
      return rv;
    }
  return rv;
}
/* }}} */
/* {{{ CI_GetSlotData */
CK_DEFINE_FUNCTION(CK_RV, CI_GetSlotData)(
  CK_ULONG ulSlotID,
  CK_I_SLOT_DATA_PTR CK_PTR ppSlotData
)
{ 
  if(ulSlotID >= CK_I_SLOT_ANZ)
    return CKR_SLOT_ID_INVALID;
  
  *ppSlotData=CK_I_slot_info_table[ulSlotID];
  
  if(*ppSlotData == NULL_PTR)
    return CKR_SLOT_ID_INVALID;
  
  return CKR_OK;
}
/* }}} */
/* {{{ CI_GetTokenData */
CK_DEFINE_FUNCTION(CK_RV, CI_GetTokenData)(
  CK_ULONG ulSlotID,
  CK_I_TOKEN_DATA_PTR CK_PTR ppTokenData
)
{ 
  CK_I_SLOT_DATA_PTR slot_data = NULL_PTR;

  if(ulSlotID > CK_I_SLOT_ANZ)
    return CKR_SLOT_ID_INVALID;
  
  slot_data =CK_I_slot_info_table[ulSlotID];
  if(slot_data == NULL_PTR)
    return CKR_SLOT_ID_INVALID;

  *ppTokenData= slot_data->token_data;

  if(*ppTokenData == NULL_PTR)
    return CKR_TOKEN_NOT_PRESENT;
  
  return CKR_OK;
}
/* }}} */
/* {{{ C_WaitForSlotEvent */
/* Functions added in for Cryptoki Version 2.01 or later */
/* C_WaitForSlotEvent waits for a slot event (token insertion,
 * removal, etc.) to occur. */
CK_DEFINE_FUNCTION(CK_RV, C_WaitForSlotEvent)
(
  CK_FLAGS flags,        /* blocking/nonblocking flag */
  CK_SLOT_ID_PTR pSlot,  /* location that receives the slot ID */
  CK_VOID_PTR pReserved   /* reserved.  Should be NULL_PTR */
)
{
  CK_RV rv = CKR_OK;

  CI_LogEntry("C_WaitForSlotEvent", "starting...", rv, 1);
  CI_CodeFktEntry("C_WaitForSlotEvent", "%x,%p,%p", 
                  flags,
                  pSlot,
		  pReserved);

  /* make sure we are initialized */
  if (!(CK_I_global_flags & CK_IGF_INITIALIZED)) 
    return CKR_CRYPTOKI_NOT_INITIALIZED;

#ifndef HAVE_THREADS
 rv = CKR_FUNCTION_NOT_SUPPORTED;
#else
# if 0
 /* while event handlign doesn't work */
  /* 1: check the flags */
  if(!(flags == 0)||(flags&CKF_DONT_BLOCK))
    {
      rv = CKR_ARGUMENTS_BAD;
      CI_VarLogEntry("C_WaitForSlotEvent", "%x not a valid flags", rv, 0,flags);
      return rv;
    }
# else
 rv = CKR_FUNCTION_NOT_SUPPORTED;
# endif /* 0 */
#endif /* HAVE_THREADS */

  CI_LogEntry("C_WaitForSlotEvent", "...complete", rv, 1);
  return rv;
}
/* }}} */

/* Data structure for all events. */
/*
 * This event sinks are linked allong two lines: one single linked list
 * that lists all events, and for each slot a line that links all events 
 * of one slot together. The slot-based line is referenced in turn from 
 * a linked list. using a hash table for the slot numbers would be too
 * expensive, as there usually only a small number of slots to a system.
 */
static CK_I_EVENT_SLOT_INFO_PTR slot_event_head = NULL_PTR;
static CK_I_EVENT_SLOT_INFO_PTR slot_event_tail = NULL_PTR;

static CK_I_EVENT_INFO_PTR event_list_head = NULL_PTR;
static CK_I_EVENT_INFO_PTR event_list_tail = NULL_PTR;

/* {{{ CI_RegisterEventSink */
/** Register a sink for a slot event.
 * when this function is called the first time for a given slot, the 
 * watching of events for that slot is activated and C_WaitForSlot Event 
 * will not return with a CKR_FUNCTION_NOT_SUPPORTED.
 *
 * TODO: in a low memery situation, this function will not roll back 
 * properly should any of the allocations fail. Fix that.
 *
 * @param slot      the slot to which this event sink is to be asigned. 
 *                  If slot is set to (-1)L, the event sink is accepted, 
 *                  but never called when an slot specific event is 
 *                  triggered.
 * @param action    callback function that will be called when the event
 *                  is triggered.
 * @param user_data pointer to arbitrary user data that will be set as the
 *                  argument to the action function, shout the raising of 
 *                  the event not set its own value.
 * @param pHandle   adress of the memory that recieves the handle that this
 *                  event is registered under.
 * @return          CKR_OK if the sink is registered successfull, 
 *                  CKR_HOST_MEMORY when allocating memory failed, 
 *                  CKR_GENERAL_ERROR in all other error conditions.
 */
CK_DEFINE_FUNCTION(CK_RV, CI_RegisterEventSink)(
 CK_SLOT_ID slot, 
 CK_I_EventActionCallback action,  
 CK_VOID_PTR user_data, 
 CK_I_EVENT_INFO_PTR CK_PTR pEvent
)
{
  CK_RV rv = CKR_OK;
  CK_I_EVENT_INFO_PTR new_event=NULL_PTR;
  CK_I_EVENT_SLOT_INFO_PTR curr_slot=NULL_PTR;

  CI_LogEntry("CI_RegisterEventSink", "starting...", rv, 2);

  /* plausibility checks */
  if(action == NULL_PTR)
    {
      rv = CKR_GENERAL_ERROR;
      CI_LogEntry("CI_RegisterEventSink", "no action supplied", rv, 0);
      return rv;
    }
  if(pEvent == NULL_PTR)
    {
      rv = CKR_GENERAL_ERROR;
      CI_LogEntry("CI_RegisterEventSink", "no pHandle supplied", rv, 0);
      return rv;
    }

  /* allocate space for the event info */
  new_event=TC_malloc(sizeof(CK_I_EVENT_INFO));
  if(new_event == NULL_PTR) 
    {
      rv = CKR_HOST_MEMORY;
      CI_LogEntry("CI_RegisterEventSink", "unable to allocat memory for event info entry", rv, 0);
      return rv;
    }

  /* set the values */
  new_event->action = action;
  new_event->user_data = user_data;
  new_event->next = NULL_PTR;

  /* insert into list */

  if(event_list_tail != NULL_PTR)
    event_list_tail->next = new_event;
  event_list_tail = new_event;

  if(event_list_head == NULL_PTR)
    event_list_head = new_event;
  

  /* check for slot in list... */
  for(curr_slot = slot_event_head; 
      (curr_slot != NULL_PTR) && (curr_slot->slot != slot) ; 
      curr_slot = curr_slot->next);
  if(curr_slot == NULL_PTR) /* we found no entry for this slot */
    {
      /* ... put int a new slot event list */
      curr_slot = TC_malloc(sizeof(CK_I_EVENT_SLOT_INFO));
      if(curr_slot == NULL_PTR)
	{
	  rv = CKR_HOST_MEMORY;
	  CI_LogEntry("CI_RegisterEventSink", 
		      "unable to allocate memory for slot event info entry", rv, 0);
	  return rv;
	}

      /* set the values of the new slot */
      curr_slot->head = NULL_PTR;
      curr_slot->tail = NULL_PTR;
      curr_slot->next = NULL_PTR;
      curr_slot->slot = slot;

      /* insert at the end of the event slot list */
      if(slot_event_head == NULL_PTR)
	slot_event_head = curr_slot;
      if(slot_event_tail != NULL_PTR)
	slot_event_tail->next = curr_slot;
      slot_event_tail = curr_slot;

      /* ... activate slot event blocking */
      
    }
  /* ... and append to slot event list */
  if(curr_slot->tail != NULL_PTR)
    curr_slot->tail->slot_next=new_event;
  
  curr_slot->tail=new_event;

  new_event->slot_next = NULL_PTR;      
  new_event->slot_info = curr_slot;

  /* return the new event info handle */
  *pEvent = new_event;

  CI_LogEntry("CI_RegisterEventSink", "...complete", rv, 2);
  
  return rv;
}
/* }}} */

/* {{{ CI_RemoveEventSink */
/** Remove an event sink from the event handler.
*/
CK_DECLARE_FUNCTION(CK_RV, CI_RemoveEventSink)(
 CK_I_EVENT_INFO_PTR event
)
{
  CK_I_EVENT_INFO_PTR tmp1_event= event_list_head;
  CK_I_EVENT_SLOT_INFO_PTR slot_info= event->slot_info;
  CK_I_EVENT_INFO_PTR tmp2_event = slot_info->head;
  CK_RV rv = CKR_OK;

  /* find the predecessor in the global list */
  while((tmp1_event->next != event) && (tmp1_event != NULL_PTR))
    tmp1_event = tmp1_event->next;

  if(tmp1_event == NULL_PTR) 
    {
      if(event_list_head == event)   /* in case the event pointer is the head */
	{
	  event_list_head = event->next;
	  if(event_list_head == NULL_PTR)
	    event_list_tail = NULL_PTR;
	}
      else  /* this event is not a valid, registered one */
	{
	  rv = CKR_GENERAL_ERROR;
	  CI_LogEntry("CI_RemoveEventSink", "invalid event pointer", rv, 0);
	  return rv;
	}
    }
  else /* this is a normal event, somewhere in the middle of the list */
    tmp1_event->next = event->next;

  /* clean up the tail */
  if(event_list_tail == event)
    event_list_tail = tmp1_event;
  
  /* find the predecessor in the slot event list */
  while((tmp2_event->slot_next != event) && (tmp2_event != NULL_PTR))
    tmp2_event = tmp2_event->slot_next;

  if(tmp2_event == NULL_PTR) 
    {
      if(slot_info->head == event)   /* in case the event pointer is the head */
	{
	  slot_info->head = event->slot_next;
	  if(slot_info->head == NULL_PTR)
	    slot_info->tail = NULL_PTR;
	}
      else  /* this event is not a valid, registered one */
	{
	  rv = CKR_GENERAL_ERROR;
	  CI_LogEntry("CI_RemoveEventSink", "invalid event pointer", rv, 0);
	  return rv;
	}
    }
  else  /* this is a normal event, somewhere in the middle of the list */
    tmp2_event->slot_next = event->slot_next;

  /* clean up the tail */
  if(slot_info->tail == event)
    slot_info->tail = tmp2_event;

  /* free the space for the event info */
  free(event);

  return rv;
}
/* }}} */

/* {{{ CI_SendSlotEvent */
/** Send an event to all event sinks registered for a slot.
 * @param slot        Slot that all sinks are triggered for.
 * @param user_data   if non-NULL, this value will be set as argument 
 *                    in the action callbacks instead of the default.
 * @param event_label if non-NULL the string will be written to he log.
 * @return            CKR_HOST_MEMORY when allocating memory failed, 
 *                    CKR_OK otherwise.
 */
CK_DEFINE_FUNCTION(CK_RV, CI_SendSlotEvent)(
 CK_SLOT_ID slot, 
 CK_VOID_PTR user_data, 
 CK_CHAR_PTR event_label
)
{
  CK_I_EVENT_INFO_PTR curr_event;
  CK_I_EVENT_SLOT_INFO_PTR curr_slot;

  /* find the slot event list */
  for(curr_slot = slot_event_head; 
      (curr_slot != NULL_PTR) && (curr_slot->slot != slot) ; 
      curr_slot = curr_slot->next);
  if(curr_slot != NULL_PTR) /* we have found an entry for this slot */
    { 
      curr_event = curr_slot->head;
      /* send one event to each sink in the slot event list */
      while(curr_event)
	{
	  CI_TriggerEvent(curr_event,user_data,event_label);
	  curr_event = curr_event->next;
	}
    }
  return CKR_OK;
}
/* }}} */

/* {{{ CI_TriggerEvent */
/** Send an event to a single event sink.
 * @param event       Event handle as received from CI_RegisterEventSink.
 * @param user_data   if non-NULL, this value will be set as argument 
 *                    in the action callbacks instead of the default.
 * @param event_label if non-NULL the string will be written to he log.
 * @return            If one of the internal pointers used or event 
 *                    is equal to NULL_PTR the function returns 
 *                    CKR_GENERAL_ERROR; otherwise the return values of the
 *                    action callback is returned.
*/
CK_DEFINE_FUNCTION(CK_RV, CI_TriggerEvent)(
 CK_I_EVENT_INFO_PTR event, 
 CK_VOID_PTR user_data, 
 CK_CHAR_PTR event_label
)
{
  CK_RV rv = CKR_OK;

  if((event == NULL_PTR) ||
     (event->slot_info == NULL_PTR) || 
     (event->action == NULL_PTR))
    return CKR_GENERAL_ERROR;

  if(event_label == NULL_PTR)
    event_label = "<no label>";

  if(user_data == NULL_PTR)
    rv = event->action(event->slot_info->slot, event->user_data);
  else
    rv = event->action(event->slot_info->slot, user_data);

  CI_VarLogEntry("CI_TriggerEvent", "trigger event: %s", rv, 2,event_label);

  return rv;
}
/* }}} */

/* {{{ CI_InitEventHandler */
/** Initialize the event handling.
*/
CK_DECLARE_FUNCTION(CK_RV, CI_InitEventHandler)(
 void
)
{
  return CKR_OK;
}
/* }}} */

/* {{{ CI_FinalizeEventHandler */
/** Finalize the event handling.
*/
CK_DECLARE_FUNCTION(CK_RV, CI_FinalizeEventHandler)(
 void
)
{
  CK_I_EVENT_INFO_PTR old_event,curr_event=event_list_head;
  CK_I_EVENT_SLOT_INFO_PTR old_slot, curr_slot = slot_event_head;

  /* Enter Critical Region !!! */

  /* free all entries in the event list */
  while(curr_event != NULL_PTR)
    {
      old_event = curr_event;
      curr_event = curr_event->next;
      free(old_event);      
    }

  while(curr_slot != NULL_PTR)
    {
      old_slot = curr_slot;
      curr_slot = curr_slot->next;
      free(old_slot);
    }
  
  /* Exit Critical Region !!! */
  return CKR_OK;
}
/* }}} */


/*
 * Local variables:
 * folded-file: t
 * end:
 */







