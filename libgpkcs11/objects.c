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
 * NAME:        objects.c
 * SYNOPSIS:    -
 * DESCRIPTION: -
 * FILES:       -
 * SEE/ALSO:    -
 * AUTHOR:      lbe
 * BUGS: *      -
 * HISTORY:     $Log$
 * HISTORY:     Revision 1.14  2000/09/19 09:14:54  lbe
 * HISTORY:     write flag for pin change onto SC, support Auth Pin path
 * HISTORY:
 * HISTORY:     Revision 1.13  2000/06/23 17:32:17  lbe
 * HISTORY:     release to secude, lockdown for 0_6_2
 * HISTORY:
 * HISTORY:     Revision 1.12  2000/03/08 09:59:08  lbe
 * HISTORY:     fix SIGBUS in cryptdb, improve readeability for C_FindObject log output
 * HISTORY:
 * HISTORY:     Revision 1.11  2000/01/31 18:09:02  lbe
 * HISTORY:     lockdown prior to win_gdbm change
 * HISTORY:
 * HISTORY:     Revision 1.10  2000/01/07 10:24:44  lbe
 * HISTORY:     introduce changes for release
 * HISTORY:
 * HISTORY:     Revision 1.9  1999/12/08 16:06:28  lbe
 * HISTORY:     clean up of token prior to creation of new gen-data token
 * HISTORY:
 * HISTORY:     Revision 1.8  1999/12/06 15:18:57  lbe
 * HISTORY:     seeing certificates in netscape works
 * HISTORY:
 * HISTORY:     Revision 1.7  1999/12/02 14:16:27  lbe
 * HISTORY:     tons of small bug fixes and bullet proofing of libgpkcs11 and cryptsh
 * HISTORY:
 * HISTORY:     Revision 1.6  1999/11/25 19:14:07  lbe
 * HISTORY:     lockdown after windows compile
 * HISTORY:
 * HISTORY:     Revision 1.5  1999/11/02 13:47:19  lbe
 * HISTORY:     change of structures and bug fix in slot.c, add more files for tcsc_token: emptyfuncs and general_data
 * HISTORY:
 * HISTORY:     Revision 1.4  1999/10/08 13:00:13  lbe
 * HISTORY:     release version 0.5.5
 * HISTORY:
 * HISTORY:     Revision 1.3  1999/10/06 07:57:22  lbe
 * HISTORY:     solved netscape symbol clash problem
 * HISTORY:
 * HISTORY:     Revision 1.2  1999/07/20 17:40:01  lbe
 * HISTORY:     fix bug in gdbm Makefile: there is not allways an 'install' around
 * HISTORY:
 * HISTORY:     Revision 1.1  1999/06/16 09:46:09  lbe
 * HISTORY:     reorder files
 * HISTORY:
 * HISTORY:     Revision 1.16  1999/01/22 08:35:33  lbe
 * HISTORY:     full build with new perisistant storage complete
 * HISTORY:
 * HISTORY:     Revision 1.15  1999/01/19 12:19:43  lbe
 * HISTORY:     first release lockdown
 * HISTORY:
 * HISTORY:     Revision 1.14  1999/01/13 16:16:00  lbe
 * HISTORY:     clampdown for persistent storage complete
 * HISTORY:
 * HISTORY:     Revision 1.13  1998/12/07 13:20:16  lbe
 * HISTORY:     TC_free von parametern f�r Zeile und Datei befreit.
 * HISTORY:
 * HISTORY:     Revision 1.12  1998/12/02 10:47:12  lbe
 * HISTORY:     work on persistent storage
 * HISTORY:
 * HISTORY:     Revision 1.11  1998/11/13 10:10:12  lbe
 * HISTORY:     added persistent storage.
 * HISTORY:
 * HISTORY:     Revision 1.10  1998/11/10 09:42:44  lbe
 * HISTORY:     hash iter geaendert: hashtabelle braucht nicht mehr an fkts uebergeben werden.
 * HISTORY:
 * HISTORY:     Revision 1.9  1998/11/04 17:12:32  lbe
 * HISTORY:     debug-lockdown
 * HISTORY:
 * HISTORY:     Revision 1.8  1998/11/03 15:59:33  lbe
 * HISTORY:     auto-lockdown
 * HISTORY:
 * HISTORY:     Revision 1.7  1998/10/12 10:00:08  lbe
 * HISTORY:     clampdown
 * HISTORY:
 * HISTORY:     Revision 1.6  1998/08/05 08:57:30  lbe
 * HISTORY:     *** empty log message ***
 * HISTORY:
 * HISTORY:     Revision 1.5  1998/07/30 15:29:26  lbe
 * HISTORY:     Win32 Port
 * HISTORY:
 * HISTORY:     Revision 1.4  1998/07/23 15:18:13  lbe
 * HISTORY:     working
 * HISTORY:
 * HISTORY:     Revision 1.3  1998/07/13 15:33:27  lbe
 * HISTORY:     Object-System redesigned.
 * HISTORY:
 * HISTORY:     Revision 1.2  1998/07/07 14:43:06  lbe
 * HISTORY:     Funktion zum einfacheren internen setzen von Objectattributen hinzugef�gt
 * HISTORY:
 * HISTORY:     Revision 1.1  1998/07/02 17:20:55  lbe
 * HISTORY:     Initial revision
 * HISTORY:
 */

static char RCSID[]="$Id$";
const char* Version_objects_c(){return RCSID;}

/* Needed for Win32-isms in cryptoki.h */
#ifndef CK_I_library_build
#define CK_I_library_build
#endif

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "internal.h"
#include "objects.h"
#include "hash.h"
#include "error.h"
#include "mutex.h"

/* for debugging with a debugger */
#include <sys/types.h>
#include <signal.h>


#ifdef HAVE_UNISTD_H

#include <unistd.h>
#endif /* HAVE_UNISTD_H */

 
/* {{{ Attribute Validity */
/* 
 * This could be made smaller if I would to use flags instead of individual 
 * bytes for each entry. But then the code would be slower.
 */
/* translate the template entries into the flags (CK_OBJECT_CLASS -> CK_I_OBJECT_CLASS) */
CK_I_OBJECT_CLASS CK_I_obj_class_xlate[] = {
  CK_IO_DATA,
  CK_IO_CERTIFICATE,
  CK_IO_PUBLIC_KEY,
  CK_IO_PRIVATE_KEY,
  CK_IO_SECRET_KEY
};


/* Kleiner Safety-Check in der Hoffnung das sich dieser Wert
 * �ndert wenn die anderen sich verschieben. Leider enthalten die 
 * offiziellen Header keine Versionsnummer. 
 */
#if (CKO_SECRET_KEY != 0x00000004)
#error CKO_SECRET_KEY value changed!
#endif

/* to check whether an element of a template/default belongs into an object */
CK_BYTE CK_I_attributes[] = {
  /* CKO_DATA,CKO_CERTIFICATE,CKO_PUBLIC_KEY,CKO_PRIVATE_KEY,CKO_SECRET_KEY */
  
  CK_IO_DATA|CK_IO_CERTIFICATE|CK_IO_PUBLIC_KEY|CK_IO_PRIVATE_KEY|CK_IO_SECRET_KEY, /* CKA_CLASS */
  CK_IO_DATA|CK_IO_CERTIFICATE|CK_IO_PUBLIC_KEY|CK_IO_PRIVATE_KEY|CK_IO_SECRET_KEY, /* CKA_TOKEN */
  CK_IO_DATA|CK_IO_CERTIFICATE|CK_IO_PUBLIC_KEY|CK_IO_PRIVATE_KEY|CK_IO_SECRET_KEY, /* CKA_PRIVATE */
  CK_IO_DATA|CK_IO_CERTIFICATE|CK_IO_PUBLIC_KEY|CK_IO_PRIVATE_KEY|CK_IO_SECRET_KEY, /* CKA_MODIFIABLE */
  CK_IO_DATA|CK_IO_CERTIFICATE|CK_IO_PUBLIC_KEY|CK_IO_PRIVATE_KEY|CK_IO_SECRET_KEY, /* CKA_LABEL */
  /* data */
  CK_IO_DATA, /* CKA_APPLICATION */
  CK_IO_DATA|CK_IO_CERTIFICATE|CK_IO_PUBLIC_KEY|CK_IO_PRIVATE_KEY|CK_IO_SECRET_KEY, /* CKA_VALUE */
  /* certificate */
  CK_IO_CERTIFICATE, /* CKA_CERTIFICATE_TYPE */
  CK_IO_CERTIFICATE, /* CKA_ISSUER */
  CK_IO_CERTIFICATE, /* CKA_SERIAL_NUMBER */
  CK_IO_CERTIFICATE|CK_IO_PUBLIC_KEY|CK_IO_PRIVATE_KEY, /* CKA_SUBJECT */
  /* keys, common */
  CK_IO_PUBLIC_KEY|CK_IO_PRIVATE_KEY|CK_IO_SECRET_KEY, /* CKA_ID */
  CK_IO_PUBLIC_KEY|CK_IO_PRIVATE_KEY|CK_IO_SECRET_KEY, /* CKA_START_DATE */
  CK_IO_PUBLIC_KEY|CK_IO_PRIVATE_KEY|CK_IO_SECRET_KEY, /* CKA_END_DATE */
  CK_IO_PUBLIC_KEY|CK_IO_PRIVATE_KEY|CK_IO_SECRET_KEY, /* CKA_DERIVE */
  CK_IO_PUBLIC_KEY|CK_IO_PRIVATE_KEY|CK_IO_SECRET_KEY, /* CKA_KEY_TYPE */
  CK_IO_PUBLIC_KEY|CK_IO_PRIVATE_KEY|CK_IO_SECRET_KEY, /* CKA_LOCAL */
  /* public keys */
  CK_IO_PUBLIC_KEY|CK_IO_SECRET_KEY, /* CKA_ENCRYPT */
  CK_IO_PUBLIC_KEY|CK_IO_SECRET_KEY, /* CKA_VERIFY */
  CK_IO_PUBLIC_KEY, /* CKA_VERIFY_RECOVER */
  CK_IO_PUBLIC_KEY|CK_IO_SECRET_KEY, /* CKA_WRAP */
  CK_IO_PUBLIC_KEY|CK_IO_PRIVATE_KEY, /* CKA_MODULUS */
  CK_IO_PUBLIC_KEY, /* CKA_MODULUS_BITS */
  CK_IO_PUBLIC_KEY|CK_IO_PRIVATE_KEY, /* CKA_PUBLIC_EXPONENT */
  CK_IO_PUBLIC_KEY|CK_IO_PRIVATE_KEY, /* CKA_PRIME */
  CK_IO_PUBLIC_KEY|CK_IO_PRIVATE_KEY, /* CKA_SUBPRIME */
  CK_IO_PUBLIC_KEY|CK_IO_PRIVATE_KEY, /* CKA_BASE */
  CK_IO_PUBLIC_KEY|CK_IO_PRIVATE_KEY, /* CKA_ECDSA_PARAMS */
  CK_IO_PUBLIC_KEY, /* CKA_EC_POINT */
  /* private keys */
  CK_IO_PRIVATE_KEY|CK_IO_SECRET_KEY, /* CKA_SENSITIVE */
  CK_IO_PRIVATE_KEY|CK_IO_SECRET_KEY, /* CKA_DECRYPT */
  CK_IO_PRIVATE_KEY|CK_IO_SECRET_KEY, /* CKA_SIGN */
  CK_IO_PRIVATE_KEY, /* CKA_SIGN_RECOVER */
  CK_IO_PRIVATE_KEY|CK_IO_SECRET_KEY, /* CKA_UNWRAP */
  CK_IO_PRIVATE_KEY|CK_IO_SECRET_KEY, /* CKA_EXTRACTABLE */
  CK_IO_PRIVATE_KEY|CK_IO_SECRET_KEY, /* CKA_ALWAYS_SENSITIVE */
  CK_IO_PRIVATE_KEY|CK_IO_SECRET_KEY, /* CKA_NEVER_EXTRACTABLE */
  CK_IO_PRIVATE_KEY, /* CKA_PRIVATE_EXPONENT */
  CK_IO_PRIVATE_KEY, /* CKA_PRIME_1 */
  CK_IO_PRIVATE_KEY, /* CKA_PRIME_2 */
  CK_IO_PRIVATE_KEY, /* CKA_EXPONENT_1 */
  CK_IO_PRIVATE_KEY, /* CKA_EXPONENT_2 */
  CK_IO_PRIVATE_KEY, /* CKA_COEFFICIENT */
  CK_IO_PRIVATE_KEY, /* CKA_VALUE_BITS */
  /* secret keys */
  CK_IO_SECRET_KEY, /* CKA_VALUE_LEN */
  /* Vendor Defined */
  CK_IO_SECRET_KEY, /* CKA_SSL_VERSION */
  CK_IO_DATA|CK_IO_CERTIFICATE|CK_IO_PUBLIC_KEY|CK_IO_PRIVATE_KEY|CK_IO_SECRET_KEY /* CKA_PERSISTENT_KEY */
};
/* }}} */
/* {{{ Attribute Translation */
static unsigned int CK_I_attrib_xlate[][2] = {
  {0, CKA_CLASS}, 
  {1, CKA_TOKEN},              
  {2, CKA_PRIVATE},            
  {3, CKA_MODIFIABLE},         
  {4, CKA_LABEL},              
  {5, CKA_APPLICATION},        
  {6, CKA_VALUE},		
  {7, CKA_CERTIFICATE_TYPE},	
  {8, CKA_ISSUER},		
  {9, CKA_SERIAL_NUMBER},      
  {10, CKA_SUBJECT},		
  {11, CKA_KEY_TYPE},		
  {12, CKA_ID},			
  {13, CKA_START_DATE},         
  {14, CKA_END_DATE},		
  {15, CKA_DERIVE},		
  {16, CKA_LOCAL},		
  {17, CKA_ENCRYPT},            
  {18, CKA_VERIFY},		
  {19, CKA_VERIFY_RECOVER},	
  {20, CKA_WRAP},		
  {21, CKA_MODULUS},		
  {22, CKA_MODULUS_BITS},	
  {23, CKA_PUBLIC_EXPONENT},	
  {24, CKA_PRIME},		
  {25, CKA_SUBPRIME},		
  {26, CKA_BASE},		
  {27, CKA_ECDSA_PARAMS},	
  {28, CKA_EC_POINT},		
  {29, CKA_SENSITIVE},		
  {30, CKA_DECRYPT},		
  {31, CKA_SIGN},               
  {32, CKA_SIGN_RECOVER},	
  {33, CKA_UNWRAP},		
  {34, CKA_EXTRACTABLE},	
  {35, CKA_ALWAYS_SENSITIVE},	
  {36, CKA_NEVER_EXTRACTABLE},	
  {37, CKA_PRIVATE_EXPONENT},	
  {38, CKA_PRIME_1},		
  {39, CKA_PRIME_2},		
  {40, CKA_EXPONENT_1},		
  {41, CKA_EXPONENT_2},		
  {42, CKA_COEFFICIENT},	
  {43, CKA_VALUE_BITS},		
  {44, CKA_VALUE_LEN},

  /* Vendor Defined */
  {45, CKA_SSL_VERSION},
  {46, CKA_PERSISTENT_KEY}
};
/* }}} */
/* {{{ Global constants for template/object creation */
CK_CHAR   CK_I_empty_str[] = "";
CK_BYTE   CK_I_empty_bytes[] = "";
CK_BBOOL  CK_I_true = TRUE;
CK_BBOOL  CK_I_false = FALSE;
CK_ULONG  CK_I_ulEmpty = 0;
CK_DATE   CK_I_empty_date = {"    ", "  ", "  "};
/* }}} */

/* {{{ CI_ReturnSession */
CK_DEFINE_FUNCTION(CK_RV, CI_ReturnSession)(
  CK_OBJECT_HANDLE hSession,
  CK_I_SESSION_DATA_PTR CK_PTR ppStoredSession
)
{
  CK_RV rv = CKR_OK;
  
  /* get session info and make sure that this session exists */
  rv = CI_HashGetEntry(CK_I_app_table.session_table,hSession,
		       (CK_VOID_PTR CK_PTR)ppStoredSession);
  if(rv != CKR_OK)
    {
      if(rv == CKR_ARGUMENTS_BAD)
	rv= CKR_SESSION_HANDLE_INVALID;
    }
  
  return rv;
}

/* }}} */
/* {{{ CI_ReturnObj */
  CK_DEFINE_FUNCTION(CK_RV, CI_ReturnObj)(
  CK_I_SESSION_DATA_PTR session_data,
  CK_OBJECT_HANDLE hObject,
  CK_I_OBJ_PTR CK_PTR ppStoredObj
)
{
  CK_RV rv = CKR_OK;

  assert(session_data->slot_data != NULL_PTR);
  assert(session_data->slot_data->token_data != NULL_PTR);

  /* make sure that the object container is initialized */
  if(session_data->slot_data->token_data->object_list == NULL_PTR)
    {
      /* no objects in application, therefore nothing may be returned */
      rv = CKR_OBJECT_HANDLE_INVALID;
      return rv;
    }

  /* get reference to key object from hashtable of application  */
  rv = CI_HashGetEntry(session_data->slot_data->token_data->object_list,
		       hObject,(CK_VOID_PTR_PTR)ppStoredObj);
  if(rv != CKR_ARGUMENTS_BAD)
    return rv; /* return if failure or success, unless wrong key */

  /* get reference to key object from hashtable of session */
  rv = CI_HashGetEntry(session_data->object_list,hObject,(CK_VOID_PTR_PTR)ppStoredObj);
  if(rv != CKR_ARGUMENTS_BAD)
    return rv; /* return if failure or success, unless wrong key */

  
  return rv;
}
/* }}} */

/* {{{ C_CreateObject */
CK_DEFINE_FUNCTION(CK_RV, C_CreateObject)(
  CK_SESSION_HANDLE hSession,
  CK_ATTRIBUTE_PTR pTemplate,
  CK_ULONG ulCount,
  CK_OBJECT_HANDLE_PTR phObject
)
{
  CK_RV rv = CKR_OK;
  CK_I_SESSION_DATA_PTR session_data = NULL_PTR;
  CK_I_OBJ_PTR new_obj = NULL_PTR;  /* object to be created */

  CI_LogEntry("C_CreateObject", "starting...", rv, 1);

#ifndef NO_LOGGING
  {
    CK_CHAR_PTR tmp = NULL;
    CI_CodeFktEntry("C_CreateObject", "%lu,%s,%lu,%p", 
      hSession,
		  tmp = CI_PrintTemplate(pTemplate,ulCount),
		  ulCount,
		  phObject);
    TC_free(tmp);
  }
#endif // NO_LOGGING

  /* make sure we are initialized */
  if (!(CK_I_global_flags & CK_IGF_INITIALIZED)) 
    {
      rv = CKR_CRYPTOKI_NOT_INITIALIZED;
      CI_LogEntry("C_CreateObject", "initialization", rv, 0);
      return rv;
    }
  
  rv = CI_ReturnSession(hSession, &session_data);
  if(rv != CKR_OK)
    {
      CI_VarLogEntry("C_CreateObject", "retrieve session data (hSession: %lu)", 
		     rv, 0,
                     hSession);
      return rv;
    }

  /* make sure that the object container is initialized */
  if(session_data->object_list == NULL_PTR)
    {
      rv = CI_InitHashtable(&(session_data->object_list),CK_I_OBJ_LIST_SIZE);
      if(rv != CKR_OK)
	{
	  CI_LogEntry("C_CreateObject", "creating session object list", rv, 0);
	  return rv;
	}
    }

  /*
   * TODO: add check of constraints:
   * - key objects must not have the VALUE_LEN attribute set, 
   *   compute it from the lenght definition of the value.
   * - key objects must have the VALUE attribute set.
   */

  rv = CI_ObjCreateObj(&new_obj);
  if(rv != CKR_OK) 
    {
      CI_LogEntry("C_CreateObject", "creating internal object", rv, 0);
      return rv;
    }

  CI_ObjReadTemplate(new_obj, pTemplate, ulCount);
  if(rv != CKR_OK) 
    {
      CI_LogEntry("C_CreateObject", "Reading Template", rv, 0);
      return rv;
    }

  CI_ObjCompleteWithDefaults(new_obj);
  if(rv != CKR_OK) 
    {
      CI_LogEntry("C_CreateObject", "completing witch defaults objects", rv, 0);
      return rv;
    }
  
  rv = CI_InternalCreateObject(session_data, new_obj, phObject);
  if(rv != CKR_OK)
    {
      CI_LogEntry("C_CreateObject", "inserting internal object", rv, 0);
      return rv;
    }

  CI_VarLogEntry("C_CreateObject", 
		 "Object Handle: %lu Object Type: %x ...complete", 
		 rv, 1, *phObject, 
		 *((CK_ULONG CK_PTR)CI_ObjLookup(new_obj,CK_IA_CLASS)->pValue));

  return rv;
}
/* }}} */
/* {{{ CI_InternalCreateObject */
CK_DEFINE_FUNCTION(CK_RV, CI_InternalCreateObject)(
  CK_I_SESSION_DATA_PTR session_data,
  CK_I_OBJ_PTR pNewObject,
  CK_OBJECT_HANDLE_PTR phObject
)
{
  CK_RV rv = CKR_OK;
  CK_VOID_PTR mutex = NULL_PTR;
  /* to test if the object is a token object */
  CK_BYTE isToken;
  CK_ULONG isTokenLen = 1;

  /* get mutex, there are some synchronized areas in here */
  rv =CK_I_ext_functions._CreateMutex(&mutex);
  if(rv != CKR_OK)
    {
      CI_LogEntry("CI_InternalCreateObject","Could not create mutex", rv ,0);
      return rv;
    }

  /* assign new handle */
  rv= CI_NewHandle(phObject);
  if(rv != CKR_OK)
    {
      CI_ObjDestroyObj(pNewObject);
      return rv; 
    }
  
  /* has the hashtable for objects in the application table allready been init'ed? */
  _LOCK(mutex);
  assert(session_data->slot_data != NULL_PTR);
  assert(session_data->slot_data->token_data != NULL_PTR);

  if(session_data->slot_data->token_data->object_list == NULL_PTR)
    {
      rv = CI_InitHashtable(&(session_data->slot_data->token_data->object_list),
			    CK_I_object_list_size);
      if(rv != CKR_OK)
	{
	  _UNLOCK(mutex);  
	  CK_I_ext_functions._DestroyMutex(mutex);
	  return rv; 
	}
    }
  _UNLOCK(mutex);  
  CK_I_ext_functions._DestroyMutex(mutex);

  /* put data in hashtable of session */
  /* we checked that the container is initialized in C_CreateObject() */
  rv = CI_ContainerAddObj(session_data->object_list, *phObject, pNewObject);
  if(rv != CKR_OK)
    {
      CI_LogEntry("CI_InternalCreateObject","failed to insert object into session obj list", rv ,0);
      CI_ObjDestroyObj(pNewObject);
      return rv; 
    }

  /* put data in hashtable of application */
  /* we checked that the container is initialized in C_CreateObject() */
  rv = CI_ContainerAddObj(session_data->slot_data->token_data->object_list, 
			  *phObject, pNewObject);
  if(rv != CKR_OK)
    {
      CI_LogEntry("CI_InternalCreateObject","failed to insert object into application obj list", rv ,0);
      CI_ContainerDelObj(session_data->object_list, *phObject); /* to stay consistent */
      /* this will delete the object */
      return rv; 
    }

  /* ok, all done. tell the object who it belongs to */
  pNewObject->session = session_data;

  /* if this is a token object it's put into the persistent storage as well */
  /* add the token objects to each session accessing the slot */

  /* get the CK_IA_TOKEN attribute value from the new object */
  rv = CI_ObjGetIntAttributeValue(pNewObject, CK_IA_TOKEN, 
				  &isToken, &isTokenLen);
  if (rv != CKR_OK) {
    if (rv != CKR_ATTRIBUTE_TYPE_INVALID) {
      CI_LogEntry("CI_InternalCreateObject", 
		  "error while testing CK_IA_TOKEN attribute", rv , 0);
      return rv;
    }
    else /* the attribute CK_IA_TOKEN doesn't exist */
      isToken = FALSE;
  }
  /* if CKR_OK, the flag isToken is then positioned */

  if (isToken) {
    CK_I_SESSION_DATA_PTR i_session_data = NULL_PTR;
    CK_ULONG key;
    CK_I_HASH_ITERATOR_PTR iter;
    CK_SLOT_ID currentSlot;
    CK_SESSION_HANDLE currentSession;
    
    /* add new object in the token */
    rv = CI_TokenObjAdd(session_data, *phObject, pNewObject); 
    if (rv != CKR_OK) { 
      CI_LogEntry("CI_InternalCreateObject",
		  "failed to insert objects into token", rv ,0); 
      /* to stay consistent */ 
      CI_ContainerDelObj(session_data->slot_data->token_data->object_list, *phObject); 
      CI_ContainerDelObj(session_data->object_list, *phObject); 
      /* this deletes the object through ref counting */ 
      return rv;  
    } 

    /* add the reference to the new object in every session connected to
     * the same slot
     * TODO : should PRIVATE and PUBLIC sessions be distinguished ?
     */
    currentSession = session_data->session_handle;
    currentSlot = session_data->slot_data->token_data->slot;
    /* iterate on the sessions and add the reference to the token object */
    rv = CI_HashIterateInit(CK_I_app_table.session_table, &iter);
    if(rv != CKR_OK) 
      return rv;
    for ( ; CI_HashIterValid(iter) ; ) {
      CI_HashIterateDeRef(iter, &key, (CK_VOID_PTR CK_PTR)(&i_session_data));

      /* look for the sessions on the same slot */
      if ( (currentSession == key) 
	   && (i_session_data->slot_data->token_data->slot == currentSlot) ) {
	/* add the object in this session object list */
	rv = CI_ContainerAddObj(i_session_data->object_list, 
				*phObject, pNewObject);
	if(rv != CKR_OK) {
	  CI_LogEntry("CI_InternalCreateObject", 
		      "adding session hash entry for Token Object", 
		      rv , 0);
	  CI_VarLogEntry("CI_InternalCreateObject", 
			 "Session handle: %d  Hashtable: %p", rv , 0,
			 key,
			 i_session_data->object_list);
	  /* here, data structures aren't consistent anymore */
	  return rv;
	}
      }
      rv = CI_HashIterateInc(iter);
      if(rv != CKR_OK) 
	return rv;
    }
    CI_HashIterateDelete(iter);
  } /* end if (isToken) */
  return rv;
}
/* }}} */
/* {{{ C_DestroyObject */
CK_DEFINE_FUNCTION(CK_RV, C_DestroyObject)(
  CK_SESSION_HANDLE hSession,
  CK_OBJECT_HANDLE hObject
)
{
  CK_RV rv = CKR_OK;
  CK_I_SESSION_DATA_PTR session_data = NULL_PTR;

  CI_LogEntry("C_DestroyObject", 
	      "starting...", 
	      rv , 1);	  
  CI_CodeFktEntry("C_DestroyObject", "%u,%u", 
                  hSession,
		  hObject);

  /* make sure we are initialized */
  if (!(CK_I_global_flags & CK_IGF_INITIALIZED)) 
    {
      CI_LogEntry("C_DestroyObject", NULL_PTR, rv , 0);
      return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
  
  rv = CI_ReturnSession(hSession, &session_data);
  if(rv != CKR_OK)
    {
      CI_VarLogEntry("C_DestroyObject", "retrieve session data (hSession: %lu)", rv, 0,
                     hSession);
      return rv;
    }

  rv = CI_InternalDestroyObject(session_data, hObject, TRUE);
  if(rv != CKR_OK)
    {
      CI_LogEntry("C_DestroyObject", "calling CI_InternalDestroyObject", rv , 0);
      return rv;
    }

  CI_LogEntry("C_DestroyObject", "...complete", rv , 1);	  

  return rv;
}
/* }}} */
/* {{{ CI_InternalDestroyObject */
/** Entfernen eines internen Objectes aus der Objektliste einer Session.
 * Object wird aus der Liste entfernt wenn es enthalten ist. 
 * @param destroy_persistent Flag ob das Object auf dem Token auch zerst�rt werden soll.
 */
CK_DEFINE_FUNCTION(CK_RV, CI_InternalDestroyObject)(
  CK_I_SESSION_DATA_PTR session_data,
  CK_OBJECT_HANDLE hObject,
  CK_BBOOL destroy_persistent
) {
  CK_RV rv = CKR_OK;
  CK_I_OBJ_PTR obj;
  CK_BYTE isToken;
  CK_ULONG isTokenLen = 1; /* number of bytes in isToken */

  CI_LogEntry("CI_InternalDestroyObject", "starting...", rv , 2);

  /* get the object and test the CK_IA_TOKEN attribute value */
  rv = CI_ReturnObj(session_data, hObject, &obj);
  if (rv != CKR_OK) {
    CI_LogEntry("CI_InternalDestroyObject", "could not get the object", 
		rv , 0);
    return CKR_OBJECT_HANDLE_INVALID;
  }
  rv = CI_ObjGetIntAttributeValue(obj, CK_IA_TOKEN, &isToken, &isTokenLen);
  if (rv != CKR_OK) {
    if (rv != CKR_ATTRIBUTE_TYPE_INVALID) {
      CI_LogEntry("CI_InternalDestroyObject", 
		  "error while testing CK_IA_TOKEN attribute", rv , 0);
      return rv;
    }
    else /* the attribute CK_IA_TOKEN doesn't exist */
      isToken = FALSE;
  }
  /* if CKR_OK, the flag isToken is then positioned */

  if (isToken && destroy_persistent) { 
    /* token object AND asked to remove token object */
    /* a token object must be removed from all sessions and the 
     * persistent cache and the persistent storage. */
    rv = CI_TokenObjDelete(session_data, hObject);
    if (rv != CKR_OK) 
      return rv;
    /* if this a token object it will also live in other sessions, and will 
     * live on after the session has been closed. So only delete if the 
     * persistent object is deleted as well.
     */
    /* remove object from the application object list */
    rv = CI_ContainerDelObj(session_data->slot_data->token_data->object_list, hObject);
    if(rv != CKR_OK) {
      CI_VarLogEntry("CI_InternalDestroyObject", 
		     "removing token object %d from application object list", 
		     rv, 0, hObject);
      return rv;
    }
  }
  else { /* session object OR not asked to remove Token objects */

    /* for a token object not to be removed, verify whether it is referenced
     * in other sessions. If not, removing it from application object list
     */
    /* A token object is referenced in each session accessing the slot
     * If there is no more session on the slot, the object has to be removed
     * from the application object list
     */

    /* for a session object created in this session, 
     * or a token object not referenced in any session,
     * removing it from the application object list */
    if ( ( isToken 
	   && (session_data->slot_data->token_data->token_info->ulSessionCount == 0) )
	 || ((!isToken) && (obj->session == session_data)) ) {
      /* remove object from the application object list */
      rv = CI_ContainerDelObj(session_data->slot_data->token_data->object_list, hObject);
      if(rv != CKR_OK) {
	CI_VarLogEntry("CI_InternalDestroyObject", 
		       "removing object %d from application object list", 
		       rv, 0, hObject);
	return rv;
      }
    }

    /* remove object from the current session, in which it exists */
    rv = CI_ContainerDelObj(session_data->object_list, hObject);
    if(rv != CKR_OK) {
      CI_LogEntry("CI_InternalDestroyObject", "removing session Hashentry", 
		  rv , 0);
      CI_VarLogEntry("CI_InternalDestroyObject", "Hashtable: %p", rv , 0, 
		     session_data->object_list);
      return rv;
    }
  }

  /* for token object to remove, or session object created in current session
   * removing the object in every session in the application
   */
  if ( (isToken && destroy_persistent)  
       || ((!isToken) && (obj->session == session_data)) ) {
    CK_I_SESSION_DATA_PTR i_session_data = NULL_PTR;
    CK_ULONG key;
    CK_I_HASH_ITERATOR_PTR iter;
    CK_SLOT_ID currentSlot;

    currentSlot = session_data->slot_data->token_data->slot;
    /* iterate on the sessions and delete the reference to the token object */
    rv = CI_HashIterateInit(CK_I_app_table.session_table, &iter);
    if(rv != CKR_OK) 
      return rv;
    for ( ; CI_HashIterValid(iter) ; ) {
      CI_HashIterateDeRef(iter, &key, (CK_VOID_PTR CK_PTR)(&i_session_data));

      /* look for the sessions on the same slot */
      if (i_session_data->slot_data->token_data->slot == currentSlot) {
	/* remove the object in this session object list if it exists */
	if (CI_HashEntryExists(i_session_data->object_list, hObject) 
	    == CKR_OK) {
	  rv = CI_ContainerDelObj(i_session_data->object_list, hObject);
	  if(rv != CKR_OK) {
	    CI_LogEntry("CI_InternalDestroyObject", 
			"removing session hash entry for Token Object", 
			rv , 0);
	    CI_VarLogEntry("CI_InternalDestroyObject", 
			   "Session handle: %d  Hashtable: %p", rv , 0,
			   i_session_data->session_handle,
			   i_session_data->object_list);
	    return rv;
	  }
	}
	rv = CI_HashIterateInc(iter);
	if(rv != CKR_OK) 
	  return rv;
      }
    }
    CI_HashIterateDelete(iter);
  }

  CI_LogEntry("CI_InternalDestroyObject", "...complete", rv , 2);

  return rv;
}  

/* }}} */
/* {{{ C_CopyObject */
CK_DEFINE_FUNCTION(CK_RV, C_CopyObject)(
  CK_SESSION_HANDLE hSession,
  CK_OBJECT_HANDLE hObject,
  CK_ATTRIBUTE_PTR pTemplate,
  CK_ULONG ulCount,
  CK_OBJECT_HANDLE_PTR phNewObject
)
{
  CK_RV rv = CKR_OK;
  CK_I_OBJ_PTR old_obj = NULL_PTR;  /* object to be copied */
  CK_I_OBJ_PTR new_obj = NULL_PTR;  /* object to be created */
  CK_I_SESSION_DATA_PTR session_data = NULL_PTR;

  CI_LogEntry("C_CopyObject", "starting...", rv , 1);

#ifndef NO_LOGGING
  {
    CK_CHAR_PTR tmp = NULL;
    CI_CodeFktEntry("C_CopyObject", "%lu,%lu,%s,%lu,%p", 
                  hSession,
		  hObject,
		  tmp = CI_PrintTemplate(pTemplate,ulCount),
		  ulCount,
		  phNewObject);
    TC_free(tmp);
  }
#endif // NO_LOGGING

  /* make sure we are initialized */
  if (!(CK_I_global_flags & CK_IGF_INITIALIZED)) 
    return CKR_CRYPTOKI_NOT_INITIALIZED;

  rv = CI_ReturnSession(hSession, &session_data);
  if(rv != CKR_OK)
    {
      CI_VarLogEntry("C_CreateObject", "retrieve session data (hSession: %lu)", rv, 0,
                     hSession);
      return rv;
    }
 
  rv = CI_ReturnObj(session_data, hObject, &old_obj);
  if(rv != CKR_OK)
    {
      CI_VarLogEntry("C_CreateObject", "retrieve object list (hSession: %lu, hKey: %lu)", rv, 0,
                     hSession, hObject);
      return rv;
    }
 
  /* create an internal object */
  rv = CI_ObjCreateObj(&new_obj);
  if(rv != CKR_OK) 
    return rv;
  rv = CI_ObjReadTemplate(new_obj,pTemplate,ulCount);
  if(rv != CKR_OK) 
    return rv;

  /* merge old object into new one */
  rv = CI_ObjMergeObj(new_obj, old_obj, FALSE);

  /* put new obj into session */
  rv = CI_InternalCreateObject(session_data, new_obj, phNewObject);

  CI_LogEntry("C_CopyObject", "...complete", rv , 1);	  

  return CKR_OK;
}
/* }}} */
/* {{{ C_GetAttributeValue */
CK_DEFINE_FUNCTION(CK_RV, C_GetAttributeValue)
(
 CK_SESSION_HANDLE hSession,
 CK_OBJECT_HANDLE hObject,
 CK_ATTRIBUTE_PTR pTemplate,
 CK_ULONG ulCount
 )
{
  CK_RV rv = CKR_OK;
  CK_ULONG i;
  CK_I_OBJ_PTR obj = NULL_PTR; 
  CK_I_SESSION_DATA_PTR session_data = NULL_PTR;
  CK_ATTRIBUTE_PTR template_entry = NULL_PTR;
  CK_BBOOL sensitive = FALSE;
  CK_BBOOL invalid = FALSE;
  CK_ATTRIBUTE_TYPE ia_type;
  CK_LONG err_retval = -1L;  
  
  CI_LogEntry("C_GetAttributeValue", "starting...", rv , 1);
  
  CI_CodeFktEntry("C_GetAttributeValue", "%lu,%lu,%p,%lu", 
    hSession,
		  hObject,
      pTemplate,
      ulCount);
  
  /* make sure we are initialized */
  if (!(CK_I_global_flags & CK_IGF_INITIALIZED)) 
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  
  rv = CI_ReturnSession(hSession, &session_data);
  if(rv != CKR_OK)
  {
    CI_VarLogEntry("C_GetAttributeValue", "retrieve session data (hSession: %lu)", rv, 0,
      hSession);
    return rv;
  }
  
  rv = CI_ReturnObj(session_data,hObject, &obj);
  if(rv != CKR_OK)
  {
    CI_VarLogEntry("C_GetAttributeValue", "retrieve object list (hSession: %lu, hObject: %lu)", 
      rv, 0,
      hSession, hObject);
    return rv;
  }
  
  /* Rule 1: Check whether the object is sensitive or extractable */
  template_entry = CI_ObjLookup(obj,CK_IA_SENSITIVE);
  if((template_entry != NULL) &&
    (TRUE == *((CK_BBOOL CK_PTR)template_entry->pValue)))
  {
    sensitive = TRUE;
  }
  template_entry = CI_ObjLookup(obj,CK_IA_EXTRACTABLE);
  if((template_entry != NULL) &&
    (FALSE == *((CK_BBOOL CK_PTR)template_entry->pValue)))
  {
    sensitive = TRUE;
  }
  
  
  for(i=0; i<ulCount ; i++,pTemplate++)
  {
    rv= CI_TranslateAttribute(pTemplate->type,&ia_type);
    /* Rule 2a: check that the Attribute is a valid one at all */
    if(rv != CKR_OK)
    {
      invalid = TRUE;
      rv = CKR_ATTRIBUTE_TYPE_INVALID;
      CI_VarLogEntry("C_GetAttributeValue",
        "Value not a valid attribute: 0x%08lx",
        rv, 0, pTemplate->type);
    }
    else
    {
      /* check that the entry exists */
      if(CI_ObjLookup(obj,ia_type) == NULL_PTR) 
      {
        /* Rule 2b: Attribute invalid for this object */
        invalid = TRUE;
        rv = CKR_ATTRIBUTE_TYPE_INVALID;
        CI_VarLogEntry("C_GetAttributeValue",
          "Attribute %s not valid for object",
          rv, 0, CI_AttributeStr(pTemplate->type));
      }
      else
      {
        /* Rule 3: get the size of the object in order for application to allocate memory */
        if(pTemplate->pValue == NULL_PTR) 
        {
          pTemplate->ulValueLen = CI_ObjLookup(obj,ia_type)->ulValueLen;
          continue;
        }
        
        /* Rule 4: if the buffer pointed to in pTemplate->pValue is large enough, copy the data */
        if(pTemplate->ulValueLen >= CI_ObjLookup(obj,ia_type)->ulValueLen)
        {
          pTemplate->ulValueLen = CI_ObjLookup(obj,ia_type)->ulValueLen;
          memcpy(pTemplate->pValue, CI_ObjLookup(obj,ia_type)->pValue, pTemplate->ulValueLen);	  
        }
        else /* Rule 5: the buffer is too small */
        {
          invalid = TRUE; 
          rv = CKR_BUFFER_TOO_SMALL;
        }
      }
    }
    
    /* is Attribute invalid? */
    if( invalid )
    {
      /* mark entry for illegal access and return */
      memcpy(&(pTemplate->ulValueLen),&err_retval,sizeof(CK_LONG));	  
      invalid = FALSE;  /* only for one entry in the template */
      
      /* reset the return value that we might have cleared */
      rv = CKR_ATTRIBUTE_TYPE_INVALID; 
    }
    /* is object sensitive ?
    we have to check, whether we can reveal the attribute, or not */
    if ( sensitive )
    {
      
      /* defines for better readability */
#define REVEALE_ATTRIBUTE break;
#define DONT_REVEALE_ATTRIBUTE \
  /* mark entry for illegal access and return */ \
  memcpy(&(pTemplate->ulValueLen),&err_retval,sizeof(CK_LONG));	  \
  rv = CKR_ATTRIBUTE_SENSITIVE; \
      break;
      /* end defines for better readability */
      
      switch ( pTemplate->type )
      {
        // These attributes may be revealed in spite of the sensitive attribute
        /* common attributes (spec 2.1 �9.2)*/
      case CKA_CLASS:         REVEALE_ATTRIBUTE;   
      case CKA_TOKEN:         REVEALE_ATTRIBUTE;   
      case CKA_PRIVATE:       REVEALE_ATTRIBUTE;   
      case CKA_MODIFIABLE:    REVEALE_ATTRIBUTE;   
      case CKA_LABEL:         REVEALE_ATTRIBUTE;   
      default:
        {
          /* object class specific attributes */
          CK_ATTRIBUTE_PTR pObjectClassAttribute;
          CI_TranslateAttribute(CKA_CLASS, &ia_type);
          pObjectClassAttribute = CI_ObjLookup(obj,ia_type);
          if (pObjectClassAttribute == NULL)
          {
            CI_VarLogEntry("C_GetAttributeValue",
              "Invalid Object", rv, 0);
            DONT_REVEALE_ATTRIBUTE;
          }
          switch (*((CK_OBJECT_CLASS CK_PTR)pObjectClassAttribute->pValue))
          {
          case CKO_DATA: // (spec 2.1 �9.3)
            {
              switch (pTemplate->type)
              {
                /* data object attributes */
              case CKA_APPLICATION: REVEALE_ATTRIBUTE;   
              case CKA_VALUE:       REVEALE_ATTRIBUTE;   
              }
              break;
            }// case CKO_DATA
            
          case CKO_CERTIFICATE: // (spec 2.1 �9.4)
            {
              /* common certificate object attributes */
              switch (pTemplate->type)
              {
              case CKA_CERTIFICATE_TYPE:  REVEALE_ATTRIBUTE;   
              default:
                {
                  /* certificate type specific attributes */
                  CK_ATTRIBUTE_PTR pCertificateType;
                  CI_TranslateAttribute(CKA_CERTIFICATE_TYPE, &ia_type);
                  pCertificateType = CI_ObjLookup(obj,ia_type);
                  if (pCertificateType == NULL)
                  {
                    CI_VarLogEntry("C_GetAttributeValue",
                      "Invalid Object", rv, 0);
                    DONT_REVEALE_ATTRIBUTE;
                  }
                  switch (*((CK_CERTIFICATE_TYPE CK_PTR)pCertificateType->pValue))
                  {
                  case CKC_X_509: /* x.509 certificate object attributes (spec 2.1 �9.4.1) */
                    {
                      switch (pTemplate->type)
                      {
                      case CKA_SUBJECT:       REVEALE_ATTRIBUTE;   
                      case CKA_ID:            REVEALE_ATTRIBUTE;   
                      case CKA_ISSUER:        REVEALE_ATTRIBUTE;   
                      case CKA_SERIAL_NUMBER: REVEALE_ATTRIBUTE;   
                      case CKA_VALUE:         REVEALE_ATTRIBUTE;   
                      default:                DONT_REVEALE_ATTRIBUTE;
                      }
                      break;
                    }// case CKC_X_509
                  default: DONT_REVEALE_ATTRIBUTE;
                  } // switch
                } //default
              } // switch
            } // case CKO_CERTIFICATE
          case CKO_PUBLIC_KEY:
          case CKO_PRIVATE_KEY:
          case CKO_SECRET_KEY:
            {
              /* commmon key object attributes (spec 2.1 �9.5)*/
              switch (pTemplate->type)
              {
              case CKA_KEY_TYPE:      REVEALE_ATTRIBUTE;
              case CKA_ID:            REVEALE_ATTRIBUTE;
              case CKA_START_DATE:    REVEALE_ATTRIBUTE;
              case CKA_END_DATE:      REVEALE_ATTRIBUTE;
              case CKA_DERIVE:        REVEALE_ATTRIBUTE;
              case CKA_LOCAL:         REVEALE_ATTRIBUTE;
              default:                
                {
                  /* key class specific attributes */
                  switch (*((CK_OBJECT_CLASS CK_PTR)pObjectClassAttribute->pValue))
                  {
                  case CKO_PUBLIC_KEY:
                    {/* common public key attributes (spec2.1 �9.6) */
                      switch (pTemplate->type)
                      {
                      case CKA_SUBJECT:         REVEALE_ATTRIBUTE;
                      case CKA_ENCRYPT:         REVEALE_ATTRIBUTE;
                      case CKA_VERIFY:          REVEALE_ATTRIBUTE;
                      case CKA_VERIFY_RECOVER:  REVEALE_ATTRIBUTE;
                      case CKA_WRAP:            REVEALE_ATTRIBUTE;
                      default:
                        {
                          /* public key type specific attributes */
                          CK_ATTRIBUTE_PTR pKeyType;
                          CI_TranslateAttribute(CKA_KEY_TYPE, &ia_type);
                          pKeyType = CI_ObjLookup(obj,ia_type);
                          if (pKeyType == NULL)
                          {
                            CI_VarLogEntry("C_GetAttributeValue",
                              "Invalid Object", rv, 0);
                            DONT_REVEALE_ATTRIBUTE;
                          }
                          switch (*((CK_KEY_TYPE CK_PTR)pKeyType->pValue))
                          {
                          case CKK_RSA: /* RSA public key attributes (spec 2.1 �9.6.1) */
                            {
                              switch (pTemplate->type)
                              {
                              case CKA_MODULUS:         REVEALE_ATTRIBUTE;
                              case CKA_MODULUS_BITS:    REVEALE_ATTRIBUTE;
                              case CKA_PUBLIC_EXPONENT: REVEALE_ATTRIBUTE;
                              default:                  DONT_REVEALE_ATTRIBUTE;
                              }
                              break;
                            } // case CKK_RSA
                          case CKK_DSA: /* DSA public key attributes (spec 2.1 �9.6.2) */
                            {
                              switch (pTemplate->type)
                              {
                              case CKA_PRIME:       REVEALE_ATTRIBUTE;
                              case CK_IA_SUBPRIME:  REVEALE_ATTRIBUTE;
                              case CKA_BASE:        REVEALE_ATTRIBUTE;
                              case CKA_VALUE:       REVEALE_ATTRIBUTE;
                              default:              DONT_REVEALE_ATTRIBUTE;
                              }
                              break;
                            } // case CKK_DSA
                          case CKK_ECDSA:  /* ECDSA public key attributes (spec 2.1 �9.6.3) */
                            {
                              switch (pTemplate->type)
                              {
                              case CKA_ECDSA_PARAMS:    REVEALE_ATTRIBUTE;
                              case CKA_EC_POINT:        REVEALE_ATTRIBUTE;
                              default:                  DONT_REVEALE_ATTRIBUTE;
                              }
                              break;
                            } // case CKK_ECDSA
                          case CKK_DH:  /* Diffie-Hellman public key attributes (spec 2.1 �9.6.4) */
                            {
                              switch (pTemplate->type)
                              {
                              case CKA_PRIME:   REVEALE_ATTRIBUTE;
                              case CKA_BASE:    REVEALE_ATTRIBUTE;
                              case CKA_VALUE:   REVEALE_ATTRIBUTE;
                              default:          DONT_REVEALE_ATTRIBUTE;
                              }
                              break;
                            } // case CKK_DH
                          case CKK_KEA: /* KEA public key attributes (spec 2.1 �9.6.5) */
                            {
                              switch (pTemplate->type)
                              {
                              case CKA_PRIME:       REVEALE_ATTRIBUTE;
                              case CK_IA_SUBPRIME:  REVEALE_ATTRIBUTE;
                              case CKA_BASE:        REVEALE_ATTRIBUTE;
                              case CKA_VALUE:       REVEALE_ATTRIBUTE;
                              default:              DONT_REVEALE_ATTRIBUTE;
                              }
                              break;
                            } // case CKK_KEA
                          default:  DONT_REVEALE_ATTRIBUTE;
                          } // switch
                        } // default
                      } // switch 
                      break;
                    } // case CKO_PUBLIC_KEY
                    
                  case CKO_PRIVATE_KEY:
                    {
                      /* common private key attributes (spec2.1 �9.7) */
                      switch (pTemplate->type)
                      {
                      case CKA_SUBJECT:           REVEALE_ATTRIBUTE;
                      case CKA_SENSITIVE:         REVEALE_ATTRIBUTE;
                      case CKA_DECRYPT:           REVEALE_ATTRIBUTE;
                      case CKA_SIGN:              REVEALE_ATTRIBUTE;
                      case CKA_SIGN_RECOVER:      REVEALE_ATTRIBUTE;
                      case CKA_UNWRAP:            REVEALE_ATTRIBUTE;
                      case CKA_EXTRACTABLE:       REVEALE_ATTRIBUTE;
                      case CKA_ALWAYS_SENSITIVE:  REVEALE_ATTRIBUTE;
                      case CKA_NEVER_EXTRACTABLE: REVEALE_ATTRIBUTE;
                      default:
                        {
                          /* public key type specific attributes */
                          CK_ATTRIBUTE_PTR pKeyType;
                          CI_TranslateAttribute(CKA_KEY_TYPE, &ia_type);
                          pKeyType = CI_ObjLookup(obj,ia_type);
                          if (pKeyType == NULL)
                          {
                            CI_VarLogEntry("C_GetAttributeValue",
                              "Invalid Object", rv, 0);
                            DONT_REVEALE_ATTRIBUTE;
                          }
                          switch ( *((CK_KEY_TYPE CK_PTR)pKeyType->pValue) )
                          {
                          case CKK_RSA:   /* RSA private key object attributes (spec 2.1 �9.7.1) */
                            {
                              switch (pTemplate->type)
                              {
                              case CKA_MODULUS:           REVEALE_ATTRIBUTE;
                              case CKA_PUBLIC_EXPONENT:   REVEALE_ATTRIBUTE;
                              case CKA_PRIVATE_EXPONENT:  DONT_REVEALE_ATTRIBUTE;
                              case CKA_PRIME_1:           DONT_REVEALE_ATTRIBUTE;
                              case CKA_PRIME_2:           DONT_REVEALE_ATTRIBUTE;
                              case CKA_EXPONENT_1:        DONT_REVEALE_ATTRIBUTE;
                              case CKA_EXPONENT_2:        DONT_REVEALE_ATTRIBUTE;
                              case CKA_COEFFICIENT:       DONT_REVEALE_ATTRIBUTE;
                              default:                    DONT_REVEALE_ATTRIBUTE;
                              }
                              break;
                            } // case CKK_RSA
                          case CKK_DSA: /* DSA private key object attributes (spec 2.1 �9.7.2) */
                            {
                              switch (pTemplate->type)
                              {
                              case CKA_PRIME:       REVEALE_ATTRIBUTE;
                              case CK_IA_SUBPRIME:  REVEALE_ATTRIBUTE;
                              case CKA_BASE:        REVEALE_ATTRIBUTE;
                              case CKA_VALUE:       DONT_REVEALE_ATTRIBUTE;
                              default:              DONT_REVEALE_ATTRIBUTE;
                              }
                              break;
                            } // case CKK_DSA
                          case CKK_ECDSA: /* ECDSA private key object attributes (spec 2.1 �9.7.3) */
                            {
                              switch (pTemplate->type)
                              {
                              case CKA_ECDSA_PARAMS:  REVEALE_ATTRIBUTE;
                              case CKA_VALUE:         DONT_REVEALE_ATTRIBUTE;
                              default:                DONT_REVEALE_ATTRIBUTE;
                              }
                              break;
                            } // case CKK_ECDSA
                          case CKK_DH:  /* Diffie-Hellman private key object attributes (spec 2.1 �9.7.4) */
                            {
                              switch (pTemplate->type)
                              {
                              case CKA_PRIME:       REVEALE_ATTRIBUTE;
                              case CKA_BASE:        REVEALE_ATTRIBUTE;
                              case CKA_VALUE:       DONT_REVEALE_ATTRIBUTE;
                              case CKA_VALUE_BITS:  DONT_REVEALE_ATTRIBUTE;
                              default:              DONT_REVEALE_ATTRIBUTE;
                              }
                              break;
                            } // case CKK_DH
                          case CKK_KEA: /* KEA private key object attributes (spec 2.1 �9.7.5) */
                            {
                              switch ( pTemplate->type)
                              {
                              case CKA_PRIME:       REVEALE_ATTRIBUTE;
                              case CK_IA_SUBPRIME:  REVEALE_ATTRIBUTE;
                              case CKA_BASE:        REVEALE_ATTRIBUTE;
                              case CKA_VALUE:       DONT_REVEALE_ATTRIBUTE;
                              default:              DONT_REVEALE_ATTRIBUTE;
                              }
                              break;
                            } // case CKK_KEA
                          default:  DONT_REVEALE_ATTRIBUTE; 
                          } // switch
                        } // default
                      } // switch 
                      break;
                    } // case CKO_PRIVATE_KEY
                  case CKO_SECRET_KEY:
                    {
                      /* common secret key attributes (spec2.1 �9.8) */
                      switch (pTemplate->type)
                      {
                      case CKA_SENSITIVE:         REVEALE_ATTRIBUTE;
                      case CKA_ENCRYPT:           REVEALE_ATTRIBUTE;
                      case CKA_DECRYPT:           REVEALE_ATTRIBUTE;
                      case CKA_SIGN:              REVEALE_ATTRIBUTE;
                      case CKA_VERIFY:            REVEALE_ATTRIBUTE;
                      case CKA_WRAP:              REVEALE_ATTRIBUTE;
                      case CKA_UNWRAP:            REVEALE_ATTRIBUTE;
                      case CKA_EXTRACTABLE:       REVEALE_ATTRIBUTE;
                      case CKA_ALWAYS_SENSITIVE:  REVEALE_ATTRIBUTE;
                      case CKA_NEVER_EXTRACTABLE: REVEALE_ATTRIBUTE;
                      default:
                        {
                          /* secret key type specific attributes */
                          CK_ATTRIBUTE_PTR pKeyType;
                          CI_TranslateAttribute(CKA_KEY_TYPE, &ia_type);
                          pKeyType = CI_ObjLookup(obj,ia_type);
                          switch (*((CK_KEY_TYPE CK_PTR)pKeyType->pValue))
                          {
                          case CKK_GENERIC_SECRET:  /* Generic secret key object attributes (spec 2.1 �9.8.1) */
                            {
                              switch (pTemplate->type)
                              {
                              case CKA_VALUE:     DONT_REVEALE_ATTRIBUTE;
                              case CKA_VALUE_LEN: REVEALE_ATTRIBUTE;
                              default:            DONT_REVEALE_ATTRIBUTE;
                              }
                              break;
                            } // case CKK_GENERIC_SECRET
                          case CKK_RC2: /* RC2 secret key object attributes (spec 2.1 �9.8.2) */
                            {
                              switch (pTemplate->type)
                              {
                              case CKA_VALUE:     DONT_REVEALE_ATTRIBUTE;
                              case CKA_VALUE_LEN: REVEALE_ATTRIBUTE;
                              default:            DONT_REVEALE_ATTRIBUTE;
                              }
                              break;
                            } // case CKK_RC2
                          case CKK_RC4: /* RC4 secret key object attributes (spec 2.1 �9.8.3) */
                            {
                              switch (pTemplate->type)
                              {
                              case CKA_VALUE:     DONT_REVEALE_ATTRIBUTE;
                              case CKA_VALUE_LEN: REVEALE_ATTRIBUTE;
                              default:            DONT_REVEALE_ATTRIBUTE;
                              }
                              break;
                            } // case CKK_RC4
                          case CKK_RC5: /* RC5 secret key object attributes (spec 2.1 �9.8.4) */
                            {
                              switch(pTemplate->type)
                              {
                              case CKA_VALUE:     DONT_REVEALE_ATTRIBUTE;
                              case CKA_VALUE_LEN: REVEALE_ATTRIBUTE;
                              default:            DONT_REVEALE_ATTRIBUTE;
                              }
                              break;
                            } // case CKK_RC5
                          case CKK_DES: /* DES secret key object attributes (spec 2.1 �9.8.5) */
                            {
                              switch (pTemplate->type)
                              {
                              case CKA_VALUE:   DONT_REVEALE_ATTRIBUTE;
                              default:          DONT_REVEALE_ATTRIBUTE;
                              }
                              break;
                            } // case CKK_DES
                          case CKK_DES2:  /* DES2 secret key object attributes (spec 2.1 �9.8.6) */
                            {
                              switch(pTemplate->type)
                              {
                              case CKA_VALUE:   DONT_REVEALE_ATTRIBUTE;
                              default:          DONT_REVEALE_ATTRIBUTE;
                              }
                              break;
                            } // case CKK_DES2
                          case CKK_DES3:  /* DES3 secret key object attributes (spec 2.1 �9.8.7) */
                            {
                              switch(pTemplate->type)
                              {
                              case CKA_VALUE:   DONT_REVEALE_ATTRIBUTE;
                              default:          DONT_REVEALE_ATTRIBUTE;
                              }
                              break;
                            } // case CKK_DES3
                          case CKK_CAST: /* CAST secret key object attributes (spec 2.1 �9.8.8) */
                            {
                              switch(pTemplate->type)
                              {
                              case CKA_VALUE:     DONT_REVEALE_ATTRIBUTE;
                              case CKA_VALUE_LEN: REVEALE_ATTRIBUTE;
                              default:            DONT_REVEALE_ATTRIBUTE;
                              }
                              break;
                            } // case CKK_CAST
                          case CKK_CAST3: /* CAST3 secret key object attributes (spec 2.1 �9.8.9) */
                            {
                              switch(pTemplate->type)
                              {
                              case CKA_VALUE:     DONT_REVEALE_ATTRIBUTE;
                              case CKA_VALUE_LEN: REVEALE_ATTRIBUTE;
                              default:            DONT_REVEALE_ATTRIBUTE;
                              }
                              break;
                            } // case CKK_CAST3
                          case /*CKK_CAST5*/ CKK_CAST128: /* CAST5 aka CAST128 secret key object attributes (spec 2.1 �9.8.10) */
                            {
                              switch(pTemplate->type)
                              {
                              case CKA_VALUE:     DONT_REVEALE_ATTRIBUTE;
                              case CKA_VALUE_LEN: REVEALE_ATTRIBUTE;
                              default:            DONT_REVEALE_ATTRIBUTE;
                              }
                              break;
                            } // case CKK_CAST128
                          case CKK_IDEA: /* IDEA secret key object attributes (spec 2.1 �9.8.11) */
                            {
                              switch(pTemplate->type)
                              {
                              case CKA_VALUE: DONT_REVEALE_ATTRIBUTE;
                              default:        DONT_REVEALE_ATTRIBUTE;
                              }
                              break;
                            } // case CKK_IDEA
                          case CKK_CDMF:  /* CDMF secret key object attributes (spec 2.1 �9.8.12) */
                            {
                              switch(pTemplate->type)
                              {
                              case CKA_VALUE:   DONT_REVEALE_ATTRIBUTE;
                              default:          DONT_REVEALE_ATTRIBUTE;
                              }
                              break;
                            } // case CKK_CDMF
                          case CKK_SKIPJACK:  /* SKIPJACK secret key object attributes (spec 2.1 �9.8.13) */
                            {
                              switch(pTemplate->type)
                              {
                              case CKA_VALUE:   DONT_REVEALE_ATTRIBUTE;
                              default:          DONT_REVEALE_ATTRIBUTE;
                              }
                              break;
                            } // case CKK_SKIPJACK
                          case CKK_BATON: /* BATON secret key object attributes (spec 2.1 �9.8.14) */
                            {
                              switch (pTemplate->type)
                              {
                              case CKA_VALUE: DONT_REVEALE_ATTRIBUTE;
                              default:        DONT_REVEALE_ATTRIBUTE;
                              }
                              break;
                            } // case CKK_BATON
                          case CKK_JUNIPER: /* JUNIPER secret key object attributes (spec 2.1 �9.8.15) */
                            {
                              switch(pTemplate->type)
                              {
                              case CKA_VALUE: DONT_REVEALE_ATTRIBUTE;
                              default:        DONT_REVEALE_ATTRIBUTE;
                              }
                              break;
                            } // case CKK_JUNIPER
                          default: DONT_REVEALE_ATTRIBUTE;
                            } // switch
                          } // default
                        } // switch
                        break;
                      } // case CKO_SECRET_KEY
                    default: DONT_REVEALE_ATTRIBUTE;
                    } // switch
                  } // default
                } // switch
                break;
              } // case CKA_*_KEY
              default: DONT_REVEALE_ATTRIBUTE
            } // switch
          } // default
        } //switch
      } // if (sensitive)
    } // for ...
    
    CI_LogEntry("C_GetAttributeValue", "...complete", rv , 1);	  
    
    return rv;
}
/* }}} */
/* {{{ C_SetAttributeValue */
CK_DEFINE_FUNCTION(CK_RV, C_SetAttributeValue)(
  CK_SESSION_HANDLE hSession,
  CK_OBJECT_HANDLE hObject,
  CK_ATTRIBUTE_PTR pTemplate,
  CK_ULONG ulCount
)
{
  CK_RV rv = CKR_OK;
  CK_ULONG i;
  CK_I_OBJ_PTR obj = NULL_PTR; 
  CK_I_SESSION_DATA_PTR session_data = NULL_PTR;
  
  CI_LogEntry("C_SetAttributeValue", "starting...", rv , 1);	  

#ifndef NO_LOGGING
  {
    CK_CHAR_PTR tmp = NULL;
    CI_CodeFktEntry("C_SetAttributeValue", "%lu,%lu,%s%,%lu", 
      hSession,
		  hObject,
		  tmp = CI_PrintTemplate(pTemplate,ulCount),
		  ulCount);
    TC_free(tmp);
  }
#endif // NO_LOGGING

  /* make sure we are initialized */
  if (!(CK_I_global_flags & CK_IGF_INITIALIZED)) 
    return CKR_CRYPTOKI_NOT_INITIALIZED;

  rv = CI_ReturnSession(hSession, &session_data);
  if(rv != CKR_OK)
    {
      CI_VarLogEntry("C_SetAttributeValue", "retrieve session data (hSession: %lu)", rv, 0,
                     hSession);
      return rv;
    }

  rv = CI_ReturnObj(session_data, hObject, &obj);
  if(rv != CKR_OK)
    {
      CI_VarLogEntry("C_SetAttributeValue", "retrieve object list (hSession: %lu, hObject: %lu)", 
		     rv, 0,
                     hSession, hObject);
      return rv;
    }
  
  /* TODO: make sure the session is not read-only */
  /* TODO: make sure the all constraints are met */

  for(i=0; i<ulCount ; i++,pTemplate++)
    {
      rv = CI_ObjSetAttribute(obj, pTemplate);
      if(rv != CKR_OK)
	{
	  CI_LogEntry("C_SetAttributeValue", "assigning new values", rv , 0);	  
	  return rv;
	}
    }

  CI_LogEntry("C_SetAttributeValue", "...complete", rv , 1);	  
  
  /* make sure that, if this is a token object, the data is saved */
  CI_TokenObjCommit(session_data,hObject);

  return rv;
  
}
/* }}} */
/* {{{ C_FindObjectsInit */
/* C_FindObjectsInit initializes a search for token and session
 * objects that match a template. */
CK_DEFINE_FUNCTION(CK_RV, C_FindObjectsInit)(
  CK_SESSION_HANDLE hSession,   /* the session's handle */
  CK_ATTRIBUTE_PTR  pTemplate,  /* attribute values to match */
  CK_ULONG          ulCount     /* attrs in search template */
)
{
  CK_RV rv =CKR_OK;
  CK_I_FIND_STATE_PTR find_state = NULL_PTR;
  CK_I_SESSION_DATA_PTR session_data = NULL_PTR;
  CK_VOID_PTR mutex = NULL_PTR;

  CI_LogEntry("C_FindObjectsInit", "starting...", rv , 1);	  

#ifndef NO_LOGGING
  {
    CK_CHAR_PTR tmp = NULL;
    CI_CodeFktEntry("C_FindObjectsInit", "%lu,%s,%lu", 
      hSession,
		  tmp = CI_PrintTemplate(pTemplate,ulCount),
		  ulCount);
    TC_free(tmp);
  }
#endif // NO_LOGGING

  /* make sure we are initialized */
  if (!(CK_I_global_flags & CK_IGF_INITIALIZED)) 
    {
      rv = CKR_CRYPTOKI_NOT_INITIALIZED;
      CI_LogEntry("C_FindObjectsInit", "initialization state", rv , 0);	  
      return rv;
    }

  /* get mutex, there are some synchronized areas in here */
  rv =CK_I_ext_functions._CreateMutex(&mutex);
  if(rv != CKR_OK)
    {
      CI_LogEntry("C_FindObjectsInit", "creating Mutex failed", rv, 0);
      return rv;
    }
  
  rv = CI_ReturnSession(hSession, &session_data);
  if(rv != CKR_OK)
    {
      CI_VarLogEntry("C_FindObjectsInit", "retrieve session data (hSession: %lu)", rv, 0,
                     hSession);
      CI_DestroyMutex(mutex);
      return rv;
    }

  /* Is there an active search? */
  if(session_data->find_state != NULL_PTR)
    {
      rv = CKR_OPERATION_ACTIVE;
      CI_LogEntry("C_FindObjectsInit", "checking find state", rv , 0);	  
      CI_DestroyMutex(mutex);
      return rv;
    }

  /* make sure that the application object container is initialized */
  /* should have been done in C_OpenSession */
  if(session_data->slot_data->token_data->object_list == NULL_PTR)
    {
      rv = CKR_GENERAL_ERROR;
      CI_LogEntry("C_FindObjectsInit", "application object list missing ", rv , 0);	  
      CI_DestroyMutex(mutex);
      return rv; 
    }

  /* make sure that the session object container is initialized */
  /* should have been done in C_OpenSession */
  if(session_data->object_list == NULL_PTR)
    {
      rv = CKR_GENERAL_ERROR;
      CI_LogEntry("C_FindObjectsInit", "session object list missing ", rv , 0);	  
      CI_DestroyMutex(mutex);
      return rv; 
    }

  find_state = TC_calloc(1,sizeof(CK_I_FIND_STATE));
  if(find_state == NULL_PTR)
    {
      rv = CKR_HOST_MEMORY;
      CI_LogEntry("C_FindObjectsInit", "allocating find_state", rv , 0);	  
      CI_DestroyMutex(mutex);
      return rv;
    }

  /* generate template object */
  rv = CI_ObjCreateObj(&(find_state->pTemplate));
  if(rv != CKR_OK) 
    {
      TC_free(find_state);
      CI_DestroyMutex(mutex);
      return rv;
    }

  rv = CI_ObjReadTemplate(find_state->pTemplate,pTemplate,ulCount);
  if(rv != CKR_OK) /* in case of error lookup is freed by CI_CreateInternalObjects */
    {
      CI_ObjDestroyObj(find_state->pTemplate);
      TC_free(find_state);
      CI_DestroyMutex(mutex);
      return rv;
    }

  /* set the private flag */
  find_state->searching_private = FALSE;
  
  rv = CI_HashIterateInit(session_data->slot_data->token_data->object_list, 
			  &(find_state->search_iter));
  if(rv != CKR_OK) 
    {
      CI_ObjDestroyObj(find_state->pTemplate);
      TC_free(find_state);
      CI_DestroyMutex(mutex);
      return rv;
    }

  session_data->find_state = find_state;
  CI_LogEntry("C_FindObjectsInit", "...complete", rv , 1);	  

  CK_I_ext_functions._DestroyMutex(mutex);

  return CKR_OK;
}
/* }}} */
/* {{{ CI_MatchObject */
/* 
 * returns true if all attributes of template are equal to the relating 
 * attributes of object. returns false otherwise.
 */
CK_DEFINE_FUNCTION(CK_BBOOL, CI_MatchObject)(
  CK_I_OBJ_PTR pTemplate,
  CK_I_OBJ_PTR object
)
{
  CK_ULONG i;

  for(i=0;i<I_ATT_MAX_NUM;i++)
    {
      /* skip if not in template */
      if(CI_ObjLookup(pTemplate,i) == NULL_PTR)
	continue;
      
      /* check existence */
      if(CI_ObjLookup(object,i) == NULL_PTR)
	return FALSE;

      /* paranoia test */
      /* TODO: since this should never become true, we need some extra error reporting */
      if(CI_ObjLookup(object,i)->type != CI_ObjLookup(pTemplate,i)->type)
	return FALSE;
      
      /* check size */
      if(CI_ObjLookup(object,i)->ulValueLen != CI_ObjLookup(pTemplate,i)->ulValueLen)
	return FALSE;
      
      /* check content */
      if(memcmp(CI_ObjLookup(object,i)->pValue, CI_ObjLookup(pTemplate,i)->pValue, CI_ObjLookup(object,i)->ulValueLen) != 0)
	return FALSE;

    }

  return TRUE;
}

/* }}} */
/* {{{ C_FindObjects */
/* C_FindObjects continues a search for token and session
 * objects that match a template, obtaining additional object
 * handles. */
CK_DEFINE_FUNCTION(CK_RV, C_FindObjects)(
  CK_SESSION_HANDLE    hSession,          /* session's handle */
  CK_OBJECT_HANDLE_PTR phObject,          /* gets obj. handles */
  CK_ULONG             ulMaxObjectCount,  /* max handles to get */
  CK_ULONG_PTR         pulObjectCount     /* actual # returned */
)
{
  CK_RV rv = CKR_OK;
  CK_ULONG key, i, j;
  CK_I_OBJ_PTR val = NULL_PTR;
  CK_I_SESSION_DATA_PTR session_data;

  CI_LogEntry("C_FindObjects", "starting...", rv , 1);
  CI_CodeFktEntry("C_FindObjects", "%lu,%p,%lu,%p", 
                  hSession,
		  phObject,
		  ulMaxObjectCount,
		  pulObjectCount);

  CI_VarLogEntry("C_FindObjects", "hSession: %lu", rv , 2, hSession);
  if(phObject == NULL_PTR) CI_LogEntry("C_FindObjects", "phObject == NULL_PTR", rv , 2);
  CI_VarLogEntry("C_FindObjects", "ulMaxObjectCount: %lu", rv , 2, ulMaxObjectCount);

  /* make sure we are initialized */
  if (!(CK_I_global_flags & CK_IGF_INITIALIZED)) 
    return CKR_CRYPTOKI_NOT_INITIALIZED;

  rv = CI_ReturnSession(hSession, &session_data);
  if(rv != CKR_OK)
    {
      CI_VarLogEntry("C_FindObjects", "retrieve session data (hSession: %lu)", rv, 0,
                     hSession);
      return rv;
    }

  /* Is there an active search? */
  if(session_data->find_state == NULL_PTR)
    return CKR_OPERATION_NOT_INITIALIZED;

  for(i = 0, j = 1 ; 
      (i < ulMaxObjectCount); 
      ++j, CI_HashIterateInc(session_data->find_state->search_iter))
    {
      if(!CI_HashIterValid(session_data->find_state->search_iter))
	{
	  if(session_data->find_state->searching_private == FALSE)
	    {
	      /* OK we tried the public objects so far. Now for the private stuff */
	      CI_LogEntry("C_FindObjects", "switching to token private obj list", rv, 1);

	      CI_HashIterateDelete(session_data->find_state->search_iter);
	      CI_HashIterateInit(session_data->object_list,
				 &(session_data->find_state->search_iter));
	      session_data->find_state->searching_private = TRUE;

	      /* check wether there are any objects */
	      if(!CI_HashIterValid(session_data->find_state->search_iter)) break;
	    }
	  else
	    break;
	}
      /* only ok, since we checked the validity of the iterator */
      rv= CI_HashIterateDeRef(session_data->find_state->search_iter,&key, (CK_VOID_PTR CK_PTR)&val);
      if(rv != CKR_OK) return rv;


      /* exclude public objects of the same session as this one. 
       * they will be checked when we do the private part.
       */
      if( (session_data->find_state->searching_private == FALSE) &&
	  (val->session == session_data)) /* same session */
	{      
	  CI_VarLogEntry("C_FindObjects", 
			 "ignoring %i. Object, handle: %i (%i hits) ", 
			 rv, 3, j,key,i);
	  continue;
	}
      
      if( CI_MatchObject(session_data->find_state->pTemplate, val) == TRUE )
	phObject[i++]=key;

      CI_VarLogEntry("C_FindObjects", 
		     "checking %i. Object, handle: %i (%i hits) ", 
		     rv, 3, j,key,i);
      
    } /* for(<...>;<...>;<...>) */
  
  *pulObjectCount = i;
  
  CI_LogEntry("C_FindObjects", "...complete", rv , 1);	  
  
  return rv;
}
/* }}} */
/* {{{ C_FindObjectsFinal */
/* C_FindObjectsFinal finishes a search for token and session
 * objects. */
CK_DEFINE_FUNCTION(CK_RV, C_FindObjectsFinal)(
  CK_SESSION_HANDLE hSession  /* the session's handle */
)
{
  CK_RV rv = CKR_OK;
  CK_I_SESSION_DATA_PTR session_data = NULL_PTR;

  CI_LogEntry("C_FindObjectsFinal", "starting...", rv , 1);	  
  CI_CodeFktEntry("C_FindObjectsFinal", "%lu", 
                  hSession);

  /* make sure we are initialized */
  if (!(CK_I_global_flags & CK_IGF_INITIALIZED)) 
    {
      rv = CKR_CRYPTOKI_NOT_INITIALIZED;
      CI_LogEntry("C_FindObjectsFinal", "checking initialization", rv , 0);	  
      return rv;
    }

  rv = CI_ReturnSession(hSession, &session_data);
  if(rv != CKR_OK)
    {
      CI_VarLogEntry("C_FindObjectsFinal", "retrieve session data (hSession: %lu)", rv, 0,
                     hSession);
      return rv;
    }

  /* Is there an active search? */
  if(session_data->find_state == NULL_PTR)
    {
      rv = CKR_OPERATION_NOT_INITIALIZED;
      CI_LogEntry("C_FindObjectsFinal", "checking for active search", rv , 0);	  
      return rv;
    }

  CI_ObjDestroyObj(session_data->find_state->pTemplate);
  CI_HashIterateDelete(session_data->find_state->search_iter);

  TC_free(session_data->find_state);
  session_data->find_state=NULL_PTR;

  CI_LogEntry("C_FindObjectsFinal", "...complete", rv , 1);	  

  return rv;
}
/* }}} */

/* ### the new Object-System ### */
CK_I_HASHTABLE_PTR CK_IA_ck2internal = NULL_PTR;

/* {{{ CI_TranslateAttribute */
CK_DEFINE_FUNCTION(CK_RV, CI_TranslateAttribute)(
  CK_ATTRIBUTE_TYPE CkAttrib,
  CK_ATTRIBUTE_TYPE CK_PTR pIAttrib
)
{
  CK_I_ATTRIBUTE_INFO_PTR attrib_info = NULL_PTR;
  CK_RV rv = CKR_OK;
  
  rv = CI_HashGetEntry(CK_IA_ck2internal,CkAttrib, (CK_VOID_PTR)&attrib_info);
  if(rv != CKR_OK) 
    {
      if(rv == CKR_ARGUMENTS_BAD) rv = CKR_ATTRIBUTE_TYPE_INVALID;
      return rv;
    }

  *pIAttrib = attrib_info->IntAttrib;
  return CKR_OK;
}
/* }}} */
/* {{{ CI_TranslateIntAttribute */
CK_DEFINE_FUNCTION(CK_RV, CI_TranslateIntAttribute)(
  CK_ATTRIBUTE_TYPE IAttrib,
  CK_ATTRIBUTE_TYPE CK_PTR pCkAttrib
)
{
  if(IAttrib > I_ATT_MAX_NUM)
    return CKR_ATTRIBUTE_TYPE_INVALID;

  *pCkAttrib = CK_I_attrib_xlate[IAttrib][1];

  return CKR_OK;
}
/* }}} */

/* {{{ CI_AttributeValid() */
CK_DEFINE_FUNCTION(CK_RV, CI_AttributeValid)(
  CK_ATTRIBUTE_TYPE Attribute,
  CK_OBJECT_CLASS  ObjClass,
  CK_BBOOL CK_PTR pValid
)
{
  CK_I_ATTRIBUTE_INFO_PTR attrib_info = NULL_PTR;
  CK_RV rv = CKR_OK;
  
  rv = CI_HashGetEntry(CK_IA_ck2internal,Attribute, (CK_VOID_PTR)&attrib_info);
  if(rv != CKR_OK) return rv;

  if(ObjClass > CK_IO_SECRET_KEY) return CKR_GENERAL_ERROR;
  *pValid = (CK_BBOOL) ( attrib_info->ObjTypes & (CK_I_obj_class_xlate[ObjClass]));
  
  return rv;
}
/* }}} */
/* {{{ CI_ObjCreateObj */
/** Create a new Object.
* 
* @return CKR_HOST_MEMORY if the memory could not be allocated, CKR_OK otherwise
* @param ppNewObj pointer into which the address of the new object will be written
*/
CK_DEFINE_FUNCTION(CK_RV, CI_ObjCreateObj)(
  CK_I_OBJ_PTR CK_PTR ppNewObj
)
{
  CK_RV rv = CKR_OK;

  if( (*ppNewObj = TC_calloc(1,sizeof(CK_I_OBJ))) == NULL_PTR)
    return CKR_HOST_MEMORY;

  if( ((*ppNewObj)->lookup = TC_calloc(I_ATT_MAX_NUM,
				       sizeof(CK_ATTRIBUTE_PTR))) 
      == NULL_PTR)
    {
      TC_free(*ppNewObj);
      return CKR_HOST_MEMORY;
    }

  rv = CI_InitHashtable(&((*ppNewObj)->table),CK_I_OBJ_INITIAL_SIZE);

  /* number of references */
  (*ppNewObj)->ref_count = 0;

  return rv;
}
/* }}} */
/* {{{ CI_ObjSetAttributeValue */
/** Setting an attribute value.
* The function will copy the contents of pValue.
* @return CKR_OK if no errors ocourred. CKR_HOST_MEMORY if an allocation
*         failed.
* @param pObject object to be manipulated
* @param AttributeType type of the attribute (CKA_*)
* @param pValue Byte string of the new attribute value
* @param ulValueLen lenght of the byte string
*/
CK_DEFINE_FUNCTION(CK_RV, CI_ObjSetAttributeValue)(
  CK_I_OBJ_PTR pObject, 
  CK_ATTRIBUTE_TYPE AttributeType,
  CK_VOID_PTR pValue, 
  CK_ULONG ulValueLen
)
{
  CK_RV rv = CKR_OK;
  CK_ATTRIBUTE_PTR temp_attr = NULL_PTR;
  CK_ATTRIBUTE_PTR old_attr = NULL_PTR;
  CK_ATTRIBUTE_TYPE int_attr_type;

  rv= CI_TranslateAttribute(AttributeType, &int_attr_type);
  if(rv != CKR_OK) { return rv; }

  old_attr = CI_ObjLookup(pObject,int_attr_type);

  temp_attr = TC_calloc(1,sizeof(CK_ATTRIBUTE));
  if(temp_attr == NULL_PTR)
    return CKR_HOST_MEMORY;

  temp_attr->type = AttributeType;
  temp_attr->ulValueLen = ulValueLen;

  temp_attr->pValue = TC_calloc(1,ulValueLen);
  if(temp_attr->pValue == NULL_PTR)
    {
      TC_free(temp_attr);
      return CKR_HOST_MEMORY;
    }

  memcpy(temp_attr->pValue, pValue, ulValueLen);
  
  
  /* Als vorletztes. Danach kann nichts mehr schiefgehen was wir zur�ck rollen m�ssten */
  rv = CI_HashPutEntry(pObject->table, AttributeType, (CK_VOID_PTR)temp_attr);
  if(rv != CKR_OK) 
    {  
      TC_free(temp_attr->pValue); 
      TC_free(temp_attr); 
      return rv; 
    }

  CI_ObjLookup(pObject,int_attr_type) = temp_attr;

  if(old_attr != NULL_PTR)
    {
      if(old_attr->pValue != NULL_PTR)
	TC_free(old_attr->pValue);
      TC_free(old_attr);
    }

  return rv;
}
/* }}} */
/* {{{ CI_ObjSetIntAttributeValue */
/** Setting an attribute value.
* Verwendet die internen Attribute (CK_IA_*) statt CKA_*.
* @return CKR_HOST_MEMORY, 
* @param
*/
CK_DEFINE_FUNCTION(CK_RV, CI_ObjSetIntAttributeValue)(
  CK_I_OBJ_PTR pObject, 
  CK_ATTRIBUTE_TYPE InternalAttributeType, 
  CK_VOID_PTR pValue, 
  CK_ULONG ulValueLen
)
{
  CK_RV rv = CKR_OK;
  CK_ATTRIBUTE_PTR temp_attr = NULL_PTR;
  CK_ATTRIBUTE_PTR old_attr = NULL_PTR;
  CK_ATTRIBUTE_TYPE attr_type;

  rv= CI_TranslateIntAttribute(InternalAttributeType, &attr_type);
  if(rv != CKR_OK) 
    { 
      CI_LogEntry("CI_ObjSetIntAttributeValue", "translating Attribute", rv, 0);
      return rv; 
    }

  old_attr = CI_ObjLookup(pObject,InternalAttributeType);

  temp_attr = TC_calloc(1,sizeof(CK_ATTRIBUTE));
  if(temp_attr == NULL_PTR)
    { 
      rv= CKR_HOST_MEMORY;
      CI_LogEntry("CI_ObjSetIntAttributeValue", "memory for temp_attr", rv, 0);
      return rv; 
    }

  temp_attr->type = attr_type;
  temp_attr->ulValueLen = ulValueLen;

  temp_attr->pValue = TC_malloc(ulValueLen);
  if(temp_attr->pValue == NULL_PTR)
    {
      TC_free(temp_attr);
      rv= CKR_HOST_MEMORY;
      CI_LogEntry("CI_ObjSetIntAttributeValue", "memory for temp_attr->pValue", rv, 0);
      return rv; 
    }

  memcpy(temp_attr->pValue, pValue, ulValueLen);
    
  /* Als vorletztes. Danach kann nichts mehr schiefgehen was wir zur�ck rollen m�ssten */
  rv = CI_HashPutEntry(pObject->table, attr_type, (CK_VOID_PTR)temp_attr);
  if(rv != CKR_OK) 
    {  
      TC_free(temp_attr->pValue); 
      TC_free(temp_attr); 
      CI_LogEntry("CI_ObjSetIntAttributeValue", "putting temp_attr into pObject->table", rv, 0);
      return rv; 
    }

  CI_ObjLookup(pObject,InternalAttributeType) = temp_attr;

  if(old_attr != NULL_PTR)
    {
      if(old_attr->pValue != NULL_PTR)
	TC_free(old_attr->pValue);
      TC_free(old_attr);
    }

  return rv;

}
/* }}} */
/* {{{ CI_ObjSetAttribute */
/** Setzen eines Attributes mit eines Attribute Struktur.
* Funktion kopiert die Attribute Struktur und den Speiche bereich auf den
* pValue zeigt.
*
* Die alte Attribute Struktur wird gel�scht oder �berschrieben.
*
* @return
* @param pObject zu �nderndes Object
* @param pAttribute Struktur mit den Werten f�r das neue Attribute
*/
CK_DEFINE_FUNCTION(CK_RV, CI_ObjSetAttribute)(
  CK_I_OBJ_PTR pObject,
  CK_ATTRIBUTE_PTR pAttribute
)
{
  CK_RV rv = CKR_OK;
  CK_ATTRIBUTE_PTR temp_attr = NULL_PTR;
  CK_ATTRIBUTE_PTR old_attr = NULL_PTR;
  CK_ATTRIBUTE_TYPE int_attr_type;

  if(pAttribute == NULL)
    return CKR_ATTRIBUTE_TYPE_INVALID;

  rv= CI_TranslateAttribute(pAttribute->type, &int_attr_type);
  if(rv != CKR_OK) { return rv; }

#ifdef EBUG
  assert(pAttribute->type == CK_I_attrib_xlate[int_attr_type][1]);
#endif /* EBUG */

  old_attr = CI_ObjLookup(pObject,int_attr_type);

  /* Alles neu allozieren damit wir im Falles eines Fehlers zur�ck rollen k�nnen */
  temp_attr = TC_calloc(1,sizeof(CK_ATTRIBUTE));
  if(temp_attr == NULL_PTR)
    return CKR_HOST_MEMORY;

  temp_attr->type = pAttribute->type;
  temp_attr->ulValueLen = pAttribute->ulValueLen;

  if(pAttribute->pValue != NULL_PTR)
    {
      temp_attr->pValue = TC_calloc(1,pAttribute->ulValueLen);
      if(temp_attr->pValue == NULL_PTR)
	{
	  TC_free(temp_attr);
	  return CKR_HOST_MEMORY;
	}
      
      memcpy(temp_attr->pValue, pAttribute->pValue, pAttribute->ulValueLen);
    }
  else
    {
      temp_attr->pValue = NULL_PTR;
      assert(pAttribute->ulValueLen == 0); 
    }
  
  /* Als vorletztes. Danach kann nichts mehr schiefgehen was wir zur�ck rollen m�ssten */
  rv = CI_HashPutEntry(pObject->table, temp_attr->type, (CK_VOID_PTR)temp_attr);
  if(rv != CKR_OK) 
    {  
      TC_free(temp_attr->pValue); 
      TC_free(temp_attr); 
      return rv; 
    }

  CI_ObjLookup(pObject,int_attr_type) = temp_attr;

  if(old_attr != NULL_PTR)
    {
      if(old_attr->pValue != NULL_PTR)
	TC_free(old_attr->pValue);
      TC_free(old_attr);
    }

  return rv;
}
/* }}} */
/* {{{ CI_ObjGetAttributeValue */
CK_DEFINE_FUNCTION(CK_RV, CI_ObjGetAttributeValue)(
  CK_I_OBJ_PTR pObject,
  CK_ATTRIBUTE_TYPE AttributeType,
  CK_BYTE_PTR pValue,
  CK_ULONG_PTR pulValueLen
)
{
  CK_RV rv = CKR_OK;
  CK_ATTRIBUTE_TYPE int_attr_type;
  CK_ATTRIBUTE_PTR temp_attr = NULL_PTR;

  rv= CI_TranslateAttribute(AttributeType, &int_attr_type);
  if(rv != CKR_OK) { return rv; }

  if((temp_attr = CI_ObjLookup(pObject,int_attr_type)) == NULL_PTR)
    return CKR_ATTRIBUTE_TYPE_INVALID;

  /* ist dies nur ein Test auf die L�nge des Puffers? */
  if(pValue == NULL_PTR)
    {
      *pulValueLen = temp_attr->ulValueLen;
      return CKR_OK;
    }

  if(*pulValueLen < temp_attr->ulValueLen)
    {
      *pulValueLen = temp_attr->ulValueLen;
      return CKR_BUFFER_TOO_SMALL;
    }

  memcpy(pValue, temp_attr->pValue, *pulValueLen);
  *pulValueLen = temp_attr->ulValueLen;

  return CKR_OK;
}
/* }}} */
/* {{{ CI_ObjSetIntBool */
CK_DEFINE_FUNCTION(CK_RV, CI_ObjSetIntBool)(
  CK_I_OBJ_PTR pObject,
  CK_ATTRIBUTE_TYPE InternalAttributeType,
  CK_BBOOL bValue
)
{
  return CI_ObjSetIntAttributeValue(pObject,
				    InternalAttributeType,
				    (CK_VOID_PTR)&bValue,
				    sizeof(CK_BBOOL));
}
/* }}} */
/* {{{ CI_ObjGetIntAttributeValue */
/** Auslesen eines Attributwertes.
* Verwendet die Technik zum Bestimmen des notwendigen Speichers wie in PKCS#11
* Section 10.2 beschrieben. Nutzt zur Identifikation der Attribute die 
* internen Werte (CK_IA_*)
* @return
* @param
*/
CK_DEFINE_FUNCTION(CK_RV, CI_ObjGetIntAttributeValue)(
  CK_I_OBJ_PTR pObject,
  CK_ATTRIBUTE_TYPE InternalAttributeType, 
  CK_BYTE_PTR pValue, 
  CK_ULONG_PTR pulValueLen
)
{
  CK_ATTRIBUTE_PTR temp_attr = NULL_PTR;

  if(InternalAttributeType > I_ATT_MAX_NUM) 
    return CKR_ATTRIBUTE_TYPE_INVALID;

  if((temp_attr = CI_ObjLookup(pObject,InternalAttributeType)) == NULL_PTR)
    return CKR_ATTRIBUTE_TYPE_INVALID;

  /* ist dies nur ein Test auf die L�nge des Puffers? */
  if(pValue == NULL_PTR)
    {
      *pulValueLen = temp_attr->ulValueLen;
      return CKR_OK;
    }

  if(*pulValueLen < temp_attr->ulValueLen)
    {
      *pulValueLen = temp_attr->ulValueLen;
      return CKR_BUFFER_TOO_SMALL;
    }

  memcpy(pValue, temp_attr->pValue, *pulValueLen);
  *pulValueLen = temp_attr->ulValueLen;

  return CKR_OK;
}
/* }}} */
/* {{{ CI_ObjReadTemplate */
/** liest ein Template in ein Objekt ein. 
*
* @return CKR_OK wenn kein Fehler Aufgetreten, andere CK_* Fehlerkodes entsprechend dem Fehler
* @param pObject Objekt in welches die Werte eingelesen werden.
* @param pTemplate Array der Attributewerte
* @param ulTemplateLen L�nge des Arrays
*/
CK_DEFINE_FUNCTION(CK_RV, CI_ObjReadTemplate)(
  CK_I_OBJ_PTR  pObject,
  CK_ATTRIBUTE_PTR pTemplate,
  CK_ULONG ulTemplateLen
)
{
  CK_RV rv = CKR_OK;
  CK_ULONG i;

  CI_LogEntry("CI_ObjReadTemplate", "starting...", rv, 2);

  /* TODO: dies l�sst das Object u.U. in einem undefinierten Zustand. */
  for(i=0; i<ulTemplateLen ; i++)
    {
      rv = CI_ObjSetAttribute(pObject, pTemplate+i);
      if(rv != CKR_OK) 
	{
	  CI_LogEntry("CI_ObjReadTemplate", "Attribute Setting", rv, 0);
	  return rv;
	}
    }

  CI_LogEntry("CI_ObjReadTemplate", "...complete", rv, 2);

  return rv;
}
/* }}} */
/* {{{ CI_ObjCopyObject */
/** kopiert Object.
* allways does a deep copy of the attribute data
*
* @return
* @param pTargetObject Ziel
* @param pSourceObject Quelle
*/
CK_DEFINE_FUNCTION(CK_RV, CI_ObjCopyObject)(
  CK_I_OBJ_PTR pTargetObject, 
  CK_I_OBJ_PTR pSourceObject 
)
{
  CK_RV rv = CKR_OK;
  CK_I_HASH_ITERATOR_PTR hash_iter;
  CK_ATTRIBUTE_PTR temp_attr = NULL_PTR;

  rv = CI_HashIterateInit(pSourceObject->table, &hash_iter);
  if(rv != CKR_OK) return rv;

  while( hash_iter != NULL_PTR)
    {
      rv = CI_HashIterateDeRef(hash_iter, NULL_PTR, (CK_VOID_PTR_PTR)&temp_attr);
      if(rv != CKR_OK) return rv;

      CI_ObjSetAttribute(pTargetObject, temp_attr);
      
      rv = CI_HashIterateInc(hash_iter);
      if(rv != CKR_OK) return rv;
    }


  return rv;
}
/* }}} */
/* {{{ CI_ObjDestroyObj */
/** zerst�rt ein Objekt. 
* allways deep destroys the data in the attribute structures.
*
* @return
* @param pObject zu l�schendes Objekt
*/
CK_DEFINE_FUNCTION(CK_RV, CI_ObjDestroyObj)(
  CK_I_OBJ_PTR  pObject
)
{
  CK_RV rv = CKR_OK;
  CK_ULONG i;

  CI_LogEntry("CI_ObjDestroyObj", "starting...", rv , 2);
  
  if(pObject == NULL_PTR)
    {
      rv = CKR_GENERAL_ERROR;
      CI_LogEntry("CI_ObjDestroyObj", "invalid object! pObject == NULL_PTR", rv , 0);
      return rv;
    }
  
  if((pObject->lookup == NULL_PTR) ||
     (pObject->table == NULL_PTR))
    {
      rv = CKR_GENERAL_ERROR;
      CI_LogEntry("CI_ObjDestroyObj", "object not correctly initialized", rv , 0);
      return rv;
    }

  for(i =0 ; i < I_ATT_MAX_NUM ; i++)
    /* wir ignorieren jetzt den Returnwert einfach mal. Wenn es ein Attribut 
     * in dem Object nicht gibt macht das auch nichts */
    CI_ObjDeleteIntAttribute(pObject, i);

  CI_LogEntry("CI_ObjDestroyObj", "Attributes deleted", rv , 2);
  
  CI_DestroyHashtable(pObject->table);

  TC_free(pObject->lookup);
  TC_free(pObject);

  CI_LogEntry("CI_ObjDestroyObj", "...complete", rv , 2);
  return rv;
}
/* }}} */
/* {{{ CI_ObjMergeObj */
/** Mischt zwei Objekte 
* Attribute aus pSourceObject werden in nach pTargetObject kopiert wenn 
* diese Attribute in pTargetObject nicht vorhanden sind. Wenn der Flag
* overwrite von null verschieden ist werden alle Attribute aus pSourceObject
* nach pTargetObject geschrieben.
* @return CKR_OK wenn kein Fehler aufgetreten ist. CKR_HOST_MEMORY wenn eine
*         Speicher-Allocation fehlschl�gt.
* @param pTargetObject Objekt in das die Attribute kopiert werden.
* @param pSourceObject Objekt dessen Attribute kopiert werden.
* @param overwrite     Flag welche Attribute nach pObject1 kopiert werden
*/
CK_DEFINE_FUNCTION(CK_RV, CI_ObjMergeObj)(
  CK_I_OBJ_PTR pTargetObject,
  CK_I_OBJ_PTR pSourceObject,
  CK_BBOOL overwrite
)
{
  CK_RV rv = CKR_OK;
  CK_ULONG i;
  CK_ATTRIBUTE_PTR temp_attr = NULL_PTR;

  CI_LogEntry("CI_ObjMergeObj", "starting...", rv, 2);

  if( (pTargetObject == NULL_PTR) || (pSourceObject== NULL_PTR) )
    {
      rv = CKR_GENERAL_ERROR;
      CI_LogEntry("CI_ObjMergeObj", "precondition: objects != NULL_PTR", rv, 0);
      return rv;
    }

  for(i = 0 ; i <I_ATT_MAX_NUM ; i++)
    {
      temp_attr = CI_ObjLookup(pSourceObject,i);
      if((temp_attr != NULL_PTR) && /* �berhauptwas  und */
	 ((CI_ObjLookup(pTargetObject,i) == NULL_PTR) ||  /* nix im Ziel */
	  overwrite))                                /* oder egal */
	{
	  rv = CI_ObjSetAttribute(pTargetObject, temp_attr); 
	  if(rv != CKR_OK)
	    {
	      CI_LogEntry("CI_ObjMergeObj", "Set new Attribute", rv, 0);
	      return rv;
	    }
	}
    }

  CI_LogEntry("CI_ObjMergeObj", "...complete", rv, 2);
  return rv;
}
/* }}} */
/* {{{ CI_ObjDeleteAttribute */
/** L�sche Attribute in Objekt
*
* @return
* @param
*/
CK_DEFINE_FUNCTION(CK_RV, CI_ObjDeleteAttribute)(
  CK_I_OBJ_PTR pObject,
  CK_ATTRIBUTE_TYPE Attribute
)
{
  CK_RV rv = CKR_OK;
  CK_ATTRIBUTE_TYPE int_att;
  rv = CI_TranslateAttribute(Attribute, &int_att);
  if(rv != CKR_OK)
    return rv;

  return CI_ObjDeleteIntAttribute(pObject, int_att);
}
/* }}} */
/* {{{ CI_ObjDeleteIntAttribute */
/** L�sche Attribute in object
* Benutze interne Attribute (CK_IA_*)
* @return CKR_OK if delete succeeded, CKR_GENERAL_ERROR otherwise
* @param
*/
CK_DEFINE_FUNCTION(CK_RV, CI_ObjDeleteIntAttribute)(
  CK_I_OBJ_PTR pObject,
  CK_ATTRIBUTE_TYPE InternalAttribute
)
{
  /* TODO: protect all object manipulations in this file with mutexes */
  CK_RV rv = CKR_OK;
  CK_ATTRIBUTE_PTR temp_attr = NULL_PTR;

  if( (temp_attr = CI_ObjLookup(pObject,InternalAttribute)) == NULL_PTR)
    {
      rv = CKR_ATTRIBUTE_TYPE_INVALID;
      /* Auskommentiert da von einigen Funktionen mit Absicht erzeugt */
      /* CI_LogEntry("CI_ObjDeleteIntAttribute", "temp_attr invalid", rv , 0); */
      return rv;
    }

  rv = CI_HashRemoveEntry(pObject->table, temp_attr->type);
  if(rv != CKR_OK)
    {
      CI_VarLogEntry("CI_ObjDeleteIntAttribute", 
		     "removing of attribute %x from Hash failed (attr ptr: %x)", 
		     rv , 0, 
		     temp_attr->type,temp_attr);
      /* do not return so we may free the memory held by the attribute anyway 
       * CI_HashRemoveEntry may only fail with CKR_ARGUMENT_BAD or CKR_OK
       */
    }

  CI_ObjLookup(pObject,InternalAttribute) = NULL_PTR;


  if(temp_attr->pValue != NULL_PTR) TC_free(temp_attr->pValue);
  TC_free(temp_attr);

  return rv;
}
/* }}} */
/* {{{ CI_ObjDumpObj */
CK_DEFINE_FUNCTION(CK_RV, CI_ObjDumpObj)(
	 CK_I_OBJ_PTR pObject,
	 FILE CK_PTR pOut
)
{
  CK_RV rv = CKR_OK; 
  CK_ULONG i;
  
  fprintf(pOut, "Object: %lx \n", (CK_ULONG)pObject);
  for(i =0 ; i< I_ATT_MAX_NUM ; i++)
    {
      if(CI_ObjLookup(pObject,i) == NULL_PTR)
	fprintf(pOut, "\tATT:%li, ATT_P:(null)\n", i);
      else
	fprintf(pOut, 
		"\tATT:%lu, ATT_P:%8lx, ATT_P->type: %2lu, ATT_P->pValue: %8lx, ATT_P->pValueLen: %lu\n", 
		i, (CK_ULONG)CI_ObjLookup(pObject,i),
		(CK_ULONG)CI_ObjLookup(pObject,i)->type,
		(CK_ULONG)CI_ObjLookup(pObject,i)->pValue,
		CI_ObjLookup(pObject,i)->ulValueLen);
    }

  return rv;
}
/* }}} */
/* {{{ CI_ObjVerifyObj */
CK_DEFINE_FUNCTION(CK_RV, CI_ObjVerifyObj)(
  CK_I_OBJ_PTR pObject
)
{
  CK_RV rv = CKR_OK;
  CK_ATTRIBUTE_PTR temp_attr = NULL_PTR;
  CK_ULONG i,found_count=0;

  /* forward.... */
  for(i=0 ; i< I_ATT_MAX_NUM ; i++)
    if( (temp_attr = CI_ObjLookup(pObject,i)) != NULL_PTR)
      {
	rv = CI_HashGetEntry(pObject->table, CK_I_attrib_xlate[i][1], (CK_VOID_PTR)(&temp_attr));
	if(rv != CKR_OK)
	  {
	    CI_VarLogEntry("CI_ObjVerifyObj", "element check for attribute %i failed", rv, 0,
			   CK_I_attrib_xlate[i][1]);
	    return rv; 
	  }
	found_count++;
      }
  
  if(found_count != pObject->table->entries)
    {
      rv = CKR_GENERAL_ERROR;
      CI_LogEntry("CI_ObjVerifyObj", "number of element check failed", rv, 0);
    }
    
  return rv;  
}
/* }}} */
/* {{{ CI_ObjInitialize */
/*
 * create the default object.
 *
 * to translate the attributes, two hash tables are used:
 * CK_IA_ck2internal: the CKA_ attribute is used as key and the 
 *                    CK_I_ATTRIB_INFO as date 
 * CK_IA_internal2ck: the CK_IA_ attribute is used as key and the CKA_ as date
 */
CK_DEFINE_FUNCTION(CK_RV, CI_ObjInitialize)(
)
{
  int i;
  CK_RV rv = CKR_OK;
  CK_I_ATTRIBUTE_INFO_PTR temp_info = NULL_PTR;

  CI_LogEntry("CI_ObjInitialize", "starting...", rv, 1);

  /* create the attribute translation table */
    rv= CI_InitHashtable(&CK_IA_ck2internal,100);
  if(rv != CKR_OK) { rv = CKR_HOST_MEMORY; goto obj_init_error; }

  /* load the table */
  for(i=0; i< I_ATT_MAX_NUM; i++)
    {
      temp_info = TC_calloc(1,sizeof(CK_I_ATTRIBUTE_INFO));
      if(temp_info == NULL_PTR)
	{ rv = CKR_HOST_MEMORY; goto obj_init_error; }
      
      temp_info->ObjTypes = CK_I_attributes[i];
      temp_info->IntAttrib = CK_I_attrib_xlate[i][0];
      
      CI_HashPutEntry(CK_IA_ck2internal, CK_I_attrib_xlate[i][1], 
		      (CK_VOID_PTR)temp_info);
      
      temp_info = NULL_PTR;
    }
	

obj_init_error:
  if(rv != CKR_OK)
    {
      if(CK_IA_ck2internal != NULL_PTR)
	{
	  CI_DestroyHashtable(CK_IA_ck2internal);
	  TC_free(CK_IA_ck2internal);
	  CK_IA_ck2internal = NULL_PTR;
	}
      if(temp_info != NULL_PTR)
	TC_free(temp_info);
    }

  CI_LogEntry("CI_ObjInitialize", "...finished", rv, 1);
  return rv;
}
/* }}} */
/* {{{ CI_ObjTemplateInit */
CK_DEFINE_FUNCTION(CK_RV, CI_ObjTemplateInit)(
  CK_I_OBJ_PTR CK_PTR ppObjectRef,
  CK_ATTRIBUTE_PTR pTemplate,
  CK_ULONG ulTemplateLen
)
{
  CK_RV rv = CKR_OK;
  CK_I_OBJ_PTR retval;

  if(*ppObjectRef != NULL_PTR) return rv;
  
  rv = CI_ObjCreateObj(&retval);
  if(rv != CKR_OK)
    {
      CI_LogEntry("CI_ObjTemplateInit", 
		  "creating object", rv, 0);
      return rv;
    }
  
  rv = CI_ObjReadTemplate(retval, pTemplate, ulTemplateLen);
  if(rv != CKR_OK)
    {
      CI_ObjDestroyObj(retval);
      CI_LogEntry("CI_ObjTemplateInit", 
		  "reading template", rv, 0);
      return rv;
    }

  *ppObjectRef = retval;

  return CKR_OK;
}
/* }}} */
/* {{{ CI_ObjFinalize */
CK_DEFINE_FUNCTION(CK_RV, CI_ObjFinalize)(
)
{
  CK_I_HASH_ITERATOR_PTR iter = NULL_PTR;
  CK_RV rv = CKR_OK;

  CI_LogEntry("CI_ObjFinalize","starting...",rv,0);

  /**** l�schen des Attribute Lookups *****/
  rv = CI_HashIterateInit(CK_IA_ck2internal,&iter);
  if(rv != CKR_OK) 
    {
      CI_LogEntry("CI_ObjFinalize", "failed to init hash iter (2)",rv,0);
      return rv;
    }

  for ( ; CI_HashIterValid(iter); )
    {
      CK_VOID_PTR val;

      /* free memory of object */
      rv = CI_HashIterateDeRef(iter, NULL_PTR, &val);
      if(rv != CKR_OK) 
	{
	  CI_LogEntry("CI_ObjFinalize","setting iter (2)",rv,0);
	  return rv;
	}

      TC_free(val);

      rv = CI_HashIterateDel(iter);
      if(rv != CKR_OK) 
	{
	  CI_LogEntry("CI_ObjFinalize","remove Hashentry (2)",rv,0);
	  return rv;
	}
    }
  /* free the iter */
  rv = CI_HashIterateDelete(iter);
  if(rv != CKR_OK) 
    {
      CI_LogEntry("CI_ObjFinalize","delete iter",rv,0);
      return rv;
    }
  
  /* free mem for obj system */
  CI_DestroyHashtable(CK_IA_ck2internal);
  CK_IA_ck2internal = NULL_PTR;
  
  return rv;
}
/* }}} */
/* {{{ CI_ObjAttribIter */
CK_DECLARE_FUNCTION(CK_RV, CI_ObjAttribIter)(
  CK_I_OBJ_PTR pObject,
  CK_I_HASH_ITERATOR_PTR CK_PTR pIterator
)
{
  return CI_HashIterateInit(pObject->table, pIterator);
}
/* }}} */ 
/* {{{ CI_ObjAttribCount */
CK_DECLARE_FUNCTION(CK_RV, CI_ObjAttribCount)(
  CK_I_OBJ_PTR pObject,
  CK_ULONG CK_PTR pCount
)
{
  if(pObject == NULL_PTR) return CKR_GENERAL_ERROR;
  if(pCount == NULL_PTR) return CKR_GENERAL_ERROR;

  *pCount = pObject->table->entries; 
  return CKR_OK;
}
/* }}} */ 
/* {{{ CI_ObjAttribIterDeRef */
CK_DECLARE_FUNCTION(CK_RV, CI_ObjAttribIterDeRef)(
  CK_I_HASH_ITERATOR_PTR pIterator,
  CK_ATTRIBUTE_PTR CK_PTR ppAttrib
)
{
  CK_ATTRIBUTE_PTR tmp_attrib;
  
  if(ppAttrib == NULL_PTR) return CKR_GENERAL_ERROR;
  *ppAttrib = TC_malloc(sizeof(CK_ATTRIBUTE));
  if(*ppAttrib == NULL_PTR) return CKR_HOST_MEMORY;

  CI_HashIterateDeRef(pIterator,NULL_PTR,(CK_VOID_PTR)&tmp_attrib);

  (*ppAttrib)->type = tmp_attrib->type;
  (*ppAttrib)->ulValueLen = tmp_attrib->ulValueLen;
  (*ppAttrib)->pValue = TC_malloc(tmp_attrib->ulValueLen);
  if((*ppAttrib)->pValue == NULL_PTR)
    {
      TC_free(*ppAttrib);
      return CKR_HOST_MEMORY;
    }

  memcpy((*ppAttrib)->pValue, tmp_attrib->pValue, tmp_attrib->ulValueLen);

  return CKR_OK;
}
/* }}} */

/* ### Object Container ### */
/* The object container guards the reference counting, 
 * as it contains wrappers for all operations on the containers.
 */
/* {{{ CI_ContainerAddObj */
/* Add an object to the container. */
CK_DEFINE_FUNCTION(CK_RV, CI_ContainerAddObj)(
  CK_I_HASHTABLE_PTR container,
  CK_ULONG key,
  CK_I_OBJ_PTR pObject
)
{
  CK_I_OBJ_PTR old_obj = NULL_PTR;
  CK_RV rv = CKR_OK;

  rv = CI_HashGetEntry(container, key, (CK_VOID_PTR)&old_obj);
  if((rv != CKR_OK) && (rv != CKR_ARGUMENTS_BAD))
    return rv;
    
  /* will overwrite the entry in the hash table */
  rv = CI_HashPutEntry(container, key, pObject);

  if(rv == CKR_OK) /* insert a success */
    {
      pObject->ref_count++;

      if(old_obj != NULL_PTR) /* there was an old object */
	{
	  old_obj->ref_count--;
	  if(old_obj->ref_count <= 0) /* this was the last reference */
	    CI_ObjDestroyObj(old_obj);
	}
    }
  
  return rv;
}
/* }}} */
/* {{{ CI_ContainerDelObj */
/* Delete an object from the container. */
CK_DEFINE_FUNCTION(CK_RV, CI_ContainerDelObj)(
  CK_I_HASHTABLE_PTR container,
  CK_ULONG key
)
{
  CK_I_OBJ_PTR old_obj = NULL_PTR;
  CK_RV rv = CKR_OK;

  rv = CI_HashGetEntry(container, key, (CK_VOID_PTR)&old_obj);
  if(rv != CKR_OK)
    return rv;

  rv = CI_HashRemoveEntry(container, key);
  if(rv != CKR_OK)
    {
      CI_LogEntry("CI_ContainerDelObj","could not remove object from container", rv ,0);
      return rv;
    }
    
  old_obj->ref_count--;
  if(old_obj->ref_count == 0) /* this was the last reference */
    {      
      CI_VarLogEntry("CI_ContainerDelObj","finaly removing object %d", rv ,2, key);
	
      rv = CI_ObjDestroyObj(old_obj);
      if(rv != CKR_OK)
	{
	  CI_LogEntry("CI_ContainerDelObj","could not destroy object", rv ,0);
	  return rv;
	}
    }
  
  return rv;
}
/* }}} */

/* Token Objects */
/* {{{ CI_TokenObjAdd */
CK_DEFINE_FUNCTION(CK_RV, CI_TokenObjAdd)(
  CK_I_SESSION_DATA_PTR  session_data,
  CK_OBJECT_HANDLE phObject, 
  CK_I_OBJ_PTR pNewObject
)
{
  CK_I_TOKEN_METHODS_PTR methods;
  CK_RV rv = CKR_OK;

  CI_LogEntry("CI_TokenObjAdd","starting...", rv ,2);

  if(CI_ObjLookup(pNewObject,CK_IA_TOKEN) == NULL_PTR)
    {
      rv = CKR_ARGUMENTS_BAD;
      CI_LogEntry("CI_TokenObjAdd","no token attribute", rv ,2);
      return rv; /* does not matter */
    }
  else
    if(*((CK_BBOOL CK_PTR)(CI_ObjLookup(pNewObject,CK_IA_TOKEN)->pValue)) != TRUE)
      {
	rv = CKR_ARGUMENTS_BAD;
	CI_VarLogEntry("CI_TokenObjAdd","not an token object (CK_IA_TOKEN: %d)", rv ,2,*((CK_BBOOL CK_PTR)CI_ObjLookup(pNewObject,CK_IA_TOKEN)));
	return rv; /* does not matter */
      }
  
  methods = SESS_METHODS(pNewObject->session);
  if(methods == NULL_PTR)
    {
      rv = CKR_TOKEN_NOT_PRESENT;
      CI_LogEntry("CI_TokenObjAdd","methods not initialized", rv ,2);
      return rv;
    }

  if(methods->TokenObjAdd == NULL_PTR)
    {
      rv = CKR_FUNCTION_NOT_SUPPORTED;
      CI_LogEntry("CI_TokenObjAdd","method TokenObjAdd not supported.", rv ,2);
      return rv;
    }

  rv = (methods->TokenObjAdd)(session_data,phObject,pNewObject);

  CI_LogEntry("CI_TokenObjAdd","...complete", rv ,2);

  return rv;
}
/* }}} */
/* {{{ CI_TokenObjDelete */
CK_DEFINE_FUNCTION(CK_RV, CI_TokenObjDelete)(
  CK_I_SESSION_DATA_PTR session_data,
  CK_OBJECT_HANDLE hObject 
)
{
  CK_I_TOKEN_METHODS_PTR methods;
  CK_I_OBJ_PTR obj;

  methods = SESS_METHODS(session_data);
  if(methods->TokenObjDelete == NULL_PTR)
    return CKR_FUNCTION_NOT_SUPPORTED;

  /* ensure that the object is an token object at all */
  CI_ReturnObj(session_data, hObject, &obj);

  if((CI_ObjLookup(obj, CK_IA_TOKEN) != NULL_PTR) &&
     ( *((CK_BBOOL CK_PTR) (CI_ObjLookup(obj, CK_IA_TOKEN)->pValue)) != TRUE) )
    return CKR_NO_TOKEN_OBJ; /* This is not a token object */

  return (methods->TokenObjDelete)(session_data,hObject);
}
/* }}} */
/* {{{ CI_TokenObjCommit */
/** commits changes of the object to the database. */
CK_DEFINE_FUNCTION(CK_RV, CI_TokenObjCommit)(
  CK_I_SESSION_DATA_PTR session_data,
  CK_OBJECT_HANDLE phObject
 )
{
  CK_I_TOKEN_METHODS_PTR methods;
  CK_I_OBJ_PTR object;


  methods = SESS_METHODS(session_data);
  if(methods->TokenObjCommit == NULL_PTR)
    return CKR_FUNCTION_NOT_SUPPORTED;

  /* TODO: A paranoia check that the object is valid */
  CI_ReturnObj(session_data,phObject,&object);

  return (methods->TokenObjCommit)(session_data, 
				   phObject, object);  
}



#define OBJECT_DEFAULT_LOAD 1
#include "obj_defaults.h"
#undef OBJECT_DEFAULT_LOAD
/* }}} */
/* {{{ CI_ObjCompleteWithDefaults */
CK_DEFINE_FUNCTION(CK_RV, CI_ObjCompleteWithDefaults)
( 
 CK_I_OBJ_PTR pObject 
)
{
  CK_RV rv = CKR_OK;
  CK_ATTRIBUTE_PTR pObjectClassAttribute;
  CK_ATTRIBUTE_PTR pCertificateType;
  CK_ATTRIBUTE_TYPE ia_type;
  CK_I_OBJ_PTR pDefaultObj;

  CI_TranslateAttribute(CKA_CLASS, &ia_type);
  pObjectClassAttribute = CI_ObjLookup(pObject,ia_type);
  if (pObjectClassAttribute == NULL)
  {
    rv = CKR_TEMPLATE_INCOMPLETE;
    CI_VarLogEntry("C_GetAttributeValue",
    "Invalid Object", rv, 0);
    return rv;
  }

  /* Set the default common attributes (spec2.1 �9.2)*/ 
  rv = CI_ObjCreateObj(&pDefaultObj);
  if(rv != CKR_OK) 
	{
	  CI_LogEntry("CI_ObjCompleteWithDefaults", "creating default object", rv, 0);
	  return rv;
	}
      
  rv = CI_ObjReadTemplate(pDefaultObj, CK_I_obj_attr_defaults_common, CK_I_OBJ_ATTR_DEFAULTS_COMMON_SIZE);
  if(rv != CKR_OK) 
	{
	  CI_LogEntry("CI_ObjCompleteWithDefaults", "reading template", rv, 0);
	  return rv;
	}

  rv = CI_ObjMergeObj(pObject, pDefaultObj, FALSE); /* copy only attribs not already set */
  if(rv != CKR_OK) 
  {
    CI_LogEntry("CI_ObjCompleteWithDefaults", "merging objects", rv, 0);
    return rv;
  }

  rv = CI_ObjDestroyObj(pDefaultObj);
  if(rv != CKR_OK) 
  {
    CI_LogEntry("CI_ObjCompleteWithDefaults", "destroying object", rv, 0);
    return rv;
  }
  pDefaultObj = NULL;

  switch (*((CK_OBJECT_CLASS CK_PTR)pObjectClassAttribute->pValue))
  {
  case CKO_DATA:
    {
      /* data object default attributes (spec2.1 �9.3)*/
      rv = CI_ObjCreateObj(&pDefaultObj);
      if(rv != CKR_OK) 
      {
        CI_LogEntry("CI_ObjCompleteWithDefaults", "creating default object", rv, 0);
        return rv;
      }
      
      rv = CI_ObjReadTemplate(pDefaultObj, CK_I_obj_attr_defaults_data, CK_I_OBJ_ATTR_DEFAULTS_DATA_SIZE);
      if(rv != CKR_OK) 
      {
        CI_LogEntry("CI_ObjCompleteWithDefaults", "reading template", rv, 0);
        return rv;
      }
      
      rv = CI_ObjMergeObj(pObject, pDefaultObj, FALSE); /* copy only attribs not already set */
      if(rv != CKR_OK) 
      {
        CI_LogEntry("CI_ObjCompleteWithDefaults", "merging objects", rv, 0);
        return rv;
      }
      
      rv = CI_ObjDestroyObj(pDefaultObj);
      if(rv != CKR_OK) 
      {
        CI_LogEntry("CI_ObjCompleteWithDefaults", "destroying object", rv, 0);
        return rv;
      }
      pDefaultObj = NULL;
      break;
    }

  case CKO_CERTIFICATE:
    {
      /* common certificate object default attributes (spec2.1 �9.5) */
      /* no common default attributes defined by spec */

      CI_TranslateAttribute(CKA_CERTIFICATE_TYPE, &ia_type);
      pCertificateType = CI_ObjLookup(pObject,ia_type);
      if (pCertificateType == NULL)
      {
        rv = CKR_TEMPLATE_INCOMPLETE;
        CI_VarLogEntry("C_GetAttributeValue",
          "Invalid Object", rv, 0);
        return rv;
      }
      
      switch (*((CK_CERTIFICATE_TYPE CK_PTR)pCertificateType->pValue))
      {
      case CKC_X_509: /* x.509 certificate object default attributes (spec 2.1 �9.4.1) */
        {
          rv = CI_ObjCreateObj(&pDefaultObj);
          if(rv != CKR_OK) 
          {
            CI_LogEntry("CI_ObjCompleteWithDefaults", "creating default object", rv, 0);
            return rv;
          }
          
          rv = CI_ObjReadTemplate(pDefaultObj, CK_I_obj_attr_defaults_certificate_x509, CK_I_OBJ_ATTR_DEFAULTS_CERTIFICATE_X509_SIZE);
          if(rv != CKR_OK) 
          {
            CI_LogEntry("CI_ObjCompleteWithDefaults", "reading template", rv, 0);
            return rv;
          }
          
          rv = CI_ObjMergeObj(pObject, pDefaultObj, FALSE); /* copy only attribs not already set */
          if(rv != CKR_OK) 
          {
            CI_LogEntry("CI_ObjCompleteWithDefaults", "merging objects", rv, 0);
            return rv;
          }
          
          rv = CI_ObjDestroyObj(pDefaultObj);
          if(rv != CKR_OK) 
          {
            CI_LogEntry("CI_ObjCompleteWithDefaults", "destroying object", rv, 0);
            return rv;
          }
          pDefaultObj = NULL;
          break;
        }// case CKC_X_509
      default: 
        {
          rv = CKR_TEMPLATE_INCONSISTENT;
          CI_LogEntry("CI_ObjCompleteWithDefaults", "depatch object type", rv, 0);
          return rv;
        }
      } // switch
      break;
    } // case
     
  case CKO_PUBLIC_KEY:
  case CKO_PRIVATE_KEY:
  case CKO_SECRET_KEY:
    {
      /* common key object default attributes (spec2.1 �9.5) */
      rv = CI_ObjCreateObj(&pDefaultObj);
      if(rv != CKR_OK) 
      {
        CI_LogEntry("CI_ObjCompleteWithDefaults", "creating default object", rv, 0);
        return rv;
      }
      
      rv = CI_ObjReadTemplate(pDefaultObj, CK_I_obj_attr_defaults_key_common, CK_I_OBJ_ATTR_DEFAULTS_KEY_COMMON_SIZE);
      if(rv != CKR_OK) 
      {
        CI_LogEntry("CI_ObjCompleteWithDefaults", "reading template", rv, 0);
        return rv;
      }
      
      rv = CI_ObjMergeObj(pObject, pDefaultObj, FALSE); /* copy only attribs not already set */
      if(rv != CKR_OK) 
      {
        CI_LogEntry("CI_ObjCompleteWithDefaults", "merging objects", rv, 0);
        return rv;
      }
      
      rv = CI_ObjDestroyObj(pDefaultObj);
      if(rv != CKR_OK) 
      {
        CI_LogEntry("CI_ObjCompleteWithDefaults", "destroying object", rv, 0);
        return rv;
      }
      pDefaultObj = NULL;
    
      switch (*((CK_OBJECT_CLASS CK_PTR)pObjectClassAttribute->pValue))
      {
      case CKO_PUBLIC_KEY:
        {
          /* common public key default attributes (spec2.1 �9.6) */
          rv = CI_ObjCreateObj(&pDefaultObj);
          if(rv != CKR_OK) 
          {
            CI_LogEntry("CI_ObjCompleteWithDefaults", "creating default object", rv, 0);
            return rv;
          }
          
          rv = CI_ObjReadTemplate(pDefaultObj, CK_I_obj_attr_defaults_key_public_common, CK_I_OBJ_ATTR_DEFAULTS_KEY_PUBLIC_COMMON_SIZE);
          if(rv != CKR_OK) 
          {
            CI_LogEntry("CI_ObjCompleteWithDefaults", "reading template", rv, 0);
            return rv;
          }
          
          rv = CI_ObjMergeObj(pObject, pDefaultObj, FALSE); /* copy only attribs not already set */
          if(rv != CKR_OK) 
          {
            CI_LogEntry("CI_ObjCompleteWithDefaults", "merging objects", rv, 0);
            return rv;
          }
          
          rv = CI_ObjDestroyObj(pDefaultObj);
          if(rv != CKR_OK) 
          {
            CI_LogEntry("CI_ObjCompleteWithDefaults", "destroying object", rv, 0);
            return rv;
          }
          pDefaultObj = NULL;
          break;
        } // case CKO_PUBLIC_KEY
        
      case CKO_PRIVATE_KEY:
        {
          /* common private key default attributes (spec2.1 �9.7) */
          rv = CI_ObjCreateObj(&pDefaultObj);
          if(rv != CKR_OK) 
          {
            CI_LogEntry("CI_ObjCompleteWithDefaults", "creating default object", rv, 0);
            return rv;
          }
          
          rv = CI_ObjReadTemplate(pDefaultObj, CK_I_obj_attr_defaults_key_private_common, CK_I_OBJ_ATTR_DEFAULTS_KEY_PRIVATE_COMMON_SIZE);
          if(rv != CKR_OK) 
          {
            CI_LogEntry("CI_ObjCompleteWithDefaults", "reading template", rv, 0);
            return rv;
          }
          
          rv = CI_ObjMergeObj(pObject, pDefaultObj, FALSE); /* copy only attribs not already set */
          if(rv != CKR_OK) 
          {
            CI_LogEntry("CI_ObjCompleteWithDefaults", "merging objects", rv, 0);
            return rv;
          }
          
          rv = CI_ObjDestroyObj(pDefaultObj);
          if(rv != CKR_OK) 
          {
            CI_LogEntry("CI_ObjCompleteWithDefaults", "destroying object", rv, 0);
            return rv;
          }
          pDefaultObj = NULL;
          break;
        } // case CKO_PRIVATE_KEY
      
      
      case CKO_SECRET_KEY:
        {
          /* common secret key default attributes (spec2.1 �9.8) */
          rv = CI_ObjCreateObj(&pDefaultObj);
          if(rv != CKR_OK) 
          {
            CI_LogEntry("CI_ObjCompleteWithDefaults", "creating default object", rv, 0);
            return rv;
          }
          
          rv = CI_ObjReadTemplate(pDefaultObj, CK_I_obj_attr_defaults_key_secret_common, CK_I_OBJ_ATTR_DEFAULTS_KEY_SECRET_COMMON_SIZE);
          if(rv != CKR_OK) 
          {
            CI_LogEntry("CI_ObjCompleteWithDefaults", "reading template", rv, 0);
            return rv;
          }
          
          rv = CI_ObjMergeObj(pObject, pDefaultObj, FALSE); /* copy only attribs not already set */
          if(rv != CKR_OK) 
          {
            CI_LogEntry("CI_ObjCompleteWithDefaults", "merging objects", rv, 0);
            return rv;
          }
          
          rv = CI_ObjDestroyObj(pDefaultObj);
          if(rv != CKR_OK) 
          {
            CI_LogEntry("CI_ObjCompleteWithDefaults", "destroying object", rv, 0);
            return rv;
          }
          pDefaultObj = NULL;
          break;
        } // case CKO_SECRET_KEY
      } // switch
      break;
    } // case keys
  default: 
    {
      rv = CKR_TEMPLATE_INCONSISTENT;
      CI_LogEntry("CI_ObjCompleteWithDefaults", "depatch object type", rv, 0);
      return rv;
    }
  } // switch
  return rv;
}

/*
 * Local variables:
 * folded-file: t
 * end:
 */
