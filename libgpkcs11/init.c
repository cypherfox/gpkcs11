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
 * NAME:        init.c
 * SYNOPSIS:    -
 * DESCRIPTION: -
 * FILES:       -
 * SEE/ALSO:    -
 * AUTHOR:      lbe
 * BUGS:        -
 */
static char RCSID[]="$Id$";
const char* Version_init_c(){return RCSID;}

#ifndef CK_I_library_build
#define CK_I_library_build
#endif

#include "internal.h"

#ifdef CK_Win32
# include <windows.h>
# include <winuser.h>
#elif CK_GENERIC
# include <dlfcn.h>
# ifdef HAVE_UNISTD_H
#  include <unistd.h>
# endif
# include <signal.h>

# ifdef HAVE_PURIFY
#  include <purify.h>
# endif /* HAVE_PURIFY */
#endif /* !CK_Win32 */

#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <assert.h>

#include "mutex.h"
#include "error.h"
#include "utils.h"
#include "init.h"
#include "objects.h"
#include "slot.h"

/* more stupid Windowisms */
# undef CreateMutex

CK_I_EXT_FUNCTION_LIST CK_I_ext_functions;

CK_ULONG CK_I_global_flags;

static CK_CHAR_PTR CK_I_config_fname = NULL_PTR; /* name of the init file */

/* {{{ C_Initialize */
CK_DEFINE_FUNCTION(CK_RV, C_Initialize)(
 CK_VOID_PTR pInitArgs
)
{
  CK_C_INITIALIZE_ARGS_PTR iargs = NULL_PTR;
  CK_RV rv = CKR_OK;
  int i;

  CI_LogEntry("C_Initialize", "starting...", rv, 1);
  CI_CodeFktEntry("C_Initialize", "%p", 
		  pInitArgs);

  /* make sure we have not been initialized before */
  if ((CK_I_global_flags & CK_IGF_INITIALIZED)) 
    {
      rv = CKR_CRYPTOKI_ALREADY_INITIALIZED;
      CI_LogEntry("C_Initialize", "check initialization", rv, 1);
      return rv;
    }

  /* get all them signal back from netscape */
  /* to be activated in time of need B-) */
#if defined(CK_GENERIC) && 0
  CI_GetSignals();
#endif /* CK_GENERIC */

  /* initialize all tokens */
  CI_TokenInit();

  if(pInitArgs == NULL_PTR)
    {
      /* assign default values */
      CK_I_ext_functions._CreateMutex  = &I_CreateMutex;
      CK_I_ext_functions._DestroyMutex = &I_DestroyMutex;
      CK_I_ext_functions._LockMutex    = &I_LockMutex;
      CK_I_ext_functions._UnlockMutex  = &I_UnlockMutex;
      
      rv = CI_ObjInitialize();
      if(rv != CKR_OK) 
	{
	  CI_LogEntry("C_Initialize",
		      "failed to initialize global objects list", rv, 0);
	  return rv;
	}
      /* Initialize the session hashtable : session_table (else only
       * initialized when a session is created) */
      rv = CI_InitHashtable(&CK_I_app_table.session_table,
			    CK_I_OBJ_INITIAL_SIZE);
      if(rv != CKR_OK)
	{
	  CI_LogEntry("C_Initialize", "creating application session list",
		      rv, 0);
	  return rv; 
	}
      
      /* Initalization successfull*/
      CK_I_global_flags |= CK_IGF_INITIALIZED;
      {
	CI_LogEntry("C_Initialize", "...complete", rv, 1);
	return rv;
      }
    }
  
  iargs = (CK_C_INITIALIZE_ARGS_PTR)pInitArgs;

#if 0  
  /* activate if the library starts to use threads, and needs to spawn them itself */
  if(iargs.flags & CKF_LIBRARY_CANT_CREATE_OS_THREADS)
    /* caller of library does not allow the use of threads, but we need it */
    return CKR_NEED_TO_CREATE_THREADS;
#endif

  /* pReseved must be NULL_PTR */
  if(iargs->pReserved != NULL_PTR)
    {
      rv = CKR_ARGUMENTS_BAD;
      CI_LogEntry("C_Initialize", "checking Parameters", rv, 1);
      return rv;
    }

  /* Check that either all or none of the mutex functions are supplied */
  i=0;
  (iargs->CreateMutex == NULL_PTR)?i:i++;
  (iargs->DestroyMutex == NULL_PTR)?i:i++;
  (iargs->LockMutex == NULL_PTR)?i:i++;
  (iargs->UnlockMutex == NULL_PTR)?i:i++;
  if((i!=0) && (i!=4))
    {
      rv = CKR_ARGUMENTS_BAD;
      CI_LogEntry("C_Initialize", "checking Mutex Fkt-Pointers", rv, 1);
      return rv;
    }

  /* Determine which type of multi-thread access we have */
  if(i==0) /* functions are not supplied */
    { 
      if(iargs->flags & CKF_OS_LOCKING_OK)
	{
	  /* 2. use default mutex functions suplies by library/OS */
	  CK_I_ext_functions._CreateMutex  = &I_CreateMutex;
	  CK_I_ext_functions._DestroyMutex = &I_DestroyMutex;
	  CK_I_ext_functions._LockMutex    = &I_LockMutex;
	  CK_I_ext_functions._UnlockMutex  = &I_UnlockMutex;
	}
      else
	/* 1. There will be no multiple thread access. */
	CK_I_global_flags |= CK_IGF_SINGLE_THREAD;
    }
  else /* functions are supplied */
    {
#if 0
      /* there is no difference at the moment so we skip the decision */
      if(iargs->flags & CKF_OS_LOCKING_OK)
	{
	  /* 4. use either the default ones or the supplied ones */
	  /* we use the suplied ones */
	}
      else
	{
	  /* 3. use the supplied ones */
	}
#endif
      CK_I_ext_functions._CreateMutex  = iargs->CreateMutex;
      CK_I_ext_functions._DestroyMutex = iargs->DestroyMutex;
      CK_I_ext_functions._LockMutex    = iargs->LockMutex;
      CK_I_ext_functions._UnlockMutex  = iargs->UnlockMutex;      
    }

  rv = CI_ObjInitialize();
  if(rv != CKR_OK) 
    {
      CI_LogEntry("C_Initialize",
                  "failed to initialize global objects list", rv, 0);
      return rv;
    }

  /* Initalization successfull*/
  CK_I_global_flags |= CK_IGF_INITIALIZED;


  CI_LogEntry("C_Initialize", "...complete", rv, 1);
  return CKR_OK;
}
/* }}} */
/* {{{ C_Finalize */
/* C_Finalize indicates that an application is done with the
 * Cryptoki library. */
CK_DEFINE_FUNCTION(CK_RV, C_Finalize)(
        CK_VOID_PTR pReserved
)
{
  CK_RV rv = CKR_OK;
  CK_SLOT_ID_PTR slot_list =NULL_PTR;
  CK_ULONG slot_num =0;
  CK_ULONG i;

  CI_LogEntry("C_Finalize", "starting...", rv, 1);

    /* make sure we are initialized */
  if (!(CK_I_global_flags & CK_IGF_INITIALIZED)) 
    return CKR_CRYPTOKI_NOT_INITIALIZED;

  if(pReserved != NULL_PTR)
    return CKR_ARGUMENTS_BAD;

  /* there can only be sessions on slot that have token */
  rv = C_GetSlotList(TRUE,NULL_PTR,&slot_num);
  if(rv != CKR_OK)
    {
      CI_LogEntry("C_Finalize", "getting count of slots", rv, 0);
      return rv;
    }

  slot_list = TC_malloc(slot_num*sizeof(CK_SLOT_ID_PTR));
  if( slot_list == NULL_PTR)
    {
      rv = CKR_HOST_MEMORY;
      CI_LogEntry("C_Finalize", "getting space for slot list", rv, 0);
      return rv;
    }

  rv = C_GetSlotList(TRUE,slot_list,&slot_num);
  if(rv != CKR_OK)
    {
      CI_LogEntry("C_Finalize", "getting slots list", rv, 0);
      return rv;
    }
  
  for(i =0 ; i< slot_num ; i++)
    {
      /* Deallocate all Sessions */
      rv = C_CloseAllSessions(slot_list[i]);
      if(rv != CKR_OK)
	{
	  CI_VarLogEntry("C_Finalize", "removing all sessions in slot %i", rv, 0,
			 slot_list[i]);
	  return rv;
	}

      /* Call CI_FinalizeToken in all Tokens */
      rv = CI_RemoveToken(slot_list[i]);
      if(rv != CKR_OK)
	{
	  CI_VarLogEntry("C_Finalize", "finalizing token in slot %i", rv, 0,
			 slot_list[i]);
	  return rv;
	}
    }
  TC_free(slot_list);

  CI_DestroyHashtable(CK_I_app_table.session_table);
  CK_I_app_table.session_table = NULL_PTR;

  /**** assert that there are no remaining objects ****/
  rv = CI_ObjFinalize();
  if(rv != CKR_OK) 
    {
       CI_LogEntry("CI_InternalCloseSession",
		  "failed to clear objects",rv,0);
      return rv;
    }

#ifdef CK_GENERIC
  /* The call for the Win32 code will be done from DllMain() */
  rv = CI_UnloadDlls();
  if(rv != CKR_OK) 
    {
       CI_LogEntry("C_Finalize",
		  "failed to unload Dlls",rv,0);
      return rv;
    }
#endif  

  CK_I_global_flags ^= CK_IGF_INITIALIZED;
  CI_LogEntry("C_Finalize", "...complete", rv, 1);
  return rv;
}
/* }}} */
/* {{{ C_InitToken */
CK_DEFINE_FUNCTION(CK_RV, C_InitToken)
(
  CK_SLOT_ID     slotID,    /* ID of the token's slot */
  CK_CHAR_PTR    pPin,      /* the SO's initial PIN */
  CK_ULONG       ulPinLen,  /* length in bytes of the PIN */
  CK_CHAR_PTR    pLabel     /* 32-byte token label (blank padded) */
)
{
  CK_RV rv = CKR_OK;
  CK_I_SLOT_DATA_PTR slot_data = NULL_PTR;
  
  CI_LogEntry("C_InitToken", "starting...", rv, 1);

  /* make sure we are initialized */
  if (!(CK_I_global_flags & CK_IGF_INITIALIZED)) 
    return CKR_CRYPTOKI_NOT_INITIALIZED;

  rv = CI_GetSlotData(slotID,&slot_data);
  if(rv != CKR_OK)
    return rv;

  if(slot_data->methods->InitToken != NULL_PTR)
    rv = (slot_data->methods->InitToken)(pPin, ulPinLen, pLabel);

  CI_LogEntry("C_InitToken", "...complete", rv, 1);
  
  return rv;
}
/* }}} */

/* {{{ CI_FindConfFile */
CK_DEFINE_FUNCTION(CK_RV, CI_FindConfFile)(
)
{
  CK_RV rv = CKR_OK;              /* function return value */
  CK_ULONG level;
  
  CI_LogEntry("CI_FindConfFile", "starting...", rv, 1);

  /*******************************************************************
   *         Find Config-File                                        *
   *******************************************************************/
  /* check environment variable GPKCS11_CONF */
  CK_I_config_fname = getenv("GPKCS11_CONF");
  if(CK_I_config_fname == NULL_PTR)
    {
      /* Architecture dependent seach for filename. */
#if defined (CK_Win32)
      /* {{{ filename for Win32 */

      /* look for <WINDOWS-VERZEICHNIS>\tcpkcs11.cnf */
      {
	CK_CHAR_PTR system_dir = NULL_PTR;
	UINT retlen;
	
	system_dir = TC_malloc(sizeof(CK_CHAR) * MAX_PATH);
	if( system_dir == NULL_PTR )
	  {
	    rv = CKR_HOST_MEMORY;
	    CI_LogEntry("CI_FindConfFile", "Allocating Buffer Space", 
			rv, 0); 
	    return rv;
	  }

	retlen =GetWindowsDirectory(system_dir, MAX_PATH);
	if(retlen == 0 )
	  {
	    rv = CKR_GENERAL_ERROR;
	    CI_VarLogEntry("CI_FindConfFile", 
			   "Retrieving Windows System Directory GetLastError(): %i", 
			   rv, 0, GetLastError()); 
	    return rv;
	  }
	
	if(retlen > MAX_PATH)
	  {
	    /* realloc würde u.U. den Block erst moven */
	    TC_free(system_dir); 
	    system_dir = TC_malloc(sizeof(CK_CHAR) * retlen);
	    if( system_dir == NULL_PTR )
	      {
		rv = CKR_HOST_MEMORY;
		CI_LogEntry("CI_FindConfFile", "Allocating Buffer Space", 
			    rv, 0); 
		return rv;
	      }

	    GetSystemDirectory(system_dir , retlen);

	    if(retlen == 0 )
	      {
		rv = CKR_GENERAL_ERROR;
		CI_VarLogEntry("CI_FindConfFile", 
			       "Retrieving Windows System Directory GetLastError(): %i", 
			       rv, 0, GetLastError()); 
		TC_free(system_dir); 		
		return rv;
	      }
	  }
	
	
	/* directory + CK_I_conf_filename + Seperator + \0 */
	CK_I_config_fname = TC_malloc(sizeof(CK_CHAR) * (strlen(system_dir) 
					     + strlen(CK_I_WINDOWS_RC_FNAME) + 1 + 1));
	if( CK_I_config_fname == NULL_PTR )
	  {
	    rv = CKR_HOST_MEMORY;
	    CI_LogEntry("CI_FindConfFile", "Allocating Buffer Space", 
			rv, 0); 
	    TC_free(system_dir); 
	    return rv;
	  }
	
	strcpy(CK_I_config_fname,system_dir);
	strcat(CK_I_config_fname,"\\");
	strcat(CK_I_config_fname,CK_I_WINDOWS_RC_FNAME);
	
	TC_free(system_dir);
      }

      /* }}} */
#else
      /* {{{ filename for Solaris and Linux*/

      {
	int fdes;
	CK_CHAR_PTR home_dir = NULL_PTR;
	
	/* look for /etc/gpkcs11rc or $HOME/.gpkcs11.rc */
	CK_I_config_fname = TC_malloc(sizeof(CK_CHAR) * ( strlen("/etc/") + 
					   strlen(CK_I_UNIX_RC_FNAME) + 1 ));
	if( CK_I_config_fname == NULL_PTR )
	  {
	    rv = CKR_HOST_MEMORY;
	    CI_LogEntry("CI_FindConfFile", "Allocating Buffer Space", 
			rv, 0); 
	    return rv;
	  }
	
	strcpy(CK_I_config_fname, "/etc/");
	strcat(CK_I_config_fname, CK_I_UNIX_RC_FNAME);
	
	CI_VarLogEntry("CI_FindConfFile", "trying %s", rv, 1,CK_I_config_fname);
	if( (fdes = open(CK_I_config_fname, O_RDWR)) == -1)
	  {
	    if(errno != ENOENT)  /* Datei existiert nur einfach nicht? */
	      {
		rv = CKR_GENERAL_ERROR;
		CI_VarLogEntry("CI_FindConfFile", 
			       "opening file '%s': %s", 
			       rv, 0, CK_I_config_fname, strerror(errno)); 
		return rv;
	      }
	    else
	      {
		TC_free(CK_I_config_fname);
		CK_I_config_fname = NULL_PTR; /* nicht gefunden */
	      }
	  }
	else
	  close(fdes);
	
	/* an entry in the home directory will override the selection */
	if((home_dir = getenv("HOME")) != NULL_PTR)
	  {
	    /* wir brauchen neuen speicher: home_dir + /. + . + CK_I_UNIX_RC_FNAME + \0 */
	    CK_CHAR_PTR tmp_name = TC_malloc(sizeof(CK_CHAR) * 
					     (strlen(home_dir)
					      + strlen(CK_I_UNIX_RC_FNAME)
					      + strlen("/.") + 1 + 1)); 
	    if( tmp_name == NULL_PTR )
	      {
		rv = CKR_HOST_MEMORY;
		CI_LogEntry("CI_FindConfFile", "Allocating Buffer Space", 
			    rv, 0); 
		return rv;
	      }
	    
	    strcpy(tmp_name, home_dir);
	    strcat(tmp_name, "/.");
	    strcat(tmp_name, CK_I_UNIX_RC_FNAME);
	    
	    CI_VarLogEntry("CI_FindConfFile", "trying %s", rv, 1,tmp_name);
	    if(( (fdes = open(tmp_name, O_RDWR)) == -1) &&
	       (errno != ENOENT))  /* Datei existiert nur einfach nicht? */
	      {
		rv = CKR_GENERAL_ERROR;
		CI_VarLogEntry("CI_FindConfFile", 
			       "opening file '%s': %s", 
			       rv, 0, tmp_name, strerror(errno)); 
		return rv;
	      }
	    
	    if(fdes != -1)
	      {
		if(CK_I_config_fname != NULL_PTR) 
		  TC_free(CK_I_config_fname);
		CK_I_config_fname = tmp_name;
		tmp_name = NULL_PTR;
		CI_VarLogEntry("CI_FindConfFile", "using '%s'", rv, 1,CK_I_config_fname);
		close(fdes);
	      }
	    else
	      {
		CI_VarLogEntry("CI_FindConfFile", "could not open '%s'", rv, 1,tmp_name);
		if(tmp_name != NULL_PTR) TC_free(tmp_name);
	      }
	  }
	
	/* wenn die Datei nicht gefunden ist auf das lokale Verzeichniss hoffen */
	if(CK_I_config_fname == NULL_PTR)
	  {
	    CK_CHAR_PTR curr_dir = getcwd(NULL_PTR, 256/* will be ignored! */);
	    /* alloc speicher: pwd + / + gpkcs11.rc + \0 */
	    CK_I_config_fname = TC_malloc(sizeof(CK_CHAR) * (strlen(CK_I_UNIX_RC_FNAME)
						 + strlen(curr_dir) +1 + 1));
	    if( CK_I_config_fname == NULL_PTR )
	      {
		rv = CKR_HOST_MEMORY;
		CI_LogEntry("CI_FindConfFile", "Allocating Buffer Space", 
			    rv, 0); 
	      }
	    
	    strcpy(CK_I_config_fname, curr_dir);
	    TC_free(curr_dir);
	    strcat(CK_I_config_fname, "/");
	    strcat(CK_I_config_fname, CK_I_UNIX_RC_FNAME);
	    
	    CI_VarLogEntry("CI_FindConfFile", "settling for %s", rv, 1,CK_I_config_fname);
	  }
      }

      /* }}} */
#endif
    }

  /*******************************************************************
   *         Get Logging File                                        *
   *******************************************************************/
  {
    CK_CHAR_PTR buf;
    
    CI_LogEntry("CI_FindConfFile", "trying Profile read", rv, 1);
    rv=CI_GetConfigString(NULL_PTR,"LoggingFile",&buf);
    if(rv == CKR_OK)
      {
	CI_SetLoggingFile(buf);
	free(buf);
      }
    else
      {
	/* if there is not special logging-file we can skip this step */
	/* and use the default                                        */
      }
  } 
  
  /*******************************************************************
   *         Get Loging Level                                        *
   *******************************************************************/
  {
    CK_CHAR_PTR buf;
    
    CI_LogEntry("CI_FindConfFile", "trying Profile read", rv, 1);
    rv=CI_GetConfigString(NULL_PTR,"LoggingLevel",&buf);
    if(rv != CKR_OK)
      return rv;
  
    level = strtoul(buf,NULL,10);
    CI_SetLogingLevel(level);
    free(buf);
  }  
 
  /*******************************************************************
   *         Get Mem-Logging File                                    *
   *******************************************************************/
  {
    CK_CHAR_PTR buf;
    
    CI_LogEntry("CI_FindConfFile", "trying Profile read", rv, 1);
    rv=CI_GetConfigString(NULL_PTR,"MemLoggingFile",&buf);
    if(rv == CKR_OK)
      {
	TC_SetMemLoggingFile(buf);
	free(buf);
      }
    else
     {
       /* if there is not special mem-logging-file we can skip this step */
       /* and use the default                                            */
     }
  }  
  
  /*******************************************************************
   *         Get Extra Library Path                                  *
   *******************************************************************/
  {
    CK_CHAR_PTR path_string = NULL_PTR; /* holder for constructed path */
    CK_C_CHAR_PTR orig_path = NULL_PTR;   /* holder for original path */
    CK_CHAR_PTR xtra_path = NULL_PTR; /* path read from the config file */
#if defined(CK_GENERIC)
    CK_C_CHAR_PTR path_var_name ="LD_LIBRARY_PATH";
    CK_C_CHAR_PTR path_sep = ":";
#else /* Windows */
    CK_C_CHAR_PTR path_var_name ="PATH";
    CK_C_CHAR_PTR path_sep = ";";
#endif
    
    /* Set extra dll path (Has to be set before we load the first token) */
    CI_VarLogEntry("CI_FindConfFile", "starting xtra path read: fname: %s", rv, 1,CK_I_config_fname);

    rv=CI_GetConfigString(NULL_PTR,"ExtraLibraryPath",&xtra_path);
    if(rv != CKR_OK)
      {
	/* if there is not extra path we can skip this step */
	return CKR_OK;
      }
    
    CI_VarLogEntry("CI_FindConfFile", "done xtra lib path read. PATH: %s", 
		   rv, 1,xtra_path);
    
    orig_path = getenv(path_var_name);
    
    if(orig_path == NULL_PTR)
      {
	/* no original path. only put the new path there */
	path_string = xtra_path;
      }
    else
      {
	/* combine the old and the new */
	
	/* (orig +':' +config+ '\0') */
	path_string = TC_malloc(strlen(orig_path) + 1 +
				strlen(xtra_path) + 1);
	if(path_string == NULL_PTR)
	  {
	    rv = CKR_HOST_MEMORY;
	    CI_LogEntry("CI_FindConfFile", "allocating memory for path_string", rv , 0);
	    return rv;
	  }
	sprintf(path_string,"%s%s%s",xtra_path,path_sep,orig_path);
	TC_free(xtra_path); /* has been copied into path_string */
      }
    
    /* This memory we will never get back. putenv is total lunacy */
    {
      CK_CHAR_PTR in_val = TC_malloc(strlen(path_var_name)+1+strlen(path_string)+1);
      sprintf(in_val,"%s=%s",path_var_name,path_string);
      if(putenv(in_val))
	{
	  rv = CKR_GENERAL_ERROR;
	  CI_VarLogEntry("CI_FindConfFile", "putenv(%s) failed", rv, 1,in_val);
	  return rv;
	}
      CI_VarLogEntry("CI_FindConfFile", "putenv(%s)", rv, 1,in_val);
    }		
    TC_free(path_string); /* has been copied into in_val */
  } /* end block for reading extra path */
  
  CI_LogEntry("CI_FindConfFile", "...done", rv, 1);
  return rv;
}
/* }}} */
/* {{{ CI_InitDllTable */
CK_DEFINE_FUNCTION(CK_I_DLL_INFO_PTR, CK_I_DLL_INFO_new)(
  void
)
{
  CK_I_DLL_INFO_PTR retval= TC_malloc(sizeof(CK_I_DLL_INFO));
  if(retval == NULL_PTR) return retval;

  /* init der Info-Structs */
  retval->handle = NULL_PTR;
  retval->dll_path = NULL_PTR;

  return retval;  
}

static CK_I_HASHTABLE_PTR CK_I_dll_list = NULL_PTR;

CK_DEFINE_FUNCTION(CK_RV, CI_InitDllTable)(
)
{
  CK_RV rv = CKR_OK;              /* function return value */

  CI_LogEntry("CI_LoadDllTable", "starting...", rv, 1);
  
  /* Initialisieren der DLL Hashtabelle */
  rv = CI_InitHashtable(&CK_I_dll_list,20);
  if(rv != CKR_OK) 
    {
      CI_LogEntry("CI_LoadDllTable", "could not init Hashtable", rv, 0);
      return rv;
    }

  CI_LogEntry("CI_LoadDllTable", "...complete", CKR_OK, 1);
  
  return CKR_OK;
}
/* }}} */
/* {{{ CI_TokenInit */
CK_DEFINE_FUNCTION(void, CI_TokenInit)(
 )
{
  token_init fkt_ptr;
  CK_I_SLOT_DATA_PTR pSlotData = NULL_PTR;
  CK_RV rv = CKR_OK;
  CK_CHAR_PTR config_list;                /* list of all token */
  CK_CHAR_PTR token_name = NULL_PTR;      /* token returned by strtok */
  CK_CHAR_PTR token_dll_name = NULL_PTR;  /* name of the token library */
  CK_CHAR_PTR init_fkt = NULL_PTR;        /* name of the initialisation function */
  char CK_PTR remainder = NULL_PTR;       /* temp for strtok, retaining rest of string */
  
  CK_ULONG slotID =0;
  
  CI_LogEntry("CI_TokenInit", "starting...", rv, 1);
  
  /* look for config file */
  if(CK_I_config_fname == NULL_PTR)
    {
      rv = CI_FindConfFile();
      if(rv != CKR_OK)
	{
	  CI_LogEntry("CI_TokenInit", "selecting config file", rv, 0);
	  return;
	}
    }

  /* init the dll table */
  if(CI_InitDllTable() != CKR_OK)
    {
      CI_LogEntry("CI_TokenInit", "could not init the DLL table", rv, 0);
      return;
    }
    
  /**** Get Token List ****/
  CI_VarLogEntry("CI_TokenInit", "starting token read: fname: %s", rv, 1,
		 CK_I_config_fname);
  rv = CI_GetConfigString(NULL_PTR,"TokenList",&config_list);
  if(rv != CKR_OK) 
    {   
      CI_LogEntry("CI_TokenInit", "could not read token list.", rv, 0);
      return;
    }

  token_name = TC_strtok_r(config_list,", ",&remainder);
  slotID = 0;
  while(token_name != NULL_PTR)
    {
      CI_VarLogEntry("CI_TokenInit", "Init'ing token. Token name: %s", rv, 1,token_name);

      /* get token library name */
      rv = CI_GetConfigString(token_name,"TokenDLL",&token_dll_name);
      if( rv != CKR_OK)
	{
	  CI_VarLogEntry("CI_TokenInit", 
			 "could not find library name for token '%s', skipping token", 
			 rv , 0, token_name);
	  goto next_token;
	}


      /* get token init sym name */
      rv = CI_GetConfigString(token_name,"InitSym",&init_fkt);
      if( rv != CKR_OK)
	{
	  CI_VarLogEntry("CI_TokenInit", 
			 "could not find init symbol for token '%s', skipping token", 
			 rv , 0, token_name);
	  goto next_token;
	}

      CI_VarLogEntry("CI_TokenInit","obtaining fkt ptr for '%s'",
		     CKR_OK,0,init_fkt);


      fkt_ptr = CI_InitTokenDll(token_name,init_fkt,token_dll_name);

      if(fkt_ptr == NULL_PTR)
	  CI_VarLogEntry("CI_TokenInit",
			 "Init'ing of Token '%s' failed: no valid init symbol",
			 CKR_GENERAL_ERROR,0,token_name);
      else
	{
	  pSlotData=NULL_PTR;
	  fkt_ptr(token_name, &pSlotData);	  
	  if(pSlotData == NULL_PTR)
	    {
	      CI_VarLogEntry("CI_TokenInit",
			     "init fkt '%s' of Token '%s' did not set slot structure",
			     CKR_GENERAL_ERROR,0,token_name,init_fkt);
	      goto next_token;
	    }

	  /* the 'token_name' is just the the ref to the config section */
	  pSlotData->config_section_name = strdup(token_name);
	  if(pSlotData->config_section_name == NULL_PTR)
	    {
	      rv = CKR_HOST_MEMORY;
	      CI_VarLogEntry("CI_TokenInit", 
			     "dupping token name", rv, 1,token_name);
	      return;
	    }

	  CI_RegisterSlot(slotID, pSlotData);

          CI_VarLogEntry("CI_TokenInit", "slot registered. Token name: %s", 
			 rv, 1,token_name);
	}

    next_token:
      if (token_dll_name != NULL_PTR) 
	{ TC_free(token_dll_name); token_dll_name= NULL_PTR; }
      if (init_fkt != NULL_PTR) 
	{ TC_free(init_fkt); init_fkt= NULL_PTR; }
      token_name = TC_strtok_r(NULL_PTR,", ",&remainder);

      slotID++;
    }
  
  CI_LogEntry("CI_TokenInit", "...complete", CKR_OK, 1);
}

/* }}} */
/* {{{ CI_GetDllHandle */

CK_DEFINE_FUNCTION(CK_RV, CI_GetDllHandle)(
  CK_CHAR_PTR pSymbolicName,
  CK_CHAR_PTR pLibraryName,
  CK_DLL_HANDLE_PTR pHandle
)
{
  CK_RV rv = CKR_OK;
  CK_I_DLL_INFO_PTR dll_info = NULL_PTR;
  
  CI_LogEntry("CI_GetDllHandle", "starting...", rv, 1);
  
  if(CK_I_dll_list == NULL_PTR)
    {
      rv = CI_InitDllTable();
      if(rv != CKR_OK)
	{
	  CI_LogEntry("CI_GetDllHandle", "could not init dll table", rv, 1);
	  return rv;
	}
    }
  
  if(pSymbolicName == NULL_PTR) pSymbolicName = pLibraryName;

  CI_LogEntry("CI_GetDllHandle", "done dll table init", rv, 1);

  rv = CI_HashGetEntry(CK_I_dll_list, CI_string_hash(pSymbolicName),
		       (CK_VOID_PTR CK_PTR)&dll_info);
  if((rv != CKR_OK) && (rv != CKR_ARGUMENTS_BAD))
    {
      CI_LogEntry("CI_GetDllHandle", "dll table retrieve", rv, 1);
      return rv;
    }
  
  /* new dll? */
  if (rv == CKR_ARGUMENTS_BAD)
    {
      dll_info = CK_I_DLL_INFO_new();
      if(dll_info == NULL_PTR)
	{
	  rv = CKR_HOST_MEMORY;
	  CI_LogEntry("CI_GetDllHandle", "could not allocate dll info", rv, 1);
	  return rv;
	}
      
      dll_info->dll_path=TC_malloc(strlen(pLibraryName)+1);
      if(dll_info->dll_path == NULL_PTR)
	{
	  rv = CKR_HOST_MEMORY;
	  CI_LogEntry("CI_GetDllHandle", "could not allocate lib name memory", rv, 1);
	  return rv;
	}
      strcpy(dll_info->dll_path,pLibraryName);
      
      rv = CI_HashPutEntry(CK_I_dll_list,CI_string_hash(pSymbolicName),dll_info);
      if(rv != CKR_OK)
	{
	  CI_LogEntry("CI_GetDllHandle", "could not put new dll in table", rv, 1);
	  return rv;
	}
    }

  /* dll not opened */
  if(dll_info->handle == NULL_PTR)
    {
      CK_CHAR_PTR reason = NULL_PTR;
#if defined(CK_Win32)
      if((dll_info->handle = LoadLibrary(dll_info->dll_path)) == NULL_PTR)
	{
	  CK_CHAR buff[1024];
	  rv = CKR_GENERAL_ERROR;

	  FormatMessage( FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
			 NULL, GetLastError(),
			 MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // Default language
			 (LPTSTR) &reason,
			 0, NULL);
	  
	  sprintf(buff, "Opening Dynamic Library '%s' failed: %s (PATH: %s)", dll_info->dll_path,reason,getenv("PATH"));
	  MessageBox(NULL, buff, "TC PKCS#11",MB_OK|MB_ICONWARNING);

	  LocalFree(reason);

#else /* ! defined(CK_Win32) */
      if((dll_info->handle = dlopen(dll_info->dll_path, RTLD_LAZY)) == NULL_PTR)
	{

	  rv = CKR_GENERAL_ERROR;
	  reason = dlerror();

#endif /* ! defined(CK_Win32) */
	  CI_VarLogEntry("CI_GetDLLHandle", "Opening Dynamic Library '%s' failed: %s", 
			 rv, 0,dll_info->dll_path,reason); 
	  return rv;      
	}
    }
  
  *pHandle = dll_info->handle;
  
  CI_LogEntry("CI_GetDllHandle", "...complete", rv, 1);
  
  return rv;
}
/* }}} */

/* {{{ CI_InitTokenDll */
CK_DEFINE_FUNCTION(token_init, CI_InitTokenDll)(
   CK_CHAR_PTR token_name,
   CK_CHAR_PTR symbol_name,
   CK_CHAR_PTR token_lib_name
)
{
  CK_DLL_HANDLE handle;
  token_init retval;
  CK_RV rv = CKR_OK;

  CI_LogEntry("CI_InitTokenDll", "starting...", rv, 1);

  rv = CI_GetDllHandle(token_name,token_lib_name,&handle);
    if(rv != CKR_OK)
    {
      CI_LogEntry("CI_InitTokenDll", "retrieving dll handle", rv, 0);
      return NULL_PTR;
    }

  CI_LogEntry("CI_InitTokenDll", "starting dref of lib handle", rv, 0);

  retval=DREF_DLL(handle, token_init, symbol_name);

  if(retval == NULL_PTR) rv = CKR_GENERAL_ERROR;
  CI_LogEntry("CI_InitTokenDll", "...complete", rv, 1);

  return retval;
}
/* }}} */
/* {{{ CI_UnloadDlls */

CK_DECLARE_FUNCTION(CK_RV, CI_UnloadDlls)(
 )
{
  CK_I_HASH_ITERATOR_PTR iter;
  CK_RV rv = CKR_OK;
  CK_I_DLL_INFO_PTR pDllInfo = NULL_PTR;
  CK_CHAR_PTR reason = NULL_PTR;
  CK_ULONG key;

  CI_LogEntry("CI_UnloadDlls", "starting...", rv, 2);

  rv = CI_HashIterateInit(CK_I_dll_list,&iter);
  if( rv != CKR_OK)
    {
      CI_LogEntry("CI_UnloadDlls", "setting iterator", rv, 0);
      return rv;
    }

  for(;iter != NULL_PTR; )
    {
      rv = CI_HashIterateDeRef(iter, &key, (CK_VOID_PTR_PTR)(&pDllInfo));
      if(rv != CKR_OK)
	{
	  CI_LogEntry("CI_UnloadDlls", "retrieving dll_info", rv, 0);
	  return rv;
	}

      /* handle == NULL_PTR -> cannot be freed. handle is initialized
       * in CI_getDllHandle, called only for token and not all dlls specified 
       * in the config file
       */
      if(pDllInfo->handle != NULL_PTR)
	{
#if defined(CK_Win32)
	  if(FreeLibrary(pDllInfo->handle) != 0)
	    {
	      reason = "How should I know? Windows doesn't tell me";
#elif defined(CK_GENERIC)
	  if(dlclose(pDllInfo->handle) != 0)
	    {
	      reason = dlerror();
#endif
	      rv = CKR_GENERAL_ERROR;
	      CI_VarLogEntry("CI_UnloadDlls", "could not release Dll '%s': %s", 
			     rv, 0,pDllInfo->dll_path, reason);
	      return rv;
	    }
	}

      TC_free(pDllInfo->dll_path);

      /* type of handle : 'HMODULE' under Windows, 'void *' else */
#if defined(CK_Win32)
      TC_free(pDllInfo->handle);
#endif
      
      TC_free(pDllInfo);

      rv = CI_HashRemoveEntry(CK_I_dll_list, key);
      if(rv != CKR_OK)
	{
	  CI_LogEntry("CI_UnloadDlls", "delete failed", rv, 0);
	  return rv;
	}

      /* removin an element will void the iterator */
      rv = CI_HashIterateInit(CK_I_dll_list, &iter);
      if(rv != CKR_OK)
	{
	  CI_LogEntry("CI_UnloadDlls", "iterate failed", rv, 0);
	  return rv;
	}
    }

  CI_DestroyHashtable(CK_I_dll_list);
  CK_I_dll_list = NULL_PTR;

  TC_free(CK_I_config_fname);
  /* The configuration file name must be reinitialized to NULL_PTR.
   * It has been initialized in the function  CI_LoadDllTable, called by
   * CI_TokenInit, called by C_Initialize.
   */
  CK_I_config_fname = NULL_PTR;

  CI_LogEntry("CI_UnloadDlls", "...complete", rv, 2);

  return rv;
}
/* }}} */
/* {{{ CI_GetConfigString */
static CK_C_CHAR_PTR CK_I_init_fail_reasons[] = {"no error",
					 "File not found",
					 "File not found",
					 "Section not found", 
					 "Field not found"};

CK_DEFINE_FUNCTION(CK_RV, CI_GetConfigString)(
  CK_CHAR_PTR pSectionName,
  CK_CHAR_PTR pFieldname,
  CK_CHAR_PTR CK_PTR ppValue
)
{
  CK_CHAR buff[512];
  CK_RV rv = CKR_OK;

  pSectionName=((pSectionName!=NULL_PTR)?pSectionName:(CK_CHAR_PTR)"PKCS11-DLL");

  if(CK_I_config_fname == NULL_PTR)
    {
      rv = CKR_GENERAL_ERROR;
      CI_VarLogEntry("CI_GetConfigString", "Reading config field failed: config file not set", 
		     rv, 0, 
		     pFieldname, 
		     pSectionName,
		     CK_I_config_fname, 
		     CK_I_init_fail_reasons[rv]);
      return rv;
    }

  rv = TCU_GetProfileString(CK_I_config_fname, pSectionName, pFieldname, 
			       buff, 510,FALSE);
  if(rv != 0)
    {
      CI_VarLogEntry("CI_GetConfigString", "Reading config field '%s' from section [%s] in file '%s' failed: %s", 
		     CKR_GENERAL_ERROR, 0, 
		     pFieldname, 
		     pSectionName,
		     CK_I_config_fname, 
		     CK_I_init_fail_reasons[rv]);
      return CKR_GENERAL_ERROR;
    }

  *ppValue = TC_malloc(strlen(buff)+1);
  if(*ppValue== NULL_PTR) return CKR_HOST_MEMORY;

  strcpy(*ppValue, buff);

  return CKR_OK;
}
/* }}} */
#if 0
/* #if defined(CK_Win32) */
/* {{{ DllMain */

BOOL __stdcall DllMain(HANDLE hModule, 
                      DWORD  ul_reason_for_call, 
                      LPVOID lpReserved)
{
#if 0
  switch( ul_reason_for_call ) 
    {
    case DLL_PROCESS_ATTACH:
      CI_TokenInit();
      CI_ReadLogLevel();
      break;	
    case DLL_THREAD_ATTACH:
      break;
    case DLL_THREAD_DETACH:
      break;
    case DLL_PROCESS_DETACH:
      CI_UnloadDlls();
      break;
    default:
      break;
    }

#endif
   return TRUE;
}
/* }}} */
#endif

/* {{{ CI_GetSignals */
/* since netscape masks all signals we have to get them back in order to
 *   make debugging easier 
 */
/* we need some unix specific defines to make this work, but only under 

 * unix it will. so if there is not unistd.h the whole thing is moot */

#ifdef HAVE_UNISTD_H

typedef void (*sig_handler)(int);

sig_handler old_tab[MAX_SIG_NUM];

void CI_dummy_sig_handle(int sig)
{
  CI_VarLogEntry("CI_dummy_sig_handle", "caught signal '%d' in PID '%d'", CKR_OK, 0,sig,getpid());
  (old_tab[sig])(sig);
  return;
}

CK_DEFINE_FUNCTION(CK_RV, CI_GetSignals)(
)
{
  int i;
  CK_RV rv = CKR_OK;

  CI_LogEntry("CI_GetSignals", "starting...", rv, 0);

  for(i=1;i<MAX_SIG_NUM;i++)
    old_tab[i]=signal(i,&CI_dummy_sig_handle);

  CI_LogEntry("CI_GetSignals", "...ending", rv, 0);

  return CKR_OK;
}

#else /* !HAVE_UNISTD_H */

CK_DEFINE_FUNCTION(CK_RV, CI_GetSignals)(

)

{

  return CKR_OK;

}
#endif /* !HAVE_UNISTD_H */
 /* }}} */
/*
 * Local variables:
 * folded-file: t
 * end:
 */
