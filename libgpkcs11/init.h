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
 * NAME:        init.h
 * SYNOPSIS:    -
 * DESCRIPTION: Declare some functions for loading dynamic libraries, independent of the OS
 * FILES:       -
 * SEE/ALSO:    -
 * AUTHOR:      lbe
 * BUGS: *      -
 * HISTORY:     $Log$
 * HISTORY:     Revision 1.5  2000/01/31 18:09:02  lbe
 * HISTORY:     lockdown prior to win_gdbm change
 * HISTORY:
 * HISTORY:     Revision 1.4  1999/11/02 13:47:18  lbe
 * HISTORY:     change of structures and bug fix in slot.c, add more files for tcsc_token: emptyfuncs and general_data
 * HISTORY:
 * HISTORY:     Revision 1.3  1999/10/08 13:00:13  lbe
 * HISTORY:     release version 0.5.5
 * HISTORY:
 * HISTORY:     Revision 1.2  1999/10/06 07:57:22  lbe
 * HISTORY:     solved netscape symbol clash problem
 * HISTORY:
 * HISTORY:     Revision 1.1  1999/06/16 09:46:08  lbe
 * HISTORY:     reorder files
 * HISTORY:
 * HISTORY:     Revision 1.5  1999/06/04 14:58:35  lbe
 * HISTORY:     change to libtool/automake complete (except for __umoddi prob)
 * HISTORY:
 * HISTORY:     Revision 1.4  1999/01/19 12:19:41  lbe
 * HISTORY:     first release lockdown
 * HISTORY:
 * HISTORY:     Revision 1.3  1998/11/04 17:12:28  lbe
 * HISTORY:     debug-lockdown
 * HISTORY:
 * HISTORY:     Revision 1.2  1998/10/12 11:16:54  lbe
 * HISTORY:     clampdown
 * HISTORY:
 * HISTORY:     Revision 1.1  1998/08/05 08:57:50  lbe
 * HISTORY:     Initial revision
 * HISTORY:
 */

#ifndef _INIT_H
#define _INIT_H 1

#include "dll_wrap.h"

/** Locate the config file.
 * The config file may be in one of the following places:
 *  NT: <windows directory>\gpkcs11.cnf ( ususally this is
 *      "c:\WinNT\system32\gpkcs11.cnf" )
 *  Solaris/Linux: either "/etc/gpkcs11rc" or "$HOME/.gpkcs11rc"
 * 
 * On all systems setting the environment variable "GPKCS11_CONF"
 * with the name of the file will override the selection.
 * 
 * the function also reads the loging level and the extra path for 
 * dynamic libraries. If the name of any library used in the system 
 * given as a relative file this path will be used in addition to 
 * the calling programs environment to look for the library.
 * Please consult you system documentation on how the file of a 
 * library is defined.
 * 
 * The above values as well as the list of the token is read from the
 * [PKCS11-DLL] section of the configuration file.
 */
CK_DECLARE_FUNCTION(CK_RV, CI_FindConfFile)(
);

/** Initialize the DLL table.
 * this function initializes the table of opened DLLs so they
 * may be closed properly when finalizing the PKCS#11 library.
 */
CK_DECLARE_FUNCTION(CK_RV, CI_InitDllTable)(
);

typedef CK_RV (*token_init)(CK_CHAR_PTR token_name, CK_I_SLOT_DATA_PTR CK_PTR ppSlotData);

/** Open the library and return the symbol handle for the init fkt.
 * function will register the handle to the library to the 
 * DLL table.
 */
CK_DECLARE_FUNCTION(token_init, CI_InitTokenDll)(
   CK_CHAR_PTR token_name,
   CK_CHAR_PTR symbol_name,
   CK_CHAR_PTR token_lib_name
);

/** Retrieve a DLL handle from the dll table
 * The function will check for the dll either by a symbolic name
 * or if that is set to NULL_PTR will use the library Name as a key.
 * @param pSymbolicName short symbolic name for the library. 
 *                If set NULL_PTR, the pLibraryName will be used.
 * @param pLibraryName file name or full path to the library. If set to 
 *                NULL_PTR function will only succeed if the pSymbolicName 
 *                is set and the function was allready opened previously.
 * @param pHandle handle of the oped library, unchanged if Function
 *                not successful
 * @return CKR_OK if looking up library handle succeeded. If the library was
 *         not previously opened and the opening trial failed the function will
 *         return CKR_GENERAL_ERROR;
 */
CK_DECLARE_FUNCTION(CK_RV, CI_GetDllHandle)(
  CK_CHAR_PTR pSymbolicName,
  CK_CHAR_PTR pLibraryName,
  CK_DLL_HANDLE_PTR pHandle
);


CK_DECLARE_FUNCTION(CK_RV, CI_UnloadDlls)(
  void
);

CK_DECLARE_FUNCTION(void, CI_TokenInit)(
  void
);

CK_DECLARE_FUNCTION(void, CI_ReadLogLevel)(
  void
 );

#define CK_I_WINDOWS_RC_FNAME "gpkcs11.ini"
#define CK_I_UNIX_RC_FNAME "gpkcs11.rc"

typedef struct CK_I_DLL_INFO
{
  CK_CHAR_PTR dll_path;
  CK_DLL_HANDLE handle;
} CK_I_DLL_INFO;

typedef CK_I_DLL_INFO CK_PTR CK_I_DLL_INFO_PTR;


CK_DECLARE_FUNCTION(CK_I_DLL_INFO_PTR, CK_I_DLL_INFO_new)(
  void
);

CK_DECLARE_FUNCTION(CK_RV, CI_GetConfigString)(
  CK_CHAR_PTR SectionName,
  CK_CHAR_PTR FieldName,
  CK_CHAR_PTR CK_PTR value
);

CK_DECLARE_FUNCTION(CK_RV, CI_GetSignals)(
);

#endif /* _INIT_H */
