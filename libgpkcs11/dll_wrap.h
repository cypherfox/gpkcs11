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
 * State:	$State$ $Locker$
 * NAME:	dll_wrap.h
 * SYNOPSIS:	-
 * DESCRIPTION: -
 * FILES:	-
 * SEE/ALSO:	-
 * AUTHOR:	lbe
 * BUGS: 	-
 */

#ifndef DLL_WRAP_H
#define DLL_WRAP_H 1

#ifndef CRYPTOKI_H
#error cryptoki.h needs to be included before this files
#endif

#if defined(CK_Win32) || defined(WINDOWS) || defined (WIN32)

#include <windows.h>

typedef HMODULE CK_DLL_HANDLE;
typedef CK_DLL_HANDLE CK_PTR CK_DLL_HANDLE_PTR;

#define DREF_DLL( libref, cast, fkt_name ) ( ( cast )(GetProcAddress(libref, fkt_name)) )

#else
/* Sun Solaris and Linux */
#include <dlfcn.h>

typedef void * CK_DLL_HANDLE;
typedef CK_DLL_HANDLE CK_PTR CK_DLL_HANDLE_PTR;

#define DREF_DLL( libref, cast, fkt_name ) ( ( cast )(dlsym(libref, fkt_name)) ) 

#endif /* ! Win32 */

#endif /* DLL_WRAP_H */
