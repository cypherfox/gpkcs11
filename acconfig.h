/* -*- c -*- */
/*
 * This file is part of TC-PKCS11. 
 * (c) 1999 TC TrustCenter for Security in DataNetworks GmbH 
 *
 * TC-PKCS11 is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *  
 * TC-PKCS11 is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *  
 * You should have received a copy of the GNU General Public License
 * along with TC-PKCS11; see the file COPYING.  If not, write to the Free
 * Software Foundation, 59 Temple Place - Suite 330, Boston, MA 02111, USA.  
 */
/*
 * RCSID:       $Id$
 * Source:      $Source$
 * Last Delta:  $Date$ $Revision$ $Author$
 * State:       $State$ $Locker$
 * NAME:        acconfig.h
 * SYNOPSIS:    -
 * DESCRIPTION: -
 * FILES:       -
 * SEE/ALSO:    -
 * AUTHOR:      lbe
 * BUGS: *      -
 * HISTORY:     $Log$
 * HISTORY:     Revision 1.6  1999/10/06 07:57:16  lbe
 * HISTORY:     solved netscape symbol clash problem
 * HISTORY:
 * HISTORY:     Revision 1.5  1999/03/01 14:36:42  lbe
 * HISTORY:     merged changes from the weekend
 * HISTORY:
 * HISTORY:     Revision 1.4  1999/01/19 12:19:35  lbe
 * HISTORY:     first release lockdown
 * HISTORY:
 * HISTORY:     Revision 1.3  1998/08/05 09:01:12  lbe
 * HISTORY:     *** empty log message ***
 * HISTORY:
 * HISTORY:     Revision 1.2  1998/07/31 09:52:36  lbe
 * HISTORY:     Win32 Port
 * HISTORY:
 * HISTORY:     Revision 1.1  1998/07/02 17:06:07  lbe
 * HISTORY:     Initial revision
 * HISTORY:
 */

/* define if the code is compiled on a UNIX machine */
#undef CK_GENERIC

/* define if the code is compiled on a Win32 machine */
#undef CK_Win32

/* Name of the Package */
#undef PACKAGE

/* Version number of this Build */
#undef VERSION
