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
 * State:	$State$ $Locker$
 * NAME:	pkcs11_proxy.h
 * SYNOPSIS:	-
 * DESCRIPTION: -
 * FILES:	-
 * SEE/ALSO:	-
 * AUTHOR:	lbe
 * BUGS: *	-
 * HISTORY:	$Log$
 * HISTORY:	Revision 1.1  2000/02/07 14:04:09  lbe
 * HISTORY:	release 0.6 and clean up of files
 * HISTORY:	
 * HISTORY:	Revision 1.2  2000/01/31 18:09:03  lbe
 * HISTORY:	lockdown prior to win_gdbm change
 * HISTORY:	
 * HISTORY:	Revision 1.1  1999/06/16 09:46:10  lbe
 * HISTORY:	reorder files
 * HISTORY:	
 * HISTORY:	Revision 1.2  1999/01/19 12:19:45  lbe
 * HISTORY:	first release lockdown
 * HISTORY:
 * HISTORY:	Revision 1.1  1998/11/04 17:45:46  lbe
 * HISTORY:	Initial revision
 * HISTORY:
 */

#ifndef PKCS11_PROXY_H
#define PKCS11_PROXY_H 1

#include "cryptoki.h"
#include <guile/gh.h>

CK_DECLARE_FUNCTION(int, CI_OpenSocket)(
);

CK_DECLARE_FUNCTION(void, CI_CloseSocket)(
);

CK_DECLARE_FUNCTION(CK_RV, CI_SendString)(
 CK_C_CHAR_PTR string,
 CK_CHAR_PTR CK_PTR retval
 );

CK_DECLARE_FUNCTION(CK_RV, CI_ParseString)(
  CK_CHAR_PTR retstring,
  SCM *retlist
);



#endif /* PKCS11_PROXY_H */
