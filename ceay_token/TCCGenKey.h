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
 * NAME:        TCCGenKey.h
 * SYNOPSIS:    -
 * DESCRIPTION: Generates (RSA) key with additional tests
 * FILES:       -
 * SEE/ALSO:    -
 * AUTHOR:      gbe
 * BUGS:        -
 */

#ifndef _TCCKEYGEN_H
#define _TCCKEYGEN_H

#include <openssl/rsa.h>

#ifdef  __cplusplus
extern "C" {
#endif
#if 0
}
#endif

const char *TCC_GenKey_Version(void);

/* Properties for TCC_KEYGEN_generate_rsa_key */
#define GK_PROP_STRONG 0x0001  /* use strong primes */

/*
 * Funktion :  TCC_GenKey_generate_rsa_key
 *             generiert ein RSA Keypair
 *
 * Parameter:  bits: keylength in bits
 *             e_value: value of exponent (e.g. RSA_F4)
 *             genkey_properties: combined GK_* property values
 *             callback: function to inform about the generation steps
 *             cb_arg: additional parmeter for callback function
 *
 * Precond  :  -
 * Postcond :  -
 * Return   :  keypair in RSA Format
 * Globals  :  -
 * Fehler   :  -
 */
RSA *TCC_GenKey_generate_rsa_key(unsigned long bits, unsigned long e_value,
                                 unsigned long genkey_properties,
                                 void (*callback)(int,int,char*),
                                 char *cb_arg);

#ifdef  __cplusplus
}
#endif

#endif /* _TCCGENKEY_H */
