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
 * NAME:        hash.h
 * SYNOPSIS:    -
 * DESCRIPTION: -
 * FILES:       -
 * SEE/ALSO:    -
 * AUTHOR:      lbe
 * BUGS: *      -
 * HISTORY:     $Log$
 * HISTORY:     Revision 1.2  2000/01/31 18:09:02  lbe
 * HISTORY:     lockdown prior to win_gdbm change
 * HISTORY:
 * HISTORY:     Revision 1.1  1999/06/16 09:46:08  lbe
 * HISTORY:     reorder files
 * HISTORY:
 * HISTORY:     Revision 1.6  1999/01/19 12:19:41  lbe
 * HISTORY:     first release lockdown
 * HISTORY:
 * HISTORY:     Revision 1.5  1998/11/10 09:43:11  lbe
 * HISTORY:     hash iter geaendert: hashtabelle braucht nicht mehr an fkts uebergeben werden.
 * HISTORY:
 * HISTORY:     Revision 1.4  1998/10/12 10:01:08  lbe
 * HISTORY:     clampdown
 * HISTORY:
 * HISTORY:     Revision 1.3  1998/08/05 08:59:15  lbe
 * HISTORY:     added function for hash of string
 * HISTORY:
 * HISTORY:     Revision 1.2  1998/07/23 15:20:11  lbe
 * HISTORY:     working
 * HISTORY:
 * HISTORY:     Revision 1.1  1998/07/02 17:14:41  lbe
 * HISTORY:     Initial revision
 * HISTORY:
 */

#ifndef _HASH_H_
#define _HASH_H_ 1

#include "cryptoki.h"

typedef struct CK_I_HASH_BUCKET {
CK_VOID_PTR val;
CK_ULONG key;
CK_ULONG index;     /* index of this bucket in the top table. i.e. the result of the the hash function */
struct CK_I_HASH_BUCKET CK_PTR next;
} CK_I_HASH_BUCKET;

typedef CK_I_HASH_BUCKET CK_PTR CK_I_HASH_BUCKET_PTR;
typedef CK_I_HASH_BUCKET_PTR CK_PTR CK_I_HASH_BUCKET_PTR_PTR;

typedef struct CK_I_HASHTABLE {
CK_ULONG tab_size;  /* table size in entries */
CK_ULONG entries;   /* current number of entries */
CK_I_HASH_BUCKET_PTR_PTR table;
} CK_I_HASHTABLE;

typedef CK_I_HASHTABLE CK_PTR CK_I_HASHTABLE_PTR;
typedef CK_I_HASHTABLE_PTR CK_PTR CK_I_HASHTABLE_PTR_PTR;

extern CK_DECLARE_FUNCTION(CK_RV, CI_InitHashtable)(
  CK_I_HASHTABLE_PTR_PTR ppHashTable,  /* returned ptr to hash table */
  CK_ULONG size                     /* size of table to be used */
);

extern CK_DECLARE_FUNCTION(CK_RV, CI_DestroyHashtable)(
  CK_I_HASHTABLE_PTR pHashTable  /* hash table to be destroyed */
);

CK_DECLARE_FUNCTION(CK_RV, CI_HashPutEntry)(
  CK_I_HASHTABLE_PTR pHashTable,  /* returned ptr to hash table */
  CK_ULONG key,                /* key of data, base for hash */
  CK_VOID_PTR val             /* data to be inserted */
);

CK_DECLARE_FUNCTION(CK_RV, CI_HashGetEntry)(
  CK_I_HASHTABLE_PTR pHashTable,  /* returned ptr to hash table */
  CK_ULONG key,                /* key of data, base for hash */
  CK_VOID_PTR_PTR val         /* returned pointer to data*/
);

CK_DECLARE_FUNCTION(CK_RV, CI_HashRemoveEntry)(
  CK_I_HASHTABLE_PTR pHashTable,  /* returned ptr to hash table */
  CK_ULONG key                /* key of data to be deleted */
);

CK_DECLARE_FUNCTION(CK_RV, CI_HashEntryExists)(
  CK_I_HASHTABLE_PTR pHashTable,  /* returned ptr to hash table */
  CK_ULONG key                /* key of data to be deleted */
);

CK_DECLARE_FUNCTION(CK_CHAR_PTR, CI_HashtableToString)(
  CK_I_HASHTABLE_PTR pHashTable  /* returned ptr to hash table */
);

/** calculate a good hash value over a string.
 * @param string string for which to compute the hashvalue
 */
CK_DECLARE_FUNCTION(CK_ULONG, CI_string_hash)(
  CK_CHAR_PTR string
);


typedef struct CK_I_HASH_ITERATOR
{
  CK_I_HASHTABLE_PTR table;
  CK_I_HASH_BUCKET_PTR curr_bucket;
}CK_I_HASH_ITERATOR;

typedef CK_I_HASH_ITERATOR CK_PTR CK_I_HASH_ITERATOR_PTR;

/* pIterator is set to NULL_PTR if there is no element. */
/*
 * Warning: any change in the Hashtable may invalidate the Iterator!
 */
CK_DECLARE_FUNCTION(CK_RV, CI_HashIterateInit)(
 CK_I_HASHTABLE_PTR pHashTable,
 CK_I_HASH_ITERATOR_PTR CK_PTR ppIterator
);

/* pIterator is set to NULL_PTR if there is no further element. */
CK_DECLARE_FUNCTION(CK_RV, CI_HashIterateInc)(
 CK_I_HASH_ITERATOR_PTR pIterator
);

/** Derefence element of the hashtable from an iterator.
 * If return of either of key or val is not requiered, set pointer to 
 * NULL_PTR 
 */
CK_DECLARE_FUNCTION(CK_RV, CI_HashIterateDeRef)(
 CK_I_HASH_ITERATOR_PTR pIterator,
 CK_ULONG_PTR pKey,
 CK_VOID_PTR_PTR ppVal
);

/** Delete the element of the hashtable the iterator points at.
 * will set the iterator to the next element in the hashtable or NULL_PTR 
 * if there is no further element.
 * The function compensates for the fact that a delete changes the
 * hash table.
 */
CK_DECLARE_FUNCTION(CK_RV, CI_HashIterateDel)(
 CK_I_HASH_ITERATOR_PTR pIterator
);

/* check the state of the iterator */
CK_DECLARE_FUNCTION(CK_BBOOL, CI_HashIterValid)(
 CK_I_HASH_ITERATOR_PTR pIterator
);

/* clear the iterator */
CK_DECLARE_FUNCTION(CK_RV, CI_HashIterateDelete)(
 CK_I_HASH_ITERATOR_PTR pIterator
);

/* CI_HashIterateDup */
CK_DECLARE_FUNCTION(CK_RV, CI_HashIterateDup)(
 CK_I_HASH_ITERATOR_PTR pIterator,
 CK_I_HASH_ITERATOR_PTR CK_PTR  ppNewIterator
);

/* handle handling function */
extern CK_ULONG handle_counter;
#define I_MAX_HANDLE (0xffffffffL)


CK_DECLARE_FUNCTION(CK_RV, CI_NewHandle)(
  CK_ULONG_PTR handle                /* handle returned */
);

#endif /* _HASH_H_ */

/*
 * Local variables:
 * folded-file: t
 * end:
 */
