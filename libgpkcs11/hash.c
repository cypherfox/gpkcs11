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
 * NAME:        hash.c
 * SYNOPSIS:    -
 * DESCRIPTION: -
 * FILES:       -
 * SEE/ALSO:    -
 * AUTHOR:      lbe
 * BUGS: *      -
 * HISTORY:     $Log$
 * HISTORY:     Revision 1.4  2000/01/31 18:09:02  lbe
 * HISTORY:     lockdown prior to win_gdbm change
 * HISTORY:
 * HISTORY:     Revision 1.3  1999/11/02 13:47:18  lbe
 * HISTORY:     change of structures and bug fix in slot.c, add more files for tcsc_token: emptyfuncs and general_data
 * HISTORY:
 * HISTORY:     Revision 1.2  1999/10/06 07:57:22  lbe
 * HISTORY:     solved netscape symbol clash problem
 * HISTORY:
 * HISTORY:     Revision 1.1  1999/06/16 09:46:08  lbe
 * HISTORY:     reorder files
 * HISTORY:
 * HISTORY:     Revision 1.9  1999/01/19 12:19:40  lbe
 * HISTORY:     first release lockdown
 * HISTORY:
 * HISTORY:     Revision 1.8  1998/12/07 13:20:05  lbe
 * HISTORY:     TC_free von parametern für Zeile und Datei befreit.
 * HISTORY:
 * HISTORY:     Revision 1.7  1998/11/20 12:40:20  lbe
 * HISTORY:     fehlerhaftes eintragen des tabellen endes in CI_HashIterInc
 * HISTORY:
 * HISTORY:     Revision 1.6  1998/11/10 09:43:16  lbe
 * HISTORY:     hash iter geaendert: hashtabelle braucht nicht mehr an fkts uebergeben werden.
 * HISTORY:
 * HISTORY:     Revision 1.5  1998/11/03 15:59:36  lbe
 * HISTORY:     auto-lockdown
 * HISTORY:
 * HISTORY:     Revision 1.4  1998/10/12 10:00:09  lbe
 * HISTORY:     clampdown
 * HISTORY:
 * HISTORY:     Revision 1.3  1998/08/05 08:59:02  lbe
 * HISTORY:     added function for hash of string
 * HISTORY:
 * HISTORY:     Revision 1.2  1998/07/23 15:18:10  lbe
 * HISTORY:     working
 * HISTORY:
 * HISTORY:     Revision 1.1  1998/07/02 17:14:19  lbe
 * HISTORY:     Initial revision
 * HISTORY:
 */
 
static char RCSID[]="$Id$";
const char* Version_hash_c(){return RCSID;}

#ifndef CK_I_library_build
#define CK_I_library_build
#endif

#include <stdlib.h>
#include <assert.h>
#include <stdio.h>

#include "internal.h"
#include "mutex.h"
#include "error.h"

/* extremely simple but should suffice */
#define CI_HASH(_table,_key)  ((_key) % (_table->tab_size)) 

/* {{{ CI_InitHashtable */
CK_DEFINE_FUNCTION(CK_RV, CI_InitHashtable)(
  CK_I_HASHTABLE_PTR_PTR ppHashTable,  /* returned ptr to hash table */
  CK_ULONG size                     /* size of table to be used */
)
{
  /* to avaoid SIGFPE */
  assert(size!=0);

  *ppHashTable = TC_calloc(1,sizeof(CK_I_HASHTABLE));
  if(*ppHashTable == NULL_PTR)
    return CKR_HOST_MEMORY;

  (*ppHashTable)->tab_size = size;
  (*ppHashTable)->table = TC_calloc(size,sizeof(CK_I_HASH_BUCKET));
  if((*ppHashTable)->table == NULL_PTR)
    {
      TC_free(*ppHashTable);
      *ppHashTable = NULL_PTR;
      return CKR_HOST_MEMORY;
    }

  return CKR_OK;
}
/* }}} */
/* {{{ CI_DestroyHashtable */
CK_DEFINE_FUNCTION(CK_RV, CI_DestroyHashtable)(
  CK_I_HASHTABLE_PTR pHashTable  /* hash table to be destroyed */
)
{
  unsigned int i;
  CK_I_HASH_BUCKET_PTR next = NULL_PTR;
  CK_I_HASH_BUCKET_PTR tmp = NULL_PTR;

  if(pHashTable == NULL_PTR) return CKR_GENERAL_ERROR;

  if(pHashTable->entries != 0)
    CI_LogEntry("CI_DestroyHashtable","**** Hashtable contains data! ****",0,1);

  for(i=0;i<pHashTable->tab_size;i++)
    {
      tmp= pHashTable->table[i];
      while(tmp != NULL_PTR)
	{
	  next = tmp->next;
	  TC_free(tmp);
	  tmp = next;
	}
    }
  
  TC_free(pHashTable->table);
  TC_free(pHashTable);

  return CKR_OK;
}
/* }}} */
/* {{{ CI_ClearHashtable */
CK_DEFINE_FUNCTION(CK_RV, CI_ClearHashtable)(
  CK_I_HASHTABLE_PTR pHashTable  /* hash table to be destroyed */
)
{
  unsigned int i;
  CK_I_HASH_BUCKET_PTR next = NULL_PTR;
  CK_I_HASH_BUCKET_PTR tmp = NULL_PTR;
  
  if(pHashTable == NULL_PTR) return CKR_GENERAL_ERROR;
  
  for(i=0;i<pHashTable->tab_size;i++)
  {
    tmp= pHashTable->table[i];
    while(tmp != NULL_PTR)
    {
      next = tmp->next;
      TC_free(tmp);
      tmp = next;
    }
    pHashTable->table[i] = NULL_PTR;
  }

  pHashTable->entries = 0;
  
  return CKR_OK;
}
/* }}} */
/* {{{ CI_HashPutEntry */
CK_DEFINE_FUNCTION(CK_RV, CI_HashPutEntry)(
  CK_I_HASHTABLE_PTR pHashTable,  /* returned ptr to hash table */
  CK_ULONG key,                /* key of data, base for hash */
  CK_VOID_PTR val             /* data to be inserted */
)
{
  CK_ULONG index; 
  CK_I_HASH_BUCKET_PTR pBucket = NULL_PTR; 
  CK_I_HASH_BUCKET_PTR tmpBucket = NULL_PTR;

  if(pHashTable == NULL_PTR) return CKR_GENERAL_ERROR;

  pBucket = TC_calloc(1,sizeof(CK_I_HASH_BUCKET));
  if(pBucket == NULL_PTR)
    return CKR_HOST_MEMORY;

  index = CI_HASH(pHashTable, key);

  /* set bucket values */
  pBucket->key = key;
  pBucket->val = val;
  pBucket->index = index;
  pBucket->next = NULL_PTR; /* sollte eigentlich schon mit dem calloc abgehandelt sein */

  if(pHashTable->table[index] == NULL_PTR)
    {
      pHashTable->table[index]=pBucket;
      pHashTable->entries++;
    }
  else
    {
      tmpBucket= pHashTable->table[index];
      while(TRUE)
	{
	  if(key == tmpBucket->key) /* same key -> replace value */
	    {
	      tmpBucket->val = pBucket->val;
	      TC_free(pBucket);
	      break;
	    }
	  else if(tmpBucket->next == NULL) /* no further bucket -> place as next */
	    {
	      tmpBucket->next = pBucket;
	      pHashTable->entries++;
	      break;
	    }
	  else   /* iterate to next bucket */
	    tmpBucket = tmpBucket->next;
	}
    }

  return CKR_OK;
}
/* }}} */
/* {{{ CI_HashGetEntry */
CK_DEFINE_FUNCTION(CK_RV, CI_HashGetEntry)(
  CK_I_HASHTABLE_PTR pHashTable,  /* returned ptr to hash table */
  CK_ULONG key,                /* key of data, base for hash */
  CK_VOID_PTR_PTR val         /* returned pointer to data*/
)
{
  CK_I_HASH_BUCKET_PTR tmpBucket = NULL_PTR;
  CK_ULONG index;

  /* Test if the table is init'ed at all. */
  if(pHashTable == NULL_PTR) return CKR_GENERAL_ERROR;

  index = CI_HASH(pHashTable,key);

  if(pHashTable->table[index] == NULL_PTR)
      return CKR_ARGUMENTS_BAD; /* no such key */
  else
    {
      tmpBucket= pHashTable->table[index];
      while(TRUE)
	{
	  if(key == tmpBucket->key) /* same key -> return value */
	    {
	      *val = tmpBucket->val;
	      break;
	    }
	  else if(tmpBucket->next == NULL) /* no furter bucker -> error! */
	    return CKR_ARGUMENTS_BAD; /* no such key */
	  else   /* iterate to next bucket */
	    tmpBucket = tmpBucket->next;
	}
    }

  return CKR_OK;
}
/* }}} */
/* {{{ CI_HashRemoveEntry */
CK_DEFINE_FUNCTION(CK_RV, CI_HashRemoveEntry)(
  CK_I_HASHTABLE_PTR pHashTable,  /* returned ptr to hash table */
  CK_ULONG key                /* key of data to be deleted */
)
{
  CK_ULONG index; 
  CK_I_HASH_BUCKET_PTR currBucket = NULL_PTR;
  CK_I_HASH_BUCKET_PTR lastBucket = NULL_PTR;

  if(pHashTable == NULL_PTR) return CKR_GENERAL_ERROR;

  index = CI_HASH(pHashTable, key);

  if(pHashTable->table[index] == NULL_PTR)
    {
      return CKR_ARGUMENTS_BAD; /* no such key */
    }
  else
    {
      currBucket = pHashTable->table[index];
      lastBucket = NULL_PTR;

      while(TRUE)
	{
	  if(key == currBucket->key) /* same key -> remove bucket */
	    {
	      if(lastBucket == NULL_PTR) /* Entry in the table array */
		/* this should set the table entry to NULL if there is no further element */
		pHashTable->table[index] = currBucket->next;
	      else
		lastBucket->next = currBucket->next;

	      TC_free(currBucket);
	      pHashTable->entries--;

	      break;
	    }
	  else if(currBucket->next == NULL) /* no furter bucket -> no such key */
	    {
	      return CKR_ARGUMENTS_BAD;
	      break;
	    }
	  else   /* iterate to next bucket */
	    {
	      lastBucket = currBucket;
	      currBucket = currBucket->next;
	    }
	}
    }

  return CKR_OK;
}
/* }}} */
/* {{{ CI_HashEntryExists */
CK_DEFINE_FUNCTION(CK_RV, CI_HashEntryExists)(
  CK_I_HASHTABLE_PTR pHashTable,  /* returned ptr to hash table */
  CK_ULONG key                 /* key of data to be deleted */
)
{
  CK_ULONG index; 
  CK_I_HASH_BUCKET_PTR currBucket = NULL_PTR;
  CK_RV rv = CKR_OK;

  if(pHashTable == NULL_PTR) return CKR_GENERAL_ERROR;

  index = CI_HASH(pHashTable, key);

  if(pHashTable->table[index] == NULL_PTR)
    {
      return CKR_ARGUMENTS_BAD; /* no such key */
    }
  else
    {
      currBucket = pHashTable->table[index];

      while(TRUE)
	{
	  if(key == currBucket->key) /* same key -> return all ok */
	    {
	      break;
	    }
	  else if(currBucket->next == NULL) /* no furter bucket -> no such key */
	    {
	      rv = CKR_ARGUMENTS_BAD;
	      break;
	    }
	  else   /* iterate to next bucket */
	    {
	      currBucket = currBucket->next;
	    }
	}
    }

  return rv;
}
/* }}} */
/* {{{ CI_HashtableToString */

/* handle , space, pointer, newline + new line */
#define CK_IH_TEXTSIZE 3+1+8+1+1

CK_DEFINE_FUNCTION(CK_CHAR_PTR, CI_HashtableToString)(
  CK_I_HASHTABLE_PTR pHashTable 
)
{
  CK_I_HASH_ITERATOR_PTR iter;
  CK_CHAR_PTR buff = NULL_PTR;
  CK_CHAR_PTR curr_p = NULL_PTR;
  CK_ULONG key, chars=0;
  CK_VOID_PTR val = NULL_PTR;

  if(pHashTable == NULL_PTR) return NULL_PTR;


  curr_p = buff = TC_malloc((CK_IH_TEXTSIZE*pHashTable->entries)+1);
  if(buff == NULL_PTR)
    return NULL_PTR;

  CI_HashIterateInit(pHashTable, &iter);
  assert( CI_HashIterValid(iter));
  for(; CI_HashIterValid(iter) ; CI_HashIterateInc(iter), curr_p+=chars)
    {
      CI_HashIterateDeRef(iter, &key, &val);

      chars = sprintf(curr_p, "%3lu:0x%p\n", key, val);
    }

  return buff;
}
/* }}} */
/* {{{ CI_string_hash */
CK_DECLARE_FUNCTION(CK_ULONG, CI_string_hash)(
  CK_CHAR_PTR string
)
{
  CK_ULONG retval =0;
  for(;*string != '\0' ; string++)
    {
      retval += *string;
      retval = retval << 1;
    }
  
  return retval;
}
/* }}} */

/* {{{ CI_HashIterateInit */
CK_DEFINE_FUNCTION(CK_RV, CI_HashIterateInit)(
 CK_I_HASHTABLE_PTR pHashTable,
 CK_I_HASH_ITERATOR_PTR CK_PTR pIterator
)
{
  CK_ULONG i;

  if(pHashTable == NULL_PTR) 
    {
      *pIterator = NULL_PTR;
      return CKR_GENERAL_ERROR;
    }

  /* any elements at all? */
  if(pHashTable->entries == 0)
    {
      *pIterator=NULL_PTR;
      return CKR_OK;
    }

  /* get the mem */
  if( (*pIterator = TC_calloc(1,sizeof(CK_I_HASH_ITERATOR))) == NULL_PTR)
    return CKR_HOST_MEMORY;

  (*pIterator)->table = pHashTable;

  for(i=0;(i < pHashTable->tab_size) && (pHashTable->table[i] == NULL_PTR);i++);
  if(i < pHashTable->tab_size)
    (*pIterator)->curr_bucket=pHashTable->table[i];
  else
    (*pIterator)=NULL_PTR;

  return CKR_OK;
}
/* }}} */
/* {{{ CI_HashIterateInc */
/* pIterator is set to NULL_PTR if there is no further element. */
CK_DEFINE_FUNCTION(CK_RV, CI_HashIterateInc)(
 CK_I_HASH_ITERATOR_PTR pIterator
)
{
  CK_ULONG i;

  /* paranoia test */
  if(pIterator == NULL_PTR)
    return CKR_GENERAL_ERROR;

  if(pIterator->table == NULL_PTR)
    return CKR_GENERAL_ERROR;

  if(pIterator->curr_bucket == NULL_PTR)
    return CKR_GENERAL_ERROR;

  if(pIterator->curr_bucket->next != NULL_PTR)
    {
      pIterator->curr_bucket = pIterator->curr_bucket->next;
      return CKR_OK;
    }

  /* OK we have to walk along the table to find the next filled bucket */
  for(i = (pIterator->curr_bucket->index)+1; ((i< pIterator->table->tab_size) && 
				 (pIterator->table->table[i] == NULL_PTR) ); i++);
  if(i < pIterator->table->tab_size)
    pIterator->curr_bucket=pIterator->table->table[i];
  else
    {
    pIterator->table=NULL_PTR;
    pIterator->curr_bucket=NULL_PTR;
    }

  return CKR_OK;
}
/* }}} */
/* {{{ CI_HashIterateDeRef */
CK_DEFINE_FUNCTION(CK_RV, CI_HashIterateDeRef)(
 CK_I_HASH_ITERATOR_PTR pIterator,
 CK_ULONG_PTR pKey,
 CK_VOID_PTR_PTR ppVal
)
{
  /* paranoia test */
  if((pIterator == NULL_PTR) ||
     (pIterator->table == NULL_PTR) ||
     (pIterator->curr_bucket == NULL_PTR))
    return CKR_GENERAL_ERROR;

  if(pKey != NULL_PTR)
    *pKey = pIterator->curr_bucket->key;

  if(ppVal != NULL_PTR)
    *ppVal = pIterator->curr_bucket->val;

  return CKR_OK;
}
/* }}} */
/* {{{ CI_HashIterateDel */
CK_DECLARE_FUNCTION(CK_RV, CI_HashIterateDel)(
 CK_I_HASH_ITERATOR_PTR pIterator
)
{
  CK_I_HASH_ITERATOR_PTR tmp_iter = NULL_PTR;
  CK_ULONG tmp_key;
  CK_RV rv = CKR_OK;

  if((pIterator == NULL_PTR) ||
     (pIterator->table == NULL_PTR) ||
     (pIterator->curr_bucket == NULL_PTR))
    return CKR_GENERAL_ERROR;

  rv = CI_HashIterateDup(pIterator,&tmp_iter);
  if(rv != CKR_OK) return rv;

  rv = CI_HashIterateInc(pIterator);
  if(rv != CKR_OK) return rv;

  rv = CI_HashIterateDeRef(tmp_iter, &tmp_key, NULL_PTR);
  if(rv != CKR_OK) return rv;

  rv = CI_HashRemoveEntry(tmp_iter->table, tmp_key);
  
  TC_free(tmp_iter); /* the iter was dup'ed */
  
  return rv;
}
/* }}} */
/* {{{ CI_HashIterateDup*/
CK_DECLARE_FUNCTION(CK_RV, CI_HashIterateDup)(
 CK_I_HASH_ITERATOR_PTR pIterator,
 CK_I_HASH_ITERATOR_PTR CK_PTR  ppNewIterator
)
{
  /* get the mem */
  if( (*ppNewIterator = TC_calloc(1,sizeof(CK_I_HASH_ITERATOR))) == NULL_PTR)
    return CKR_HOST_MEMORY;
  
  (*ppNewIterator)->table = (pIterator)->table;
  (*ppNewIterator)->curr_bucket = (pIterator)->curr_bucket;
    
  return CKR_OK;
}
/* }}} */
/* {{{ CI_HashIterateDelete */
/* clear the iterator */
CK_DECLARE_FUNCTION(CK_RV, CI_HashIterateDelete)(
 CK_I_HASH_ITERATOR_PTR pIterator
)
{
  free(pIterator);
  return CKR_OK;
}
/* }}} */
/* {{{ CI_HashIterValid */
CK_DECLARE_FUNCTION(CK_BBOOL, CI_HashIterValid)(
 CK_I_HASH_ITERATOR_PTR pIterator
)
{
  if((pIterator == NULL) ||
     (pIterator->table == NULL_PTR) ||
     (pIterator->curr_bucket == NULL_PTR))
    return FALSE;

  return TRUE;     
}
/* }}} */

/* handle handling functions */
static CK_ULONG CK_I_handle_counter = 1 ; /* must not start with 0 due to CK_INVALID_HANDLE */
/* static CK_ULONG CK_I_handle_counter = 0xfe000000L ; */ /* must not start with 0 due to CK_INVALID_HANDLE */

/* {{{ CI_NewHandle */
CK_DEFINE_FUNCTION(CK_RV, CI_NewHandle)(
  CK_ULONG_PTR handle                 /* handle returned */
)
{
  CK_RV rv = CKR_OK;
   CK_VOID_PTR mutex = NULL_PTR;
 
  /* get mutex, there are some synchronized areas in here */
  CI_CreateMutex(&mutex);

  _LOCK(mutex);
  if(CK_I_handle_counter == I_MAX_HANDLE)
    rv = CKR_GENERAL_ERROR;
  else
    *handle = (++CK_I_handle_counter);
  _UNLOCK(mutex);

  CI_DestroyMutex(mutex);
  return rv;
}
/* }}} */

/*
 * Local variables:
 * folded-file: t
 * end:
 */
