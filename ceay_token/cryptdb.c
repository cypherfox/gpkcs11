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
 * NAME:        cryptdb.c
 * SYNOPSIS:    -
 * DESCRIPTION: -
 * FILES:       -
 * SEE/ALSO:    -
 * AUTHOR:      lbe
 * BUGS: *      -
 * HISTORY:     $Log$
 * HISTORY:     Revision 1.1.1.1  2000/10/15 16:49:06  cypherfox
 * HISTORY:     import of gpkcs11-0.7.2, first version for SourceForge
 * HISTORY:
 * HISTORY:     Revision 1.14  2000/09/19 09:14:49  lbe
 * HISTORY:     write flag for pin change onto SC, support Auth Pin path
 * HISTORY:
 * HISTORY:     Revision 1.13  2000/07/31 17:40:57  lbe
 * HISTORY:     lockdown for release of protected auth path
 * HISTORY:
 * HISTORY:     Revision 1.12  2000/03/08 09:59:06  lbe
 * HISTORY:     fix SIGBUS in cryptdb, improve readeability for C_FindObject log output
 * HISTORY:
 * HISTORY:     Revision 1.11  2000/02/08 16:12:45  lbe
 * HISTORY:     last changes from beta testers
 * HISTORY:
 * HISTORY:     Revision 1.10  2000/01/31 18:09:00  lbe
 * HISTORY:     lockdown prior to win_gdbm change
 * HISTORY:
 * HISTORY:     Revision 1.9  2000/01/07 10:24:42  lbe
 * HISTORY:     introduce changes for release
 * HISTORY:
 * HISTORY:     Revision 1.8  1999/12/10 16:58:40  jzu
 * HISTORY:     new data-token (2)
 * HISTORY:
 * HISTORY:     Revision 1.7  1999/12/02 16:41:50  lbe
 * HISTORY:     small changes, cosmetics
 * HISTORY:
 * HISTORY:     Revision 1.6  1999/12/01 13:44:45  lbe
 * HISTORY:     debug build system for missing central lib directory and debug afchine changes
 * HISTORY:
 * HISTORY:     Revision 1.5  1999/12/01 11:37:22  lbe
 * HISTORY:     write back changes by afchine
 * HISTORY:
 * HISTORY:     Revision 1.4  1999/11/02 13:47:15  lbe
 * HISTORY:     change of structures and bug fix in slot.c, add more files for tcsc_token: emptyfuncs and general_data
 * HISTORY:
 * HISTORY:     Revision 1.3  1999/10/06 07:57:19  lbe
 * HISTORY:     solved netscape symbol clash problem
 * HISTORY:
 * HISTORY:     Revision 1.2  1999/07/20 17:39:58  lbe
 * HISTORY:     fix bug in gdbm Makefile: there is not allways an 'install' around
 * HISTORY:
 * HISTORY:     Revision 1.1  1999/06/04 14:58:37  lbe
 * HISTORY:     change to libtool/automake complete (except for __umoddi prob)
 * HISTORY:
 * HISTORY:     Revision 1.7  1999/03/18 14:10:21  lbe
 * HISTORY:     entered patches from externals
 * HISTORY:
 * HISTORY:     Revision 1.6  1999/03/01 14:36:44  lbe
 * HISTORY:     merged changes from the weekend
 * HISTORY:
 * HISTORY:     Revision 1.5  1999/01/22 08:35:32  lbe
 * HISTORY:     full build with new perisistant storage complete
 * HISTORY:
 * HISTORY:     Revision 1.4  1999/01/19 12:19:37  lbe
 * HISTORY:     first release lockdown
 * HISTORY:
 * HISTORY:     Revision 1.3  1999/01/19 10:10:19  lbe
 * HISTORY:     pre package clampdown
 * HISTORY:
 * HISTORY:     Revision 1.2  1999/01/18 13:02:33  lbe
 * HISTORY:     swapped Berkeley DB for gdbm
 * HISTORY:
 * HISTORY:     Revision 1.1  1999/01/13 16:15:21  lbe
 * HISTORY:     Initial revision
 * HISTORY:
 */
 
static char RCSID[]="$Id$";
const char* Version_cryptdb_c(){return RCSID;}

#define MIN(a, b) ((b>a)?a:b)
 
/* Stupid Windows-isms */
#ifndef CK_I_library_build
#define  CK_I_library_build
#endif /* CK_I_library_build */

#include "cryptdb.h"
#include "error.h"
#include "string.h"
#include <openssl/sha.h>
#include "assert.h"
#include <openssl/rand.h>

#include <sys/types.h>
#include <time.h>

#ifdef CK_Win32
#include <winsock2.h>
#include <gdbmerrno.h>
#include <gdbm.h>
#else
#include <netinet/in.h>
#include <sys/types.h>
#include <signal.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif /* HAVE_UNISTD_H */
#endif /* !CK_Win32 */

/* Entry types */
#define CDB_E_VERSION 0
#define CDB_E_SO_PIN 1
#define CDB_E_USER_PIN 2
#define CDB_E_OBJECT 3

/* Entry Flags */
/* Entry is encrypted */
#define CDB_F_ENCRYPTED 0x01

/* table flags */
#define CDB_F_TOKEN_EMPTY 0x01

/* 
   Define so's and user's initial PIN 
*/
CK_CHAR_PTR    DefaultPin = "12345678";    /* default so's and user's PIN */  
CK_ULONG       DefPinLen = 8;		   /* length in bytes of the PIN */

/* type byte, flag byte, 20 Byte digest (we are using SHA1) */
/* the pin and version entries only contain the type flag (one byte) */
#define CDB_KEY_LEN   22

/* 20 byte hash + 16 byte salt */ 
#define CDB_SALT_LEN 16 
#define CDB_PIN_DATA_LEN (SHA_DIGEST_LENGTH + CDB_SALT_LEN)

#undef l2c
#define l2c(l,c)        (*((c)++)=(unsigned char)(((l)     )&0xff), \
                         *((c)++)=(unsigned char)(((l)>> 8L)&0xff), \
                         *((c)++)=(unsigned char)(((l)>>16L)&0xff), \
                         *((c)++)=(unsigned char)(((l)>>24L)&0xff))


/* {{{ static CK_RV CDB_ParseObject(CK_CHAR_PTR, CK_ULONG, CK_I_OBJ_PTR CK_PTR) */
static CK_RV CDB_ParseObject(CK_CHAR_PTR buffer, CK_ULONG buff_len, 
			     CK_I_OBJ_PTR CK_PTR new_obj)
{
  CK_ULONG scan_len;
  CK_ATTRIBUTE new_attr={0,NULL,0};
  CK_RV rv = CKR_OK;
  CK_I_OBJ_PTR curr_obj;
  CK_CHAR_PTR read_pos;
  const char* attr_name;
  CK_ULONG attr_size,tmp_ulong;

  /* create a new object */
  rv = CI_ObjCreateObj(&curr_obj);
  if(rv != CKR_OK)
    {
      CI_LogEntry("CDB_ParseObject","Creating new object failed",rv,0);
      return rv;
    }	  
  
  scan_len=0;
  read_pos = buffer;

  while(scan_len<buff_len)
    {
      /* Padding? Then end this */
      if(*read_pos =='#') break;

      /* attribute type */
      tmp_ulong= *((CK_ULONG*)read_pos);
      
      new_attr.type=ntohl(tmp_ulong);
      scan_len+=sizeof(CK_ULONG);
      read_pos+=sizeof(CK_ULONG);
      attr_name= CI_AttributeStr(new_attr.type);

      /* attribure length */
      tmp_ulong= *((CK_ULONG*)read_pos);

      new_attr.ulValueLen=ntohl(tmp_ulong);
      scan_len+=sizeof(CK_ULONG);
      read_pos+=sizeof(CK_ULONG);
      
      /* attribute value */
      new_attr.pValue=realloc(new_attr.pValue, new_attr.ulValueLen);
      if(new_attr.pValue == NULL_PTR) return CKR_HOST_MEMORY;

      memcpy(new_attr.pValue,read_pos,new_attr.ulValueLen);
      scan_len += new_attr.ulValueLen; 
      read_pos += new_attr.ulValueLen; 

      /* insert new data into object */
      CI_VarLogEntry("CDB_ParseObject","Setting Attribute '%s', size %i",
		     rv,1,attr_name,new_attr.ulValueLen);

      rv = CI_ObjSetAttribute(curr_obj,&new_attr);
      if(rv != CKR_OK)
	{
	  CI_ObjDestroyObj(curr_obj);
	  CI_VarLogEntry("CDB_ParseObject","Setting Attribute '%s' failed.",
			 rv,0,attr_name);
	  return rv;
	}

    }

  TC_free(new_attr.pValue);
  
  *new_obj = curr_obj;  
  return rv;
}

/* }}} */
/* {{{ static CK_RV CDB_EncodeObject(CK_I_OBJ_PTR, CK_CHAR_PTR CK_PTR, CK_ULONG CK_PTR) */
static CK_RV CDB_EncodeObject(CK_I_OBJ_PTR pObject, CK_CHAR_PTR CK_PTR ppBuffer, CK_ULONG CK_PTR pBufferLen)
{
  CK_ULONG buff_len=0;
  CK_ATTRIBUTE_PTR curr_attr;
  int i;
  char *write_pos;

#if !defined(CK_Win32) && defined(DEBUG_SIGNAL)
  kill(getpid(),SIGHUP);
#endif 

  /* get size of buffer and malloc */
  for(i=0; i< I_ATT_MAX_NUM ; i++)
    if((curr_attr = CI_ObjLookup( pObject, i )) != NULL)
    {
      buff_len+=sizeof(CK_ATTRIBUTE_TYPE);
      buff_len+=sizeof(CK_ULONG); /* curr_attr->ulValueLen */
      buff_len+=curr_attr->ulValueLen;
    }

  /* space for padding */
  buff_len += 8-(buff_len%8);

  *ppBuffer = TC_malloc(buff_len);
  if(*ppBuffer == NULL_PTR)
    return CKR_HOST_MEMORY;

  /* printf stuff to buffer */
  buff_len =0;
  write_pos=*ppBuffer;

  assert(sizeof(CK_ATTRIBUTE_TYPE) == sizeof(u_long));
  assert(sizeof(CK_ULONG) == sizeof(u_long));

  for(i=0; i< I_ATT_MAX_NUM ; i++)
    if((curr_attr = CI_ObjLookup( pObject, i )) != NULL)
      {
	CK_ULONG tmp_Ulong;

	tmp_Ulong = htonl(curr_attr->type);
	memcpy(write_pos,&tmp_Ulong,sizeof(CK_ULONG));

	write_pos += sizeof(CK_ULONG);
	buff_len+=sizeof(CK_ULONG);

	tmp_Ulong = htonl(curr_attr->ulValueLen);
	memcpy(write_pos,&tmp_Ulong,sizeof(CK_ULONG));

	write_pos += sizeof(CK_ULONG);
	buff_len+=sizeof(CK_ULONG);

	memcpy(write_pos,curr_attr->pValue,curr_attr->ulValueLen);
	buff_len+=curr_attr->ulValueLen;
	write_pos+=curr_attr->ulValueLen;
      }

  /* insert padding */
  if(buff_len%8 != 0) 
    {
      int len = 8 - (buff_len%8);
      memcpy(&((*ppBuffer)[buff_len]),"#######",len);
      buff_len += len;
    }

  *pBufferLen = buff_len;

  return CKR_OK;
}
/* }}} */

/* {{{ CK_I_CRYPT_DB_PTR CDB_Open(CK_CHAR_PTR file_name) */
CK_I_CRYPT_DB_PTR CDB_Open(CK_CHAR_PTR file_name)
{
  CK_I_CRYPT_DB_PTR retval;

  retval = TC_malloc(sizeof(CK_I_CRYPT_DB));
  if(retval == NULL_PTR)
    {
      CI_LogEntry("CDB_Open","not enough memory",CKR_HOST_MEMORY ,0);
      return NULL_PTR;
    }
  memset(retval, 0, sizeof(CK_I_CRYPT_DB));

  retval->table = gdbm_open(file_name, 0 /* use system default */, 
			    GDBM_WRCREAT, 0600, NULL_PTR);
  if(retval->table == NULL_PTR)
    {
      CI_VarLogEntry("CDB_Open","failure to open table '%s': %s",
		     CKR_GENERAL_ERROR ,0, 
		     file_name, gdbm_strerror(gdbm_errno));
      TC_free(retval);

      return NULL_PTR;      
    }

   /*
    * If the db has not yet been created, then create it with 
    * default pin set.
    * Initialize user's token with pin "12345678" 
    */
  if (CDB_PinExists(retval, FALSE) == CKR_USER_PIN_NOT_INITIALIZED)
    {
      /* Initialize token and user pin */
      CDB_NewPin(retval, TRUE, NULL, 0, DefaultPin, DefPinLen); //SO's Pin
      CDB_NewPin(retval, FALSE, NULL, 0, DefaultPin, DefPinLen); //User's Pin
    }

  return retval;
}
/* }}} */
/* {{{ CK_RV CDB_Close(CK_I_CRYPT_DB_PTR cdb) */
CK_RV CDB_Close(CK_I_CRYPT_DB_PTR cdb)
{
  gdbm_close(cdb->table);
  cdb->table = NULL_PTR;
  
  return CKR_OK;
}
/* }}} */

/* {{{ CK_RV CDB_CheckPin(CK_I_CRYPT_DB_PTR, CK_BBOOL, CK_CHAR_PTR, CK_ULONG) */
CK_BBOOL CDB_CheckPin(CK_I_CRYPT_DB_PTR cdb, CK_BBOOL so_pin, 
		      CK_CHAR_PTR pin , CK_ULONG pinLen)
{
  datum data, key;
  SHA_CTX ctx;
  unsigned char hash[SHA_DIGEST_LENGTH];

  key.dsize = 1;
  key.dptr = TC_malloc(1);

  if(so_pin)
    key.dptr[0] = CDB_E_SO_PIN;
  else
    key.dptr[0] = CDB_E_USER_PIN;
  
  data = gdbm_fetch(cdb->table, key);
  if(data.dptr == NULL_PTR)
    {
      return CKR_PIN_INCORRECT;
    }

  /*
   * 1. Read Salt from data.dptr[20-35] first
   * 2. doing CI_Ceay_SHA1_Update(&ctx, salt, CDB_SALT_LEN)
   * 3. compare to hash and data.dptr[0-19]
   */
  CI_Ceay_SHA1_Init(&ctx);
  CI_Ceay_SHA1_Update(&ctx, &data.dptr[SHA_DIGEST_LENGTH], CDB_SALT_LEN);
  CI_Ceay_SHA1_Update(&ctx, pin, pinLen);
  CI_Ceay_SHA1_Final(hash,&ctx);
  
  if(memcmp(data.dptr, hash, SHA_DIGEST_LENGTH) == 0)
    {
      if (so_pin == TRUE)
	cdb->flags |= CK_I_CDB_F_SO_PIN_SET;
      else
	cdb->flags |= CK_I_CDB_F_USER_PIN_SET;
      return CKR_OK;
    }

  TC_free(key.dptr);

  return CKR_PIN_INCORRECT;
}
/* }}} */
/* {{{ CK_RV CDB_NewPin(CK_I_CRYPT_DB_PTR,CK_BBOOL,CK_CHAR_PTR,CK_ULONG,CK_CHAR_PTR,CK_ULONG) */
CK_RV CDB_NewPin(CK_I_CRYPT_DB_PTR cdb, CK_BBOOL so_pin, 
		 CK_CHAR_PTR old_pin, CK_ULONG old_pinLen, 
		 CK_CHAR_PTR new_pin, CK_ULONG new_pinLen)
{
  CK_RV rv = CKR_OK;
  datum data, key;
  SHA_CTX ctx;
  unsigned char salt[CDB_SALT_LEN];
  unsigned char seed[4], *seed_ptr;
  long time_val; 
  CK_CHAR_PTR crypt_key = NULL_PTR;

  key.dsize = 1;
  key.dptr = TC_malloc(1);

  if (old_pin != NULL_PTR)
    {
      if(CDB_CheckPin(cdb, so_pin, old_pin, old_pinLen))
	return CKR_PIN_INCORRECT;
    }
  else
    {
     if(so_pin && !(cdb->flags & CDB_F_TOKEN_EMPTY))
       return CKR_GENERAL_ERROR;
   }
  
  if(so_pin)
    key.dptr[0] = CDB_E_SO_PIN;
  else
    key.dptr[0] = CDB_E_USER_PIN;
  
  data.dsize = CDB_PIN_DATA_LEN;
  data.dptr =TC_malloc(CDB_PIN_DATA_LEN);

  if(data.dptr == NULL_PTR)
    {
      rv = CKR_GENERAL_ERROR;
      goto newPin_err;
    }

  time_val = time(NULL_PTR);

  seed_ptr = seed;
  l2c(time_val, seed_ptr);

  CI_Ceay_RAND_seed(seed,sizeof(long));
  CI_Ceay_RAND_bytes(salt, CDB_SALT_LEN);

  CI_Ceay_SHA1_Init(&ctx);
  CI_Ceay_SHA1_Update(&ctx, salt, CDB_SALT_LEN);
  CI_Ceay_SHA1_Update(&ctx, new_pin, new_pinLen);
  CI_Ceay_SHA1_Final(data.dptr,&ctx);
  
  memcpy(&(data.dptr[SHA_DIGEST_LENGTH]), salt, CDB_SALT_LEN);

  if( gdbm_store(cdb->table, key, data, GDBM_REPLACE) != 0)
    {
      rv = CKR_GENERAL_ERROR;
      goto newPin_err;
    }

  if (old_pin != NULL_PTR)
    {
      /*get last random generated encrypted key*/
      crypt_key = CDB_GetRndPin(cdb, old_pin, old_pinLen);
      /*generate a random encrypt key to encrypt db objects*/
      CDB_RndPin(cdb, &crypt_key, new_pin, new_pinLen);
    }
  else
    CDB_RndPin(cdb, &crypt_key, new_pin, new_pinLen); 
  
  TC_free(crypt_key);  

 newPin_err:
  TC_free(key.dptr);
  TC_free(data.dptr);
    
  return CKR_OK;
}
/* }}} */
/* {{{ CK_RV CDB_SetPin(CK_I_CRYPT_DB_PTR, CK_BBOOL, CK_CHAR_PTR, CK_ULONG) */
CK_RV CDB_SetPin(CK_I_CRYPT_DB_PTR cdb, CK_BBOOL so_pin, CK_CHAR_PTR pin, CK_ULONG pinLen)
{
  CK_CHAR tmp_key_block[24];
  des_key_schedule *tmp_key_sched;

  if(so_pin)
    {
      tmp_key_sched = cdb->so_key_sched;
      cdb->flags |= CK_I_CDB_F_SO_PIN_SET;
    }
  else
    {
      tmp_key_sched = cdb->user_key_sched;
      cdb->flags |= CK_I_CDB_F_USER_PIN_SET;
    }

  memset(tmp_key_block,'#',24);
  memcpy(tmp_key_block,pin,MIN(pinLen,24)); /* space of three des blocks */
  
  des_set_odd_parity((des_cblock*)&(tmp_key_block[0]));
  des_set_odd_parity((des_cblock*)&(tmp_key_block[8]));
  des_set_odd_parity((des_cblock*)&(tmp_key_block[16]));
  
  des_set_key((des_cblock*)&(tmp_key_block[0]) ,tmp_key_sched[0]);
  des_set_key((des_cblock*)&(tmp_key_block[8]) ,tmp_key_sched[1]);
  des_set_key((des_cblock*)&(tmp_key_block[16]),tmp_key_sched[2]);

  return CKR_OK;
}
/* }}} */

/* {{{ CK_RV CDB_GetObjectInit(CK_I_CRYPT_DB_PTR cdb) */
CK_RV CDB_GetObjectInit(CK_I_CRYPT_DB_PTR cdb)
{
  cdb->old_key = gdbm_firstkey(cdb->table);
  if(cdb->old_key.dptr == NULL_PTR)
    return CKR_GENERAL_ERROR;

  return CKR_OK;
} 
/* }}} */
/* {{{ CK_RV CDB_GetObjectUpdate(CK_I_CRYPT_DB_PTR cdb, CK_I_OBJ_PTR CK_PTR next_obj) */
CK_RV CDB_GetObjectUpdate(CK_I_CRYPT_DB_PTR cdb, CK_I_OBJ_PTR CK_PTR next_obj)
{
  CK_RV rv = CKR_OK;
  datum data;
  des_cblock ivec;
  CK_CHAR_PTR crypt_buffer;
  CK_ATTRIBUTE key_attrib;

  do {
    /* get the object */
    if(cdb->old_key.dptr == NULL_PTR)
      {
	*next_obj = NULL_PTR;
	CI_LogEntry("CDB_Open","no further objects",
		    CKR_OK ,0);
	return CKR_OK; /* the calling code must check for the empty obj */
      }
    
    data = gdbm_fetch(cdb->table, cdb->old_key);
    if(data.dptr == NULL_PTR)
      {
	CI_VarLogEntry("CDB_Open","failure to fetch next entry: %s",
		       CKR_GENERAL_ERROR ,0, 
		       gdbm_strerror(gdbm_errno));
	*next_obj = NULL_PTR;
	
	return CKR_GENERAL_ERROR;            
      }
    
    if (cdb->old_key.dptr[0] == CDB_E_OBJECT)
      {
	
	/* decrypt object into a string */
	if(data.dsize%8 != 0)
	  {
	    rv = CKR_GENERAL_ERROR;
	    CI_VarLogEntry("CDB_GetObjectUpdate","data.size (%d) %% 8 != 0",
			   rv,0,data.dsize);
	    return rv; 
	  }
	if(data.dsize == 0)
	  {
	    rv = CKR_GENERAL_ERROR;
	    CI_VarLogEntry("CDB_GetObjectUpdate","data.size (%d) == 0",
			   rv,0,data.dsize);
	    return rv; 
	  }
	
	crypt_buffer = malloc(data.dsize);
	if(crypt_buffer == NULL_PTR)
	  return CKR_HOST_MEMORY;
	
	/* set the ivec */
	memcpy(ivec,"A Secret",8);
  
	if(((CK_CHAR_PTR)cdb->old_key.dptr)[1]&CDB_F_ENCRYPTED)
	  {
	    /* check that the pin is provided */
	    if(! cdb->flags & CK_I_CDB_F_USER_PIN_SET)
	      {
		rv = CKR_USER_NOT_LOGGED_IN;
		CI_VarLogEntry("CDB_GetObjectUpdate","User pin not set for decryption",rv,0);
		return rv;
	      }
	    /* decode the stuff */
	    des_ede3_cbc_encrypt(data.dptr,
				 crypt_buffer,
				 data.dsize,
				 cdb->user_key_sched[0],
				 cdb->user_key_sched[1],
				 cdb->user_key_sched[2],
				 &(ivec),
				 0); /* no encrypt */
	  }
	else
	  {
	    crypt_buffer = data.dptr;
	  }
	
	/* parse into structure */
	rv =CDB_ParseObject(crypt_buffer,data.dsize,next_obj);
	if(rv != CKR_OK)
	  return rv;
	
	/* add key to structure */
	key_attrib.type = CKA_PERSISTENT_KEY;
	key_attrib.pValue = cdb->old_key.dptr;
	key_attrib.ulValueLen = cdb->old_key.dsize;
	
	rv = CI_ObjSetAttribute(*next_obj,&key_attrib);
	if(rv != CKR_OK)
	  {
	    CI_ObjDestroyObj(*next_obj);
	    CI_VarLogEntry("CDB_GetObjectUpdate","Setting Attribute '%s' failed.",
			   rv,0,CI_AttributeStr(key_attrib.type));
	    return rv;
	  }
	
	/* advance the key one element */
	cdb->old_key = gdbm_nextkey(cdb->table, cdb->old_key);
	
	break;
      }
    
    /* advance the key one element */
    cdb->old_key = gdbm_nextkey(cdb->table, cdb->old_key);
    /* no error check yet, as there is an object, but the test at the
     * start of the next invocation will fail and report the lack of
     * further objects */
  }while (TRUE);
  
  return CKR_OK;
  
}
/* }}} */
/* {{{ CK_RV CDB_GetObjectFinal(CK_I_CRYPT_DB_PTR cdb) */
CK_RV CDB_GetObjectFinal(CK_I_CRYPT_DB_PTR cdb)
{
  return CKR_OK;
}
/* }}} */

/* {{{ CK_RV CDB_PutObject(CK_I_CRYPT_DB_PTR cdb, CK_I_OBJ_PTR new_obj) */
CK_RV CDB_PutObject(CK_I_CRYPT_DB_PTR cdb, CK_I_OBJ_PTR new_obj)
{
  datum key, data;
  CK_RV rv = CKR_OK;
  CK_CHAR_PTR obj_buffer;

  CK_ULONG buff_len;
  CK_CHAR key_data[CDB_KEY_LEN]; 

  /* generate a one-line format of the object */
  rv = CDB_EncodeObject(new_obj, &obj_buffer, &buff_len);
  if(rv != CKR_OK)
    return rv;

  /* generate a key */
  CI_Ceay_SHA1(obj_buffer,buff_len,&(key_data[2]));
  key_data[0]= CDB_E_OBJECT;
  key_data[1]= 0;
  
  /* optionally encrypt the object. This is only nessecary on private objects */
  if((CI_ObjLookup(new_obj ,CK_IA_PRIVATE) != NULL_PTR) &&
     (*((CK_BBOOL CK_PTR)(CI_ObjLookup(new_obj ,CK_IA_PRIVATE)->pValue)) == TRUE ))
    {
      CK_CHAR_PTR tmp_buffer;
      des_cblock ivec;

      assert(buff_len%8 == 0);

      tmp_buffer = TC_malloc(buff_len);
      if(tmp_buffer == NULL_PTR) 
	{
	  free(obj_buffer);
	  return CKR_HOST_MEMORY;
	}
			  
      /* set the ivec */
      memcpy(ivec,"A Secret",8);
  
      des_ede3_cbc_encrypt(obj_buffer,
			   tmp_buffer,
			   buff_len,
			   cdb->user_key_sched[0], 
			   cdb->user_key_sched[1], 
			   cdb->user_key_sched[2],
			   &ivec,
			   1); /* do encrypt */

      TC_free(obj_buffer);
      obj_buffer = tmp_buffer;

      key_data[1]|=CDB_F_ENCRYPTED;
    }

  /* write the key/data to the database */
  key.dsize= CDB_KEY_LEN;
  key.dptr= key_data;

  data.dsize= buff_len;
  data.dptr= obj_buffer;

  if(gdbm_store(cdb->table,key,data,GDBM_REPLACE) != 0)
    {
      CI_VarLogEntry("CDB_GetObjectFinal","could not insert data:%s",
		     rv,0,gdbm_strerror(gdbm_errno));
      return CKR_GENERAL_ERROR;
    }

  /* put the key into the object */
  CI_ObjSetIntAttributeValue(new_obj,CK_IA_PERSISTENT_KEY, key_data, CDB_KEY_LEN);

  /* clean up */
  TC_free(obj_buffer);

  return CKR_OK;
}
/* }}} */

/* {{{ CK_RV CDB_DeleteObject(CK_I_CRYPT_DB_PTR cdb, CK_I_OBJ_PTR new_obj) */
CK_RV CDB_DeleteObject(CK_I_CRYPT_DB_PTR cdb, CK_I_OBJ_PTR new_obj)
{
  datum key;
  CK_RV rv = CKR_OK;
  CK_CHAR key_buff[CDB_KEY_LEN];
  CK_ULONG buff_len=CDB_KEY_LEN;

  /* get the key */
  rv = CI_ObjGetIntAttributeValue(new_obj, CK_IA_PERSISTENT_KEY, key_buff, &buff_len);
  if(rv != CKR_OK)
    return rv;

  /* create the key-DBT */
  key.dptr = key_buff;
  key.dsize = CDB_KEY_LEN;

  /* delete the object */
  if(gdbm_delete(cdb->table, key) != 0)
    {
      CI_VarLogEntry("CDB_GetObjectFinal","could not remove data:%s",
		     rv,0,gdbm_strerror(gdbm_errno));
      return CKR_GENERAL_ERROR;
    }

  return CKR_OK;
}
/* }}} */

/* {{{ CK_RV CDB_UpdateObject(CK_I_CRYPT_DB_PTR cdb, CK_I_OBJ_PTR new_obj) */
CK_RV CDB_UpdateObject(CK_I_CRYPT_DB_PTR cdb, CK_I_OBJ_PTR new_obj)
{
  CK_RV rv = CKR_OK;

  /* delete the old object */
  /* will only manipulate the entry in the database, not the object in mem */
  rv = CDB_DeleteObject(cdb,new_obj);
  if(rv != CKR_OK)
    return rv;

  /* create the object again with the new data */
  rv = CDB_PutObject(cdb,new_obj);
  /* we will close anyway */

  return rv;
}
/* }}} */

/* {{{ CK_RV CDB_DeleteAllObjects(CK_I_CRYPT_DB_PTR cdb) */
CK_RV CDB_DeleteAllObjects(CK_I_CRYPT_DB_PTR cdb)
{
  CK_RV rv = CKR_OK;
  int ret;

  while(1)
    {
      /* deleting invalidate the hashtable, thus we have to find the beginning each time */
      cdb->old_key = gdbm_firstkey(cdb->table);
      if(cdb->old_key.dptr == NULL_PTR)
	{
	  rv = CKR_OK;
	  CI_LogEntry("CDB_Open","no find first key in table",
		      rv ,0);

	  break;
	}

      /* get the object */
      if(cdb->old_key.dptr == NULL_PTR)
	{
	  rv = CKR_OK;
	  CI_LogEntry("CDB_Open","no further objects",
		      rv ,0);
	  break;
	}
      
      ret = gdbm_delete(cdb->table, cdb->old_key);
      if(ret != 0)
	{
	  rv = CKR_GENERAL_ERROR;
	  CI_VarLogEntry("CDB_Open","failure to delete next entry: %s",
			 rv ,0, 
			 gdbm_strerror(gdbm_errno));
	  return rv;
	}
      
    }

  /* set the flag that the database is clean. Now a new SO-PIN may be set */
  cdb->flags |= CDB_F_TOKEN_EMPTY;

  return CKR_OK;
}
/* }}} */

/* {{{ CK_RV CDB_PinExists(CK_I_CRYPT_DB_PTR cdb, CK_BBOOL so_pin) */
/* Check if it is a newly created db  */
CK_RV CDB_PinExists(CK_I_CRYPT_DB_PTR cdb, CK_BBOOL so_pin)
{
  datum key;
  char buf;

  key.dsize = 1;
  key.dptr = &buf;

  if(so_pin)
    key.dptr[0] = CDB_E_SO_PIN;
  else
    key.dptr[0] = CDB_E_USER_PIN;
  
  if (!gdbm_exists(cdb->table, key))
    return CKR_USER_PIN_NOT_INITIALIZED;

  return CKR_OK;
} 
/* }}} */

/* {{{ CK_RV CDB_GetPrivObject(CK_I_CRYPT_DB_PTR cdb, CK_I_OBJ_PTR CK_PTR next_obj) */
/*
  The same as CDB_GetObjectUpdate, but it "only" gets private objects out of the db
  USAGE: after user login
  For what I tested so far, certificates are invisible to users in Netscape
  This is because all private objects are encoded by user's pin. If a user is not login,
  the private objects won't be able to be loaded and decoded to the cache memory.in 
  Ceay_ReadPersistent 
*/
CK_RV CDB_GetPrivObject(CK_I_CRYPT_DB_PTR cdb, CK_I_OBJ_PTR CK_PTR next_obj)
{
  CK_RV rv = CKR_OK;
  datum data;
  des_cblock ivec;
  CK_CHAR_PTR crypt_buffer;
  CK_ATTRIBUTE key_attrib;

  do 
  {
    /* get the object */
    if(cdb->old_key.dptr == NULL_PTR)
      {
		*next_obj = NULL_PTR;
		CI_LogEntry("CDB_Open","no further objects", CKR_OK ,0);
		return CKR_OK;
      }

     if(cdb->old_key.dptr[0] == CDB_E_OBJECT && (((CK_CHAR_PTR)cdb->old_key.dptr)[1] & CDB_F_ENCRYPTED))
		break;

     cdb->old_key = gdbm_nextkey(cdb->table, cdb->old_key);
  } while (TRUE);

  data = gdbm_fetch(cdb->table, cdb->old_key);
  if(data.dptr == NULL_PTR)
  {
	CI_VarLogEntry("CDB_Open","failure to fetch next entry: %s",
		       CKR_GENERAL_ERROR ,0, 
		       gdbm_strerror(gdbm_errno));
	*next_obj = NULL_PTR;
	
	return CKR_GENERAL_ERROR; 
  }

  /* decrypt object into a string */
  if(data.dsize%8 != 0)
    {
      rv = CKR_GENERAL_ERROR;
      CI_VarLogEntry("CDB_GetPriObject","data.size (%d) %% 8 != 0",
		     rv,0,data.dsize);
      return rv; 
    }
  if(data.dsize == 0)
    {
      rv = CKR_GENERAL_ERROR;
      CI_VarLogEntry("CDB_GetPriObject","data.size (%d) == 0",
		     rv,0,data.dsize);
      return rv; 
    }

  crypt_buffer = malloc(data.dsize);
  if(crypt_buffer == NULL_PTR)
    return CKR_HOST_MEMORY;
  
  /* set the ivec */
  memcpy(ivec,"A Secret",8);
  
 /* check that the pin is provided */
	if(! (cdb->flags & CK_I_CDB_F_USER_PIN_SET))
	{
	  rv = CKR_USER_NOT_LOGGED_IN;
	  CI_VarLogEntry("CDB_GetPriObject","User pin not set for decryption",rv,0);
	  return rv;
	}
    /* decode the stuff */
	  des_ede3_cbc_encrypt(data.dptr, //Piling, 1999/12/02
			   crypt_buffer, //Piling, 1999/12/02
			   data.dsize,
			   cdb->user_key_sched[0],
			   cdb->user_key_sched[1],
			   cdb->user_key_sched[2],
			   &(ivec),
			   0); /* no encrypt */

  /* parse into structure */
  rv =CDB_ParseObject(crypt_buffer,data.dsize,next_obj);
  if(rv != CKR_OK)
    return rv;
  
  /* add key to structure */
  key_attrib.type = CKA_PERSISTENT_KEY;
  key_attrib.pValue = cdb->old_key.dptr;
  key_attrib.ulValueLen = cdb->old_key.dsize;
  
  rv = CI_ObjSetAttribute(*next_obj,&key_attrib);
  if(rv != CKR_OK)
    {
      CI_ObjDestroyObj(*next_obj);
      CI_VarLogEntry("CDB_GetPriObject","Setting Attribute '%s' failed.",
		     rv,0,CI_AttributeStr(key_attrib.type));
      return rv;
    }

  cdb->old_key = gdbm_nextkey(cdb->table, cdb->old_key);
  return CKR_OK; 
}
/* }}} */

/* {{{ CK_RV CDB_RndPin(CK_CHAR_PTR,CK_ULONG) */
/* Random generate a key to encrypt 
   private objects */
CK_RV CDB_RndPin(CK_I_CRYPT_DB_PTR cdb, CK_CHAR_PTR CK_PTR crypt_key, CK_CHAR_PTR pin, CK_ULONG pinLen)
{
  CK_CHAR tmp_key_block[24];
  des_key_schedule tmp_key_sched[3];
  datum data, key;
  unsigned char seed[sizeof(long)], *seed_ptr;
  long time_val; 
  des_cblock ivec;
  
  CI_LogEntry("CDB_RndPin","starting...", 0 ,0);

  //random key index
  key.dptr = "prnd";
  key.dsize = strlen(key.dptr);

  data.dsize = sizeof(tmp_key_block);
  data.dptr =TC_malloc(data.dsize);
  if(data.dptr == NULL_PTR)
		return CKR_GENERAL_ERROR;
 
  memset(tmp_key_block,'#', 24);
  memcpy(tmp_key_block,pin,MIN(pinLen, 24)); /* space of three des blocks */
  
  des_set_odd_parity((des_cblock*)&(tmp_key_block[0]));
  des_set_odd_parity((des_cblock*)&(tmp_key_block[8]));
  des_set_odd_parity((des_cblock*)&(tmp_key_block[16]));
  
  des_set_key((des_cblock*)&(tmp_key_block[0]) ,tmp_key_sched[0]);
  des_set_key((des_cblock*)&(tmp_key_block[8]) ,tmp_key_sched[1]);
  des_set_key((des_cblock*)&(tmp_key_block[16]),tmp_key_sched[2]);

  if (*crypt_key == NULL_PTR)
  {
    *crypt_key = TC_malloc(data.dsize);
    time_val = time(NULL_PTR);
    seed_ptr = seed;
    l2c(time_val, seed_ptr);
    
    CI_Ceay_RAND_seed(seed,sizeof(long));
    CI_Ceay_RAND_bytes(*crypt_key, data.dsize);
  }

  /* set the ivec */
  memcpy(ivec,"A Secret",8);

  des_ede3_cbc_encrypt(*crypt_key,
		       data.dptr,
		       data.dsize,
		       tmp_key_sched[0],
		       tmp_key_sched[1],
		       tmp_key_sched[2],
		       &(ivec),
		       1); /* encrypt */
  
  if( gdbm_store(cdb->table, key, data, GDBM_REPLACE) != 0)
  {
    TC_free(data.dptr);
    return CKR_GENERAL_ERROR;   
  }
  
  TC_free(data.dptr);
  
  CI_LogEntry("CDB_RndPin","finished...", 0 ,0);	  
  return CKR_OK;
}
/* }}} */

/* {{{ CK_CHAR_PTR CDB_GetRndPin(CK_I_CRYPT_DB_PTR, CK_CHAR_PTR, CK_ULONG) */
CK_CHAR_PTR CDB_GetRndPin(CK_I_CRYPT_DB_PTR cdb,CK_CHAR_PTR pin, CK_ULONG pinLen)
{ 
  CK_CHAR rnd_key_block[24];
  des_key_schedule rnd_key_sched[3];
  datum key;
  datum data;
  des_cblock ivec;
  CK_CHAR_PTR crypt_buffer;

  CI_LogEntry("CDB_GetRndPin","starting...", 0 ,0);

  //random key index
  key.dptr = "prnd";
  key.dsize = strlen("prnd");

  /* Piling, 2000/01/04, fetch encrypt key */
  data = gdbm_fetch(cdb->table, key);

  crypt_buffer = TC_malloc(data.dsize);
  if(crypt_buffer == NULL_PTR)
    return NULL_PTR;
  
  /* set the ivec */
  memcpy(ivec,"A Secret",8);
  
  memset(rnd_key_block,'#',24);
  memcpy(rnd_key_block,pin,MIN(pinLen,24)); /* space of three des blocks */

  des_set_odd_parity((des_cblock*)&(rnd_key_block[0]));
  des_set_odd_parity((des_cblock*)&(rnd_key_block[8]));
  des_set_odd_parity((des_cblock*)&(rnd_key_block[16]));

  des_set_key((des_cblock*)&(rnd_key_block[0]) ,rnd_key_sched[0]);
  des_set_key((des_cblock*)&(rnd_key_block[8]) ,rnd_key_sched[1]);
  des_set_key((des_cblock*)&(rnd_key_block[16]),rnd_key_sched[2]);
  
  des_ede3_cbc_encrypt(data.dptr, 
			   crypt_buffer, 
			   data.dsize,
			   rnd_key_sched[0],
			   rnd_key_sched[1],
			   rnd_key_sched[2],
			   &(ivec),
			   0); /* no encrypt */

  CI_LogEntry("CDB_GetRndPin","finished...", 0 ,0);
  return crypt_buffer;
}
/* }}} */

/*
 * Local variables:
 * folded-file: t
 * end:
 */
