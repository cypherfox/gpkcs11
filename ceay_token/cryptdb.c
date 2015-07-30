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
//#include <winsock2.h>
#include <winsock.h>
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

#include "CI_Ceay.h"

/**
Entry types
*/
/// Version of
#define CDB_E_VERSION			0
/// Security officer PIN
#define CDB_E_SO_PIN			1
/// User PIN
#define CDB_E_USER_PIN		2
/// Crypto object like private, public or secret key
#define CDB_E_OBJECT			3
/// Token information in PKCS#11 structure CK_TOKEN_INFO
#define CDB_E_TOKEN_INFO	4

/**
Entry Flags
*/
/// Entry is encrypted
#define CDB_F_ENCRYPTED 0x01

/**
Table flags
*/
/**
@brief Token is empty

This flag is strange.
<ol>
  <li>It is was originally only set at the end of CDB_DeleteAllObjects.</li>
  <li>It was never reset at any storing function like CDB_NewPin or
      CDB_PutTokenInformation or CDB_PutObject.</li>
  <li>It is checked in CDB_NewPin, if a default SO PIN should be set and the
      token is not empty.
</ol>

@todo Remove this flag or handle it correct.
*/
#define CDB_F_TOKEN_EMPTY 0x01

/* 
   Define so's and user's initial PIN 
*/
CK_CHAR_PTR    DefaultPin    = "12345678";
CK_ULONG       DefaultPinLen = 8;

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

/**
@todo Check return values of all functions in context of CDB failures to CKR_HOST_MEMORY.
*/


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
  CK_ULONG tmp_ulong;

  CI_LogEntry("CDB_ParseObject","starting...",rv,2);
  
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
      if (new_attr.ulValueLen > 0)
      {
        new_attr.pValue=realloc(new_attr.pValue, new_attr.ulValueLen);
        if(new_attr.pValue == NULL_PTR) 
        {
          rv = CKR_HOST_MEMORY;
          CI_VarLogEntry("CDB_ParseObject","Setting Attribute '%s' failed. Faild at allocation of %d bytes of memory",
  			    rv,0,attr_name, new_attr.ulValueLen);
          return rv;
        }
      }

      memcpy(new_attr.pValue,read_pos,new_attr.ulValueLen);
      scan_len += new_attr.ulValueLen; 
      read_pos += new_attr.ulValueLen; 

      /* insert new data into object */
      CI_VarLogEntry("CDB_ParseObject","Setting Attribute '%s', size %i",
		     rv,2,attr_name,new_attr.ulValueLen);

      rv = CI_ObjSetAttribute(curr_obj,&new_attr);
      if(rv != CKR_OK)
	{
	  CI_ObjDestroyObj(curr_obj);
	  CI_VarLogEntry("CDB_ParseObject","Setting Attribute '%s' failed.",
			 rv,0,attr_name);
	  return rv;
	}

    }

  free(new_attr.pValue);
  
  *new_obj = curr_obj;  
  CI_LogEntry("CDB_ParseObject","... complete",rv,2);
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

#if !defined(CK_Win32) && !defined(DEBUG_SIGNAL)
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

/**
@fn CK_I_CRYPT_DB_PTR CDB_Create (CK_CHAR_PTR)

If the db has not yet been created, then create it with 
default pin set. Initialize user's token with pin "12345678"

@returns
<dl>
  <dt>Pointer to the database:</dt>
  <dd>if the database could be successfully created</dd>
  <dt>NULL_PTR:</dt>
  <dd>otherwise</dd>
</dl>

@todo Check wether gdbm_open(..., GDBM_NEWDB, ...) overwrites an existing
database file. If it does remove the CDB_PinExists calls.
*/

CK_I_CRYPT_DB_PTR CDB_Create(CK_CHAR_PTR file_name ///< [in] File name of the existing database
                             )
{
  CK_I_CRYPT_DB_PTR retval;

  retval = TC_malloc(sizeof(CK_I_CRYPT_DB));
  if(retval == NULL_PTR)
    {
      CI_LogEntry("CDB_Create","not enough memory",CKR_HOST_MEMORY ,0);
      return NULL_PTR;
    }
  memset(retval, 0, sizeof(CK_I_CRYPT_DB));

  retval->table = gdbm_open(file_name, 0 /* use system default */, 
			    GDBM_NEWDB, 0600, NULL_PTR);
  if(retval->table == NULL_PTR)
    {
      CI_VarLogEntry("CDB_Create","failure to create table '%s': %s",
		     CKR_GENERAL_ERROR ,0, 
		     file_name, gdbm_strerror(gdbm_errno));
      TC_free(retval);

      return NULL_PTR;      
		}
	retval->flags |= CDB_F_TOKEN_EMPTY;	

  /* Initialize user pin */
  if (CDB_PinExists(retval, CK_FALSE) == CKR_USER_PIN_NOT_INITIALIZED)
    {
      CDB_NewPin(retval, CK_FALSE, NULL, 0, DefaultPin, DefaultPinLen);
    }

  /* Initialize token pin */
  if (CDB_PinExists(retval, CK_TRUE) == CKR_USER_PIN_NOT_INITIALIZED)
    {
      CDB_NewPin(retval, CK_TRUE, NULL, 0, DefaultPin, DefaultPinLen);
    }

  return retval;
}

/* }}} */

/**
CK_I_CRYPT_DB_PTR CDB_Open(CK_CHAR_PTR, int)

The function opens an existing database file either in
<ul>
  <li>read-only mode (open_mode=GDBM_READER)
  <li>read-write mode (open_mode=GDBM_WRITER)
</ul>

CDB_Open() uses the system default for block size (STATBLKSIZE) to open the
database.

@note The database can only be opened in read-write mode if the underlying file
system is read-writable. A read-only mode exists for e.g. CD-ROMs or is
possible for network shares. This is possible for the database file itself or
the containing directory.

@returns The function returns the pointer of the database structure. In case of
one of the following errors it returns a NULL_PTR:
<ol>
  <li>the database does not exist
  <li>the opening mode is not valid
  <li>the requested opening mode (GDBM_WRITER) is not supportable, because the
      file system is read-only
</ol>
*/

CK_I_CRYPT_DB_PTR CDB_Open(CK_CHAR_PTR file_name, ///< [in] File name of the existing database
                           int         open_mode  ///< [in] Opening mode for database {GDBM_READER, GDBM_WRITER}
                           )
{
  CK_I_CRYPT_DB_PTR retval;

  retval = TC_malloc(sizeof(CK_I_CRYPT_DB));
  if(retval == NULL_PTR)
    {
      CI_LogEntry("CDB_Open","not enough memory",CKR_HOST_MEMORY ,0);
      return NULL_PTR;
    }
  memset(retval, 0, sizeof(CK_I_CRYPT_DB));

  // first check if there is a database file. if not, we don't want to create one!
  retval->table = gdbm_open(file_name, 0, GDBM_READER, 0600, NULL_PTR);
  if (retval->table == NULL_PTR)
    {
    TC_free(retval);
    return NULL_PTR;
    }
  gdbm_close(retval->table);

  // check if there is an valid open_mode
  if ((open_mode!=GDBM_READER) && (open_mode!=GDBM_WRITER))
    {
    return NULL_PTR;
    }

  // open the database file
  retval->table = gdbm_open(file_name, 0, open_mode, 0600, NULL_PTR);
  if(retval->table == NULL_PTR)
    {
      CI_VarLogEntry("CDB_Open","failure to open table '%s': %s",
		     CKR_GENERAL_ERROR ,0, 
		     file_name, gdbm_strerror(gdbm_errno));
      TC_free(retval);

      return NULL_PTR;      
    }
	return retval;
}


/**
@fn CK_RV CDB_Close (CK_I_CRYPT_DB_PTR)

The function closes the database file and resets the database table entry.

@return
<dl>
  <dt>CKR_OK:</dt>
  <dd>always</dd>
</dl>
*/

CK_RV CDB_Close (CK_I_CRYPT_DB_PTR cdb ///< [in] Pointer of the database structure
                 )
{
  gdbm_close(cdb->table);
  cdb->table = NULL_PTR;
  
  return CKR_OK;
}


/**
@fn CK_BBOOL CDB_IsFileReadOnly (CK_CHAR_PTR)

Assumes the given database file is existing.
A read-only database file is either in a parent folder with read-only
attributes or has read-only attribute itself.

@returns
<dl>
  <dt>CK_TRUE:</dt>
  <dd>if the given database file is read-only in file system. This valid, too for not existing files.</dd>
  <dt>CK_FALSE:</dt>
  <dd>if the given database file is writeable in file system.
</dl>
*/

CK_BBOOL CDB_IsFileReadOnly (CK_CHAR_PTR file_name ///< [in] File name of the existing database
                             )
{
  FILE* pfile;
  pfile = fopen (file_name, "rb");
  if (pfile==NULL)
    {
    CI_VarLogEntry("CDB_IsFileReadOnly","failure to open database file '%s'", CKR_TOKEN_NOT_PRESENT, 0, file_name);
    return CK_TRUE;
  }else
  {
    fclose(pfile);
  }

  pfile = fopen (file_name, "ab");
  if (pfile==NULL)
    {
    CI_VarLogEntry("CDB_IsFileReadOnly","database file '%s' is read-only", CKR_OK, 2, file_name);
    return CK_TRUE;
    }
  else
    {
    CI_VarLogEntry("CDB_IsFileReadOnly","database file '%s' is read-write", CKR_OK, 2, file_name);
    fclose(pfile);
    return CK_FALSE;
    }
}

/**
@fn CK_RV CDB_CheckPin(CK_I_CRYPT_DB_PTR, CK_BBOOL, CK_CHAR_PTR, CK_ULONG)

The function checks an existing PIN either as
<ul>
  <li>security officer PIN (so_pin=CK_TRUE)
  <li>user PIN             (so_pin=CK_FALSE)
</ul>

The check is done in 3 steps
<ol>
  <li>Read Salt from data.dptr[20-35] first</li>
  <li>Doing CI_Ceay_SHA1_Update(&ctx, salt, CDB_SALT_LEN)</li>
  <li>Compare to hash and data.dptr[0-19]</li>
</ol>

@returns The following return values
<dl>
  <dt>CKR_OK</dt>
  <dd>if the given password is equal to the stored password</dd>
  <dt>CKR_PIN_INCORRECT:</dt>
  <dd>if gdbm_fetch() fails with the key "key.dptr[0]=so_pin" - key not extractable?\n
      if the given password is not the stored password
  </dd>
</dl>
*/

CK_RV CDB_CheckPin(CK_I_CRYPT_DB_PTR cdb,    ///< [in] Pointer to database
                   CK_BBOOL          so_pin, ///< [in] Boolean type of PIN
		               CK_CHAR_PTR       pin,    ///< [in] Pointer password as array of char
                   CK_ULONG          pinLen  ///< [in] Length of password in bytes
                   )
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

/**
@fn CK_RV CDB_NewPin (CK_I_CRYPT_DB_PTR,CK_BBOOL,CK_CHAR_PTR,CK_ULONG,CK_CHAR_PTR,CK_ULONG)

The function stores the new PIN either as
<ul>
  <li>security officer PIN (so_pin=CK_TRUE)
  <li>user PIN             (so_pin=CK_FALSE)
</ul>

The given old PIN will be checked against the stored on in the database. After
a successfully proof, the new PIN is hashed by SHA1 and its value is be
replaced in the database by access key CDB_E_SO_PIN respectively
CDB_E_USER_PIN. If the old PIN is given with a NULL_PTR the function trys to
get the old key. Finally the function generates a new key to get encryption
access to the database objects.

@return
<dl>
  <dt>CKR_OK:</dt>
  <dd>if the new PIN was successfully stored in the database
  <dt>CKR_PIN_INCORRECT:</dt>
  <dd>if the given old pin is not equal to the stored on ein the database</dd>
  <dt>CKR_GENERAL_ERROR:</dt>
  <dd>
    <ul>
      <li>if the old_pin==NULL_PTR and so_pin==CK_TRUE and cdb->flags & CDB_F_TOKEN_EMPTY reset</li>
      <li>if the replacement of the new pin in the database fails</li>
    </ul>
 </dd>
</dl>

@note It is forbidden to change the security officer PIN from default after
storing some objects in the database. This is may be historical based, that
Ceay_TokenInit in the past always deletes the entrys of a given database file
(instead of now creating a new database file)
*/

CK_RV CDB_NewPin (CK_I_CRYPT_DB_PTR cdb,        ///< [in] Pointer to the database structure
                  CK_BBOOL          so_pin,     ///< [in] Boolean type of PIN
		              CK_CHAR_PTR       old_pin,    ///< [in] Pointer to the old PIN
                  CK_ULONG          old_pinLen, ///< [in] Length of the old PIN in byte
		              CK_CHAR_PTR       new_pin,    ///< [in] Pointer to the new PIN
                  CK_ULONG          new_pinLen  ///< [in] Length of the new PIN in byte
                  )
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
    {
    CDB_RndPin(cdb, &crypt_key, new_pin, new_pinLen);
    }
  
  TC_free(crypt_key);  

 newPin_err:
  TC_free(key.dptr);
  TC_free(data.dptr);
    
  return rv;
}


/**
@fn CK_RV CDB_PinExists(CK_I_CRYPT_DB_PTR, CK_BBOOL)

The function checks the type of PIN either as
<ul>
  <li>security officer PIN (so_pin=CK_TRUE)
  <li>user PIN             (so_pin=CK_FALSE)
</ul>

The function checks wether the given PIN type exists in the database.
database.

@return
<dl>
  <dt>CKR_OK:</dt>
  <dd>if the PIN type is stored in the database</dd>
  <dt>CKR_USER_PIN_NOT_INITIALIZED:</dt>
  <dd>if the PIN type is not stored in the database</dd>
</dl>
*/

CK_RV CDB_PinExists (CK_I_CRYPT_DB_PTR cdb,   ///< [in] Pointer to the database structure
                     CK_BBOOL          so_pin ///< [in] Boolean type of PIN
                     )
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


/**
@fn CK_RV CDB_SetPin(CK_I_CRYPT_DB_PTR, CK_BBOOL, CK_CHAR_PTR, CK_ULONG)

The function generates a key by two types of PIN either as
<ul>
  <li>security officer PIN (so_pin=CK_TRUE)
  <li>user PIN             (so_pin=CK_FALSE)
</ul>

The function uses the PIN to initialize the 3-DES key for the access to the
database.

@return
<dl>
  <dt>CKR_OK:</dt>
  <dd>always</dd>
</dl>

@note Do no mistake this function with CDB_NewPin(). This function does not set
a PIN into the database.
@todo Therefore the name of this function should be renamed to CDB_SetKey
*/

CK_RV CDB_SetPin (CK_I_CRYPT_DB_PTR cdb,    ///< [in] Pointer to the database structure
                  CK_BBOOL          so_pin, ///< [in] Boolean type of PIN
                  CK_CHAR_PTR       pin,    ///< [in] Pointer to the PIN
                  CK_ULONG          pinLen  ///< [in] Length of the PIN in byte
                  )
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


/**
@fn CK_RV CDB_PutTokenInfo (CK_I_CRYPT_DB_PTR, CK_TOKEN_INFO_PTR)
*/

CK_RV CDB_PutTokenInfo (CK_I_CRYPT_DB_PTR cdb,       ///< [in] Pointer to the database structure
                        CK_TOKEN_INFO_PTR pTokenInfo ///< [in] Pointer to the token information
                        )
{
	datum key, data;
  CK_RV rv = CKR_OK;
	CK_CHAR key_data;

  key_data = CDB_E_TOKEN_INFO;
  
  /* write the key/data to the database */
  key.dsize = 1;
  key.dptr = &key_data;

  data.dsize= sizeof (CK_TOKEN_INFO);
  data.dptr= (char*)pTokenInfo;

  if(gdbm_store(cdb->table,key,data,GDBM_REPLACE) != 0)
    {
			rv = CKR_GENERAL_ERROR;
      CI_VarLogEntry("CDB_SetTokenInfo","could not insert data:%s",
		     rv,0,gdbm_strerror(gdbm_errno));
      return rv;
    }
  return rv;
}


/* }}} */
/* {{{ CK_RV CDB_GetTokenInfo (CK_I_CRYPT_DB_PTR cdb, CK_TOKEN_INFO_PTR CK_PTR ppTokenInfo) */
CK_RV CDB_GetTokenInfo (CK_I_CRYPT_DB_PTR cdb, CK_TOKEN_INFO_PTR CK_PTR ppTokenInfo)
{
	datum key;
	datum data;
  CK_RV rv = CKR_OK;
  CK_CHAR key_data;

  key_data = CDB_E_TOKEN_INFO;
  
  /* write the key/data to the database */
  key.dsize = 1;
  key.dptr = &key_data;

	data = gdbm_fetch(cdb->table,key);

	if (data.dptr == NULL)
  {
		rv = CKR_GENERAL_ERROR;
    CI_LogEntry("CDB_GetTokenInfo","no data was found", rv, 0);
    return rv;
  }

	if (data.dsize != sizeof (CK_TOKEN_INFO))
	{
		rv = CKR_GENERAL_ERROR;
    CI_LogEntry("CDB_GetTokenInfo","illegal size of data found in db ", rv, 0);
    return rv;
	}

	CK_PTR ppTokenInfo = (CK_TOKEN_INFO CK_PTR)data.dptr;
  return rv;
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
	
  do 
	{
    /* get the object */
    if(cdb->old_key.dptr == NULL_PTR)
		{
			*next_obj = NULL_PTR;
			CI_LogEntry("CDB_Open","no further objects", CKR_OK ,0);
			return CKR_OK; /* the calling code must check for the empty obj */
		}
    
		/* if the entry is an object and ... (1) */
    if (cdb->old_key.dptr[0] == CDB_E_OBJECT)
		{
			/* (1) ... is encrypted, we ... (2) */
			if ( ((CK_CHAR_PTR)cdb->old_key.dptr)[1] & CDB_F_ENCRYPTED )
			{
				/* (2) ... have to check that the pin is provided */
				if( cdb->flags & CK_I_CDB_F_USER_PIN_SET )
				{
					break;
				}
			}else
			{
				/* (1) ... is not ecrypted, we can get it */
				break;
			}
		}
		cdb->old_key = gdbm_nextkey(cdb->table, cdb->old_key);
	}while (TRUE);

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
	
	/* only if the object is encrypted, we have to decrypt it */
	if(((CK_CHAR_PTR)cdb->old_key.dptr)[1]&CDB_F_ENCRYPTED)
	{
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

/**
@fn CK_RV CDB_DeleteAllObjects (CK_I_CRYPT_DB_PTR)

The function deletes entry by entry each key of database. If it fails to delete
an entry the function returns immediatly with an error. If all entrys were
deleted, the flag CDB_F_TOKEN_EMPTY is been set.

@return
<dl>
  <dt>CKR_OK:</dt>
  <dd>if all entrys were successfully deleted</dd>
  <dt>CKR_GENERAL_ERROR:</dt>
  <dd>if failure occured in deleting an entry of the database<dd>
</dl>

*/

CK_RV CDB_DeleteAllObjects (CK_I_CRYPT_DB_PTR cdb ///< [in] Pointer to database
                           )
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
	  CI_LogEntry("CDB_DeleteAllObjects", "no find first key in table",
		      rv ,0);

	  break;
	}

      /* get the object */
      if(cdb->old_key.dptr == NULL_PTR)
	{
	  rv = CKR_OK;
	  CI_LogEntry("CDB_DeleteAllObjects", "no further objects",
		      rv ,0);
	  break;
	}
      
      ret = gdbm_delete(cdb->table, cdb->old_key);
      if(ret != 0)
	{
	  rv = CKR_GENERAL_ERROR;
	  CI_VarLogEntry("CDB_DeleteAllObjects", "failure to delete next entry: %s",
			 rv ,0, 
			 gdbm_strerror(gdbm_errno));
	  return rv;
	}
      
    }

  /* set the flag that the database is clean. Now a new SO-PIN may be set */
  cdb->flags |= CDB_F_TOKEN_EMPTY;

  return CKR_OK;
}


/**
@fn CK_RV CDB_GetPrivObject (CK_I_CRYPT_DB_PTR, CK_I_OBJ_PTR CK_PTR)

The same as CDB_GetObjectUpdate, but it "only" gets private objects out of the db
USAGE: after user login

@note For what I tested so far, certificates are invisible to users in Netscape
This is because all private objects are encoded by user's pin. If a user is not login,
the private objects won't be able to be loaded and decoded to the cache memory.in 
Ceay_ReadPersistent.
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

/**
@fn CK_RV CDB_RndPin (CK_I_CRYPT_DB_PTR, CK_CHAR_PTR CK_PTR, CK_CHAR_PTR, CK_ULONG)

@todo Therefore the name of this function should be renamed to CDB_RndKey
*/

CK_RV CDB_RndPin(CK_I_CRYPT_DB_PTR  cdb,       ///< [in]  Pointer to the database structure
                 CK_CHAR_PTR CK_PTR crypt_key, ///< [out] Pointer to the pointer of the key
                 CK_CHAR_PTR        pin,       ///< [in]  Pointer to the PIN
                 CK_ULONG           pinLen     ///< [in]  Length of the PIN in byte
                 )
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


/**
@fn CK_CHAR_PTR CDB_GetRndPin (CK_I_CRYPT_DB_PTR, CK_CHAR_PTR, CK_ULONG)

@todo Therefore the name of this function should be renamed to CDB_GetRndKey
*/

CK_CHAR_PTR CDB_GetRndPin (CK_I_CRYPT_DB_PTR cdb,   ///< [in] Pointer to the database structure
                           CK_CHAR_PTR       pin,   ///< [in] Pointer to the PIN
                           CK_ULONG          pinLen ///< [in] Length of the PIN in byte
                           )
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


/*
 * Local variables:
 * folded-file: t
 * end:
 */
