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
 * NAME:        objects.h
 * SYNOPSIS:    -
 * DESCRIPTION: -
 * FILES:       -
 * SEE/ALSO:    -
 * AUTHOR:      lbe
 * BUGS: *      -
 * HISTORY:     $Log$
 * HISTORY:     Revision 1.8  2000/03/08 09:59:08  lbe
 * HISTORY:     fix SIGBUS in cryptdb, improve readeability for C_FindObject log output
 * HISTORY:
 * HISTORY:     Revision 1.7  2000/01/31 18:09:03  lbe
 * HISTORY:     lockdown prior to win_gdbm change
 * HISTORY:
 * HISTORY:     Revision 1.6  2000/01/07 10:24:44  lbe
 * HISTORY:     introduce changes for release
 * HISTORY:
 * HISTORY:     Revision 1.5  1999/12/01 11:37:22  lbe
 * HISTORY:     write back changes by afchine
 * HISTORY:
 * HISTORY:     Revision 1.4  1999/11/02 13:47:19  lbe
 * HISTORY:     change of structures and bug fix in slot.c, add more files for tcsc_token: emptyfuncs and general_data
 * HISTORY:
 * HISTORY:     Revision 1.3  1999/10/08 13:00:13  lbe
 * HISTORY:     release version 0.5.5
 * HISTORY:
 * HISTORY:     Revision 1.2  1999/10/06 07:57:22  lbe
 * HISTORY:     solved netscape symbol clash problem
 * HISTORY:
 * HISTORY:     Revision 1.1  1999/06/16 09:46:10  lbe
 * HISTORY:     reorder files
 * HISTORY:
 * HISTORY:     Revision 1.12  1999/01/22 08:35:33  lbe
 * HISTORY:     full build with new perisistant storage complete
 * HISTORY:
 * HISTORY:     Revision 1.11  1999/01/19 12:19:43  lbe
 * HISTORY:     first release lockdown
 * HISTORY:
 * HISTORY:     Revision 1.10  1999/01/13 16:17:57  lbe
 * HISTORY:     clampdown for persistent storage complete
 * HISTORY:
 * HISTORY:     Revision 1.9  1998/12/02 10:47:31  lbe
 * HISTORY:     work on persistent storage
 * HISTORY:
 * HISTORY:     Revision 1.8  1998/11/13 10:10:14  lbe
 * HISTORY:     added persistent storage.
 * HISTORY:
 * HISTORY:     Revision 1.7  1998/11/10 09:43:00  lbe
 * HISTORY:     hash iter geaendert: hashtabelle braucht nicht mehr an fkts uebergeben werden.
 * HISTORY:
 * HISTORY:     Revision 1.6  1998/11/03 15:58:41  lbe
 * HISTORY:     auto-lockdown
 * HISTORY:
 * HISTORY:     Revision 1.5  1998/10/12 10:09:19  lbe
 * HISTORY:     clampdown
 * HISTORY:
 * HISTORY:     Revision 1.4  1998/07/23 15:20:17  lbe
 * HISTORY:     working
 * HISTORY:
 * HISTORY:     Revision 1.3  1998/07/13 15:33:46  lbe
 * HISTORY:     Object-System redesigned
 * HISTORY:
 * HISTORY:     Revision 1.2  1998/07/07 14:43:54  lbe
 * HISTORY:     Funktion zum einfacheren internen setzen von Objectattributen hinzugefügt
 * HISTORY:
 * HISTORY:     Revision 1.1  1998/07/02 17:21:22  lbe
 * HISTORY:     Initial revision
 * HISTORY:
 */

#ifndef _OBJECTS_H_
#define _OBJECTS_H_ 1

#include "internal.h"

#include <stdio.h>

/* object classes to identify incorrect attributes */
typedef CK_ULONG CK_I_OBJECT_CLASS;

#define CK_IO_DATA         0x00000001
#define CK_IO_CERTIFICATE  0x00000002
#define CK_IO_PUBLIC_KEY   0x00000004
#define CK_IO_PRIVATE_KEY  0x00000008
#define CK_IO_SECRET_KEY   0x00000010

/* new attributes for exclusice internal use: */
#define CKA_SSL_VERSION      CKA_VENDOR_DEFINED|0x00000001
#define CKA_PERSISTENT_KEY   CKA_VENDOR_DEFINED|0x00000002

/* Create of a handle and insertion in session object list we need more than onece, hence this is done in sepparate function */
CK_DECLARE_FUNCTION(CK_RV, CI_InternalCreateObject)(
  CK_I_SESSION_DATA_PTR session_data,
  CK_I_OBJ_PTR pNewObject,
  CK_OBJECT_HANDLE_PTR phObject
);

CK_DECLARE_FUNCTION(CK_RV, CI_InternalDestroyObject)(
  CK_I_SESSION_DATA_PTR session_data,
  CK_OBJECT_HANDLE hObject,
  CK_BBOOL destroy_persistent /* permanently destroy a persistent object */
);

CK_DECLARE_FUNCTION(CK_BBOOL, CI_MatchObject)(
  CK_I_OBJ_PTR pTemplate,
  CK_I_OBJ_PTR object
);

CK_DECLARE_FUNCTION(CK_RV, CI_ReturnObj)(
  CK_I_SESSION_DATA_PTR session_data,
  CK_OBJECT_HANDLE hObject,
  CK_I_OBJ_PTR CK_PTR ppStoredObj
);

CK_DECLARE_FUNCTION(CK_RV, CI_ReturnSession)(
  CK_OBJECT_HANDLE hSession,
  CK_I_SESSION_DATA_PTR CK_PTR ppStoredSession
);


/* ### the new object system ### */
typedef struct CK_I_ATTRIBUTE_INFO 
{
  CK_ULONG ObjTypes; /* uses the CK_IO_* Flags */
  CK_ATTRIBUTE_TYPE IntAttrib;  /* uses the CK_IA_* Attributes */
} CK_I_ATTRIBUTE_INFO;

typedef CK_I_ATTRIBUTE_INFO CK_PTR CK_I_ATTRIBUTE_INFO_PTR;

/** Initialize the tables of the object system. */
CK_DECLARE_FUNCTION(CK_RV, CI_ObjInitialize)(
 void
);

/** translate the CKA_ Attributes into CK_IA_ ones */
CK_DECLARE_FUNCTION(CK_RV, CI_TranslateAttribute)(
  CK_ATTRIBUTE_TYPE CkAttrib,
  CK_ATTRIBUTE_TYPE CK_PTR pIAtrrib
);

CK_DECLARE_FUNCTION(CK_RV, CI_TranslateIntAttribute)(
  CK_ATTRIBUTE_TYPE IAttrib,
  CK_ATTRIBUTE_TYPE CK_PTR pCkAttrib
);

/** Check validity of attribute in a object type.
 * @param Attribute attribute to be checked
 * @param ObjClass class of object that the attribute
 *        is checked for.
 * @param pValid reference to flag that will be set by the function to TRUE 
 *        if the attribute is valid for the given object class. Will be set to
 *        FALSE otherwise.
 * @return CKR_OK if the check encoutered no internal error.
 */
CK_DECLARE_FUNCTION(CK_RV, CI_AttributeValid)(
  CK_ATTRIBUTE_TYPE Attribute,
  CK_OBJECT_CLASS  ObjClass,
  CK_BBOOL CK_PTR pValid
);

CK_DECLARE_FUNCTION(CK_RV, CI_ObjCreateObj)(
  CK_I_OBJ_PTR CK_PTR ppNewObj
);

CK_DECLARE_FUNCTION(CK_RV, CI_ObjSetAttributeValue)(
  CK_I_OBJ_PTR pObject, 
  CK_ATTRIBUTE_TYPE AttributeType,
  CK_VOID_PTR pValue, 
  CK_ULONG ulValueLen
);

/* Verwendet die internen Attribute (CK_IA_*) statt CKA_* */
CK_DECLARE_FUNCTION(CK_RV, CI_ObjSetIntAttributeValue)(
  CK_I_OBJ_PTR pObject, 
  CK_ATTRIBUTE_TYPE InternalAttributType, 
  CK_VOID_PTR pValue, 
  CK_ULONG ulValueLen
);

/**
 */
CK_DECLARE_FUNCTION(CK_RV, CI_ObjSetAttribute)(
  CK_I_OBJ_PTR pObject,
  CK_ATTRIBUTE_PTR pAttribute
);

/** Convenience function for setting a CK_BBOOL value in an object.
 *
 */
CK_DECLARE_FUNCTION(CK_RV, CI_ObjSetIntBool)(
  CK_I_OBJ_PTR pObject ,
  CK_ATTRIBUTE_TYPE InternalAttributeType, 
  CK_BBOOL bValue
);

/** Retrieve the value of an attribute.
 * The function uses the technique to determine the amount of memory as 
 * described in the PKCS#11 standard section 10.2. The standard attribute
 * defines (CKA_*) are used to identify the attributes.
 * @return
 * @param
 */
CK_DECLARE_FUNCTION(CK_RV, CI_ObjGetAttributeValue)(
  CK_I_OBJ_PTR pObject,
  CK_ATTRIBUTE_TYPE AttributeType,
  CK_BYTE_PTR pValue,
  CK_ULONG_PTR pulValueLen
);

/**
 */
CK_DECLARE_FUNCTION(CK_RV, CI_ObjGetIntAttributeValue)(
  CK_I_OBJ_PTR pObject ,
  CK_ATTRIBUTE_TYPE InternalAttributeType, 
  CK_BYTE_PTR pValue, 
  CK_ULONG_PTR pulValueLen
);

/** Convert a PKCS#11 style template into an object. 
 */
CK_DECLARE_FUNCTION(CK_RV, CI_ObjReadTemplate)(
  CK_I_OBJ_PTR  pObject,
  CK_ATTRIBUTE_PTR pTemplate,
  CK_ULONG ulTemplateLen
);

/** copy an object. 
 */
CK_DECLARE_FUNCTION(CK_RV, CI_ObjCopyObject)(
  CK_I_OBJ_PTR pTargetObject, 
  CK_I_OBJ_PTR pSourceObject 
);

/* destroy an object. */
CK_DECLARE_FUNCTION(CK_RV, CI_ObjDestroyObj)(
       CK_I_OBJ_PTR pObject
);

/** merge to objects
 * @param pTargetObject Object into which Attributes are copied.
 * @param pSourceObject Object whose Attributes are copied.
 * @param overwrite if equal to TRUE Attributes already set in 
 *                  <b>pTargetObject<b> are overwritten by Attributes set 
 *                  in <b>pSourceObject<b>
 */
CK_DECLARE_FUNCTION(CK_RV, CI_ObjMergeObj)(
       CK_I_OBJ_PTR pTargetObject,
       CK_I_OBJ_PTR pSourceObject,
       CK_BBOOL overwrite
);

CK_DECLARE_FUNCTION(CK_RV, CI_ObjDeleteAttribute)(
       CK_I_OBJ_PTR pObject,
       CK_ATTRIBUTE_TYPE Attribute
);

CK_DECLARE_FUNCTION(CK_RV, CI_ObjDeleteIntAttribute)(
       CK_I_OBJ_PTR pObject,
       CK_ATTRIBUTE_TYPE InternalAttribute
);

CK_DECLARE_FUNCTION(CK_RV, CI_ObjDumpObj)(
      CK_I_OBJ_PTR pObject,
      FILE CK_PTR pOut
);

CK_DECLARE_FUNCTION(CK_RV, CI_ObjVerifyObj)(
 CK_I_OBJ_PTR pObject
);

CK_DECLARE_FUNCTION(CK_RV, CI_ObjFinalize)(
 void
);

CK_DECLARE_FUNCTION(CK_RV, CI_ObjAttribCount)(
 CK_I_OBJ_PTR pObject,
 CK_ULONG CK_PTR pCount
);

CK_DECLARE_FUNCTION(CK_RV, CI_ObjAttribIter)(
 CK_I_OBJ_PTR pObject,
 CK_I_HASH_ITERATOR_PTR CK_PTR pIterator
);

CK_DECLARE_FUNCTION(CK_RV, CI_ObjAttribIterDeRef)(
 CK_I_HASH_ITERATOR_PTR pIterator,
 CK_ATTRIBUTE_PTR CK_PTR ppAttrib
);

/** Init a object template if not allready done.
 * the token implementation use templates to set default values. These are 
 * objects in their own right, but need only be parsed once. This function 
 * checks the values and initializes the function if nesseccary.
 * @param ppObjectRef   points to the address of the template object. if 
 *                      *ppObjectRef is != NULL the function will return 
 *                      immediateley.
 * @param pTemplate     template of CKA_ATTRIBUTE tripels to set the attributes 
 *                      of the template object with.
 * @param ulTemplateLen number of elements in the template
 */
CK_DEFINE_FUNCTION(CK_RV, CI_ObjTemplateInit)(
  CK_I_OBJ_PTR CK_PTR ppObjectRef,
  CK_ATTRIBUTE_PTR pTemplate,
  CK_ULONG ulTemplateLen
);

/** Add an object to the container.
 * will check if there is an already object of the key and clean up.
 * The object will be a reference and not a copy of the original obj.
 */
CK_DECLARE_FUNCTION(CK_RV, CI_ContainerAddObj)(
 CK_I_HASHTABLE_PTR container,
 CK_ULONG key,
 CK_I_OBJ_PTR pObject
);

/** Delete an object from the container.
 * will free the mem of the object if this was the last reference
 */
CK_DECLARE_FUNCTION(CK_RV, CI_ContainerDelObj)(
 CK_I_HASHTABLE_PTR container,
 CK_ULONG key
);

/** Add Object to application list.
 * To make dynamic loading possible we only export functions as some operating
 * system have difficulties exporting variables. This function wraps direct 
 * manipulations of the application list outside the libgpkcs11.
 * @return the CK_RV value that the actual call to CI_ContainerAddObj returned.
 */
CK_DECLARE_FUNCTION(CK_RV, CI_AppListAddObj)(
  CK_ULONG key,
  CK_I_OBJ_PTR val
);

#define CI_ObjLookup( obj, int_attrib ) (obj->lookup[int_attrib])

CK_DEFINE_FUNCTION(CK_RV, CI_TokenObjAdd)(
  CK_I_SESSION_DATA_PTR  session_data,
  CK_OBJECT_HANDLE phObject, 
  CK_I_OBJ_PTR pNewObject
);

CK_DEFINE_FUNCTION(CK_RV, CI_TokenObjDelete)(
  CK_I_SESSION_DATA_PTR session_data,
  CK_OBJECT_HANDLE phObject
);

CK_DEFINE_FUNCTION(CK_RV, CI_TokenObjCommit)(
  CK_I_SESSION_DATA_PTR session_data,
  CK_OBJECT_HANDLE phObject 
);


#endif /* _OBJECTS_H_ */

/*
 * Local variables:
 * folded-file: t
 * end:
 */
