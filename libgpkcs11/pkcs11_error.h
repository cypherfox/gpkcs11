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
 * NAME:        error.h
 * SYNOPSIS:    -
 * DESCRIPTION: -
 * FILES:       -
 * SEE/ALSO:    -
 * AUTHOR:      lbe
 * BUGS:        -
 */

#ifndef ERROR_H
#define ERROR_H
#include "cryptoki.h"

CK_DECLARE_FUNCTION(CK_C_CHAR_PTR,CI_ErrorStr)(
  CK_RV rv
);
CK_DECLARE_FUNCTION(CK_C_CHAR_PTR,CI_MechanismStr)(
  CK_MECHANISM_TYPE rv
);
CK_DECLARE_FUNCTION(CK_C_CHAR_PTR,CI_AttributeStr)(
  CK_ATTRIBUTE_TYPE attrib
);
CK_DECLARE_FUNCTION(CK_ULONG,CI_AttributeNum)(
  CK_CHAR_PTR pAttribName
);
CK_DECLARE_FUNCTION(CK_CHAR_PTR, CI_PrintableByteStream)(
  CK_C_BYTE_PTR      stream,
  CK_ULONG         len
);

CK_DEFINE_FUNCTION(CK_CHAR_PTR, CI_ScanableByteStream)(
   CK_C_BYTE_PTR stream,
   CK_ULONG len
);

CK_DECLARE_FUNCTION(CK_CHAR_PTR, CI_ScanableMechanism)(
  CK_MECHANISM_PTR pMechanism						       
);

CK_DECLARE_FUNCTION(CK_CHAR_PTR, CI_PrintTemplate)(
  CK_ATTRIBUTE_PTR pTemplate,
  CK_ULONG         ulCount
);

#ifndef NO_LOGGING
CK_DECLARE_FUNCTION(void, CI_LogEntry)(
  CK_C_CHAR_PTR FunctionName, /* Name of the current function */
  CK_C_CHAR_PTR ProcessDesc,  /* Description of the current process */
  CK_RV rv,                 /* return value in case of imediate abort of function */
  CK_ULONG level            /* logging level at which message will be printed */
);

CK_DECLARE_FUNCTION(void, CI_SetLogingLevel)(
  CK_ULONG level
);

CK_DEFINE_FUNCTION(void, CI_SetLoggingFile)(
  CK_CHAR_PTR logFileName
);

CK_DEFINE_FUNCTION(void, CI_EvalLogFileName)(
 void
);

#else
#define CI_LogEntry(f,p,r,l) do{}while(0)
#define CI_SetLogingLevel(l) do{}while(0)
#endif /* NO_LOGGING */

CK_DECLARE_FUNCTION(void, CI_VarLogEntry)(
  CK_C_CHAR_PTR FunctionName, /* Name of the current function */
  CK_C_CHAR_PTR ProcessDesc,  /* Description of the current process */
  CK_RV rv,                 /* return value in case of imediate abort of function */
  CK_ULONG level,            /* logging level at which message will be printed */
  ...
);

CK_DECLARE_FUNCTION(void, CI_CodeFktEntry)(
  CK_C_CHAR_PTR FunctionName,     /* Name of the current function */
  CK_C_CHAR_PTR ProcessDesc,      /* Description of the current process */
  ...
);


#ifndef NO_MEM_LOGGING

#include <stdlib.h>

#define TC_free(handle) __TC_free(handle, __LINE__, __FILE__)
#define TC_calloc(nelem, elsize) __TC_calloc(nelem,elsize, __LINE__, __FILE__)
#define TC_malloc(size) __TC_malloc(size, __LINE__, __FILE__)

CK_DEFINE_FUNCTION(void, TC_SetMemLoggingFile)(
  CK_C_CHAR_PTR memLogFileName
);

CK_DEFINE_FUNCTION(void, TC_EvalMemLogFileName)(
 void
);

CK_DECLARE_FUNCTION(void,__TC_free)(
  void *ptr,
  unsigned int line,
  const char *file
);

CK_DECLARE_FUNCTION(void*,__TC_calloc)(
  size_t nelem, 
  size_t elsize,
  unsigned int line,
  const char *file
);

CK_DECLARE_FUNCTION(void*,__TC_malloc)(
  size_t size,
  unsigned int line,
  const char *file
);

#else /* NO_MEM_LOGGING */

#include <stdlib.h>

#define  TC_SetMemLoggingFile(foo)
#define  TC_EvalMemLoggingFile(foo)

#define TC_free(handle) free(handle)
#define TC_calloc(nelem, elsize) calloc(nelem,elsize)
#define TC_malloc(size) malloc(size)

#endif /* NO_LOGGING */

#endif /* ERROR_H */



