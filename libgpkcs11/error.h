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
 * NAME:        error.h
 * SYNOPSIS:    -
 * DESCRIPTION: -
 * FILES:       -
 * SEE/ALSO:    -
 * AUTHOR:      lbe
 * BUGS: *      -
 * HISTORY:     $Log$
 * HISTORY:     Revision 1.6  2000/06/23 17:32:17  lbe
 * HISTORY:     release to secude, lockdown for 0_6_2
 * HISTORY:
 * HISTORY:     Revision 1.5  2000/01/31 18:09:02  lbe
 * HISTORY:     lockdown prior to win_gdbm change
 * HISTORY:
 * HISTORY:     Revision 1.4  1999/12/03 09:35:44  jzu
 * HISTORY:     logging-bug fixed
 * HISTORY:
 * HISTORY:     Revision 1.3  1999/12/02 16:41:50  lbe
 * HISTORY:     small changes, cosmetics
 * HISTORY:
 * HISTORY:     Revision 1.2  1999/12/02 13:52:37  jzu
 * HISTORY:     personal log-files
 * HISTORY:
 * HISTORY:     Revision 1.1  1999/06/16 09:46:07  lbe
 * HISTORY:     reorder files
 * HISTORY:
 * HISTORY:     Revision 1.7  1999/01/19 12:19:39  lbe
 * HISTORY:     first release lockdown
 * HISTORY:
 * HISTORY:     Revision 1.6  1998/12/07 13:20:01  lbe
 * HISTORY:     TC_free von parametern für Zeile und Datei befreit.
 * HISTORY:
 * HISTORY:     Revision 1.5  1998/11/13 10:10:20  lbe
 * HISTORY:     added persistent storage.
 * HISTORY:
 * HISTORY:     Revision 1.4  1998/11/10 09:43:21  lbe
 * HISTORY:     hash iter geaendert: hashtabelle braucht nicht mehr an fkts uebergeben werden.
 * HISTORY:
 * HISTORY:     Revision 1.3  1998/11/04 17:12:25  lbe
 * HISTORY:     debug-lockdown
 * HISTORY:
 * HISTORY:     Revision 1.2  1998/10/12 10:08:21  lbe
 * HISTORY:     clampdown
 * HISTORY:
 * HISTORY:     Revision 1.1  1998/07/23 15:19:47  lbe
 * HISTORY:     working
 * HISTORY:
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



