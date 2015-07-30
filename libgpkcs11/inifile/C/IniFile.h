/************************************************************************
   T h e   O p e n   W i n d o w s   P r o j e c t
 ------------------------------------------------------------------------
   Filename   : IniFile.h
   Author(s)  : Carsten Breuer
 ------------------------------------------------------------------------
 Copyright (c) 2000 by Carsten Breuer (C.Breuer@openwin.de)
/************************************************************************/

#ifndef INIFILE_H
#define INIFILE_H

#ifdef LINUX /* Remove CR, on unix systems. */
#define INI_REMOVE_CR
#define DONT_HAVE_STRUPR
#endif

#ifndef CCHR_H
#define CCHR_H
typedef const char cchr;
#endif

#ifndef __cplusplus
typedef char bool;
#ifndef true
#define true  1
#endif

#ifndef TRUE
#define TRUE  1
#endif

#ifndef false
#define false 0
#endif

#ifndef FALSE
#define FALSE 0
#endif
#endif //__cplusplus

#define tpNULL       0
#define tpSECTION    1
#define tpKEYVALUE   2
#define tpCOMMENT    3

#define MAX_KEY_LENGTH 128
#define MAX_VALUE_LENGTH 512
#define MAX_COMMENT_LENGTH 256
#define MAX_TEXT_LENGTH (MAX_KEY_LENGTH + 1 + MAX_VALUE_LENGTH + 1 + MAX_COMMENT_LENGTH)

#ifdef __cplusplus
extern "C" {
#endif

struct ENTRY
{
   char   Type;
   char  *Text;
   struct ENTRY *pPrev;
   struct ENTRY *pNext;
} ENTRY;

typedef struct
{
   struct ENTRY *pSec;
   struct ENTRY *pKey;
   char          KeyText [MAX_KEY_LENGTH];
   char          ValText [MAX_VALUE_LENGTH];
   char          Comment [MAX_COMMENT_LENGTH];
} EFIND;

/* Macros */
#define ArePtrValid(Sec,Key,Val) ((Sec!=NULL)&&(Key!=NULL)/*&&(Val!=NULL)*/)

/* Connectors of this file (Prototypes) */

bool    OpenIniFile (cchr *FileName);

bool    ReadBool    (cchr *Section, cchr *Key, bool   Default);
int     ReadInt     (cchr *Section, cchr *Key, int    Default);
double  ReadDouble  (cchr *Section, cchr *Key, double Default);
cchr   *ReadString  (cchr *Section, cchr *Key, cchr  *Default);

void    WriteBool   (cchr *Section, cchr *Key, bool   Value);
void    WriteInt    (cchr *Section, cchr *Key, int    Value);
void    WriteDouble (cchr *Section, cchr *Key, double Value);
void    WriteString (cchr *Section, cchr *Key, cchr  *Value);

bool	DeleteKey (cchr *Section, cchr *Key);

void    CloseIniFile ();
bool    WriteIniFile (cchr *FileName);

#ifdef __cplusplus
}; // extern c
#endif

#endif

