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
 * NAME:	utils.c
 * SYNOPSIS:	-
 * DESCRIPTION: -
 * FILES:	-
 * SEE/ALSO:	-
 * AUTHOR:	lin
 * BUGS: *	-
 * HISTORY:	$Log$
 * HISTORY:	Revision 1.5  2000/01/31 18:09:03  lbe
 * HISTORY:	lockdown prior to win_gdbm change
 * HISTORY:	
 * HISTORY:	Revision 1.4  1999/12/02 14:16:27  lbe
 * HISTORY:	tons of small bug fixes and bullet proofing of libgpkcs11 and cryptsh
 * HISTORY:	
 * HISTORY:	Revision 1.3  1999/11/02 13:47:19  lbe
 * HISTORY:	change of structures and bug fix in slot.c, add more files for tcsc_token: emptyfuncs and general_data
 * HISTORY:	
 * HISTORY:	Revision 1.2  1999/10/06 07:57:23  lbe
 * HISTORY:	solved netscape symbol clash problem
 * HISTORY:	
 * HISTORY:	Revision 1.1  1999/06/16 09:46:11  lbe
 * HISTORY:	reorder files
 * HISTORY:	
 * HISTORY:	Revision 1.4  1999/06/04 14:58:36  lbe
 * HISTORY:	change to libtool/automake complete (except for __umoddi prob)
 * HISTORY:	
 * HISTORY:	Revision 1.3  1999/01/19 12:19:47  lbe
 * HISTORY:	first release lockdown
 * HISTORY:
 * HISTORY:	Revision 1.2  1999/01/18 16:30:09  lbe
 * HISTORY:	util cleanup and package build
 * HISTORY:
 * HISTORY:	Revision 1.1  1999/01/18 13:02:34  lbe
 * HISTORY:	swapped Berkeley DB for gdbm
 * HISTORY:
 */

static char RCSID[]="$Id$";
const char* Version_utils_c(){return RCSID;}

#include "utils.h"

#include <errno.h>
#include <stdio.h>
#include <ctype.h>  /* isdigit */

#ifndef LINELEN 
#define LINELEN 4096
#endif

#ifndef StdErr
#define StdErr stderr
#endif 


char achStrUpChar [] = {			/* IBM Codepage 850	*/
    '\0',  '\1',  '\2',  '\3',  '\4',  '\5',  '\6',  '\7',
   '\10', '\11', '\12', '\13', '\14', '\15', '\16', '\17',
   '\20', '\21', '\22', '\23', '\24', '\25', '\26', '\27',
   '\30', '\31', '\32', '\33', '\34', '\35', '\36', '\37',
     ' ',   '!',   '"',   '#',   '$',   '%',   '&',  '\'',
     '(',   ')',   '*',   '+',   ',',   '-',   '.',   '/',
     '0',   '1',   '2',   '3',   '4',   '5',   '6',   '7',
     '8',   '9',   ':',   ';',   '<',   '=',   '>',   '?',
     '@',   'A',   'B',   'C',   'D',   'E',   'F',   'G',
     'H',   'I',   'J',   'K',   'L',   'M',   'N',   'O',
     'P',   'Q',   'R',   'S',   'T',   'U',   'V',   'W',
     'X',   'Y',   'Z',   '[',  '\\',   ']',   '^',   '_',
     '`',   'A',   'B',   'C',   'D',   'E',   'F',   'G',
     'H',   'I',   'J',   'K',   'L',   'M',   'N',   'O',
     'P',   'Q',   'R',   'S',   'T',   'U',   'V',   'W',
     'X',   'Y',   'Z',   '{',   '|',   '}',   '~','\177',
     'Ä',   'ö',   'ê',   '∂',   'é',   '∑',   'è',   'Ä',
     '“',   '”',   '‘',   'ÿ',   '◊',   'ﬁ',   'é',   'è',
     'ê',   'í',   'í',   '‚',   'ô',   '„',   'Í',   'Î',
  '\230',   'ô',   'ö',   'ù','\234',   'ù','\236','\237',
     'µ',   '÷',   '‡',   'È',   '•',   '•','\246','\247',
  '\250','\251','\252','\253','\254','\255','\256','\257',
  '\260','\261','\262','\263','\264',   'µ',   '∂',   '∑',
  '\270','\271','\272','\273','\274','\275','\276','\277',
  '\300','\301','\302','\303','\304','\305',   '«',   '«',
  '\310','\311','\312','\313','\314','\315','\316','\317',
  '\320','\321',   '“',   '”',   '‘','\325',   '÷',   '◊',
     'ÿ','\331','\332','\333','\334','\335',   'ﬁ','\337',
     '‡','\341',   '‚',   '„',   'Â',   'Â','\346','\347',
  '\350',   'È',   'Í',   'Î',   'Ì',   'Ì','\356','\357',
  '\360','\361','\362','\363','\364','\365','\366','\367',
  '\370','\371','\372','\373','\374','\375','\376','\377'
};


/* {{{ void CorrectPathName(char *pc) */
/* ersetzt Backslashes durch slashes bzw. umgekehrt. */
void CorrectPathName(char *pc)
{
#if !defined(WINDOWS) && !defined(WIN32) && !defined(MSDOS)
  for (; *pc; pc++ )
     if ( *pc == '\\' )
       *pc = '/';
#else
  for (; *pc; pc++ )
     if ( *pc == '/' )
       *pc = '\\';
#endif
}

/* }}} */
/* {{{ static BOOL ReadLine(FILE *pf, char *pc, int MaxLen ) */

static BOOL ReadLine(FILE *pf, char *pc, int MaxLen )
{
  if ( !fgets( pc, MaxLen, pf ) )
    { *pc = 0x0;
     return(FALSE);
    }

  for ( ; *pc; pc++ )	                         /* Tabs etc. in Spaces konvertieren */
    if ( !isprint((int) *pc) )
      *pc = ' ';

 return( TRUE );
}

/* }}} */
/* {{{ char *NormalizeStringUpCase(char *pszString) */
/** Entfernt Leerzeichen am Anfang und am Ende sowie mehrfache
 *  Leerzeichen, wandelt Klein- in Gro·buchstaben.
 *  @return Zeiger auf normalisierte Zeichenkette.
 */
char *NormalizeStringUpCase(char *pszString)
{
  char *s = pszString;
  char *t = pszString;

  while ((s[0]==' ')||(s[0]=='\t')) ++s;

  while ((*t++ = StrUpChar(*s++)) != 0)
    if ((s[0]==' ')||(s[0]=='\t')) {
      while ((s[1]==' ')||(s[1]=='\t')) ++s;
      if (s[1]==0) ++s;
    }

  return (pszString);
} /* NormalizeStringUpCase */
/* }}} */
/* {{{ void NormalizeString(char *s ) */
void NormalizeString(char *s )
/* remove leading and trailing spaces */
{int l, l2;

  l = strlen(s);
  while ( l &&( s[l-1] == ' ' ) )                /* remove trailing spaces */
    s[--l] = 0x0;
  for ( l=0; s[l] == ' '; l++ )                  /* number of leading spaces */
     ;
  for ( l2=l; s[l2]; l2++ )
    s[l2-l] = s[l2];
  s[l2-l] = 0x0;
}

/* }}} */
/* {{{ static int StringIsEmpty(char *pc) */
static int StringIsEmpty(char *pc)
{ if ( !pc[0] )
    return 1;
  for ( ; (*pc==' ')||(*pc=='\t')||(*pc=='\r')||(*pc=='\n'); pc++ )
     ;
 return( *pc == 0x0 );
}

/* }}} */
/* {{{ int TCU_GetProfileString(const char *,const char*,const char*,char*,int,BOOL) */
/* return codes:
    1 oder 2: ConfgiFilename nicht gefunden
    3: Section nicht gefunden
    4: FieldName nicht gefunden 
*/
int TCU_GetProfileString( const char *ConfigFilename, const char *Section, 
			  const char *FieldName,
                          char *Value, int MaxValueLen, BOOL NormalizeNames )
{
  FILE *cf;
  static char fn[512];
  char line[LINELEN+1], keyword[LINELEN+1], value[LINELEN+1], *pc;
  int LineNo=0, ret=3;
  BOOL SectionFound=FALSE;
  
#ifdef UTIL_Debug
  fprintf( StdErr, "trying config file '%s'\n", ConfigFilename );
#endif
  *value = 0x0;
  if ( !(cf = fopen( ConfigFilename, "rt" )) )
    {
      ret = 2;
      goto ende;
    }
  while ( ReadLine( cf, line, LINELEN ) )
  {
    LineNo++;
    if ( line[0] == '[' )	  /* start of section ? */
      { 
	pc = strchr(line,']');
	if ( pc )
	  *pc = 0x0;	/* delete from ']' */
	else fprintf( StdErr, "%s:%d sectionnames must be enclosed in '[' ']' \n", 
		      ConfigFilename, LineNo );
        if ( NormalizeNames )
          NormalizeStringUpCase( &line[1] );
	else NormalizeString( &line[1] );
	if ( strcmp( &line[1], Section ) )
          continue;
	else 
          { 
	    SectionFound = TRUE;
	    ret = 4;
	  }
      }
    else if ( line[0] == '#' )
	;                           /* comment line */
    else if ( SectionFound )
      { 
	pc = strchr( line, '=' );
	if ( pc )
	  { 
	    strncpy( keyword, line, pc-line );
            keyword[pc-line] = 0x0;
            if ( NormalizeNames )
              NormalizeStringUpCase( keyword );
	    else NormalizeString( keyword );
	    sscanf( ++pc, "%s", value );
            if ( !strcmp( keyword, FieldName ) )
              { 
		strncpy( Value, pc, MaxValueLen );
		NormalizeString(Value);
		ret = 0;
		goto ende;
	      }
	  }
	else if ( !StringIsEmpty(line) )
	  fprintf( StdErr, "%s:%d keyword and value must be separated with '=' (%s)\n", 
		   ConfigFilename, LineNo, line);
	/* otherwise the line is empty */
      }
  }
  
 ende:
  if ( cf )
    fclose( cf );
  return ret;
}

/* }}} */

/* {{{ char *TC_strtok_r(char *s1, const char *s2, char**lasts) */

#include <string.h>

char *TC_strtok_r(char *s1, const char *s2, char**lasts)
{

#if defined(_WINDOWS) || defined(WIN32) || !defined(HAVE_STRTOK_R)

  char *token;
 
  if(lasts == NULL)
    {
      errno = EINVAL;
      return NULL;
    }

  if (s1 == NULL)
    {
      if (*lasts == NULL)
        {
          errno = EINVAL;
          return NULL;
        }
      else
        s1 = *lasts;
    }
 
  /* Scan leading delimiters.  */
  s1 += strspn(s1, s2);
  if (*s1 == '\0')
    {
      *lasts = NULL;
      return NULL;
    }

  /* Find the end of the token.  */
  token = s1;
  s1 = strpbrk(token, s2);
  if (s1 == NULL)
    /* This token finishes the string.  */
    *lasts = NULL;
  else
    {
      /* Terminate the token and make *LASTS point past it.  */
      *s1 = '\0';
      *lasts = s1 + 1;
    }
  return token;

#else

  return strtok_r(s1,s2,lasts);

#endif /* !WINDOWS && !WIN32 */
}

/* }}} */



/*
 * Local variables:
 * folded-file: t
 * end:
 */






