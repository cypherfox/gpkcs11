/* -*- c -*- */
/*
 * Copyright (c) TC TrustCenter - Projekt SPROXY - all rights reserved
 * RCSID:       $Id$
 * Source:      $Source$
 * Last Delta:  $Date$ $Revision$ $Author$
 * State:       $State$ $Locker$
 * NAME:        utils.c
 * SYNOPSIS:    -
 * DESCRIPTION: Generation of Certificates
 * FILES:       -
 * SEE/ALSO:    -
 * AUTHOR:      lbe
 * BUGS: *      -
 * HISTORY:     $Log$
 * HISTORY:     Revision 1.1  1999/08/02 12:40:22  lbe
 * HISTORY:     more CVS cleanup
 * HISTORY:
 */

static char RCSID[]="$Id$";

#include <stdlib.h>
#include "utils.h"

/*
 * Funktion :  BUF_MEM_init()
 *             initialisiert einen BUF_MEM
 *
 * Parameter:  self:    zu initialisierender BUF_MEM
 *
 * Precond  :  -
 * Postcond :  -
 * Return   :  den initialisierten BUF_MEM
 * Globals  :  -
 * Fehler   :  -
 */
 
BUF_MEM *BUF_MEM_init(BUF_MEM *self)
{
   if (self)
   {
      self->data=NULL;
      self->length=0;
      self->max   =0;
   }
   return self;
}

/*
 * Funktion :  BUF_MEM_superfree()
 *             gibt im BUF_MEM allozierte Daten frei, ohne den BUF_MEM selber
 *             freizugeben
 *
 * Parameter:  self:    freizugebender BUF_MEM
 *
 * Precond  :  -
 * Postcond :  -
 * Return   :  Fehlercode:
 *             TRUE:    Operation erfolgreich
 *             FALSE:   Fehler: bm nicht gesetzt
 * Globals  :  -
 * Fehler   :  -
 */
 
BUF_MEM *BUF_MEM_superfree(BUF_MEM *self)
{
   if (self)
   {
      if (self->data)
         free(self->data);
      BUF_MEM_init(self);
   }
   return self;
}
 
/*
 * Funktion :  BUF_MEM_cat()
 *             haengt die uebergebenen Daten an den BUF_MEM an
 *             Zusaetzlich wird am Ende eine Null angehaengt, welche
 *             jedoch nicht Teil des offiziellen Pufferinhaltes ist.
 *             Auf diese Weise ist bei Strings immer ein Stringende gegeben.
 *             Es kann allso immer ein printf("%s",buffer->data geschehen.
 *             F<FC>r die Funktion ist zu beachten, dass beim Anf<FC>gen von Str
ings
 *             die abschlie<DF>ende Null nicht zur Laenge der Daten gezaehlt wir
d !
 *
 * Parameter:  self:    BUF_MEM
 *             add:     anzuhaengende Daten
 *
 * Precond  :  -
 * Postcond :  -
 * Return   :  L<E4>nge des Puffers nach Abschlu<DF> der Operation (0 im Fehlerf
alle)
 * Globals  :  -
 * Fehler   :  -
 */
 
unsigned long BUF_MEM_cat(BUF_MEM *self, const char *add, long len)
{
   long newLength;
   long oldLength;
 
   if (!self || self->length < 0)
      return 0;
   if (!len)
      return self->length;
   if (!add  || len < 0)
      return 0;
 
   oldLength=self->length;
   newLength=oldLength+len;
 
   if (BUF_MEM_grow(self,newLength+1) <= 0)
      return 0;
   memcpy(self->data+oldLength,add,len);
   self->data[newLength]=0x00;
   self->length--;
   return (long)(self->length);
}
 
/*
 * Funktion :  BUF_MEM_catBM()
 *             haengt den uebergebenen BUF_MEM an den BUF_MEM an
 *
 * Parameter:  self:    BUF_MEM
 *             other:   anzuhaengende Daten
 *
 * Precond  :  -
 * Postcond :  -
 * Return   :  L<E4>nge des Puffers nach Abschlu<DF> der Operation (0 im Fehlerf
alle)
 * Globals  :  -
 * Fehler   :  -
 */
 
unsigned long BUF_MEM_catBM(BUF_MEM *self, const BUF_MEM *other)
{
   if (!self || !other)
      return FALSE;
   return BUF_MEM_cat(self,other->data,other->length);
}
 
/*
 * Funktion :  BUF_MEM_catStr()
 *             haengt den uebergebenen String an den BUF_MEM an.
 *             der String mu<DF> mit Null abgeschlossen werden !
 *
 * Parameter:  self:    BUF_MEM
 *             data:    anzuhaengende Daten
 *
 * Precond  :  -
 * Postcond :  -
 * Return   :  L<E4>nge des Puffers nach Abschlu<DF> der Operation (0 im Fehlerf
alle)
 * Globals  :  -
 * Fehler   :  -
 */
 
unsigned long BUF_MEM_catStr(BUF_MEM *self, const char *data)
{
   if (!self || !data)
      return FALSE;
   return BUF_MEM_cat(self,data,strlen(data));
}
 
/*
 * Funktion :  BUF_MEM_delBytes()
 *             loescht ab Indexposition start len Bytes aus dem BUF_MEM.
 *             start beginnt bei 0.
 *
 * Parameter:  self:    freizugebender BUF_MEM
 *             start:   Startindex der zu l<F6>schenden Daten [0,self->length[
 *             len:     L<E4>nge der zu l<F6>schenden Daten
 *
 * Precond  :  -
 * Postcond :  -
 * Return   :  L<E4>nge des Puffers nach Abschlu<DF> der Operation (0 im Fehlerf
alle)
 * Globals  :  -
 * Fehler   :  -
 */
 
unsigned long BUF_MEM_delBytes(BUF_MEM *self, long start, long len)
{
   long oldLen;
   long index;
   long copyLen;
 
   if (!self || !self->length || !self->data)
      return 0;
   if (start < 0 || len < 0)
      return 0;
   if (len == 0)
      return self->length;
   if (self->length < start)
      return self->length;
   if (self->length== start)
   {
      self->length--;
      self->data[self->length]=0x00;
      return self->length;
   }
   if (self->length <= start+len)
   {
      len = self->length - start;
      memset(self->data + start,0x00,self->length - start);
      self->length=start;
      return self->length;
   }
   oldLen=self->length;
   copyLen=self->length-start-len;
   for(index=0;index<copyLen;index++)
   {
      self->data[start+index]=self->data[start+len+index];
   }
   self->length=start+index;
   index=start+index;
   self->data[index]=0x00;
   memset(self->data+index,0x00,oldLen-index);
   return self->length;
}
 
/*
 * Funktion :  BUF_MEM_getLine()
 *             liefert und entfernt die erste Zeile aus dem BUF_MEM.
 *             Eine Zeile wird mit '\n', '\n''\r' oder mit '\r''\n' abgeschlosse
n.
 *
 *             Wurde kein Zeilenende gefunden, wird der Teil der Zeile geliefert
 *             und aus dem BUF_MEM entfernt, welcher in den Zeilenpuffer passt.
 *
 * Parameter:  self:    freizugebender BUF_MEM
 *             buf:     Puffer, in den die ermittelte Zeile geschrieben wird.
 *             len:     L<E4>nge des Zeilenpuffers
 *
 * Precond  :  -
 * Postcond :  -
 * Return   :  L<E4>nge der gelieferten Zeile (0 im Fehlerfalle)
 * Globals  :  -
 * Fehler   :  -
 */
 
unsigned long BUF_MEM_getLine( BUF_MEM *self, char* buf,long len)
{
   long nCount;
   long  nFoundEnd=0;
 
   if (!self || !self->length || !self->data || !buf || len<2)
      return 0;
   if (len> self->length)
      len = self->length;
 
   if (len==1)
   {
      buf[0]=self->data[0];
      buf[1]=0x00;
      self->length=0;
      self->data[0]=0x00;
      if (buf[0] == '\n' || buf[0] == '\r')
      {
         buf[0]=0x00;
         return 0;
      }
      return 1;
   }
 
   for(nCount=0;nCount<len;nCount++)
   {
      buf[nCount]=self->data[nCount];
      if (self->data[nCount] == '\n' && self->data[nCount+1] == '\r')
      {
         nFoundEnd=2;
         break;
      }
      if (self->data[nCount] == '\n')
      {
         nFoundEnd=1;
         break;
      }
      if (self->data[nCount] == '\r' && self->data[nCount+1] == '\n')
      {
         nFoundEnd=2;
         break;
      }
   }
   buf[nCount]=0x00;
   if (!nFoundEnd)
   {
      for(;nCount<len-1;nCount++)
      {
         if (self->data[nCount] == '\n' && self->data[nCount+1] == '\r')
         {
            nFoundEnd=2;
            break;
         }
         if (self->data[nCount] == '\n')
         {
            nFoundEnd=1;
            break;
         }
         if (self->data[nCount] == '\r' && self->data[nCount+1] == '\n')
         {
            nFoundEnd=2;
            break;
         }
      }
   }
   BUF_MEM_delBytes(self,0,nCount+nFoundEnd);
   return strlen(buf);
}
 
