;
; This file is part of GPKCS11. 
; (c) 1999-2001 TC TrustCenter GmbH 
;
; GPKCS11 is free software; you can redistribute it and/or modify
; it under the terms of the GNU General Public License as published by
; the Free Software Foundation; either version 2, or (at your option)
; any later version.
;  
; GPKCS11 is distributed in the hope that it will be useful,
; but WITHOUT ANY WARRANTY; without even the implied warranty of
; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
; GNU General Public License for more details.
;  
; You should have received a copy of the GNU General Public License
; along with GPKCS11; see the file COPYING.  If not, write to the Free
; Software Foundation, 59 Temple Place - Suite 330, Boston, MA 02111, USA.  
;
; RCSID:       $Id$
; Source:      $Source$
; Last Delta:  $Date$ $Revision$ $Author$
; State:       $State$ $Locker$
; NAME:        rassoc.scm
; SYNOPSIS:    -
; DESCRIPTION: reverse assoc lists (see below)
; FILES:       -
; SEE/ALSO:    -
; AUTHOR:      lbe
; BUGS:        -
;
;; the functions use regular association lists, but retrieve pairs based on the
;; _value_ (the cdr) of a pair
;; in all other regards the functions work as the ass* equivs.
;; However I make no statement about the performance of these functions.

(define (rassoc value assoc-list)
  (cond ((eq? (cdr assoc-list) '()) #f)
	((equal? (cdar assoc-list) value) (car assoc-list))
	(#t (rassoc value (cdr assoc-list)))
	))

(define (rassq value assoc-list)
  (cond ((eq? (cdr assoc-list) '()) #f)
	((eq? (cdar assoc-list) value) (car assoc-list))
	(#t (rassoc value (cdr assoc-list)))
	))

(define (rassv value assoc-list)
  (cond ((eq? (cdr assoc-list) '()) #f)
	((eqv? (cdar assoc-list) value) (car assoc-list))
	(#t (rassoc value (cdr assoc-list)))
	))

