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
; NAME:        find_objects.scm
; SYNOPSIS:    -
; DESCRIPTION: search for objects on all avaliable token.
; FILES:       -
; SEE/ALSO:    -
; AUTHOR:      lbe
; BUGS:        -

;; work around debug signals from my library. Uncomment this if you are using
;; gpkcs11, compiled for debug.
;(sigaction SIGHUP SIG_IGN)

;; init
(C-Initialize)

;; get the list of active token
(define token-list (cdr (C-GetSlotList #t)))

(define (print-slot-object-list slot)
       (let ( (sess-handle (cdr (C-OpenSession slot 4))) )
	 (C-FindObjectsInit sess-handle '() )	 
	 (let ( (object-list (cdr (C-FindObjects sess-handle))) )
	   (map (lambda (obj-handle)
		  (let ((obj-type (C-GetAttributeValue sess-handle 
						       obj-handle
						       (list (attr-2-cka "CKA_CLASS"))
						       )
				  ))
		    (map display (list "Handle:" obj-handle " type: " obj-type))
		    (newline)
		    ))
		object-list)
	   )
	 (C-FindObjectsFinal sess-handle)
	 (C-CloseSession sess-handle)
	 )
       )

(map print-slot-object-list token-list)
