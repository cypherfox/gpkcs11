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
; NAME:        list_objects.scm
; SYNOPSIS:    -
; DESCRIPTION: list all objects that are availiable on all tokens of an
;              module
; FILES:       -
; SEE/ALSO:    -
; AUTHOR:      lbe
; BUGS:        -

(define (pkcs11-list-module-objects)
  (let ((iter (lambda (slot-list)
		(cond ((eq? '() slot-list) #f)
		      (#t (let ((sess-handle (cdr (C-OpenSession (car slot-list) 4))))
			    (C-FindObjectsInit sess-handle '())
			    (display "For slot: " )
			    (display (car slot-list))
			    (display " Objects: ")
			    (display (C-FindObjects sess-handle))
			    (newline)
			    (C-FindObjectsFinal sess-handle)
			    (C-CloseSession sess-handle)
			    )
			  (iter (cdr slot-list))
			  )
		      )
		))
	)
    ;; ignore a failure. TODO: check what error the retval signifies; 
    ;; ignore CKR_ALREADY_INITIALIEZED
    (C-Initialize)
    ;; ignore errors as well. The slot-list will be nil
    (iter (cdr (C-GetSlotList #t)))    
    )  
)




(C-Login sess-handle1 1 "Saruman")

(C-FindObjectsInit sess-handle1 '())
(C-FindObjects sess-handle1)
(C-FindObjectsFinal sess-handle1)