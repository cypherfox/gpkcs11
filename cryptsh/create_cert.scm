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
; NAME:        create_cert.scm
; SYNOPSIS:    -
; DESCRIPTION: script will use the cryptsh to create a certificate on the
;              pkcs11 token
; FILES:       -
; SEE/ALSO:    -
; AUTHOR:      lbe
; BUGS:        -


(load "pkcs11_init.scm")

; will print the return code and return the actual data
(define (print-ret-code expression)
  (let ((code (cond ((pair? expression) (car expression))
		    (#t expression)))
	(value (cond ((pair? expression) (cdr expression))
		     (#t '() ))))
    (display (string-append "returned (" (ckr-2-return-code code) ")"))
    (newline)
    value
    ))

(C-Initialize)

(C-GetInfo)

(C-GetSlotList #t)

(C-GetSlotInfo 0)
(C-GetTokenInfo 0)

(let ( (ret-pair (C-GetMechanismList 0)) )
  (cons (car ret-pair)
	(on-all ckm-2-mech (cdr ret-pair))
	))

(define sess-handle1 (cdr (C-OpenSession 0 4)))

(define mechanism (list (mech-2-ckm "CKM_RSA_PKCS_KEY_PAIR_GEN") ""))
(define public-template (list (list (attr-2-cka "CKA_ID") "01:" 1)
			      (list (attr-2-cka "CKA_TOKEN") "01:" 1)
			      (list (attr-2-cka "CKA_KEY_TYPE") "00:00:00:00:" 4)
			      (list (attr-2-cka "CKA_PUBLIC_EXPONENT") "00:01:00:01:" 4)
			      (list (attr-2-cka "CKA_MODULUS_BITS") "00:00:08:00:" 4)
			      )) 
(define private-template (list (list (attr-2-cka "CKA_ID") "02:" 1)
			       (list (attr-2-cka "CKA_TOKEN") "01:" 1)
			       (list (attr-2-cka "CKA_KEY_TYPE") "00:00:00:00:" 4)
			      ))

(display "creating key pair")
(display public-template)
(newline)

(let ((key-pair (print-ret-code (C-GenerateKeyPair sess-handle1 mechanism 
						   public-template private-template)))
      )
  (let ((public-handle (car key-pair))
	(private-handle (cadr key-pair))
	; due to the code that parses this, it is linear if given in the following order.
	; any other order will degrade the performance, but work correctly
	; in reverse order it will take  O^2
	; entries with labels other than the ones below will be ignored.
	(subject-info 
	 '(("country" .      "Middle Earth")         ; country (C)
	   ("state" .        "The Shire")            ; state or province (SP)
	   ("locality" .     "Minas Arnor")          ; locality / city   (L)
	   ("organization" . "Powermongers Inc.")    ; Organisation   (O) 
	   ("unit" .         "Planar Adjustment")    ; Abteilung     (OU)
	   ("common_name" .  "Gandalf the Grey")     ; common Name (CN)
	   ("email" .        "behnke@trustcenter.de");  (EMail)
	   )
	 ))
    (display (list "public handle: " public-handle))
    (display (list "private handle: " private-handle))
    (newline)

    (create-cert-req sess-handle1 private-handle public-handle subject-info "new_cert.der")
    ))

(C-CloseSession sess-handle1)
(C-Finalize)
(quit)