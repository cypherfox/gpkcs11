;
; this script will use the cryptsh to create a certificate on the
; pkcs11 token
;

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
	; due to the code that parses this it is linear if given in the following order.
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