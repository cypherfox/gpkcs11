
(load "pkcs11_init.scm")

; will print the return code and return the actual data
(define (print-ret-code expression)
  (let ((code (cond ((pair? expression) (car expression))
		    (#t expression)))
	(value (cond ((pair? expression) (cdr expression))
		     (#t '()))))
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

;; big endian! to be used on the sun!
;; I need a wrapper for this!
;(C-FindObjectInit 0 '((CKA_CLASS, "00:00:00:01:", 0x00000004)))
(C-FindObjectsInit 2 (list (list (attr-2-cka "CKA_CLASS") "00:00:00:01:" 4)))
(C-FindObjects 2)
(C-FindObjectsFinal 2)

(let ( (ret-pair (C-GetMechanismList 0)) )
  (cons (car ret-pair)
	(on-all ckm-2-mech (cdr ret-pair))
	))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;; RC4 ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(define template (list (list (attr-2-cka "CKA_CLASS") "00:00:00:04:" 4) 
		       (list (attr-2-cka "CKA_KEY_TYPE") "00:00:00:12:" 4) 
		       (list (attr-2-cka "CKA_ENCRYPT") "01:" 1) 
		       (list (attr-2-cka "CKA_VALUE") 
			     (string-append "1d:2e:61:de:b1:6f:a0:e4:14:77:43:4f:13:a9:66:78:"
					    "80:13:48:48:57:36:5d:e3:67:a8:48:23:24:a3:5c:e2:"
					    "60:85:ec:99:41:da:06:e5:15:b3:5c:9a:09:e1:64:6b:"
					    "b6:3d:28:bd:99:aa:e5:a8:63:06:7c:12:e3:ed:ed:70:"
					    "08:11:eb:4b:e0:6f:bd:72:c8:8d:43:5c:11:23:4f:4d:"
					    "66:c0:bb:31:f2:59:e3:75:05:b9:2c:18:2a:32:15:88:"
					    "5d:23:d2:0b:4b:4b:4a:8b:11:54:ab:6d:b2:d2:8d:ce:"
					    "d7:eb:f2:b0:36:5f:5a:a9:94:5f:99:9a:33:44:ed:3b:")
			     #x80) 
		       ))

(define obj-handle1 (cdr (C-CreateObject sess-handle1 template)))

(display "opening session for rc4 encryption")
(newline)

(define sess-handle2 (cdr (C-OpenSession 0 4)))

(define rc4-mechanism (list (mech-2-ckm "CKM_RC4") ""))

(print-ret-code (C-EncryptInit sess-handle2 rc4-mechanism obj-handle1))

(define rc4-result 
  (print-ret-code (C-EncryptUpdate sess-handle2 
				   (ci-parse-byte-stream "48:43:fc:ee:9e:03:cd:c5:"))))

(define expect (ci-parse-byte-stream "84:6a:6d:b3:7c:60:45:88:"))

(cond ((string=? expect rc4-result) (display "rc4 succeeds")
				    (newline))
      (#t (display (string-append "rc4 mismatch, expected '" 
				  (ci-unparse-string expect)
				  "', got '" 
				  (ci-unparse-string rc4-result)
				  "' ("))
	  (display (string-length rc4-result))
	  (display ")")
	  (newline))
      )

(print-ret-code (C-CloseSession sess-handle2))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;; DES-ECB ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define template (list (list (attr-2-cka "CKA_CLASS") "00:00:00:04:" 4)
		       (list (attr-2-cka "CKA_KEY_TYPE") "00:00:00:13:" 4)
		       (list (attr-2-cka "CKA_ENCRYPT") "01:" 1)
		       (list (attr-2-cka "CKA_VALUE") "6b:b6:04:dc:f7:fd:6e:2a:" 8))
  )

(define obj-handle2 (print-ret-code (C-CreateObject sess-handle1 template)))

(define sess-handle2 (print-ret-code (C-OpenSession 0 4)))

(define des-ecb-mechanism (list (mech-2-ckm "CKM_DES_ECB") ""))

(print-ret-code (C-EncryptInit sess-handle2 des-ecb-mechanism obj-handle2))

(define des-ecb-result 
  (print-ret-code (C-EncryptUpdate sess-handle2 
				   (ci-parse-byte-stream "3b:7e:cf:78:7d:e2:b6:bb:"))))

(define expect (ci-parse-byte-stream "45:55:4e:ba:4a:2d:1e:70:"))

(cond ((string=? expect des-ecb-result) (display "des-ecb succeeds")
				    (newline))
      (#t (display (string-append "des-ecb mismatch, expected '" 
				  (ci-unparse-string expect)
				  "', got '" 
				  (ci-unparse-string des-ecb-result)
				  "'"))
	  (newline))
      )

(display "length of des-ecb-result: ")
(display (string-length des-ecb-result))
(newline)

(C-CloseSession sess-handle2)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;; DES-ECB ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define template (list (list (attr-2-cka "CKA_CLASS") "00:00:00:04:" 4)
		       (list (attr-2-cka "CKA_KEY_TYPE") "00:00:00:13:" 4)
		       (list (attr-2-cka "CKA_ENCRYPT") "01:" 1)
		       (list (attr-2-cka "CKA_VALUE") "d3:32:e3:ea:1c:8c:c7:c1:" 8))
  )

(define obj-handle3 (print-ret-code (C-CreateObject sess-handle1 template)))

(define sess-handle3 (print-ret-code (C-OpenSession 0 4)))

(define des-cbc-mechanism (list (mech-2-ckm "CKM_DES_CBC") 
				(ci-parse-byte-stream "23:a3:0b:dd:9c:d5:d7:eb:")))

(print-ret-code (C-EncryptInit sess-handle3 des-cbc-mechanism obj-handle3))

(define des-cbc-result 
  (print-ret-code (C-EncryptUpdate sess-handle3 
				   (ci-parse-byte-stream "6f:9d:43:cc:09:8d:c6:07:"))))

(define expect (ci-parse-byte-stream "e3:ae:3a:64:ef:73:70:36:"))

(cond ((string=? expect des-cbc-result) (display "des-ecb succeeds")
				    (newline))
      (#t (display (string-append "des-cbc mismatch, expected '" 
				  (ci-unparse-string expect)
				  "', got '" 
				  (ci-unparse-string des-cbc-result)
				  "'"))
	  (newline))
      )

(display "length of des-cbc-result: ")
(display (string-length des-cbc-result))
(newline)

(print-ret-code (C-CloseSession sess-handle3))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;; The End ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(display "complete")
(newline)

(exit)