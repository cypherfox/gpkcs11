;;; search for objects on all availiable token

;; work around debug signals from my library
(sigaction SIGHUP SIG_IGN)

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
