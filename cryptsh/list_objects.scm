; list the objects that are availible on all tokens of the module

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