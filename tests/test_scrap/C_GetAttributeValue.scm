#
# Testing C_GetAttributeValue
#
# define two template, 
# open a session,
# create object using the first template.
# try to get data back using further sets of templates.
# (The actual calls to C_GetAttributeValues are in the exp code.)
#

# this one lacks the MODULUS_BITS entry
(define CGAV-obj-template1 
  (list (list (attr-2-cka "CKA_CLASS") "00:00:00:04:" 4) 
	(list (attr-2-cka "CKA_KEY_TYPE") (key-type-2-ckk "CKK_RSA") 4) 
	(list (attr-2-cka "CKA_MODULUS") "01:23:45:67:89:ab:" 6 )
	)

# this one is sensitive
(define CGAV-obj-template2
  (list (list (attr-2-cka "CKA_CLASS") "00:00:00:04:" 4) 
	(list (attr-2-cka "CKA_KEY_TYPE") (key-type-2-ckk "CKK_RSA") 4) 
	(list (attr-2-cka "CKA_MODULUS") "01:23:45:67:89:ab:" 6 )
	(list (attr-2-cka "CKA_SENSITIVE") t 4)
	)

(define test-template1 (list (list (attr2cka "CKA_MODULUS_BITS") 0 0 )))

(define sess-handle1 (cdr (C-OpenSession 0 4)))
(define obj-handle1 (cdr (C-CreateObject sess-handle1 )))
(define obj-handle1 (cdr (C-CreateObject sess-handle1 )))
