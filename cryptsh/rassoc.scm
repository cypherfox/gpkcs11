;; reverse assoc lists
;; the functions use regular association lists, but retrieve pairs based on the
;; _value_ (the cdr) of a pair
;; in all other regards the functions work as the ass* equivs.
;; However I make statement about the performance of these functions.

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

