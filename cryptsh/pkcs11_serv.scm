;; - scheme -
;; Copyright (c) TC TrustCenter for Security in Data Networks GmbH - all rights reserved
;; RCSID:        $Id$
;; Source:       $Source$
;; Last Delta:   $Date$ $Revision$ $Author$
;; State:        $State$ $Locker$
;; NAME:         pkcs11_serv.scm
;; SYNOPSOS :    -
;; DESCRIPTION:  -
;; FILES:        -
;; SEE/ALSO:     -
;; AUTHOR :      lbe
;; BUGS:         -
;; HISTORY:      $Log$
;; HISTORY:      Revision 1.1  1999/06/16 09:46:06  lbe
;; HISTORY:      reorder files
;; HISTORY:
;; HISTORY:      Revision 1.1  1998/11/04 17:43:52  lbe
;; HISTORY:      debug-lockdown
;; HISTORY:
;;


; global variable may be set to stop the server gracefully
(define serv-break #f)

;; to have a handy dummy for testing around
;; it simply echos the data
(define (dummy-dispatch port)
  (let ((line (read port)))
    (write-line line)
    (write-line line port)
    (close-port port)
  ))

;; another simple dummy: the remote scheme interpreter
(define (remote-dispatch port)
  (let ((expr (read port))
	)
    (let ((retval (eval expr))
	)
    (write-line expr)
    (write-line retval)
    (write retval port)
    (close-port port)
  )))

;; wait for incoming socket connections and call dispatcher with the port
;; dispatcher must be of prototype (lambda port)
;;
(define (pkcs11-serv dispatcher)
  (let ((serv_sock (socket AF_INET SOCK_STREAM (protoent:proto (getprotobyname "tcp"))))
	)
    (bind serv_sock AF_INET INADDR_ANY 4711)
    (listen serv_sock 5)    ; accept a backlog of up to 5 further connections
    (do ((acc_sock (accept serv_sock) (accept serv_sock)))
	(serv-break acc_sock)
      (write-line "ACCEPT")
      (display "Family: ")(write-line (sockaddr:fam (cdr acc_sock)))
      (display "Address: ")(write-line (hostent:name (gethost (sockaddr:addr (cdr acc_sock)))))
      (display "Port: ")(write-line (sockaddr:port (cdr acc_sock)))
      (apply dispatcher (list (car acc_sock)))
      )
    (close-port serv_sock) ; clean up afterwards
    ))

