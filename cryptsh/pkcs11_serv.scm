; - scheme -
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
; Copyright (c) TC TrustCenter for Security in Data Networks GmbH - all rights reserved
; RCSID:        $Id$
; Source:       $Source$
; Last Delta:   $Date$ $Revision$ $Author$
; State:        $State$ $Locker$
; NAME:         pkcs11_serv.scm
; SYNOPSOS :    -
; DESCRIPTION:  start cryptsh as a server to accept command on a socket port
; FILES:        -
; SEE/ALSO:     -
; AUTHOR :      lbe
; BUGS:         -
;


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

