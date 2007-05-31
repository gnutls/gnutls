;;; GNUTLS-EXTRA --- Guile bindings for GnuTLS-EXTRA.
;;; Copyright (C) 2007  Free Software Foundation
;;;
;;; GNUTLS-EXTRA is free software; you can redistribute it and/or modify
;;; it under the terms of the GNU General Public License as published by
;;; the Free Software Foundation; either version 2 of the License, or
;;; (at your option) any later version.
;;;
;;; GNUTLS-EXTRA is distributed in the hope that it will be useful,
;;; but WITHOUT ANY WARRANTY; without even the implied warranty of
;;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;;; GNU General Public License for more details.
;;;
;;; You should have received a copy of the GNU General Public License
;;; along with GNUTLS-EXTRA; if not, write to the Free Software
;;; Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,
;;; USA.

;;; Written by Ludovic Courtès <ludo@chbouib.org>.


;;;
;;; Exercise the OpenPGP key API part of GnuTLS-extra.
;;;

(use-modules (gnutls)
             (gnutls extra)
             (srfi srfi-1)
             (srfi srfi-4)
             (srfi srfi-11))

(define %public-key-file
  (search-path %load-path "openpgp-pub.asc"))

(define %private-key-file
  (search-path %load-path "openpgp-sec.asc"))

(define %key-id
  ;; Change me if you change the key files.
  '#u8(#xbd #x57 #x2c #xdc #xcc #xc0 #x7c #x35))

(define (file-size file)
  (stat:size (stat file)))


(dynamic-wind

    (lambda ()
      #t)

    (lambda ()
      (let ((raw-pubkey  (make-u8vector (file-size %public-key-file)))
            (raw-privkey (make-u8vector (file-size %private-key-file))))

        (uniform-vector-read! raw-pubkey (open-input-file %public-key-file))
        (uniform-vector-read! raw-privkey (open-input-file %private-key-file))

        (let ((pub (import-openpgp-public-key raw-pubkey
                                              openpgp-key-format/base64))
              (sec (import-openpgp-private-key raw-privkey
                                               openpgp-key-format/base64)))

          (exit (and (openpgp-public-key? pub)
                     (openpgp-private-key? sec)
                     (equal? (openpgp-public-key-id pub) %key-id)
                     (u8vector? (openpgp-public-key-fingerprint pub))
                     (every string? (openpgp-public-key-names pub))
                     (member (openpgp-public-key-version pub) '(3 4))
                     (list? (openpgp-public-key-usage pub))
                     (let-values (((pk bits)
                                   (openpgp-public-key-algorithm pub)))
                       (and (string? (pk-algorithm->string pk))
                            (number? bits))))))))

    (lambda ()
      ;; failure
      (exit 1)))

;;; arch-tag: 2ee2a377-7f4d-4031-92a8-275090e4f83d
