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

;;; Written by Ludovic Courtès <ludo@chbouib.org>

(define-module (gnutls extra)

;;; Important note: As written above, this part of the code is ditributed
;;; under the GPL, not the LGPL.

  :use-module (gnutls)

  :export (;; OpenPGP keys
           openpgp-public-key? openpgp-private-key?
           import-openpgp-public-key import-openpgp-private-key
           openpgp-public-key-id openpgp-public-key-id!
           openpgp-public-key-fingerprint openpgp-public-key-fingerprint!
           openpgp-public-key-name openpgp-public-key-names
           openpgp-public-key-algorithm openpgp-public-key-version
           openpgp-public-key-usage

           ;; OpenPGP keyrings
           openpgp-keyring? import-openpgp-keyring
           openpgp-keyring-contains-key-id?

           ;; certificate credentials
           set-certificate-credentials-openpgp-keys!

           ;; enum->string functions
           openpgp-key-format->string

           ;; enum values
           openpgp-key-format/raw
           openpgp-key-format/base64))


(load-extension "libguile-gnutls-extra-v-0" "scm_init_gnutls_extra")

;;; Local Variables:
;;; mode: scheme
;;; coding: latin-1
;;; End:

;;; arch-tag: 2eb7693e-a221-41d3-8a14-a57426e9e670
