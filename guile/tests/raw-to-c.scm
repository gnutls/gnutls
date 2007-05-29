(use-modules (r6rs i/o ports)
             (ice-9 format))

(define line-len 12)

(let ((input (open-input-file "openpgp-keyring.gpg")))
  (let loop ((byte (get-u8 input))
             (total 0))
    (if (eof-object? byte)
        #t
        (begin
          (format #t "0x~:@(~2,'0x, " byte)
          (if (>= (+ 1 total) line-len) (newline))
          (loop (get-u8 input)
                (modulo (+ total 1) line-len))))))
(newline)