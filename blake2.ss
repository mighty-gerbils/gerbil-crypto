;;; -*- Scheme -*-
;;;; Gerbil simplified API for BLAKE2 cryptographic hashing functions
;;;; Functionality imported from std/crypto/digest

(export #t)

(import
  :std/misc/bytes :std/sugar
  :std/crypto/digest)

;; : Bytes64 <- Bytes
(def (blake2b<-bytes b (start 0) (end (u8vector-length b)))
  (unless (and (u8vector? b) (<= 0 start end (u8vector-length b))) (error 'blake2b b start end))
  (def d (make-digest digest::blake2b512))
  (digest-update! d b start end)
  (digest-final! d))

;; Convenience function to compute the blake2b hash of a string, as first reduced to bytes,
;; using the UTF-8 encoding by default. This function should probably only be used for debugging.
;; : Bytes64 <- String ?EncodingSymbol
(def (blake2b<-string s (encoding 'UTF-8))
  (blake2b<-bytes (string->bytes s encoding)))
