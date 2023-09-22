(export #t)

(import
  :gerbil/gambit
  :std/crypto/etc
  :std/misc/bytes)

(def (randomUIntN n-bits)
  (def n-bytes (n-bits->n-u8 n-bits))
  (extract-bit-field n-bits 0 (u8vector->nat (random-bytes n-bytes))))

(def (randomUInt256) (randomUIntN 256))
