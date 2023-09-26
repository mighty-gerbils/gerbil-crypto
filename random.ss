(export #t)

(import
  (only-in :gerbil/gambit extract-bit-field)
  (only-in :std/crypto/etc random-bytes)
  :std/misc/bytes)

(def (randomUIntN n-bits)
  (def n-bytes (n-bits->n-u8 n-bits))
  (extract-bit-field n-bits 0 (u8vector->nat (random-bytes n-bytes))))

(def (randomUInt256) (randomUIntN 256))
