(export #t)

(import
  (only-in :gerbil/gambit extract-bit-field)
  (only-in :std/crypto/etc random-bytes)
  (only-in :std/misc/number n-bits->n-u8)
  (only-in :std/misc/bytes u8vector->uint))

(def (randomUIntN n-bits)
  (let (n-bytes (n-bits->n-u8 n-bits))
    (extract-bit-field n-bits 0 (u8vector->uint (random-bytes n-bytes)))))

(def (randomUInt256) (randomUIntN 256))
