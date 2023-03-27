(export #t)

(import
  :gerbil/gambit/bits
  :std/crypto/etc
  :clan/number)

(def (randomUIntN n-bits)
  (def n-bytes (n-bytes<-n-bits n-bits))
  (extract-bit-field n-bits 0 (nat<-bytes (random-bytes n-bytes))))

(def (randomUInt256) (randomUIntN 256))
