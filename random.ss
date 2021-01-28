(export #t)

(import
  :gerbil/gambit/bits :gerbil/gambit/bytes :gerbil/gambit/random
  :clan/number)

(def (randomUIntN n-bits)
  (def order (arithmetic-shift 1 n-bits)) ;; order of the number group
  (def n-bytes (n-bytes<-n-bits n-bits))
  (def r (random-integer order))
  (if (file-exists? "/dev/urandom")
    (let (u (nat<-bytes (call-with-input-file "/dev/urandom" (cut read-bytes n-bytes <>))))
      (extract-bit-field n-bits 0 (+ r u)))
    r))

(def (randomUInt256) (randomUIntN 256))
