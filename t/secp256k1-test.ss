(export #t)

(import :gerbil/gambit
        :std/misc/number :std/sugar :std/test :std/text/hex
        :clan/base
        ../secp256k1 ../secp256k1-ffi)

;; Test vectors from ocaml's secp256k1-ml library
(def msgh ;; sha256 for "testing"
  "cf80cd8aed482d5d1527d7dc72fceff84e6326592848447d2dc0b0e87dfc9a90")
(def sig1h ;; a signature of this message, in der format
  "3044022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f817980220294f14e883b3f525b5367756c2a11ef6cf84b730b36c17cb0c56f0aab2c98589")
(def pk1h ;; public key used to verify the message
  "040a629506e1b65cd9d2e0ba9c75df9c4fed0db16dc9625ed14397f0afc836fae595dc53f8b0efe61e703075bd9b143bac75ec0e19f82a2208caeb32be53414c40")
(def sk2h ;; secret key used to generate the public key below
  "67e56582298859ddae725f972992a07c6c4fb9f62a8fff58ce3ca926a1063530")
(def pk2h ;; public key that corresponds to the secret key above
  "04c591a8ff19ac9c4e4e5793673b83123437e975285e7b442f4ee2654dffca5e2d2103ed494718c697ac9aebcfd19612e224db46661011863ed2fc54e71861e2a6")
(def sig2h ;; signature of the message with this secret key
  "30440220182a108e1448dc8f1fb467d06a0f3bb8ea0533584cb954ef8da112f1d60e39a202201c66f36da211c087f3af88b50edf4f9bdaa6cf5fd6817e74dca34db12390c6e9")

(def h hex-encode)
(def b hex-decode)

(defrule (check-parse/serialize parse serialize datum)
  (check-equal? (h (serialize (parse (b datum)))) datum))

(def secp256k1-test
  (test-suite "test suite for glow/crypto/secp256k1"
    (test-case "parse and serialize"
      (check-parse/serialize secp256k1-pubkey<-bytes bytes<-secp256k1-pubkey pk1h)
      (check-parse/serialize secp256k1-pubkey<-bytes bytes<-secp256k1-pubkey pk2h)
      (check-parse/serialize secp256k1-signature<-bytes/der bytes<-secp256k1-signature/der sig1h)
      (check-parse/serialize secp256k1-signature<-bytes/der bytes<-secp256k1-signature/der sig2h)
      (check-parse/serialize (compose bytes<-secp256k1-signature/compact secp256k1-signature<-bytes/der)
                             (compose bytes<-secp256k1-signature/der secp256k1-signature<-bytes/compact)
                             sig1h)
      (check-equal? (u8vector-length (bytes<-secp256k1-pubkey (secp256k1-pubkey<-bytes (b pk2h)) #t)) 33))
    (test-case "valid signature"
      (check-equal? (verify-secp256k1-signature
                     (secp256k1-signature<-bytes/der (b sig1h))
                     (b msgh)
                     (secp256k1-pubkey<-bytes (b pk1h)))
                    #t)
      (check-equal? (h (bytes<-secp256k1-signature/der (make-secp256k1-signature (b msgh) (b sk2h))))
                    sig2h))
    (test-case "invalid signature"
      (def msg2 (b msgh))
      (def u8vector-ref-set! u8vector-set!)
      (increment! (u8vector-ref msg2 31))
      (check-equal?
       (verify-secp256k1-signature
        (secp256k1-signature<-bytes/der (b sig1h)) msg2 (secp256k1-pubkey<-bytes (b pk1h)))
       #f))
    (test-case "secret key"
      (check-equal? (verify-secp256k1-seckey (b sk2h)) #t)
      (check-equal? (h (bytes<-secp256k1-pubkey (secp256k1-pubkey<-seckey (b sk2h)))) pk2h))
    (test-case "recover"
      (def rsig (make-secp256k1-recoverable-signature (b msgh) (b sk2h)))
      (check-equal? (h (bytes<-secp256k1-signature/der (convert-secp256k1-recoverable-signature rsig)))
                    sig2h)
      (defvalues (compact recid) (bytes<-secp256k1-recoverable-signature rsig))
      (check-equal? (h (bytes<-secp256k1-signature/der (secp256k1-signature<-bytes/compact compact)))
                    sig2h)
      (check-equal? (h (bytes<-secp256k1-signature/der (make-secp256k1-signature (b msgh) (b sk2h))))
                    sig2h)
      (check-equal? (h (secp256k1-recoverable-signature<-bytes compact recid)) (h rsig))
      (check-equal? (h (bytes<-secp256k1-pubkey (secp256k1-recover rsig (b msgh)))) pk2h))))

#|
;; TODO: also test the following functions
normalize-secp256k1-signature
negate-secp256k1-seckey!
negate-secp256k1-pubkey!
secp256k1-seckey-tweak-add!
secp256k1-pubkey-tweak-add!
secp256k1-seckey-tweak-mul!
secp256k1-pubkey-tweak-mul!
secp256k1-context-randomize!
secp256k1-pubkey-combine
|#
