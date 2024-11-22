(export #t)

(import :gerbil/gambit
        :std/misc/number :std/sugar :std/test :std/text/hex
        :clan/base
        ../ed25519
        ../ed25519-ffi)

;; Test vectors from RFC 8032
;; https://datatracker.ietf.org/doc/html/rfc8032#section-7.1
(def sk1h
  "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
(def pk1h
  "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
(def msg1h "") ;; empty message
(def sig1h
  "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")

(def sk2h
  "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
(def pk2h
  "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")
(def msg2h "72") ;; single byte
(def sig2h
  "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00")

(def sk3h
  "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7")
(def pk3h
  "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025")
(def msg3h
  "af82") ;; two bytes
(def sig3h
  "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a")

(def (h x) (hex-encode x))
(def (b s)
  (if (string? s)
      (hex-decode s)
      s))

(defrule (check-parse/serialize parse serialize datum)
  (check-equal? (h (serialize (parse (b datum)))) datum))

(def ed25519-test
  (test-suite "test suite for clan/crypto/ed25519"
    (test-case "parse and serialize"
      (check-parse/serialize ed25519-pubkey<-bytes bytes<-ed25519-pubkey pk1h)
      (check-parse/serialize ed25519-pubkey<-bytes bytes<-ed25519-pubkey pk2h)
      (check-parse/serialize ed25519-signature<-bytes bytes<-ed25519-signature sig1h)
      (check-parse/serialize ed25519-signature<-bytes bytes<-ed25519-signature sig2h))

    (test-case "keypair generation from seed"
      (def seed (hex-decode (substring sk1h 0 64)))
      (defvalues (pk1 sk1-bytes) (ed25519-seed-keypair seed))
      (check-equal? (h pk1) pk1h)
      (def sk1 (import-secret-key/bytes sk1-bytes))
      (check-equal? (h (ed25519-sk-to-seed (ed25519-seckey-data sk1)))
                   (substring sk1h 0 64)))

    (test-case "public key derivation"
      (def seed (hex-decode (substring sk1h 0 64)))
      (defvalues (pk1 sk1-bytes) (ed25519-seed-keypair seed))
      (def sk (import-secret-key/bytes sk1-bytes))
      (check-equal? (h (public-key<-secret-key sk)) pk1h)
      (def seed2 (hex-decode (substring sk2h 0 64)))
      (defvalues (pk2 sk2-bytes) (ed25519-seed-keypair seed2))
      (def sk2 (import-secret-key/bytes sk2-bytes))
      (check-equal? (h (public-key<-secret-key sk2)) pk2h))

    (test-case "signature verification"
      (check-equal?
       (verify-ed25519-signature
        (b sig1h)
        (b msg1h)
        (b pk1h))
       #t)

      (check-equal?
       (verify-ed25519-signature
        (b sig2h)
        (b msg2h)
        (b pk2h))
       #t)

      (check-equal?
       (verify-ed25519-signature
        (b sig3h)
        (b msg3h)
        (b pk3h))
       #t))

    (test-case "signature creation"
      (def msg1 (hex-decode msg1h))
      (defvalues (_ignored1 sk1-bytes) (ed25519-seed-keypair (hex-decode (substring sk1h 0 64))))
      (def sk1 (import-secret-key/bytes sk1-bytes))
      (check-equal? (h (make-ed25519-signature msg1 (ed25519-seckey-data sk1))) sig1h)

      (def msg2 (hex-decode msg2h))
      (defvalues (_ignored2 sk2-bytes) (ed25519-seed-keypair (hex-decode (substring sk2h 0 64))))
      (def sk2 (import-secret-key/bytes sk2-bytes))
      (check-equal? (h (make-ed25519-signature msg2 (ed25519-seckey-data sk2))) sig2h))

    (test-case "invalid signatures"
      (def bad-sig (b sig1h))
      (u8vector-set! bad-sig 0 (modulo (+ (u8vector-ref bad-sig 0) 1) 256))
      (check-equal?
       (verify-ed25519-signature
        bad-sig
        (b msg1h)
        (b pk1h))
       #f))

    (test-case "key conversion"
      (defvalues (_ignored sk1-bytes) (ed25519-seed-keypair (hex-decode (substring sk1h 0 64))))
      (def sk1 (import-secret-key/bytes sk1-bytes))
      (check-equal? (h (ed25519-sk-to-seed (ed25519-seckey-data sk1)))
                   (substring sk1h 0 64))

      (def curve-pk (ed25519-pk-to-curve25519 (b pk1h)))
      (check-equal? (u8vector-length curve-pk) 32)

      (def curve-sk (ed25519-sk-to-curve25519 (ed25519-seckey-data sk1)))
      (check-equal? (u8vector-length curve-sk) 32))))
