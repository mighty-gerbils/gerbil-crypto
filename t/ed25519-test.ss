(export #t)

(import :gerbil/gambit
        :std/misc/number :std/sugar :std/test :std/text/hex
        :clan/base
        ../ed25519 ../ed25519-ffi)

;; Test vectors
(def msgh 
  "9bd9f44f4dcc75bd531b56b2cd280b0bb38fc1cd6d1230e14861d861de092e79")
(def sigh
  "f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43a5bb704786be79fc476f91d3f3f89b03984d8068dcf1bb7dfc6637b45450ac04")
(def pkh
  "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa")

(def h hex-encode)
(def b hex-decode)

(defrule (check-parse/serialize parse serialize datum)
  (check-equal? (h (serialize (parse (b datum)))) datum))

(def ed25519-test
  (test-suite "test suite for gerbil/crypto/ed25519"
    (test-case "parse and serialize"
      (check-parse/serialize ed25519ph-pubkey<-bytes bytes<-ed25519ph-pubkey pkh)
      (check-parse/serialize ed25519ph-signature<-bytes bytes<-ed25519ph-signature sigh))
    
    (test-case "valid signature"
      (let* ((sig (ed25519ph-signature<-bytes (b sigh)))
             (pk (ed25519ph-pubkey<-bytes (b pkh)))
             (msg (b msgh)))
        (check-equal? 
          (verify-ed25519ph-signature 
            sig
            msg 
            pk)
          #t)))
    
    ; (test-case "invalid signature"
    ;   (def msg2 (b msgh))
    ;   (u8vector-set! msg2 31 (+ (u8vector-ref msg2 31) 1))
    ;   (check-equal?
    ;    (verify-ed25519ph-signature
    ;     (ed25519-sig-data (ed25519ph-signature<-bytes (b sigh)))
    ;     msg2 
    ;     (ed25519ph-pubkey<-bytes (b pkh)))
    ;    #f))
    
    ; (test-case "secret key"
    ;   (def seed (make-u8vector 32 0))
    ;   (check-equal? (verify-ed25519ph-seckey (ed25519ph-seckey<-seed seed)) #t)
    ;   (check-equal? (h (bytes<-ed25519ph-pubkey (ed25519ph-pubkey<-seckey (ed25519ph-seckey<-seed seed))))
    ;                pkh))
    
    ; (test-case "high level API"
    ;   (def seed (make-u8vector 32 0))
    ;   (def secret-key (generate-secret-key-from-seed seed))
    ;   (def public-key (public-key-from-secret-key secret-key))
    ;   (def msg (b msgh))
    ;   (def signature (make-message-signature secret-key msg))
    ;   (check-equal? (verify-message-signature signature public-key msg) #t)
    ;   (check-equal? (verify-secret-key secret-key) #t))
      ))

#|
;; TODO: also test the following functions
import-secret-key/bytes
export-secret-key/bytes
import-secret-key/json  
export-secret-key/json
|# 
