(export #t)
(import
  :gerbil/gambit/bits :gerbil/gambit/bytes :gerbil/gambit/foreign
  :std/misc/bytes :std/misc/repr
  :clan/base :clan/io
  :clan/poo/object :clan/poo/brace :clan/poo/mop :clan/poo/type :clan/poo/io :clan/poo/number
  ./random ./secp256k1-ffi)

;; NB: We hide secret keys behind an opaque data structure, so the data won't leak as easily.
(defstruct secp256k1-seckey (data) print: #f equal: #t)
(define-type SecretKey
  {(:: @ [Type.])
   sexp: 'SecretKey
   .length-in-bytes: 32
   .element?: (lambda (x) (and (secp256k1-seckey? x) (element? Bytes32 (secp256k1-seckey-data x))))
   .string<-: repr
   .<-string: invalid
   .bytes<-: invalid
   .<-bytes: invalid
   .sexp<-: (lambda (_) '(invalid "Not showing secret key"))
   .json<-: invalid
   .<-json: invalid})

;; USE WITH CAUTION.
;; Do not leak such data to the outside world. In the future, keep it even tighter locked.
(def (import-secret-key/bytes b) (secp256k1-seckey (validate Bytes32 b)))
(def (export-secret-key/bytes x) (secp256k1-seckey-data x))
(def (import-secret-key/json j) (import-secret-key/bytes (<-json Bytes32 j)))
(def (export-secret-key/json x) (json<- Bytes32 (export-secret-key/bytes x)))

(def secp256k1-p #xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F)
(def secp256k1-order #xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141)

(def (generate-secret-key-data)
  (bytes<- UInt256 (modulo (randomUInt256) secp256k1-order)))

;; Right now, we use the foreign object as the "canonical" in-memory representation.
;; Should we instead use canonical bytes that parsed into a foreign object on a need basis?
;; TODO: implement :pr methods so we can have easy access to the 0x representation.
(define-type PublicKey
  {(:: @ [methods.marshal<-bytes Type.])
   .Bytes: Bytes64
   .element?: (lambda (x) (and (foreign? x) (equal? (foreign-tags x) '(secp256k1-pubkey*))))
   .sexp<-: (lambda (k) `(<-json PublicKey ,(.json<- k)))
   ;; uncompressed public key has an extra byte at the beginning, which we remove:
   ;; https://bitcoin.stackexchange.com/questions/57855/c-secp256k1-what-do-prefixes-0x06-and-0x07-in-an-uncompressed-public-key-signif
   .bytes<-: (lambda (k) (subu8vector (bytes<-secp256k1-pubkey k) 1 65))
   .<-bytes: (lambda (b) (secp256k1-pubkey<-bytes (bytes-append #u8(4) b)))
   .json<-: (lambda (x) (json<- .Bytes (.bytes<- x)))
   .<-json: (lambda (x) (.<-bytes (<-json Bytes x)))
   .string<-: .json<-
   .<-string: .<-json})
