(export #t)
(import
  :gerbil/gambit
  :std/misc/bytes :std/misc/repr :std/text/hex
  :clan/base :clan/io
  :clan/poo/object :clan/poo/brace :clan/poo/mop :clan/poo/type :clan/poo/io :clan/poo/number
  ./random ./ed25519-ffi)

;; Hide secret keys behind opaque data structure
(defstruct ed25519-seckey (data) print: #f equal: #t)
(define-type SecretKey
  {(:: @ [Type.])
   sexp: 'SecretKey
   .length-in-bytes: 64
   .element?: (lambda (x) (and (ed25519-seckey? x) (element? Bytes64 (ed25519-seckey-data x))))
   .string<-: repr
   .<-string: invalid
   .bytes<-: invalid
   .<-bytes: invalid
   .sexp<-: (lambda (_) '(invalid "Not showing secret key"))
   .json<-: invalid
   .<-json: invalid})

;; USE WITH CAUTION.
;; Do not leak such data to the outside world
(def (import-secret-key/bytes b) (ed25519-seckey (validate Bytes64 b)))
(def (export-secret-key/bytes x) (ed25519-seckey-data x))
(def (import-secret-key/json j) (import-secret-key/bytes (<-json Bytes64 j)))
(def (export-secret-key/json x) (json<- Bytes64 (export-secret-key/bytes x)))

;; Generate secret key from seed
(def (generate-secret-key-from-seed seed)
  (assert! (bytes32? seed))
  (ed25519-seckey (ed25519ph-seckey<-seed seed)))

;; Public key type
(define-type PublicKey
  {(:: @ [methods.marshal<-bytes Type.])
   .Bytes: Bytes32
   .element?: bytes32?
   .sexp<-: (lambda (k) `(<-json PublicKey ,(.json<- k)))
   .bytes<-: identity
   .<-bytes: ed25519ph-pubkey<-bytes
   .json<-: (lambda (x) (json<- .Bytes (.bytes<- x)))
   .<-json: (lambda (x) (.<-bytes (<-json Bytes x)))
   .string<-: .json<-
   .<-string: .<-json})

;; Signature type
(defstruct ed25519-sig (data) print: #f equal: #t)

(def (marshal-signature signature port)
  (write-u8vector (ed25519-sig-data signature) port))

(def (unmarshal-signature port)
  (def sig-bytes (unmarshal-n-u8 64 port))
  (ed25519-sig sig-bytes))

(.def (Signature @ [methods.bytes<-marshal Type.] .bytes<- .<-bytes)
   sexp: 'Signature
   .length-in-bytes: 64
   .element?: (lambda (x) (and (ed25519-sig? x) (element? Bytes64 (ed25519-sig-data x))))
   .marshal: marshal-signature
   .unmarshal: unmarshal-signature
   .sexp<-: (lambda (x) `(<-json Signature ,(.json<- x)))
   .string<-: (compose hex-encode .bytes<-)
   .<-string: (compose .<-bytes hex-decode)
   .json<-: .string<-
   .<-json: .<-string)

;; Create signature from message and secret key
(def (make-message-signature secret-key message)
  (ed25519-sig
   (make-ed25519ph-signature message (ed25519-seckey-data secret-key))))

;; Verify signature
(def (verify-message-signature signature pubkey message)
  (verify-ed25519ph-signature 
   (ed25519-sig-data signature)
   message
   pubkey))

;; Derive public key from secret key
(def (public-key-from-secret-key secret-key)
  (ed25519ph-pubkey<-seckey (ed25519-seckey-data secret-key)))

;; Verify secret key is valid
(def (verify-secret-key secret-key)
  (verify-ed25519ph-seckey (ed25519-seckey-data secret-key)))

;; Helper functions for bytes type checking
(def (bytesN? x n) 
  (and (u8vector? x) (= (u8vector-length x) n)))

(def (bytes32? x) 
  (bytesN? x 32))

(def (bytes64? x)
  (bytesN? x 64))

;; Helper for assertions
(def (assert! condition . args)
  (unless condition
    (apply error args))) 
