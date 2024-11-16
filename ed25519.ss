(export #t)
(import
  :gerbil/gambit
  :std/misc/bytes :std/misc/repr :std/text/hex
  :std/assert
  :clan/base :clan/io
  :clan/poo/object :clan/poo/brace :clan/poo/mop :clan/poo/type :clan/poo/io :clan/poo/number
  ./random ./ed25519-ffi)

(def (bytesN? x n) (and (u8vector? x) (= (u8vector-length x) n)))
(def (bytes32? x) (bytesN? x 32))
(def (bytes64? x) (bytesN? x 64))

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

;; Define types for public key and signature
(define-type PublicKey
  {(:: @ [methods.marshal<-bytes Type.])
   .Bytes: Bytes32
   .element?: (lambda (x) (bytesN? x 32))
   .sexp<-: (lambda (k) `(<-json PublicKey ,(.json<- k)))
   .bytes<-: identity
   .<-bytes: (lambda (b) (ed25519-pubkey<-bytes b))
   .json<-: (lambda (x) (json<- .Bytes (.bytes<- x)))
   .<-json: (lambda (x) (.<-bytes (<-json Bytes x)))
   .string<-: .json<-
   .<-string: .<-json})

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

;; Key generation functions
(def (generate-keypair)
  (defvalues (pk sk) (ed25519-keypair))
  (values pk (ed25519-seckey sk)))

(def (generate-keypair/seed seed)
  (assert! (bytes32? seed))
  (defvalues (pk sk) (ed25519-seed-keypair seed))
  (values pk (ed25519-seckey sk)))

;; Signature creation and verification
(def (make-message-signature secret-key message)
  (ed25519-sig
   (make-ed25519-signature message (ed25519-seckey-data secret-key))))

(def (verify-signature signature message public-key)
  (verify-ed25519-signature 
   (ed25519-sig-data signature)
   message
   public-key))

;; Key conversion utilities
(def (public-key<-secret-key secret-key)
  (ed25519-pubkey<-seckey (ed25519-seckey-data secret-key)))

(def (secret-key->seed secret-key)
  (ed25519-sk-to-seed (ed25519-seckey-data secret-key)))

(def (public-key->curve25519 public-key)
  (ed25519-pk-to-curve25519 public-key))

(def (secret-key->curve25519 secret-key)
  (ed25519-sk-to-curve25519 (ed25519-seckey-data secret-key)))

;; Pretty printing for signatures
(defmethod (@@method :pr ed25519-sig)
  (λ (self (port (current-output-port)) (options (current-representation-options)))
    (write (sexp<- Signature self) port)))