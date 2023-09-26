(export #t)
(import
  :gerbil/gambit
  :std/misc/bytes :std/misc/repr :std/text/hex
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
   .<-bytes: (lambda (b) (secp256k1-pubkey<-bytes (u8vector-append #u8(4) b)))
   .json<-: (lambda (x) (json<- .Bytes (.bytes<- x)))
   .<-json: (lambda (x) (.<-bytes (<-json Bytes x)))
   .string<-: .json<-
   .<-string: .<-json})

(defstruct secp256k1-sig (data) print: #f equal: #t)

;; TODO: Handle decoding to/from Ethereum-style v,r,s with magic chain-id dependent v.
(def (marshal-signature signature port)
  (defvalues (bytes recid) (bytes<-secp256k1-recoverable-signature (secp256k1-sig-data signature)))
  (write-u8vector bytes port)
  (write-u8 (+ recid 27) port))

(def (unmarshal-signature port)
  (def compact (unmarshal-n-u8 64 port))
  (def recid (- (read-u8 port) 27))
  (secp256k1-sig (secp256k1-recoverable-signature<-bytes compact recid)))

(def Bytes65 (BytesN 65))

(.def (Signature @ [methods.bytes<-marshal Type.] .bytes<- .<-bytes)
   sexp: 'Signature
   .length-in-bytes: 65
   .element?: (lambda (x) (and (secp256k1-sig? x) (element? Bytes65 (secp256k1-sig-data x))))
   .marshal: marshal-signature
   .unmarshal: unmarshal-signature
   .sexp<-: (lambda (x) `(<-json Signature ,(.json<- x)))
   .string<-: (compose hex-encode .bytes<-)
   .<-string: (compose .<-bytes hex-decode)
   .json<-: .string<-
   .<-json: .<-string)

(def (vrs<-signature sig)
  (def bytes (bytes<- Signature sig))
  (def v (u8vector-ref bytes 64))
  (def r (u8vector-uint-ref bytes 0 big 32))
  (def s (u8vector-uint-ref bytes 32 big 32))
  (values v r s))

(def (signature<-vrs v r s)
  (def bytes (make-u8vector 65))
  (u8vector-uint-set! bytes 0 r big 32)
  (u8vector-uint-set! bytes 32 s big 32)
  (u8vector-set! bytes 64 v)
  (<-bytes Signature bytes))

#; ;;TODO: figure out why this message will work at the REPL but not here even with (import :std/misc/repr) (import :clan/poo/brace) and/or (import (prefix-in (only-in <MOP> @method) @))
(defmethod (@@method :pr secp256k1-sig)
  (λ (self (port (current-output-port)) (options (current-representation-options)))
    (write (sexp<- Signature self) port)))

;; Signature <- 'a:Type SecKey 'a
(def (make-message-signature secret-key message32)
  (secp256k1-sig
   (make-secp256k1-recoverable-signature message32 (secp256k1-seckey-data secret-key))))

;; (OrFalse PublicKey) <- Signature Digest
(def (recover-signer-public-key signature message32)
  (with-catch false (cut secp256k1-recover (secp256k1-sig-data signature) message32)))
