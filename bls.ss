(export #t)
(import
  :gerbil/gambit
  :std/misc/bytes :std/misc/repr :std/text/hex
  :clan/base :clan/io
  :clan/poo/object :clan/poo/brace :clan/poo/mop :clan/poo/type :clan/poo/io :clan/poo/number
  ./random ./bls-ffi)

(def (bytesN? x n) (and (u8vector? x) (= (u8vector-length x) n)))
(def Bytes32 (BytesN 32))
(def Bytes48 (BytesN 48))
(def Bytes64 (BytesN 64))
(def Bytes96 (BytesN 96))

;; Hide secret keys behind opaque data structure
(defstruct bls-seckey (data) print: #f equal: #t)
(define-type SecretKey
  {(:: @ [Type.])
   sexp: 'SecretKey
   .length-in-bytes: 32
   .element?: (lambda (x) (and (bls-seckey? x) (element? Bytes32 (bls-seckey-data x))))
   .string<-: repr
   .<-string: invalid
   .bytes<-: invalid
   .<-bytes: invalid
   .sexp<-: (lambda (_) '(invalid "Not showing secret key"))
   .json<-: invalid
   .<-json: invalid})

;; USE WITH CAUTION.
;; Do not leak such data to the outside world
(def (import-secret-key/bytes b)
  (def scalar (new-blst-scalar))
  (with-blst-mutex blst-scalar-deserialize scalar b)
  (bls-seckey (bytes<-blst-scalar scalar)))

(def (export-secret-key/bytes x) (bls-seckey-data x))
(def (import-secret-key/json j) (import-secret-key/bytes (<-json Bytes32 j)))
(def (export-secret-key/json x) (json<- Bytes32 (export-secret-key/bytes x)))

;; Define mutex for thread safety
(def blst-mutex (make-mutex 'bls))

(defrule (with-blst-mutex f a ...)
  (with-lock blst-mutex (lambda () (f a ...))))

;; Right now, we use the foreign object as the "canonical" in-memory representation
(define-type PublicKey
  {(:: @ [methods.marshal<-bytes Type.])
   .Bytes: Bytes48
   .element?: (lambda (x) (and (foreign? x) (equal? (foreign-tags x) '(blst-p1*))))
   .sexp<-: (lambda (k) `(<-json PublicKey ,(.json<- k)))
   .bytes<-: bytes<-blst-pubkey
   .<-bytes: blst-pubkey<-bytes
   .json<-: (lambda (x) (json<- .Bytes (.bytes<- x)))
   .<-json: (lambda (x) (.<-bytes (<-json Bytes x)))
   .string<-: .json<-
   .<-string: .<-json})

(defstruct bls-sig (data) print: #f equal: #t)

(def (marshal-signature signature port)
  (write-u8vector (bytes<-blst-signature (bls-sig-data signature)) port))

(def (unmarshal-signature port)
  (def bytes (unmarshal-n-u8 96 port))
  (bls-sig (blst-signature<-bytes bytes)))

(.def (Signature @ [methods.bytes<-marshal Type.] .bytes<- .<-bytes)
   sexp: 'Signature
   .length-in-bytes: 96
   .element?: (lambda (x) (and (bls-sig? x) (element? Bytes96 (bls-sig-data x))))
   .marshal: marshal-signature
   .unmarshal: unmarshal-signature
   .sexp<-: (lambda (x) `(<-json Signature ,(.json<- x)))
   .string<-: (compose hex-encode .bytes<-)
   .<-string: (compose .<-bytes hex-decode)
   .json<-: .string<-
   .<-json: .<-string)

;; Generate random secret key
(def (generate-secret-key)
  (def ikm (random-bytes 32))
  (def sk (new-blst-scalar))
  (with-blst-mutex blst-keygen sk ikm)
  (import-secret-key/bytes (bytes<-blst-scalar sk)))

;; Convert blst_scalar to bytes
(def (bytes<-blst-scalar sk)
  (def bytes (make-u8vector 32))
  (with-blst-mutex blst-scalar-serialize bytes sk)
  bytes)

;; Convert bytes to blst_scalar 
(def (blst-scalar<-bytes bytes)
  (def scalar (new-blst-scalar))
  (with-blst-mutex blst-scalar-deserialize scalar bytes)
  scalar)

;; Sign a message with secret key
(def (make-message-signature secret-key message32)
  (bls-sig (make-blst-signature message32 (bls-seckey-data secret-key))))

;; Verify a signature
(def (verify-signature signature message32 public-key)
  (verify-blst-signature (bls-sig-data signature) message32 public-key))

;; Get public key from secret key
(def (derive-public-key secret-key)
  (def seckey-data (bls-seckey-data secret-key))
  ;; Validate secret key is in valid range
  (def scalar (new-blst-scalar))
  (with-blst-mutex blst-scalar-deserialize scalar seckey-data)
  ;; Derive public key
  (blst-pubkey<-seckey seckey-data))

;; Aggregate multiple signatures
(def (aggregate-signatures sig-vector)
  (bls-sig (blst-aggregate-signatures (vector-map bls-sig-data sig-vector))))

;; Aggregate multiple public keys
(def (aggregate-public-keys pk-vector)
  (blst-aggregate-public-keys pk-vector))

;; Verify aggregated signature against aggregated public key
(def (verify-aggregate-signature agg-signature message32 agg-pubkey)
  (verify-blst-signature (bls-sig-data agg-signature) message32 agg-pubkey))

;; Helper to iterate over bytes with index
(def (for-each-with-index proc vec)
  (let loop ((i 0))
    (when (< i (u8vector-length vec))
      (proc i (u8vector-ref vec i))
      (loop (+ i 1)))))

;; Helper to aggregate messages for batch verification
(def (aggregate-messages messages)
  (def result (make-u8vector 32 0))
  (for-each (lambda (msg)
              (for-each-with-index 
               (lambda (i b)
                 (u8vector-set! result i 
                   (bitwise-xor (u8vector-ref result i) b)))
               msg))
            (vector->list messages))
  result)

;; Batch verify multiple signatures
(def (batch-verify-signatures signatures messages public-keys)
  (and (= (vector-length signatures) 
          (vector-length messages)
          (vector-length public-keys))
       (let ((agg-sig (aggregate-signatures signatures))
             (agg-pk (aggregate-public-keys public-keys))
             (agg-msg (aggregate-messages messages)))
         (verify-aggregate-signature agg-sig agg-msg agg-pk))))

(def (new-blst-scalar)
  (or (blst-scalar-alloc) (error "failed malloc of blst_scalar")))
