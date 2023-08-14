;;; -*- Scheme -*-
;;;; Gerbil FFI for secp256k1
;;
;; To be linked with libsecp256k1: -lsecp256k1

;; TODO: use opaque objects, not arrays, for secret keys and for signatures,
;; and only allow importing / exporting the data as array via marshalling to a standard format.

(export
  secp256k1-pubkey<-bytes
  bytes<-secp256k1-pubkey
  secp256k1-signature<-bytes/compact
  secp256k1-signature<-bytes/der
  bytes<-secp256k1-signature/der
  bytes<-secp256k1-signature/compact
  verify-secp256k1-signature
  normalize-secp256k1-signature
  make-secp256k1-signature
  verify-secp256k1-seckey
  secp256k1-pubkey<-seckey
  negate-secp256k1-seckey!
  negate-secp256k1-pubkey!
  secp256k1-seckey-tweak-add!
  secp256k1-pubkey-tweak-add!
  secp256k1-seckey-tweak-mul!
  secp256k1-pubkey-tweak-mul!
  secp256k1-context-randomize!
  secp256k1-pubkey-combine
  secp256k1-recoverable-signature<-bytes
  convert-secp256k1-recoverable-signature
  bytes<-secp256k1-recoverable-signature
  make-secp256k1-recoverable-signature
  secp256k1-recover)

(import
  :gerbil/gambit/bits :gerbil/gambit/bytes :gerbil/gambit/exceptions :gerbil/gambit/threads
  :std/assert :std/foreign
  :std/misc/bytes
  :std/sugar
  :std/text/hex
  :clan/base)

(begin-ffi
    (secp256k1-context* secp256k1-pubkey* secp256k1-ecdsa-signature*
     SECP256K1_CONTEXT_NONE SECP256K1_CONTEXT_VERIFY SECP256K1_CONTEXT_SIGN
     secp256k1-context-create
     secp256k1-context-randomize
     secp256k1-context-clone
     secp256k1-ec-pubkey-alloc
     secp256k1-ec-pubkey-create
     secp256k1-ec-pubkey-parse
     secp256k1-ec-pubkey-serialize
     secp256k1-ecdsa-signature-alloc
     secp256k1-ecdsa-signature-parse-der
     secp256k1-ecdsa-signature-parse-compact
     secp256k1-ecdsa-signature-serialize-der
     secp256k1-ecdsa-signature-serialize-compact
     secp256k1-ecdsa-signature-normalize
     secp256k1-ecdsa-verify
     secp256k1-ecdsa-sign
     secp256k1-ec-seckey-verify
     secp256k1-ec-pubkey-create
     secp256k1-ec-seckey-negate
     secp256k1-ec-pubkey-negate
     secp256k1-ec-seckey-tweak-add
     secp256k1-ec-pubkey-tweak-add
     secp256k1-ec-seckey-tweak-mul
     secp256k1-ec-pubkey-tweak-mul
     secp256k1-ec-pubkey-combine
     secp256k1-ecdsa-recoverable-signature-alloc
     secp256k1-ecdsa-recoverable-signature-create
     secp256k1-ecdsa-recoverable-signature-parse-compact
     secp256k1-ecdsa-recoverable-signature-serialize-compact
     secp256k1-ecdsa-sign-recoverable
     secp256k1-ecdsa-recoverable-signature-convert
     secp256k1-ecdsa-recover)

(c-declare #<<END-C
#include <string.h>

#include <secp256k1.h>
#include <secp256k1_recovery.h>

#ifndef ___HAVE_FFI_U8VECTOR
#define ___HAVE_FFI_U8VECTOR
#define U8_DATA(obj) ___CAST (___U8*, ___BODY_AS (obj, ___tSUBTYPED))
#define U8_LEN(obj) ___HD_BYTES (___HEADER (obj))
#endif

static ___SCMOBJ ffi_release_secp256k1_context (void *ptr)
{
  secp256k1_context_destroy ((secp256k1_context*)ptr);
  return ___FIX (___NO_ERR);
}

static secp256k1_pubkey* ffi_secp256k1_ec_pubkey_alloc (void)
{
  return malloc(sizeof(secp256k1_pubkey));
}

static int ffi_secp256k1_ec_pubkey_parse
  (secp256k1_context* ctx, secp256k1_pubkey* pubkey, ___SCMOBJ in)
{
  return secp256k1_ec_pubkey_parse(ctx, pubkey, U8_DATA(in), U8_LEN(in));
}

static int ffi_secp256k1_ec_pubkey_serialize
  (secp256k1_context* ctx, ___SCMOBJ out, secp256k1_pubkey* pubkey)
{
  size_t size = U8_LEN(out);
  int flags = (size == 33) ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED;
  secp256k1_ec_pubkey_serialize(ctx, U8_DATA(out), &size, pubkey, flags);
  return size;
}

static secp256k1_ecdsa_signature* ffi_secp256k1_ecdsa_signature_alloc(void)
{
  return malloc(sizeof(secp256k1_ecdsa_signature));
}

static int ffi_secp256k1_ecdsa_signature_parse_der
  (secp256k1_context* ctx, secp256k1_ecdsa_signature* sig, ___SCMOBJ in)
{
  return secp256k1_ecdsa_signature_parse_der(ctx, sig, U8_DATA(in), U8_LEN(in));
}

static int ffi_secp256k1_ecdsa_signature_parse_compact
  (secp256k1_context* ctx, secp256k1_ecdsa_signature* sig, ___SCMOBJ in) // u8vector(64)
{
  return secp256k1_ecdsa_signature_parse_compact(ctx, sig, U8_DATA(in));
}

static int ffi_secp256k1_ecdsa_signature_serialize_der
  (secp256k1_context* ctx, ___SCMOBJ out, secp256k1_ecdsa_signature* sig)
{
  size_t size = U8_LEN(out);
  int ret = secp256k1_ecdsa_signature_serialize_der(ctx, U8_DATA(out), &size, sig);
  return size << 1 | (ret&1); // |
}

static int ffi_secp256k1_ecdsa_signature_serialize_compact
  (secp256k1_context* ctx, ___SCMOBJ out, secp256k1_ecdsa_signature* sig) // u8vector(64)
{
  return secp256k1_ecdsa_signature_serialize_compact(ctx, U8_DATA(out), sig);
}

static int ffi_secp256k1_ecdsa_verify(const secp256k1_context* ctx, const secp256k1_ecdsa_signature *sig, ___SCMOBJ msg32, const secp256k1_pubkey *pubkey)
{
  return secp256k1_ecdsa_verify(ctx, sig, U8_DATA(msg32), pubkey);
}

static int ffi_secp256k1_ecdsa_sign(const secp256k1_context* ctx, secp256k1_ecdsa_signature *signature, ___SCMOBJ msg32, ___SCMOBJ seckey)
{
  return secp256k1_ecdsa_sign(ctx, signature, U8_DATA(msg32), U8_DATA(seckey), NULL, NULL);
}

static int ffi_secp256k1_ec_seckey_verify(const secp256k1_context* ctx, ___SCMOBJ seckey)
{
  return secp256k1_ec_seckey_verify(ctx, U8_DATA(seckey));
}

static int ffi_secp256k1_ec_pubkey_create(const secp256k1_context* ctx, secp256k1_pubkey *pubkey, ___SCMOBJ seckey)
{
  return secp256k1_ec_pubkey_create(ctx, pubkey, U8_DATA(seckey));
}

static int ffi_secp256k1_ec_seckey_negate(const secp256k1_context* ctx, ___SCMOBJ seckey)
{
  return secp256k1_ec_seckey_negate(ctx, U8_DATA(seckey));
}

static int ffi_secp256k1_ec_seckey_tweak_add(const secp256k1_context* ctx, ___SCMOBJ seckey, ___SCMOBJ tweak)
{
  return secp256k1_ec_seckey_tweak_add(ctx, U8_DATA(seckey), U8_DATA(tweak));
}

static int ffi_secp256k1_ec_pubkey_tweak_add(const secp256k1_context* ctx, secp256k1_pubkey *pubkey, ___SCMOBJ tweak)
{
  return secp256k1_ec_pubkey_tweak_add(ctx, pubkey, U8_DATA(tweak));
}

static int ffi_secp256k1_ec_seckey_tweak_mul(const secp256k1_context* ctx, ___SCMOBJ seckey, ___SCMOBJ tweak)
{
  return secp256k1_ec_seckey_tweak_mul(ctx, U8_DATA(seckey), U8_DATA(tweak));
}

static int ffi_secp256k1_ec_pubkey_tweak_mul(const secp256k1_context* ctx, secp256k1_pubkey *pubkey, ___SCMOBJ tweak)
{
  return secp256k1_ec_pubkey_tweak_mul(ctx, pubkey, U8_DATA(tweak));
}

// NB: obj is supposed to be a u8vector of length 32
static int ffi_secp256k1_context_randomize (secp256k1_context* ctx, ___SCMOBJ obj)
{
  return secp256k1_context_randomize(ctx, U8_DATA(obj));
}

static int ffi_secp256k1_ec_pubkey_combine(const secp256k1_context* ctx, secp256k1_pubkey *out, ___SCMOBJ ins)
{
  const secp256k1_pubkey* cpks[1024];
  int size = ___INT(___VECTORLENGTH(ins));
  int count;
  if (size > 1024) { return 0; }
  for (count = 0; count < size; count++) {
        cpks[count] = ___CAST(secp256k1_pubkey*,___FIELD(___VECTORREF(ins,___FIX(count)),___FOREIGN_PTR));
  }
  return secp256k1_ec_pubkey_combine(ctx, out, cpks, size);
}

static int ffi_secp256k1_ecdsa_recoverable_signature_parse_compact
  (secp256k1_context* ctx, ___SCMOBJ ersig65, ___SCMOBJ input64, int recid)
{
  return secp256k1_ecdsa_recoverable_signature_parse_compact(ctx, (secp256k1_ecdsa_recoverable_signature*)U8_DATA(ersig65), U8_DATA(input64), recid);
}

static int ffi_secp256k1_ecdsa_recoverable_signature_convert
  (secp256k1_context* ctx, secp256k1_ecdsa_signature* sig, ___SCMOBJ ersig65)
{
  return secp256k1_ecdsa_recoverable_signature_convert(ctx, sig, (secp256k1_ecdsa_recoverable_signature*)U8_DATA(ersig65));
}

static int ffi_secp256k1_ecdsa_recoverable_signature_serialize_compact
  (secp256k1_context* ctx, ___SCMOBJ output64, ___SCMOBJ ersig65)
{
  int recid = 0;
  int ret = secp256k1_ecdsa_recoverable_signature_serialize_compact(ctx, U8_DATA(output64), &recid, (secp256k1_ecdsa_recoverable_signature*)U8_DATA(ersig65));
  return (recid << 1) | (ret & 1); // |
}

static int ffi_secp256k1_ecdsa_sign_recoverable
  (const secp256k1_context* ctx, ___SCMOBJ signature, ___SCMOBJ msg32, ___SCMOBJ seckey)
{
  return secp256k1_ecdsa_sign_recoverable(ctx, (secp256k1_ecdsa_recoverable_signature*)U8_DATA(signature), U8_DATA(msg32), U8_DATA(seckey), NULL, NULL);
}

static int ffi_secp256k1_ecdsa_recover
  (const secp256k1_context* ctx, secp256k1_pubkey *pubkey, ___SCMOBJ signature, ___SCMOBJ msg32)
{
  return secp256k1_ecdsa_recover(ctx, pubkey, (secp256k1_ecdsa_recoverable_signature*)U8_DATA(signature), U8_DATA(msg32));
}

END-C
)

(c-define-type secp256k1-context "secp256k1_context")
(c-define-type secp256k1-context*
               (pointer secp256k1-context (secp256k1-context*) "ffi_release_secp256k1_context"))
(c-define-type secp256k1-pubkey "secp256k1_pubkey")
(c-define-type secp256k1-pubkey* (pointer secp256k1-pubkey (secp256k1-pubkey*)))
(c-define-type secp256k1-ecdsa-signature "secp256k1_ecdsa_signature")
(c-define-type secp256k1-ecdsa-signature* (pointer secp256k1-ecdsa-signature (secp256k1-ecdsa-signature*)))
;(c-define-type secp256k1-seckey "unsigned char[32]")
;(c-define-type secp256k1-tweak "unsigned char[32]")
(c-define-type secp256k1-ecdsa-recoverable-signature "secp256k1_ecdsa_recoverable_signature")

;; flags to pass to secp256k1_context_create
(define-const SECP256K1_CONTEXT_NONE)
(define-const SECP256K1_CONTEXT_VERIFY)
(define-const SECP256K1_CONTEXT_SIGN)
;; flags for 33-byte vs 65-byte pubkeys / signatures
;(define-const SECP256K1_EC_COMPRESSED)
;(define-const SECP256K1_EC_UNCOMPRESSED)

(define-c-lambda secp256k1-context-create
  (int) secp256k1-context*
  "secp256k1_context_create")
(define-c-lambda secp256k1-context-randomize
  (secp256k1-context* scheme-object) int ;; -> bool
  "ffi_secp256k1_context_randomize")
(define-c-lambda secp256k1-context-clone
  (secp256k1-context*) secp256k1-context*
  "secp256k1_context_clone") ;; TODO: error when NULL ?

(define-c-lambda secp256k1-ec-pubkey-alloc
  () secp256k1-pubkey*
  "ffi_secp256k1_ec_pubkey_alloc")
(define-c-lambda secp256k1-ec-pubkey-parse
  (secp256k1-context* secp256k1-pubkey* scheme-object) int ;; u8vector -> bool
  "ffi_secp256k1_ec_pubkey_parse")
(define-c-lambda secp256k1-ec-pubkey-serialize
  (secp256k1-context* scheme-object secp256k1-pubkey*) int ;; ... u8vector ... -> bool ;; flags implicit
  "ffi_secp256k1_ec_pubkey_serialize")
(define-c-lambda secp256k1-ecdsa-signature-parse-der
  (secp256k1-context* secp256k1-ecdsa-signature* scheme-object) int
  "ffi_secp256k1_ecdsa_signature_parse_der")
(define-c-lambda secp256k1-ecdsa-signature-parse-compact
  (secp256k1-context* secp256k1-ecdsa-signature* scheme-object) int
  "ffi_secp256k1_ecdsa_signature_parse_compact")
(define-c-lambda secp256k1-ecdsa-signature-serialize-der
  (secp256k1-context* scheme-object secp256k1-ecdsa-signature*) int
  "ffi_secp256k1_ecdsa_signature_serialize_der")
(define-c-lambda secp256k1-ecdsa-signature-serialize-compact
  (secp256k1-context* scheme-object secp256k1-ecdsa-signature*) int
  "ffi_secp256k1_ecdsa_signature_serialize_compact")

(define-c-lambda secp256k1-ecdsa-signature-alloc
  () secp256k1-ecdsa-signature*
  "ffi_secp256k1_ecdsa_signature_alloc")
(define-c-lambda secp256k1-ecdsa-verify
  (secp256k1-context* secp256k1-ecdsa-signature* scheme-object secp256k1-pubkey*) int
  "ffi_secp256k1_ecdsa_verify")
(define-c-lambda secp256k1-ecdsa-signature-normalize
  (secp256k1-context* secp256k1-ecdsa-signature* secp256k1-ecdsa-signature*) int
  "secp256k1_ecdsa_signature_normalize")
(define-c-lambda secp256k1-ecdsa-sign
  (secp256k1-context* secp256k1-ecdsa-signature* scheme-object scheme-object) int
  "ffi_secp256k1_ecdsa_sign")

(define-c-lambda secp256k1-ec-seckey-verify
  (secp256k1-context* scheme-object) int ;; -> bool
  "ffi_secp256k1_ec_seckey_verify")
(define-c-lambda secp256k1-ec-pubkey-create
  (secp256k1-context* secp256k1-pubkey* scheme-object) int ;; -> bool
  "ffi_secp256k1_ec_pubkey_create")
(define-c-lambda secp256k1-ec-seckey-negate
  (secp256k1-context* scheme-object) int
  "ffi_secp256k1_ec_seckey_negate")
(define-c-lambda secp256k1-ec-pubkey-negate
  (secp256k1-context* secp256k1-pubkey*) int
  "secp256k1_ec_pubkey_negate")
(define-c-lambda secp256k1-ec-seckey-tweak-add
  (secp256k1-context* scheme-object scheme-object) int ;; -> bool
  "ffi_secp256k1_ec_seckey_tweak_add")
(define-c-lambda secp256k1-ec-pubkey-tweak-add
  (secp256k1-context* secp256k1-pubkey* scheme-object) int ;; -> bool
  "ffi_secp256k1_ec_pubkey_tweak_add")
(define-c-lambda secp256k1-ec-seckey-tweak-mul
  (secp256k1-context* scheme-object scheme-object) int ;; -> bool
  "ffi_secp256k1_ec_seckey_tweak_mul")
(define-c-lambda secp256k1-ec-pubkey-tweak-mul
  (secp256k1-context* secp256k1-pubkey* scheme-object) int ;; -> bool
  "ffi_secp256k1_ec_pubkey_tweak_mul")
(define-c-lambda secp256k1-ec-pubkey-combine
  (secp256k1-context* secp256k1-pubkey* scheme-object) int ;; -> bool
  "ffi_secp256k1_ec_pubkey_combine")

(define-c-lambda secp256k1-ecdsa-recoverable-signature-parse-compact
  (secp256k1-context* scheme-object scheme-object int) int
  "ffi_secp256k1_ecdsa_recoverable_signature_parse_compact")
(define-c-lambda secp256k1-ecdsa-recoverable-signature-convert
  (secp256k1-context* secp256k1-ecdsa-signature* scheme-object) int
  "ffi_secp256k1_ecdsa_recoverable_signature_convert")
(define-c-lambda secp256k1-ecdsa-recoverable-signature-serialize-compact
  (secp256k1-context* scheme-object scheme-object) int
  "ffi_secp256k1_ecdsa_recoverable_signature_serialize_compact")
(define-c-lambda secp256k1-ecdsa-sign-recoverable
  (secp256k1-context* scheme-object scheme-object scheme-object) int
  "ffi_secp256k1_ecdsa_sign_recoverable")
(define-c-lambda secp256k1-ecdsa-recover
  (secp256k1-context* secp256k1-pubkey* scheme-object scheme-object) int
  "ffi_secp256k1_ecdsa_recover")

);ffi

;; Create context just once, because it's an expensive operation.
;; This assumes single instantiation of this module in a single-threaded environment.
;; NB: If and when we enable SMP support for Gambit, we need to handle the context better.
(def secp256k1-ctx
  (secp256k1-context-create (bitwise-ior SECP256K1_CONTEXT_VERIFY SECP256K1_CONTEXT_SIGN)))

(def secp256k1-mutex (make-mutex 'secp256k1))

(def (bytesN? x n) (and (bytes? x) (= (bytes-length x) n)))
(def (bytes32? x) (bytesN? x 32))
(def (bytes33? x) (bytesN? x 33))
(def (bytes64? x) (bytesN? x 64))
(def (bytes65? x) (bytesN? x 65))

(defrule (with-secp256k1-ctx f a ...)
  (with-lock secp256k1-mutex (lambda () (f secp256k1-ctx a ...))))
(defrule (with-secp256k1-ctx/check f a ...)
  (let ((n (with-secp256k1-ctx f a ...)))
    (if (even? n) (error "secp256k1 error" 'f) (fxarithmetic-shift n -1))))

(def (new-secp256k1-pubkey)
  (or (secp256k1-ec-pubkey-alloc) (error "failed malloc of pubkey")))

;; : Pubkey <- Bytes
(def (secp256k1-pubkey<-bytes bytes)
  (unless (or (bytes33? bytes) (bytes65? bytes))
    (error "bad bytes length" 'secp256k1-pubkey<-bytes bytes))
  (def pubkey (new-secp256k1-pubkey))
  (with-secp256k1-ctx/check secp256k1-ec-pubkey-parse pubkey bytes)
  pubkey)

;; : Bytes <- Pubkey Bool
(def (bytes<-secp256k1-pubkey pubkey (compressed? #f))
  (def bytes (make-bytes (if compressed? 33 65)))
  (with-secp256k1-ctx secp256k1-ec-pubkey-serialize bytes pubkey)
  bytes)

(def (new-secp256k1-signature)
  (or (secp256k1-ecdsa-signature-alloc) (error "failed malloc of ecdsa-signature")))

;; Sig <- Bytes64
(def (secp256k1-signature<-bytes/compact bytes)
  (assert! (bytes64? bytes))
  (def sig (new-secp256k1-signature))
  (with-secp256k1-ctx/check secp256k1-ecdsa-signature-parse-compact sig bytes)
  sig)

;; : Sig <- Bytes
(def (secp256k1-signature<-bytes/der bytes)
  (def sig (new-secp256k1-signature))
  (with-secp256k1-ctx/check secp256k1-ecdsa-signature-parse-der sig bytes)
  sig)

;; : Bytes <- Sig
(def (bytes<-secp256k1-signature/der sig)
  (def bytes (make-bytes 71))
  (def len (with-secp256k1-ctx/check secp256k1-ecdsa-signature-serialize-der bytes sig))
  (if (= len 71) bytes (subu8vector bytes 0 len)))

;; : Bytes64 <- Sig
(def (bytes<-secp256k1-signature/compact sig)
  (def bytes (make-bytes 64))
  (with-secp256k1-ctx secp256k1-ecdsa-signature-serialize-compact bytes sig)
  bytes)

;; : Bool <- Sig Bytes32 Pubkey
(def (verify-secp256k1-signature sig msg32 pubkey)
  (assert! (bytes32? msg32))
  (= 1 (with-secp256k1-ctx secp256k1-ecdsa-verify sig msg32 pubkey)))

;; Return two values: a boolean that is true if the previous signature was *not* normalized,
;; and the normalized signature
;; : Bool Sig <- Sig
(def (normalize-secp256k1-signature sigin)
  (def sigout (new-secp256k1-signature))
  (values (= 1 (with-secp256k1-ctx secp256k1-ecdsa-signature-normalize sigout sigin)) sigout))

;; : Sig <- Bytes32 Seckey
(def (make-secp256k1-signature msg32 seckey)
  (assert! (and (bytes32? msg32) (bytes32? seckey)))
  (def sig (new-secp256k1-signature))
  (with-secp256k1-ctx/check secp256k1-ecdsa-sign sig msg32 seckey)
  sig)

;; : Bool <- Seckey
(def (verify-secp256k1-seckey seckey)
  (assert! (bytes32? seckey))
  (= 1 (with-secp256k1-ctx secp256k1-ec-seckey-verify seckey)))

;; : Pubkey <- Seckey
(def (secp256k1-pubkey<-seckey seckey)
  (assert! (bytes32? seckey))
  (def pubkey (new-secp256k1-pubkey))
  (with-secp256k1-ctx/check secp256k1-ec-pubkey-create pubkey seckey)
  pubkey)

;; <- Seckey
(def (negate-secp256k1-seckey! seckey)
  (assert! (bytes32? seckey))
  (with-secp256k1-ctx/check secp256k1-ec-seckey-negate seckey))

;; <- Pubkey
(def (negate-secp256k1-pubkey! pubkey)
  (with-secp256k1-ctx/check secp256k1-ec-pubkey-negate pubkey))

;; <- Seckey Bytes32
(def (secp256k1-seckey-tweak-add! seckey tweak32)
  (assert! (and (bytes32? seckey) (bytes32? tweak32)))
  (with-secp256k1-ctx/check secp256k1-ec-seckey-tweak-add seckey tweak32))

;; <- Pubkey Bytes32
(def (secp256k1-pubkey-tweak-add! pubkey tweak32)
  (assert! (bytes32? tweak32))
  (with-secp256k1-ctx/check secp256k1-ec-pubkey-tweak-add pubkey tweak32))

;; <- Seckey Bytes32
(def (secp256k1-seckey-tweak-mul! seckey tweak32)
  (assert! (and (bytes32? seckey) (bytes32? tweak32)))
  (with-secp256k1-ctx/check secp256k1-ec-seckey-tweak-mul seckey tweak32))

;; <- Pubkey Bytes32
(def (secp256k1-pubkey-tweak-mul! pubkey tweak32)
  (assert! (and (bytes32? tweak32)))
  (with-secp256k1-ctx/check secp256k1-ec-pubkey-tweak-mul pubkey tweak32))

;; <- Bytes32
(def (secp256k1-context-randomize! seed32)
  (assert! (bytes32? seed32))
  (with-secp256k1-ctx/check secp256k1-context-randomize seed32))

;; Pubkey <- (Vector Pubkey)
(def (secp256k1-pubkey-combine pubkey-vector)
  (def pubkey (new-secp256k1-pubkey))
  (with-secp256k1-ctx/check secp256k1-ec-pubkey-combine pubkey pubkey-vector)
  pubkey)

;; RSig <- Bytes64 UInt2
(def (secp256k1-recoverable-signature<-bytes bytes recid)
  (assert! (and (bytes64? bytes) (<= 0 recid 3)))
  (def ersig (make-bytes 65))
  (with-secp256k1-ctx/check secp256k1-ecdsa-recoverable-signature-parse-compact ersig bytes recid)
  ersig)

;; Sig <- RSig
(def (convert-secp256k1-recoverable-signature rsig)
  (assert! (bytes65? rsig))
  (def sig (new-secp256k1-signature))
  (with-secp256k1-ctx secp256k1-ecdsa-recoverable-signature-convert sig rsig)
  sig)

;; Bytes64 UInt2 <- RSig
;; see https://bitcoin.stackexchange.com/questions/38351/ecdsa-v-r-s-what-is-v
;; for information about recovery id
(def (bytes<-secp256k1-recoverable-signature rsig)
  (assert! (bytes65? rsig))
  (def bytes (make-bytes 64))
  (values bytes
          (with-secp256k1-ctx/check secp256k1-ecdsa-recoverable-signature-serialize-compact bytes rsig)))

;; RSig <- Bytes32 Seckey
(def (make-secp256k1-recoverable-signature msg32 seckey)
  (assert! (and (bytes32? msg32) (bytes32? seckey)))
  (def rsig (make-bytes 65))
  (with-secp256k1-ctx/check secp256k1-ecdsa-sign-recoverable rsig msg32 seckey)
  rsig)

;; Pubkey <- RSig Bytes32
(def (secp256k1-recover rsig msg32)
  (assert! (and (bytes65? rsig) (bytes32? msg32)))
  (def pubkey (new-secp256k1-pubkey))
  (with-secp256k1-ctx/check secp256k1-ecdsa-recover pubkey rsig msg32)
  pubkey)
