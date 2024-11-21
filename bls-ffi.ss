;;; -*- Scheme -*-
;;;; Gerbil FFI for blst
;;
;; Implementation of BLS12-381

(export
  blst-pubkey<-bytes
  bytes<-blst-pubkey
  blst-signature<-bytes
  bytes<-blst-signature
  verify-blst-signature
  make-blst-signature
  verify-blst-seckey
  blst-pubkey<-seckey
  blst-aggregate-signatures
  blst-aggregate-public-keys
  blst-keygen
  blst-scalar-alloc
  blst-scalar-serialize
  blst-scalar-deserialize)

(import
  :gerbil/gambit
  :std/assert :std/foreign
  :std/misc/bytes
  :std/sugar
  :std/text/hex
  :clan/base)

(begin-ffi
  (blst-p1* blst-p2* blst-scalar* 
   blst-p1-alloc blst-p2-alloc blst-scalar-alloc
   blst-keygen blst-sk-to-pk blst-sign blst-verify
   blst-p1-serialize blst-p2-serialize 
   blst-p1-deserialize blst-p2-deserialize
   blst-p1-aggregate blst-p2-aggregate
   blst-scalar-serialize blst-scalar-deserialize)

(c-declare #<<END-C
#include <string.h>
#include <stdbool.h>
#include <blst.h>

#ifndef ___HAVE_FFI_U8VECTOR
#define ___HAVE_FFI_U8VECTOR
#define U8_DATA(obj) ___CAST (___U8*, ___BODY_AS (obj, ___tSUBTYPED))
#define U8_LEN(obj) ___HD_BYTES (___HEADER (obj))
#endif

static ___SCMOBJ ffi_release_blst_p1 (void *ptr)
{
  free(ptr);
  return ___FIX (___NO_ERR);
}

static ___SCMOBJ ffi_release_blst_p2 (void *ptr)
{
  free(ptr);
  return ___FIX (___NO_ERR);
}

static ___SCMOBJ ffi_release_blst_scalar (void *ptr)
{
  free(ptr);
  return ___FIX (___NO_ERR);
}

static blst_p1* ffi_blst_p1_alloc (void)
{
  return malloc(sizeof(blst_p1));
}

static blst_p2* ffi_blst_p2_alloc (void)
{
  return malloc(sizeof(blst_p2));
}

static blst_scalar* ffi_blst_scalar_alloc (void)
{
  return malloc(sizeof(blst_scalar));
}

static int ffi_blst_keygen(blst_scalar *sk, ___SCMOBJ ikm)
{
  blst_scalar key;
  blst_keygen(&key, U8_DATA(ikm), U8_LEN(ikm), NULL, 0);
  memcpy(sk, &key, sizeof(blst_scalar));
  return 1;
}

static void ffi_blst_sk_to_pk(blst_p1* pk, ___SCMOBJ sk_bytes) {
  blst_scalar sk;
  blst_scalar_from_bendian(&sk, U8_DATA(sk_bytes));
  blst_sk_to_pk_in_g1(pk, &sk);
}

static void ffi_blst_sign(blst_p2 *sig, const blst_scalar *sk, ___SCMOBJ msg)
{
  const byte DST[] = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
  blst_hash_to_g2(sig, U8_DATA(msg), U8_LEN(msg), DST, sizeof(DST)-1, NULL, 0);
  blst_sign_pk_in_g1(sig, sig, sk);
}

static int ffi_blst_verify(const blst_p2 *sig, const blst_p1 *pk, ___SCMOBJ msg)
{
  blst_p1_affine pk_aff;
  blst_p2_affine sig_aff;
  blst_p1_to_affine(&pk_aff, pk);
  blst_p2_to_affine(&sig_aff, sig);
  
  const byte DST[] = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
  return blst_core_verify_pk_in_g1(&pk_aff, &sig_aff, 1,
                                  U8_DATA(msg), U8_LEN(msg), 
                                  DST, sizeof(DST)-1,
                                  NULL, 0);
}

static void ffi_blst_p1_serialize(___SCMOBJ out, const blst_p1* p) {
  blst_p1_affine p1_aff;
  blst_p1_to_affine(&p1_aff, p);
  blst_p1_affine_serialize(U8_DATA(out), &p1_aff);
}

static void ffi_blst_p2_serialize(___SCMOBJ out, const blst_p2 *p2)
{
  blst_p2_affine p2_aff;
  blst_p2_to_affine(&p2_aff, p2);
  blst_p2_affine_serialize(U8_DATA(out), &p2_aff);
}

static int ffi_blst_p1_deserialize(blst_p1 *p1, ___SCMOBJ in) {
  blst_p1_affine p1_aff;
  int result = blst_p1_deserialize(&p1_aff, U8_DATA(in));
  if (result) {
    blst_p1_from_affine(p1, &p1_aff);
  }
  return result;
}

static int ffi_blst_p2_deserialize(blst_p2 *p2, ___SCMOBJ in)
{
  blst_p2_affine p2_aff;
  int result = blst_p2_deserialize(&p2_aff, U8_DATA(in));
  blst_p2_from_affine(p2, &p2_aff);
  return result;
}

static void ffi_blst_p2_aggregate(blst_p2 *out, const blst_p2 *in)
{
  blst_p2_add(out, out, in);
}

static void ffi_blst_p1_aggregate(blst_p1 *out, const blst_p1 *in)
{
  blst_p1_add(out, out, in);
}

static void ffi_blst_scalar_serialize(___SCMOBJ out, const blst_scalar* s) {
  byte tmp[32];
  blst_bendian_from_scalar(tmp, s);
  memcpy(U8_DATA(out), tmp, 32);
}

static void ffi_blst_scalar_deserialize(blst_scalar* s, ___SCMOBJ in) {
  blst_scalar_from_bendian(s, U8_DATA(in));
}

END-C
)

(c-define-type blst-p1 "blst_p1")
(c-define-type blst-p1* (pointer blst-p1 (blst-p1*) "ffi_release_blst_p1"))
(c-define-type blst-p2 "blst_p2")
(c-define-type blst-p2* (pointer blst-p2 (blst-p2*) "ffi_release_blst_p2"))
(c-define-type blst-scalar "blst_scalar")
(c-define-type blst-scalar* (pointer blst-scalar (blst-scalar*) "ffi_release_blst_scalar"))

(define-c-lambda blst-p1-alloc () blst-p1* "ffi_blst_p1_alloc")
(define-c-lambda blst-p2-alloc () blst-p2* "ffi_blst_p2_alloc")
(define-c-lambda blst-scalar-alloc () blst-scalar* "ffi_blst_scalar_alloc")

(define-c-lambda blst-keygen (blst-scalar* scheme-object) int "ffi_blst_keygen")
(define-c-lambda blst-sk-to-pk (blst-p1* scheme-object) void "ffi_blst_sk_to_pk")
(define-c-lambda blst-sign (blst-p2* blst-scalar* scheme-object) void "ffi_blst_sign")
(define-c-lambda blst-verify (blst-p2* blst-p1* scheme-object) int "ffi_blst_verify")

(define-c-lambda blst-p1-serialize (scheme-object blst-p1*) void "ffi_blst_p1_serialize")
(define-c-lambda blst-p2-serialize (scheme-object blst-p2*) void "ffi_blst_p2_serialize")
(define-c-lambda blst-p1-deserialize (blst-p1* scheme-object) int "ffi_blst_p1_deserialize")
(define-c-lambda blst-p2-deserialize (blst-p2* scheme-object) int "ffi_blst_p2_deserialize")

(define-c-lambda blst-p1-aggregate (blst-p1* blst-p1*) void "ffi_blst_p1_aggregate")
(define-c-lambda blst-p2-aggregate (blst-p2* blst-p2*) void "ffi_blst_p2_aggregate")
(define-c-lambda blst-scalar-serialize (scheme-object blst-scalar*) void "ffi_blst_scalar_serialize")
(define-c-lambda blst-scalar-deserialize (blst-scalar* scheme-object) void "ffi_blst_scalar_deserialize")

);ffi

;; Create context just once
(def blst-mutex (make-mutex 'blst))

(def (bytes48? x) (and (u8vector? x) (= (u8vector-length x) 48)))
(def (bytes96? x) (and (u8vector? x) (= (u8vector-length x) 96)))

(defrule (with-blst-mutex f a ...)
  (with-lock blst-mutex (lambda () (f a ...))))

(def (new-blst-p1)
  (or (blst-p1-alloc) (error "failed malloc of blst_p1")))

(def (new-blst-p2)
  (or (blst-p2-alloc) (error "failed malloc of blst_p2")))

(def (new-blst-scalar)
  (or (blst-scalar-alloc) (error "failed malloc of blst_scalar")))

;; : PublicKey <- Bytes
(def (blst-pubkey<-bytes bytes)
  (unless (bytes48? bytes)
    (error "bad bytes length" 'blst-pubkey<-bytes bytes))
  (def pubkey (new-blst-p1))
  (blst-p1-deserialize pubkey bytes)
  pubkey)

;; : Bytes <- PublicKey
(def (bytes<-blst-pubkey pubkey)
  (def bytes (make-u8vector 48))
  (with-blst-mutex blst-p1-serialize bytes pubkey)
  bytes)

;; : Signature <- Bytes
(def (blst-signature<-bytes bytes)
  (unless (bytes96? bytes)
    (error "bad bytes length" 'blst-signature<-bytes bytes))
  (def sig (new-blst-p2))
  (blst-p2-deserialize sig bytes)
  sig)

;; : Bytes <- Signature
(def (bytes<-blst-signature sig)
  (def bytes (make-u8vector 96))
  (blst-p2-serialize bytes sig)
  bytes)

;; : Bool <- Signature Bytes PublicKey
(def (verify-blst-signature sig msg pubkey)
  (= 1 (with-blst-mutex blst-verify sig pubkey msg)))

;; : Signature <- Bytes SecretKey
(def (make-blst-signature msg seckey)
  (def sig (new-blst-p2))
  (with-blst-mutex blst-sign sig seckey msg)
  sig)

;; : Bool <- SecretKey
(def (verify-blst-seckey seckey)
  (def pubkey (new-blst-p1))
  (with-blst-mutex blst-sk-to-pk pubkey seckey)
  #t)

;; : PublicKey <- SecretKey
(def (blst-pubkey<-seckey seckey)
  (def pubkey (new-blst-p1))
  (with-blst-mutex blst-sk-to-pk pubkey seckey)
  pubkey)

;; : Signature <- (Vector Signature)
(def (blst-aggregate-signatures sig-vector)
  (def result (new-blst-p2))
  (for-each (lambda (sig) (with-blst-mutex blst-p2-aggregate result sig))
            (vector->list sig-vector))
  result)

;; : PublicKey <- (Vector PublicKey)
(def (blst-aggregate-public-keys pk-vector)
  (def result (new-blst-p1))
  (for-each (lambda (pk) (with-blst-mutex blst-p1-aggregate result pk))
            (vector->list pk-vector))
  result)
