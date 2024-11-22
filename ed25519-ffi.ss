;;; -*- Scheme -*-
;;;; Gerbil FFI for libsodium ed25519

(export
  ed25519-pubkey<-bytes
  bytes<-ed25519-pubkey
  ed25519-signature<-bytes
  bytes<-ed25519-signature
  verify-ed25519-signature
  make-ed25519-signature
  verify-ed25519-seckey
  ed25519-pubkey<-seckey
  ed25519-keypair
  ed25519-seed-keypair
  ed25519-sk-to-pk
  ed25519-sk-to-seed
  ed25519-pk-to-curve25519
  ed25519-sk-to-curve25519)

(import
  :gerbil/gambit
  :std/assert :std/foreign
  :std/misc/bytes
  :std/sugar
  :std/text/hex
  :clan/base)

(begin-ffi
  (ed25519-context*
   crypto_sign_ed25519_BYTES
   crypto_sign_ed25519_PUBLICKEYBYTES
   crypto_sign_ed25519_SECRETKEYBYTES
   crypto_sign_ed25519_SEEDBYTES
   crypto_sign_ed25519_keypair
   crypto_sign_ed25519_seed_keypair
   crypto_sign_ed25519_sk_to_pk
   crypto_sign_ed25519_sk_to_seed
   crypto_sign_ed25519_pk_to_curve25519
   crypto_sign_ed25519_sk_to_curve25519
   crypto_sign_ed25519_detached
   crypto_sign_ed25519_verify_detached)

(c-declare #<<END-C
#include <sodium.h>

#ifndef ___HAVE_FFI_U8VECTOR
#define ___HAVE_FFI_U8VECTOR
#define U8_DATA(obj) ___CAST (___U8*, ___BODY_AS (obj, ___tSUBTYPED))
#define U8_LEN(obj) ___HD_BYTES (___HEADER (obj))
#endif

static int ffi_crypto_sign_ed25519_keypair(___SCMOBJ pk, ___SCMOBJ sk)
{
  return crypto_sign_ed25519_keypair(U8_DATA(pk), U8_DATA(sk));
}

static int ffi_crypto_sign_ed25519_seed_keypair(___SCMOBJ pk, ___SCMOBJ sk, ___SCMOBJ seed)
{
  return crypto_sign_ed25519_seed_keypair(U8_DATA(pk), U8_DATA(sk), U8_DATA(seed));
}

static int ffi_crypto_sign_ed25519_sk_to_pk(___SCMOBJ pk, ___SCMOBJ sk)
{
  return crypto_sign_ed25519_sk_to_pk(U8_DATA(pk), U8_DATA(sk));
}

static int ffi_crypto_sign_ed25519_sk_to_seed(___SCMOBJ seed, ___SCMOBJ sk)
{
  return crypto_sign_ed25519_sk_to_seed(U8_DATA(seed), U8_DATA(sk));
}

static int ffi_crypto_sign_ed25519_pk_to_curve25519(___SCMOBJ curve25519_pk, ___SCMOBJ ed25519_pk)
{
  return crypto_sign_ed25519_pk_to_curve25519(U8_DATA(curve25519_pk), U8_DATA(ed25519_pk));
}

static int ffi_crypto_sign_ed25519_sk_to_curve25519(___SCMOBJ curve25519_sk, ___SCMOBJ ed25519_sk)
{
  return crypto_sign_ed25519_sk_to_curve25519(U8_DATA(curve25519_sk), U8_DATA(ed25519_sk));
}

static int ffi_crypto_sign_ed25519_detached(___SCMOBJ sig, ___SCMOBJ msg, ___SCMOBJ sk)
{
  unsigned long long siglen;
  return crypto_sign_ed25519_detached(U8_DATA(sig), &siglen, U8_DATA(msg), U8_LEN(msg), U8_DATA(sk));
}

static int ffi_crypto_sign_ed25519_verify_detached(___SCMOBJ sig, ___SCMOBJ msg, ___SCMOBJ pk)
{
  return crypto_sign_ed25519_verify_detached(U8_DATA(sig), U8_DATA(msg), U8_LEN(msg), U8_DATA(pk));
}

END-C
)

(define-const crypto_sign_ed25519_BYTES)
(define-const crypto_sign_ed25519_PUBLICKEYBYTES)
(define-const crypto_sign_ed25519_SECRETKEYBYTES)
(define-const crypto_sign_ed25519_SEEDBYTES)

(define-c-lambda crypto_sign_ed25519_keypair
  (scheme-object scheme-object) int
  "ffi_crypto_sign_ed25519_keypair")

(define-c-lambda crypto_sign_ed25519_seed_keypair
  (scheme-object scheme-object scheme-object) int
  "ffi_crypto_sign_ed25519_seed_keypair")

(define-c-lambda crypto_sign_ed25519_sk_to_pk
  (scheme-object scheme-object) int
  "ffi_crypto_sign_ed25519_sk_to_pk")

(define-c-lambda crypto_sign_ed25519_sk_to_seed
  (scheme-object scheme-object) int
  "ffi_crypto_sign_ed25519_sk_to_seed")

(define-c-lambda crypto_sign_ed25519_pk_to_curve25519
  (scheme-object scheme-object) int
  "ffi_crypto_sign_ed25519_pk_to_curve25519")

(define-c-lambda crypto_sign_ed25519_sk_to_curve25519
  (scheme-object scheme-object) int
  "ffi_crypto_sign_ed25519_sk_to_curve25519")

(define-c-lambda crypto_sign_ed25519_detached
  (scheme-object scheme-object scheme-object) int
  "ffi_crypto_sign_ed25519_detached")

(define-c-lambda crypto_sign_ed25519_verify_detached
  (scheme-object scheme-object scheme-object) int
  "ffi_crypto_sign_ed25519_verify_detached")

);ffi

(def (bytesN? x n) (and (u8vector? x) (= (u8vector-length x) n)))
(def (bytes32? x) (bytesN? x 32))
(def (bytes64? x) (bytesN? x 64))

;; : Pubkey <- Bytes
(def (ed25519-pubkey<-bytes bytes)
  (unless (bytes32? bytes)
    (error "bad bytes length" 'ed25519-pubkey<-bytes bytes))
  bytes)

;; : Bytes <- Pubkey
(def (bytes<-ed25519-pubkey pubkey)
  (assert! (bytes32? pubkey))
  pubkey)

;; : Sig <- Bytes
(def (ed25519-signature<-bytes bytes)
  (unless (bytes64? bytes)
    (error "bad bytes length" 'ed25519-signature<-bytes bytes))
  bytes)

;; : Bytes <- Sig
(def (bytes<-ed25519-signature sig)
  (assert! (bytes64? sig))
  sig)

;; : Bool <- Sig Bytes Pubkey
(def (verify-ed25519-signature sig msg pubkey)
  (assert! (and (bytes64? sig) (bytes32? pubkey)))
  (zero? (crypto_sign_ed25519_verify_detached sig msg pubkey)))

;; : Sig <- Bytes Seckey
(def (make-ed25519-signature msg seckey)
  (assert! (bytes64? seckey))
  (def sig (make-u8vector crypto_sign_ed25519_BYTES))
  (crypto_sign_ed25519_detached sig msg seckey)
  sig)

;; : Bool <- Seckey
(def (verify-ed25519-seckey seckey)
  (assert! (bytes64? seckey))
  #t) ;; Ed25519 accepts any 64-byte secret key

;; : Pubkey <- Seckey
(def (ed25519-pubkey<-seckey seckey)
  (assert! (bytes64? seckey))
  (def pubkey (make-u8vector crypto_sign_ed25519_PUBLICKEYBYTES))
  (crypto_sign_ed25519_sk_to_pk pubkey seckey)
  pubkey)

;; Generate a new keypair
;; : (Values Pubkey Seckey)
(def (ed25519-keypair)
  (def pk (make-u8vector crypto_sign_ed25519_PUBLICKEYBYTES))
  (def sk (make-u8vector crypto_sign_ed25519_SECRETKEYBYTES))
  (crypto_sign_ed25519_keypair pk sk)
  (values pk sk))

;; Generate a keypair from seed
;; : (Values Pubkey Seckey) <- Bytes32
(def (ed25519-seed-keypair seed)
  (assert! (bytes32? seed))
  (def pk (make-u8vector crypto_sign_ed25519_PUBLICKEYBYTES))
  (def sk (make-u8vector crypto_sign_ed25519_SECRETKEYBYTES))
  (crypto_sign_ed25519_seed_keypair pk sk seed)
  (values pk sk))

;; Extract public key from secret key
;; : Pubkey <- Seckey
(def (ed25519-sk-to-pk sk)
  (assert! (bytes64? sk))
  (def pk (make-u8vector crypto_sign_ed25519_PUBLICKEYBYTES))
  (crypto_sign_ed25519_sk_to_pk pk sk)
  pk)

;; Extract seed from secret key
;; : Bytes32 <- Seckey
(def (ed25519-sk-to-seed sk)
  (assert! (bytes64? sk))
  (def seed (make-u8vector crypto_sign_ed25519_SEEDBYTES))
  (crypto_sign_ed25519_sk_to_seed seed sk)
  seed)

;; Convert Ed25519 public key to Curve25519
;; : Bytes32 <- Pubkey
(def (ed25519-pk-to-curve25519 pk)
  (assert! (bytes32? pk))
  (def curve-pk (make-u8vector 32))
  (crypto_sign_ed25519_pk_to_curve25519 curve-pk pk)
  curve-pk)

;; Convert Ed25519 secret key to Curve25519
;; : Bytes32 <- Seckey
(def (ed25519-sk-to-curve25519 sk)
  (assert! (bytes64? sk))
  (def curve-sk (make-u8vector 32))
  (crypto_sign_ed25519_sk_to_curve25519 curve-sk sk)
  curve-sk)