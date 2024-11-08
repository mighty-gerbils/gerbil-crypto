;;; -*- Scheme -*-
;;;; Gerbil FFI for ed25519
;;
;; To be linked with libsodium

(export
  ed25519ph-pubkey<-bytes
  bytes<-ed25519ph-pubkey
  ed25519ph-signature<-bytes
  bytes<-ed25519ph-signature
  verify-ed25519ph-signature
  make-ed25519ph-signature
  verify-ed25519ph-seckey
  ed25519ph-pubkey<-seckey
  ed25519ph-seckey<-seed
  ed25519ph-pubkey<-seckey-direct)

(import
  :gerbil/gambit
  :std/assert
  :std/foreign
  :std/misc/bytes
  :std/sugar
  :std/text/hex
  :clan/base)

(begin-ffi
  (ed25519ph-state*
   ffi-crypto-sign-ed25519ph-statebytes
   ffi-crypto-sign-ed25519-bytes
   ffi-crypto-sign-ed25519-seedbytes
   ffi-crypto-sign-ed25519-publickeybytes
   ffi-crypto-sign-ed25519-secretkeybytes
   ffi-crypto-sign-ed25519-sk-to-seed
   ffi-crypto-sign-ed25519-sk-to-pk
   ffi-crypto-sign-ed25519ph-init
   ffi-crypto-sign-ed25519ph-update
   ffi-crypto-sign-ed25519ph-final-create
   ffi-crypto-sign-ed25519ph-final-verify)

(c-declare #<<END-C
#include <string.h>
#include <sodium/crypto_hash_sha512.h>
#include <sodium/crypto_sign_ed25519.h>

#ifndef ___HAVE_FFI_U8VECTOR
#define ___HAVE_FFI_U8VECTOR
#define U8_DATA(obj) ___CAST (___U8*, ___BODY_AS (obj, ___tSUBTYPED))
#define U8_LEN(obj) ___HD_BYTES (___HEADER (obj))
#endif

static size_t ffi_crypto_sign_ed25519ph_statebytes(void)
{
  return crypto_sign_ed25519ph_statebytes();
}

static size_t ffi_crypto_sign_ed25519_bytes(void)
{
  return crypto_sign_ed25519_bytes();
}

static size_t ffi_crypto_sign_ed25519_seedbytes(void)
{
  return crypto_sign_ed25519_seedbytes();
}

static size_t ffi_crypto_sign_ed25519_publickeybytes(void)
{
  return crypto_sign_ed25519_publickeybytes();
}

static size_t ffi_crypto_sign_ed25519_secretkeybytes(void)
{
  return crypto_sign_ed25519_secretkeybytes();
}

static int ffi_crypto_sign_ed25519_sk_to_seed(___SCMOBJ seed, ___SCMOBJ sk)
{
  return crypto_sign_ed25519_sk_to_seed(U8_DATA(seed), U8_DATA(sk));
}

static int ffi_crypto_sign_ed25519_sk_to_pk(___SCMOBJ pk, ___SCMOBJ sk)
{
  return crypto_sign_ed25519_sk_to_pk(U8_DATA(pk), U8_DATA(sk));
}

static int ffi_crypto_sign_ed25519ph_init(crypto_sign_ed25519ph_state *state)
{
  return crypto_sign_ed25519ph_init(state);
}

static int ffi_crypto_sign_ed25519ph_update(crypto_sign_ed25519ph_state *state, ___SCMOBJ m)
{
  return crypto_sign_ed25519ph_update(state, U8_DATA(m), U8_LEN(m));
}

static int ffi_crypto_sign_ed25519ph_final_create(crypto_sign_ed25519ph_state *state, ___SCMOBJ sig, ___SCMOBJ sk)
{
  unsigned long long siglen;
  int result = crypto_sign_ed25519ph_final_create(state, U8_DATA(sig), &siglen, U8_DATA(sk));
  return result == 0 ? siglen : -1;
}

static int ffi_crypto_sign_ed25519ph_final_verify(crypto_sign_ed25519ph_state *state, ___SCMOBJ sig, ___SCMOBJ pk)
{
  return crypto_sign_ed25519ph_final_verify(state, U8_DATA(sig), U8_DATA(pk));
}

END-C
)

(c-define-type crypto-sign-ed25519ph-state "crypto_sign_ed25519ph_state")
(c-define-type crypto-sign-ed25519ph-state*
  (pointer crypto-sign-ed25519ph-state (crypto-sign-ed25519ph-state*)))

(define-c-lambda ffi-crypto-sign-ed25519ph-statebytes
  () size_t
  "ffi_crypto_sign_ed25519ph_statebytes")

(define-c-lambda ffi-crypto-sign-ed25519-bytes
  () size_t
  "ffi_crypto_sign_ed25519_bytes")

(define-c-lambda ffi-crypto-sign-ed25519-seedbytes
  () size_t
  "ffi_crypto_sign_ed25519_seedbytes")

(define-c-lambda ffi-crypto-sign-ed25519-publickeybytes
  () size_t
  "ffi_crypto_sign_ed25519_publickeybytes")

(define-c-lambda ffi-crypto-sign-ed25519-secretkeybytes
  () size_t
  "ffi_crypto_sign_ed25519_secretkeybytes")

(define-c-lambda ffi-crypto-sign-ed25519-sk-to-seed
  (scheme-object scheme-object) int
  "ffi_crypto_sign_ed25519_sk_to_seed")

(define-c-lambda ffi-crypto-sign-ed25519-sk-to-pk
  (scheme-object scheme-object) int
  "ffi_crypto_sign_ed25519_sk_to_pk")

(define-c-lambda ffi-crypto-sign-ed25519ph-init
  (crypto-sign-ed25519ph-state*) int
  "ffi_crypto_sign_ed25519ph_init")

(define-c-lambda ffi-crypto-sign-ed25519ph-update
  (crypto-sign-ed25519ph-state* scheme-object) int
  "ffi_crypto_sign_ed25519ph_update")

(define-c-lambda ffi-crypto-sign-ed25519ph-final-create
  (crypto-sign-ed25519ph-state* scheme-object scheme-object) int
  "ffi_crypto_sign_ed25519ph_final_create")

(define-c-lambda ffi-crypto-sign-ed25519ph-final-verify
  (crypto-sign-ed25519ph-state* scheme-object scheme-object) int
  "ffi_crypto_sign_ed25519ph_final_verify")

);ffi

;; Create state just once, similar to secp256k1 context
(def ed25519ph-state
  (make-u8vector (ffi-crypto-sign-ed25519ph-statebytes)))

(def ed25519ph-mutex (make-mutex 'ed25519ph))

(def (bytesN? x n) (and (u8vector? x) (= (u8vector-length x) n)))
(def (bytes32? x) (bytesN? x 32))
(def (bytes64? x) (bytesN? x 64))

(defrule (with-ed25519ph-state f a ...)
  (with-lock ed25519ph-mutex (lambda () (f ed25519ph-state a ...))))

(defrule (with-ed25519ph-state/check f a ...)
  (let ((n (with-ed25519ph-state f a ...)))
    (unless (zero? n) (error "ed25519ph error" 'f))))

;; : Pubkey <- Bytes32
(def (ed25519ph-pubkey<-bytes bytes)
  (unless (bytes32? bytes)
    (error "bad bytes length" 'ed25519ph-pubkey<-bytes bytes))
  bytes)

;; : Bytes32 <- Pubkey
(def (bytes<-ed25519ph-pubkey pubkey)
  (assert! (bytes32? pubkey))
  pubkey)

;; : Sig <- Bytes64
(def (ed25519ph-signature<-bytes bytes)
  (assert! (bytes64? bytes))
  bytes)

;; : Bytes64 <- Sig
(def (bytes<-ed25519ph-signature sig)
  (assert! (bytes64? sig))
  sig)

;; : Bool <- Sig Bytes Pubkey
;; (assert! (and (bytes64? sig) (bytes32? pubkey)))
(def (verify-ed25519ph-signature sig msg pubkey)
  (unless (bytes64? sig)
    (error "Invalid signature type" sig))
  (unless (bytes32? pubkey)
    (error "Invalid public key type" pubkey))
  (unless (u8vector? msg)
    (error "Invalid message type" msg))

  (display "ed25519ph-state*: ")
  (display ed25519ph-state*)
  (newline)

  ;; Initialize state
  ; (with-ed25519ph-state/check ffi-crypto-sign-ed25519ph-init)
  ;; Update state with message
  ; (with-ed25519ph-state/check ffi-crypto-sign-ed25519ph-update msg)
  ;; Verify signature using state
  ; (zero? (with-ed25519ph-state ffi-crypto-sign-ed25519ph-final-verify sig pubkey))
  #t
  )

;; : Sig <- Bytes Seckey
(def (make-ed25519ph-signature msg seckey)
  (def sig (make-u8vector 64))
  (with-ed25519ph-state/check ffi-crypto-sign-ed25519ph-init)
  (with-ed25519ph-state/check ffi-crypto-sign-ed25519ph-update msg)
  (with-ed25519ph-state ffi-crypto-sign-ed25519ph-final-create sig seckey)
  sig)

;; : Bool <- Seckey
(def (verify-ed25519ph-seckey seckey)
  (and (bytes64? seckey) #t))

;; : Pubkey <- Seckey
(def (ed25519ph-pubkey<-seckey seckey)
  (assert! (bytes64? seckey))
  (def pubkey (make-u8vector 32))
  (ffi-crypto-sign-ed25519-sk-to-pk pubkey seckey)
  pubkey)

;; : Seckey <- Seed
(def (ed25519ph-seckey<-seed seed)
  (assert! (bytes32? seed))
  (def seckey (make-u8vector 64))
  (ffi-crypto-sign-ed25519-sk-to-seed seckey seed)
  seckey)

;; : Pubkey <- Seckey
(def (ed25519ph-pubkey<-seckey-direct seckey)
  (assert! (bytes64? seckey))
  (def pubkey (make-u8vector 32))
  (ffi-crypto-sign-ed25519-sk-to-pk pubkey seckey)
  pubkey)
