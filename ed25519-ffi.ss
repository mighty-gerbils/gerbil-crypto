;;; -*- Scheme -*-
;;;; Gerbil FFI for ed25519
;;
;; To be linked with libsodium

(export
    finalize-signature
    verify-signature
)

(import
  :gerbil/gambit
  :std/foreign
  :clan/base
)

(begin-ffi
    (ffi-crypto-sign-ed25519ph-statebytes
     ffi-crypto-sign-ed25519-bytes
     ffi-crypto-sign-ed25519-seedbytes
     ffi-crypto-sign-ed25519-publickeybytes
     ffi-crypto-sign-ed25519-secretkeybytes
     ffi-crypto-sign-ed25519-sk-to-seed
     ffi-crypto-sign-ed25519-sk-to-pk
     ffi-crypto-sign-ed25519ph-init
     ffi-crypto-sign-ed25519ph-update
     ffi-crypto-sign-ed25519ph-final-create
     ffi-crypto-sign-ed25519ph-final-verify
    )
(c-declare #<<END-C
#include <string.h>

#include <sodium/crypto_hash_sha512.h>
#include <sodium/crypto_sign_ed25519.h>

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

static int ffi_crypto_sign_ed25519_sk_to_seed(unsigned char *seed, const unsigned char *sk)
{
  return crypto_sign_ed25519_sk_to_seed(seed, sk);
}

static int ffi_crypto_sign_ed25519_sk_to_pk(unsigned char *pk, const unsigned char *sk)
{
  return crypto_sign_ed25519_sk_to_pk(pk, sk);
}

static int ffi_crypto_sign_ed25519ph_init(crypto_sign_ed25519ph_state *state)
{
  crypto_hash_sha512_init(&state->hs);
  return 0;
}

static int ffi_crypto_sign_ed25519ph_update(crypto_sign_ed25519ph_state *state, const unsigned char *m, unsigned long long mlen)
{
  return crypto_hash_sha512_update(&state->hs, m, mlen);
}

static int ffi_crypto_sign_ed25519ph_final_create(crypto_sign_ed25519ph_state *state, unsigned char *sig, unsigned long long *siglen_p, const unsigned char *sk)
{
  return crypto_sign_ed25519ph_final_create(state, sig, siglen_p, sk);
}

static int ffi_crypto_sign_ed25519ph_final_verify(crypto_sign_ed25519ph_state *state, const unsigned char *sig, const unsigned char *pk)
{
  return crypto_sign_ed25519ph_final_verify(state, sig, pk);
}

END-C
)

(c-define-type unsigned-char* (pointer unsigned-char (unsigned-char*)))
(c-define-type unsigned-long-long* (pointer unsigned-long-long (unsigned-long-long*)))
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
  (unsigned-char* unsigned-char*) int
  "ffi_crypto_sign_ed25519_sk_to_seed")

(define-c-lambda ffi-crypto-sign-ed25519-sk-to-pk
  (unsigned-char* unsigned-char*) int
  "ffi_crypto_sign_ed25519_sk_to_pk")

(define-c-lambda ffi-crypto-sign-ed25519ph-init
  (crypto-sign-ed25519ph-state*) int
  "ffi_crypto_sign_ed25519ph_init")

(define-c-lambda ffi-crypto-sign-ed25519ph-update
  (crypto-sign-ed25519ph-state* unsigned-char* unsigned-long-long) int
  "ffi_crypto_sign_ed25519ph_update")

(define-c-lambda ffi-crypto-sign-ed25519ph-final-create
  (crypto-sign-ed25519ph-state* unsigned-char* unsigned-long-long* unsigned-char*) int
  "ffi_crypto_sign_ed25519ph_final_create")

(define-c-lambda ffi-crypto-sign-ed25519ph-final-verify
  (crypto-sign-ed25519ph-state* unsigned-char* unsigned-char*) int
  "ffi_crypto_sign_ed25519ph_final_verify")
); ffi

(def unsigned-long-long-max 18446744073709551615)

(def (make-unsigned-long-long value)
  (if (and (>= value 0) (< value unsigned-long-long-max))
    value
    (error "Value out of range for unsigned long long")))

(def (finalize-signature state sig sk)
  (let ((siglen (make-unsigned-long-long 0)))
    (let ((result (ffi-crypto-sign-ed25519ph-final-create state sig siglen sk)))
      (if (zero? result)
        siglen
        (error "Failed to create signature" result))))
)

(def (verify-signature state sig pk)
  (let ((result (ffi-crypto-sign-ed25519ph-final-verify state sig pk)))
    (if (zero? result)
        #t
        #f
    )
  )
)
