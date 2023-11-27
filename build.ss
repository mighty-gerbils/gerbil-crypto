#!/usr/bin/env gxi
;; -*- Gerbil -*-
;; This is the build file for Gerbil-crypto. Invoke it using
;; ./build.ss [cmd]
;; where [cmd] is typically left empty (same as "compile")
;; Note that may you need to first:
;;   gxpkg install github.com/fare/gerbil-utils
;;   gxpkg install github.com/fare/gerbil-poo

(import
  :std/cli/multicall
  :std/format :std/misc/path
  :clan/building
  :clan/filesystem :clan/versioning)

(def here (path-parent (this-source-file)))

(def (build-spec)
  [[gxc: "keccak" "-cc-options" (format "-I~a" here)]
   [static-include: "keccak-tiny-unrolled.c"]
   "secp256k1-ffi" "secp256k1" "blake2"
   "password" "random" "version"])

(init-build-environment!
 name: "Gerbil-crypto"
 deps: '("clan" "clan/poo")
 spec: build-spec
 pkg-config-libs: '("libsecp256k1")
 nix-deps: '("secp256k1"))

(define-entry-point (nix)
  (help: "Build using nix-build" getopt: [])
  (create-version-file)
  (run-process ["nix-build"])
  (void))
