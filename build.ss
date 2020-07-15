#!/usr/bin/env gxi
;; -*- Gerbil -*-
;; This is the build file for Gerbil-crypto. Invoke it using
;; ./build.ss [cmd]
;; where [cmd] is typically left empty (same as "compile")
;; Note that may you need to first:
;;   gxpkg install github.com/fare/gerbil-utils

(import
  :clan/building :std/format
  :clan/filesystem :clan/path :clan/versioning)

(def here (path-parent (this-source-file)))

(def (build-spec)
  [[gxc: "keccak" "-cc-options" (format "-I~a" here)]
   [gxc: "secp256k1"]
   "version"])

(init-build-environment!
 name: "Gerbil-crypto"
 deps: '("clan")
 spec: build-spec
 pkg-config-libs: '("libsecp256k1")
 nix-deps: '("secp256k1"))
