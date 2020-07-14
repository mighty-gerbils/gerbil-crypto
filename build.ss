#!/usr/bin/env gxi
;; -*- Gerbil -*-
;; This is the build file for Gerbil-crypto. Invoke it using
;; ./build.ss [cmd]
;; where [cmd] is typically left empty (same as "compile")
;; Note that may you need to first:
;;   gxpkg install github.com/fare/gerbil-utils

(import
  :std/build-script :std/format
  :utils/filesystem :utils/path :utils/versioning)

(def here (path-parent (this-source-file)))

(current-directory here)

;; TODO: somehow autodetect detect where this comes from...
(def secp256k1-options
  ["-cc-options" (format "-I~a" (path-expand "~/.nix-profile/include/"))
   "-cc-options" "-I/nix/var/nix/profiles/default/include"
   "-cc-options" "-I/run/current-system/sw/include"
   "-cc-options" (format "-L~a" (path-expand "~/.nix-profile/lib/"))
   "-cc-options" "-L/nix/var/nix/profiles/default/lib"
   "-cc-options" "-L/run/current-system/sw/lib"
   "-cc-options" "-lsecp256k1"])

(def (build-spec)
  [[gxc: "keccak" "-cc-options" (format "-I~a" here)]
   [gxc: "secp256k1" secp256k1-options ...]
   "version"])

(def (main . args)
  (when (match args ([] #t) (["compile" . _] #t) (_ #f))
    (update-version-from-git name: "Gerbil-crypto"))
  (defbuild-script ;; defines an inner "main"
    (build-spec)
    ;;verbose: 9
    )
  (apply main args))
