#!/usr/bin/env gxi
;; To run tests, use: ./unit-tests.ss

(import :gerbil/expander :clan/utils/path :clan/utils/source)
(def here (path-parent (this-source-file)))
(current-directory here)
(add-load-path here)
(import-module ':crypto/t/unit-tests #t #t)
(def main (eval 'crypto/t/unit-tests#main))
