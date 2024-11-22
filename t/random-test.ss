(export #t)

(import :gerbil/gambit
        :std/assert :std/iter :std/sugar :std/test
        ../random)

(def random-test
  (test-suite "test suite for clan/crypto/random"
    (test-case "random"
      (for ((_ (in-range 100)))
        (assert! (< -1 (randomUInt256) (expt 2 256)))))))
