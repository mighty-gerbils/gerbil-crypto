(export #t)

(import :gerbil/gambit
        :std/test
        :std/text/hex
        ../blake2)

;; blake2-test : TestSuite
(def blake2-test
  (test-suite "test suite for clan/crypto/blake2"
    (test-case "digest test vectors for blake2b"
      (for-each (match <> ([h s] (check-equal? (hex-encode (blake2b<-string s)) h)))
                [;; Vector from https://en.wikipedia.org/wiki/BLAKE_(hash_function)#BLAKE2
                 ["786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce" ""]
                 ["a8add4bdddfd93e4877d2746e62817b116364a1fa7bc148d95090bc7333b3673f82401cf7aa2e4cb1ecd90296e3f14cb5413f8ed77be73045b13914cdcd6a918" "The quick brown fox jumps over the lazy dog"]
                 ["ab6b007747d8068c02e25a6008db8a77c218d94f3b40d2291a7dc8a62090a744c082ea27af01521a102e42f480a31e9844053f456b4b41e8aa78bbe5c12957bb" "The quick brown fox jumps over the lazy dof"]]))))
