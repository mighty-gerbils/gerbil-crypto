(import
  :gerbil/gambit/ports
  :std/format :std/iter :std/misc/process
  :clan/utils/exit :clan/utils/ports
  :clan/t/test-support)

(set-current-ports-encoding-standard-unix!)

(def (main . args)
  (eval-print-exit
   (silent-exit
    (match args
      ([] (run-tests "."))
      (["meta"] (println "meta all test"))
      (["all"] (run-tests "." test-files: (find-test-files ".")))
      (["test" . files] (run-tests "." test-files: files))))))
