(export #t)
(import
  :std/misc/repr
  :clan/base
  :clan/poo/mop :clan/poo/type :clan/poo/brace)

(defstruct password (string) print: #f equal: #t)
(define-type Password
  {(:: @ [Type.])
   sexp: 'Password
   .element?: (lambda (x) (and (password? x) (element? String (password-string x))))
   .string<-: repr
   .<-string: invalid
   .bytes<-: invalid
   .<-bytes: invalid
   .marshal: invalid
   .unmarshal: invalid
   .sexp<-: (lambda (_) '(invalid "Not showing password"))
   .json<-: invalid
   .<-json: invalid})

;; USE WITH CAUTION.
;; Do not leak such data to the outside world. In the future, keep it even tighter locked.
(def (import-password/string j) (password (validate String j)))
(def (export-password/string j) (password-string j))

