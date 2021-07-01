(ns mellon.generate
  (:require [clojure.string :as s]
            [mellon.random :as m.random]))

(defn load-dict
  [file]
  (s/split-lines (slurp file)))

(defn generate-passphrase
  ([byte-gen] (fn
                ([dict] (generate-passphrase byte-gen dict))
                ([dict length] (generate-passphrase byte-gen dict length))))
  ([byte-gen dict]
   (fn [length] (generate-passphrase byte-gen dict length)))
  ([byte-gen dict length]
   (s/join " " (repeatedly length #(m.random/rand-element byte-gen dict)))))

