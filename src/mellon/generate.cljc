(ns mellon.generate
  (:require [clojure.string :as s]
            [mellon.random :as m.random]
            [clojure.core.async :as async :refer [<! go go-loop]]))

(defn generate-passphrase
  [prbg dict length]
  (go-loop [words []]
    (if (>= (count words) length)
      (s/join " " words)
      (recur (conj words (<! (m.random/rand-element prbg dict)))))))

