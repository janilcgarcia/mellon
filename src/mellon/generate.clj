(ns mellon.generate
  (:require [clojure.string :as s]
            [mellon.random :as m.rand]))

(defn load-dict
  [file]
  (s/split-lines (slurp file)))

(defn generate-passphrase
  [dict len]
  (let [byte-gen m.rand/system-byte-generator]
    (s/join " " (repeatedly len #(m.rand/rand-element byte-gen dict)))))

