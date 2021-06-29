(ns mellon.crypto.core
  (:require [clojure.core.async :refer [go-loop <! >! close! chan]]))

(defn extended-keyed-hash-generator
  [hashes hash key message length]
    (let [hash-info (hash hashes)
        digest-size (:max-digest-size hash-info)
        h (:fn hash-info)
        out-chan (chan)
        nblocks (Math/ceil (/ length digest-size))]
    (go-loop [out []
              generated 0
              H (<! (h key (concat [0] message)))]
      (if (>= generated nblocks)
        (do
          (>! out-chan (take length out))
          (close! out-chan))
        (recur
         (concat out H)
         (inc generated)
         (<! (h key (concat [1] message))))))
    out-chan))
