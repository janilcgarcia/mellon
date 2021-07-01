(ns mellon.crypto.core
  (:require [clojure.core.async :refer [go-loop <! >! close! chan]]
            [mellon.utils :as u]))

(defn extended-keyed-hash
  "Transforms a hash into a extended digest hash. You can produce hashes of
  any size with this function. It takes a key, a message and the length of the
  produced digest, then returns a channel where the result can be extracted.

  The hash function must take [key message f] where f is the callback which
  receives the digest of the function. Hash functions with longer digests
  produce faster results."
  [hash key message length]
  (let [hash (partial u/->>call-chan hash)
        result (chan)]
    (go-loop [H (<! (hash key (concat [0] message)))
              n 0
              bs []]
      (if (>= n length)
        (do
          (>! result
              (take length
                    (->> bs
                         (map vec)
                         flatten)))
          (close! result))
        (recur
         (<! (hash key (concat [1] H)))
         (+ n (count H))
         (conj bs H))))
    result))
