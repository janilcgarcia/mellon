(ns mellon.async-random
  (:require [clojure.core.async :as async :refer [go-loop go <! >! chan]]
            [mellon.crypto.jvm :as crypto]))

(defn system-producer
  [in out]
  (let [random (java.security.SecureRandom.)]
    (go-loop []
      (let [req (<! in)
            bytes (byte-array req)]
        (.nextBytes random bytes)
        (>! out bytes))
      (recur))))

(defn- start-hmac-generate
  [k v hash-in hash-out in out]
  (go-loop [k k
            v v]
    (when-let [req (<! in)]
      (>! hash-in {:key k :message (concat [0] v) :length (+ req 128)})
      
      (let [output (<! hash-out)
            v (drop req output)]
        (>! hash-in {:key k :message (concat [1] v) :length 128})
        (let [new-k (<! hash-out)]
          (>! out (take req output))
          (recur new-k v))))))

(defn hmac-sha2-512-prbg-producer
  [seed salt in out]
  (let [hash-in (chan)
        hash-out (chan)
        salt (if (nil? salt)
               (repeat 16 0)
               salt)
        key seed]
    (crypto/hash-extend-hmac-sha2-512 hash-in hash-out)
    (go
      (>! hash-in {:key salt :message (concat [0] key) :length 128})
      (let [k (<! hash-out)]
        (>! hash-in {:key k :message (concat [1] salt) :length 128})
        (let [v (<! hash-out)]
          (start-hmac-generate k v hash-in hash-out in out))))))
