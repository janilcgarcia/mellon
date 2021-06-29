(ns mellon.async-random
  (:require [clojure.core.async :as async :refer [go-loop go <! >! chan close!]]))

(defn- connect-hash-prbg
  [in ext-hash seed salt]
  (let [salt (if (nil? salt)
               (repeat 16 0)
               salt)
        key seed
        out (chan)]
    (go
      (let [k (<! (ext-hash salt (concat [0] key) 128))
            v (<! (ext-hash k (concat [1] salt) 128))]
        (loop [k k
               v v]
          (if-let [nbytes (<! in)]
            (let [output (<! (ext-hash k (concat [0] v) (+ nbytes 128)))
                  new-v (drop nbytes output)]
              (do
                (>! out (take nbytes output))
                (recur (<! (ext-hash k (concat [1] new-v) 128))
                       new-v)))
            (close! out)))))
    out))

(defn ->hash-prbg
  [ext-hash seed salt]
  (let [generator-input (chan)
        generator-output (connect-hash-prbg generator-input ext-hash seed salt)]
    [generator-input generator-output]))

(defn- connect-system-prbg
  [in sys-random]
  (let [out (chan)]
    (go-loop []
      (if-let [nbytes (<! in)]
        (do 
          (>! out (<! (sys-random nbytes)))
          (recur))
        (close! out)))
    out))

(defn ->system-prbg
  [sys-random]
  (let [generator-input (chan)
        generator-output (connect-system-prbg generator-input sys-random)]
    [generator-input generator-output]))

(defn next-bytes
  [prbg nbytes]
  (let [[gen-in gen-out] prbg]
    (go
      (>! gen-in nbytes))
    gen-out))

(defn close-prbg
  [prbg]
  (let [[in _] prbg]
    (close! in)))

