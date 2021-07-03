(ns mellon.utils
  (:require [clojure.core.async :as async :refer [chan close! >! go]]))

(defn call-chan
  "Create a channel that produces one single value passed as argument to
  the callback of f. f can take only the callback as argument."
  [f & args]
  (let [result-channel (chan)
        callback (fn [result]
                   (go
                     (>! result-channel result)
                     (close! result-channel)))]
    (f callback)
    result-channel))

(defn ->>call-chan
  "Creates a channel that produces one single value passed as argument to
  the callback (last argument) of f. args are passed as arugments to
  caller too (before the actual callback)."
  [f & args]
  (let [result-channel (chan)
        callback (fn [result]
                   (go
                     (>! result-channel result)
                     (close! result-channel)))]
    (apply f (concat args [callback]))
    result-channel))

(defn ->call-chan
  "Creates a channel that produces one single value passed as argument to
  the callback (first argument) of caller. args are passed as arugments to
  caller too (after the callback)."
  ([f & args]
   (let [result-channel (chan)
         callback (fn [result]
                    (go
                      (>! result-channel result)
                      (close! result-channel)))]
     (apply f (concat [callback] args))
     result-channel)))

(defn bytes->long
  "Convert a big-endian bit vector into a long. "
  [bs]
  (reduce (fn [acc b]
            (bit-or (bit-shift-left acc 8)
                    (bit-and 0xFF b)))
          0 bs))

(defn int->bytes
  "Convert an integer to big-endian bytes"
  [n]
  [(bit-and (unsigned-bit-shift-right n 24) 0xFF)
   (bit-and (unsigned-bit-shift-right n 16) 0xFF)
   (bit-and (unsigned-bit-shift-right n 8) 0xFF)
   (bit-and n 0xFF)])

(defn fn-to-chan
  "Creates a wrapper function that calls the passed f in a go block and then
  captures it's value in a channel."
  [f]
  (fn [& args]
    (go (apply f args))))
