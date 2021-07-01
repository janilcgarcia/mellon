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
