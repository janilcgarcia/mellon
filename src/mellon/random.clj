(ns mellon.random
  (:require [clojure.core.async :as async :refer [go-loop go <! >! chan close!]])
  (:require [mellon.native-utils :as native]
            [mellon.utils :refer [bytes->long
                                  int->bytes]]))

;; CSPRBGs
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
                (>! out (vec (take nbytes output)))
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

;; Bit utility
(defn- find-highest-bit
  "Find the highest bit in an integer"
  [n]
  (loop [number n
         highest 0]
    (if (= number 0)
      highest
      (recur (unsigned-bit-shift-right number 1) (inc highest)))))

;; Random generation functions
(defn rand-bits
  "Generate n random bits. Uses a byte-vector generator (and discards unused
  bits). The bits are generated as big-endian and only consumes from the
  byte generator enough bytes to create the bitvector."
  ([prbg] (fn [nbits] (rand-bits prbg nbits)))
  ([prbg nbits]
   (go
     (let [required-bytes (int (/ (+ nbits 7) 8))
           bytes (<! (next-bytes prbg required-bytes))
           last-bits (mod nbits 8)
           mask (dec (bit-shift-left (byte 1) last-bits))]
       (update bytes 0 (fn [n]
                           (if (= last-bits 0)
                             n
                             (bit-and n mask))))))))

(defn rand-double
  "Generates a random number in the interval [0.0, 1.0] using a byte-generator"
  [prbg]
  (go
    (let [bits (<! (rand-bits prbg native/max-int-bits))
          random-long (bytes->long bits)]
      (/ (double random-long) native/max-int))))

(defn rand-max-int
  "Based on a byte-generator, creates a new random integral with the max
  value defined by the max-int argument."
  ([prbg] (fn [max-int] (rand-max-int prbg max-int)))
  ([prbg max-int]
   (if (<= max-int 0)
     (throw (ex-message "Max value must be > 0")))

   (let [bits (find-highest-bit (int max-int))]
     (go-loop [int-bits (<! (rand-bits prbg bits))]
       (let [generated (bytes->long int-bits)]
         (if (<= generated max-int)
           generated
           (recur (<! (rand-bits prbg bits)))))))))

(defn rand-in-range
  "Generates a random integral number in the specified range, using a the given
  byte-generator."
  ([prbg] (fn [min-value max-value]
                (rand-in-range prbg min-value max-value)))
  ([prbg min-value max-value]
   (go
     (let [delta (- max-value min-value)
           gdelta (<! (rand-max-int prbg delta))]
       (+ min-value gdelta)))))

(defn rand-element
  "Choose one among the elements of an nth-able collection randomically
  using the given byte-generator"
  ([prbg] (fn [coll] (rand-element prbg coll)))
  ([prbg coll]
   (go
     (let [size (count coll)
           rand-index (<! (rand-max-int prbg (dec size)))]
       (nth coll rand-index)))))
