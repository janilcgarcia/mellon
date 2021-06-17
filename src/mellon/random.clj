(ns mellon.random)

(defn rand-bits
  ([gen-bytes] (fn [nbits] (rand-bits gen-bytes nbits)))
  ([gen-bytes nbits]
   (let [required-bytes (int (/ (+ nbits 7) 8))
         bytes (gen-bytes required-bytes)
         last-bits (mod nbits 8)
         mask (dec (bit-shift-left (byte 1) last-bits))]
     (update bytes (dec required-bytes) (fn [n]
                                          (if (= last-bits 0)
                                            n
                                            (bit-and n mask)))))))

(defn- find-highest-bit
  [n]
  (loop [number n
         highest 0]
    (if (= number 0)
      highest
      (recur (unsigned-bit-shift-right number 1) (inc highest)))))

(defn bits->int
  [bit-vec]
  (loop [n 0
         v (reverse bit-vec)]
    (if (empty? v)
      n
      (recur (bit-or (bit-shift-left n 8) ;; shift n by 8 bits
                     (bit-and 0xFF (first v))) ;; bit-or it with the byte
             (rest v)))))

(defn rand-max-int
  ([gen-bytes] (fn [max-int] (rand-max-int gen-bytes max-int)))
  ([gen-bytes max-int]
   (if (<= max-int 0)
     (throw (IllegalArgumentException. "Max value must be > 0")))
   (let [int-bits (rand-bits gen-bytes (find-highest-bit max-int))
         generated (bits->int int-bits)]
     (if (<= generated max-int)
       generated
       (recur gen-bytes max-int)))))

(defn rand-in-range
  ([gen-bytes] (fn [min-value max-value] (rand-in-range gen-bytes
                                                        min-value
                                                        max-value)))
  ([gen-bytes min-value max-value]
   (let [delta (- max-value min-value)
         gdelta (rand-max-int gen-bytes delta)]
     (+ min-value gdelta))))

(defn rand-element
  ([gen-bytes] (fn [coll] (rand-element gen-bytes coll)))
  ([gen-bytes coll]
   (let [size (count coll)
         rand-index (rand-max-int gen-bytes (dec size))]
     (nth coll rand-index))))

(defn secure-random-bytes-generator
  [secure-random]
  (fn [nbytes]
    (let [bytes (byte-array nbytes)]
      (.nextBytes secure-random bytes)
      (vec bytes))))

(defn secure-random
  ([] (java.security.SecureRandom.))
  ([algo] (java.security.SecureRandom/getInstance algo))
  ([algo provider] (java.security.SecureRandom/getInstance algo provider)))

(def ^:private default-secure-random (secure-random))

(def default-bytes-generator (secure-random-bytes-generator default-secure-random))

(defn blake2xs-bytes-generator
  [seed])
