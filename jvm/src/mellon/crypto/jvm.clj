(ns mellon.crypto.jvm
  "Defines cryptographic primitives in the JVM. Defines the functions as
  one-pass and by callback to be compatible with WebCrypto."

  (:import [org.bouncycastle.crypto.digests Blake2bDigest Blake2sDigest]
           [org.bouncycastle.crypto.macs KMAC]
           [org.bouncycastle.crypto.params KeyParameter ParametersWithSalt]
           [java.security MessageDigest]
           [javax.crypto Mac]
           [javax.crypto.spec SecretKeySpec])

  (:require [clojure.core.async :as async
             :refer [<! >! go-loop go chan close!]]
            [mellon.crypto.core :as c.core]
            [mellon.utils :refer [int->bytes]]))

(defn- make-digest-with-digest
  [digest message]
  (let [out (byte-array (.getDigestLength digest))]
    (-> (doto digest
          (.update (byte-array message) 0 (count message)))
        (.digest)
        vec)))

(defn- make-digest-with-do-final
  [digest message length]
  (let [out (byte-array length)]
    (doto digest
      (.update (byte-array message) 0 (count message))
      (.doFinal out 0))
    (vec out)))

(defn keyed-blake2b
  "Keyed version of the BLAKE2b algorithm. Optimal in 64-bit processors."
  [key message]
  (cond
    (empty? key) (-> (Blake2bDigest.) (make-digest-with-do-final message 64))
    (> (count key) 64) (recur (keyed-blake2b nil key) message)
    :otherwise (-> (Blake2bDigest. (byte-array key) 64 nil nil)
                   (make-digest-with-do-final message 64))))

(defn keyed-blake2s
  "Keyed version of the BLAKE2s algorithm. Optimal in 32-bit processors."
  [key message]
  (cond
    (empty? key) (-> (Blake2bDigest.) (make-digest-with-do-final message 32))
    (> (count key) 64) (recur (keyed-blake2s nil key) message)
    :otherwise (-> (Blake2bDigest. (byte-array key) 32 nil nil)
                   (make-digest-with-do-final message 32))))

(defn- hmac-sha2
  "Generates a HMAC for a SHA2 algorithm using the JCA algorithms which can
  be hardware accelerated. The first argument is the JCA name of the digest
  algorithm."
  [sha key message]
  (let [hmac-name (str "Hmac" sha)
        hmac (doto
                 (Mac/getInstance hmac-name)
               (.init (SecretKeySpec. (byte-array key) hmac-name)))]
    (make-digest-with-do-final hmac message (.getMacLength hmac))))

(defn hmac-sha2-512
  "Calculates the HMAC with the SHA512 algorithm on the key and message
  passed."
  [key message]
  (hmac-sha2 "SHA512" key message))

(defn hmac-sha2-256
  "Calculates the HMAC with the SHA256 algorithm on the key and message
  passed."
  [key message]
  (hmac-sha2 "SHA256" key message))

(defn- keyed-sha3
  "Prefix key MAC using SHA3. It is non-standard but entirely secure with the
  SHA3 construction. Also uses the JCA implementaiton for hardware acceleration
  when available. Consider using KMAC whenever JCA makes that available."
  [length key message]
  (let [digest (doto
                   (MessageDigest/getInstance (str "SHA3-" length))
                 (.update (byte-array key)))]

    (make-digest-with-digest digest message)))

(defn keyed-sha3-512
  "Calculates the MAC of the message using SHA3-512 in prefix mode using the
  key. Although Prefix MAC using SHA3 is not standard, it is secure by the
  definition of SHA3."
  [key message]
  (keyed-sha3 "512" key message))

(defn keyed-sha3-256
  "Calculates the MAC of the message using SHA3-256 in prefix mode using the
  key. Although Prefix MAC using SHA3 is not standard, it is secure by the
  definition of SHA3."
  [key message]
  (keyed-sha3 "256" key message))

(defn- secure-random
  ([] (secure-random nil))
  ([algo]
   (if (nil? algo)
     (java.security.SecureRandom.)
     (java.security.SecureRandom/getInstance algo))))

(defn- system-random-next-bytes
  ([rand] (fn [nbytes] (system-random-next-bytes rand nbytes)))
  ([rand nbytes]
   (let [bytes (byte-array nbytes)]
     (.nextBytes rand bytes)
     (vec bytes))))

(defn system-random
  "Creates a system random CSPRBG generation function. Uses the system crypto
  random to gather bytes in each call, so it is mutable and does not hold
  referential transparency."
  ([] (system-random nil))
  ([algo]
   (let [r (secure-random algo)]
     (system-random-next-bytes r))))

(defn extended-keyed-hash
  "Hash the message using the key put produces a hash of variable size which
  can be bigger than the digest output of the original hash.
  hash must be a keyed hash function which takes in order key and message and
  produces a sequence of bytes."
  [hash key message length]
  (loop [H (hash key (concat (int->bytes length) [0] message))
         n 0
         bs []]
    (if (>= n length)
      (take length (->> bs (map vec) flatten))
      (recur (hash key (concat [1] H))
             (+ n (count H))
             (conj bs H)))))
