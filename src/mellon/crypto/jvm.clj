(ns mellon.crypto.jvm
  "Defines cryptographic primitives in the JVM. Defines in channels to be
  compatible with WebCrypto implementations"
  (:import [org.bouncycastle.crypto.digests Blake2bDigest Blake2sDigest]
           [org.bouncycastle.crypto.macs KMAC]
           [org.bouncycastle.crypto.params KeyParameter ParametersWithSalt]
           [java.security MessageDigest]
           [javax.crypto Mac]
           [javax.crypto.spec SecretKeySpec])
  (:require [clojure.core.async :as async :refer [<! >! go-loop go chan close!]]
            [mellon.crypto.core :as c.core]))

(defn- make-digest-jca-api
  [digest message]
  (let [out (byte-array (.getDigestLength digest))]
    (.digest (doto digest
               (.update (byte-array message))))))

(defn- make-digest-bc-api
  [digest message length]
  (let [out (byte-array length)]
    (doto digest
      (.update (byte-array message) 0 (count message))
      (.doFinal out 0))
    out))

(defn- sync-keyed-blake2b
  ([key message length]
   (if (> (count key) 64)
     (recur (sync-keyed-blake2b nil key 64) message length)
     (-> (Blake2bDigest.
          (if (nil? key)
            nil
            (byte-array key))
          length nil nil)
         (make-digest-bc-api message length)))))

(defn- sync-keyed-blake2s
  ([key message length]
   (if (> (count key) 32)
     (recur (sync-keyed-blake2s nil key 32) message length)
     (-> (Blake2sDigest.
          (if (nil? key)
            nil
            (byte-array key))
          length nil nil)
         (make-digest-bc-api message length)))))

(defn- keyed-blake2b
  ([key message] (keyed-blake2b key message 64))
  ([key message length]
   (let [out (chan)]
     (go
       (>! out (sync-keyed-blake2b key message length))
       (close! out))
     out)))

(defn- keyed-blake2s
  ([key message] (keyed-blake2s key message 32))
  ([key message length]
   
   (let [out-chan (chan)]
     (go (>! out-chan (sync-keyed-blake2s key message length))
         (close! out-chan))
     out-chan)))

(defn- hmac-sha2
  [sha key message]
  (let [out-chan (chan)
        hmac-name (str "Hmac" sha)
        hmac (doto
                 (Mac/getInstance hmac-name)
               (.init (SecretKeySpec. (byte-array key) hmac-name)))]
    (go (>! out-chan (make-digest-bc-api hmac message (.getMacLength hmac)))
        (close! out-chan))
    out-chan))

(def ^:private hmac-sha2-512 (partial hmac-sha2 "SHA512"))
(def ^:private hmac-sha2-256 (partial hmac-sha2 "SHA256"))

(defn- keyed-sha3
  [len key message]
  (let [out-chan (chan)
        digest (doto
                   (MessageDigest/getInstance (str "SHA3-" len))
                 (.update (byte-array key)))]
    (go
      (>! out-chan (make-digest-jca-api digest message))
      (close! out-chan))
    out-chan))


(def ^:private keyed-hashes
  {:keyed-blake2b {:max-digest-size 64
                   :fn keyed-blake2b}
   :keyed-blake2s {:max-digest-size 32
                   :fn keyed-blake2s}
   :hmac-sha2-512 {:max-digest-size 64
                   :fn hmac-sha2-512}
   :hmac-sha2-256 {:max-digest-size 32
                   :fn hmac-sha2-256}
   :prefix-sha3-512 {:max-digest-size 64
                     :fn (partial keyed-sha3 "512")}
   :prefix-sha3-256 {:max-digest-size 32
                     :fn (partial keyed-sha3 "256")}})

(defn get-keyed-hash
  [hash]
  (:fn (hash keyed-hashes)))

(def available-keyed-hashes
  (vec (keys keyed-hashes)))

(def extended-keyed-hash (partial c.core/extended-keyed-hash-generator keyed-hashes))

(defn- secure-random
  ([] (secure-random nil))
  ([algo]
   (if (nil? algo)
     (java.security.SecureRandom.)
     (java.security.SecureRandom/getInstance algo))))

(defn system-random
  ([] (make-system-random nil))
  ([algo]
   (let [r (secure-random algo)]
     (fn [nbytes]
       (let [bytes (byte-array nbytes)
             out (chan)]
         (.nextBytes r bytes)
         (go (>! out bytes)
             (close! out))
         out)))))

