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
            [mellon.crypto.core :as c.core]))

(defn- make-digest-jca-api
  [digest message]
  (let [out (byte-array (.getDigestLength digest))]
    (-> (doto digest
          (.update (byte-array message)))
        (.digest)
        vec)))

(defn- make-digest-bc-api
  [digest message length]
  (let [out (byte-array length)]
    (doto digest
      (.update (byte-array message) 0 (count message))
      (.doFinal out 0))
    (vec out)))

(defn keyed-blake2b
  "Keyed version of the BLAKE2b algorithm. Optimal in 64-bit processors.
  Calculates the hash and returns by the callback f"
  ([key message] (fn [f] (keyed-blake2b key message f)))
  ([key message f]
   (if (> (count key) 64)
     (recur nil key
            (fn [key]
              (keyed-blake2b key message f)))
     (-> (Blake2bDigest.
          (if (nil? key)
            nil
            (byte-array key))
          64 nil nil)
         (make-digest-bc-api message 64)
         f))))

(defn keyed-blake2s
  "Keyed version of the BLAKE2s algorithm. Optimal in 32-bit processors.
  Calculates the hash and returns by the callback f."
  ([key message] (fn [f] (keyed-blake2s key message f)))
  ([key message f]
   (if (> (count key) 32)
     (recur nil key
            (fn [key]
              (keyed-blake2s key message 32 f)))
     (-> (Blake2sDigest.
          (if (nil? key)
            nil
            (byte-array key))
          32 nil nil)
         (make-digest-bc-api message 32)
         f))))

(defn- hmac-sha2
  "Generates a HMAC for a SHA2 algorithm using the JCA algorithms which can
  be hardware accelerated. The first argument is the JCA name of the digest
  algorithm."
  [sha key message f]
  (let [hmac-name (str "Hmac" sha)
        hmac (doto
                 (Mac/getInstance hmac-name)
               (.init (SecretKeySpec. (byte-array key) hmac-name)))]
    (f (make-digest-bc-api hmac message (.getMacLength hmac)))))

(defn hmac-sha2-512
  "Calculates the HMAC with the SHA512 algorithm on the key and message passed.
  Returns by calling the callback f."
  ([key message] (fn [f] (hmac-sha2-512 key message f)))
  ([key message f]
   (hmac-sha2 "SHA512" key message f)))

(defn hmac-sha2-256
  "Calculates the HMAC with the SHA256 algorithm on the key and message passed.
  Returns by calling the callback f."
  ([key message] (fn [f] (hmac-sha2-256 key message f)))
  ([key message f]
   (hmac-sha2 "SHA256" key message f)))

(defn- keyed-sha3
  "Prefix key MAC using SHA3. It is non-standard but entirely secure with the
  SHA3 construction. Also uses the JCA implementaiton for hardware acceleration
  when available. Consider using KMAC whenever JCA makes that available."
  [length key message f]
  (let [digest (doto
                   (MessageDigest/getInstance (str "SHA3-" length))
                 (.update (byte-array key)))]
    
    (f (make-digest-jca-api digest message))))

(defn keyed-sha3-512
  "Calculates the MAC of the message using SHA3-512 in prefix mode using the
  key. Although Prefix MAC using SHA3 is not standard, it is secure by the
  definition of SHA3.
  Returns by calling f with the digest"
  ([key message] (fn [f] (keyed-sha3-512 key message f)))
  ([key message f]
   (keyed-sha3 "512" key message f)))

(defn keyed-sha3-256
  "Calculates the MAC of the message using SHA3-256 in prefix mode using the
  key. Although Prefix MAC using SHA3 is not standard, it is secure by the
  definition of SHA3.
  Returns by calling f with the digest"
  ([key message] (fn [f] (keyed-sha3-256 key message f)))
  ([key message f]
   (keyed-sha3 "256" key message f)))

(def keyed-blake2b-spec
  "Spec for the BLAKE2b algorithm. Specs contain metadata for the algorithm."
  {:max-digest-size 64
   :fn keyed-blake2b})

(def keyed-blake2s-spec
  "Spec for the BLAKE2s algorithm. Specs contain metadata for the algorithm."
  {:max-digest-size 32
   :fn keyed-blake2s})

(def hmac-sha2-512-spec
  "Spec for the HMAC-SHA-256 algorithm. Specs contain metadata for the algorithm."
  {:max-digest-size 64
   :fn hmac-sha2-512})

(def hmac-sha2-256-spec
  "Spec for the HMAC-SHA-256 algorithm. Specs contain metadata for the algorithm."
  {:max-digest-size 32
   :fn hmac-sha2-256})

(def keyed-sha3-512-spec
  "Spec for the SHA3-512 algorithm. Specs contain metadata for the algorithm."
  {:max-digest-size 64
   :fn keyed-sha3-512})

(def keyed-sha3-256-spec
  "Spec for the SHA2-256 algorithm. Specs contain metadata for the algorithm."
  {:max-digest-size 32
   :fn keyed-sha3-256})

(defn- secure-random
  ([] (secure-random nil))
  ([algo]
   (if (nil? algo)
     (java.security.SecureRandom.)
     (java.security.SecureRandom/getInstance algo))))

(defn- system-random-next-bytes
  ([rand] (fn [nbytes f] (system-random-next-bytes rand nbytes f)))
  ([rand nbytes f]
   (let [bytes (byte-array nbytes)]
     (.nextBytes rand bytes)
     (f (vec bytes)))))

(defn system-random
  ([] (system-random nil))
  ([algo]
   (let [r (secure-random algo)]
     (system-random-next-bytes r))))

