(ns mellon.crypto.jvm
  "Defines cryptographic primitives in the JVM. Defines in channels to be
  compatible with WebCrypto implementations"
  (:import [org.bouncycastle.crypto.digests Blake2bDigest Blake2sDigest]
           [org.bouncycastle.crypto.macs KMAC]
           [org.bouncycastle.crypto.params KeyParameter ParametersWithSalt]
           [java.security MessageDigest]
           [javax.crypto Mac]
           [javax.crypto.spec SecretKeySpec])
  (:require [clojure.core.async :as async :refer [<! >! go-loop]]))

(defn- spec-always-valid
  [_]
  true)

(defn- spec-throw-ex
  [ex]
  (fn
    [_]
    (throw ex)))

(defn- spec-validate-digest-size
  [spec size]
  (let [valid-size (:valid-digest-size spec spec-always-valid)]
    (assert (valid-size size)
            "Invalid size of digest output")))

(defn- spec-prepare-key
  [spec key]
  (let [valid-key (:valid-key spec spec-always-valid)
        derive-key (:derive-key spec (spec-throw-ex
                                      (ex-info "Can't derive key"
                                               {:derive-key :missing})))]
    (if (valid-key key)
      key
      (derive-key key))))

(defn- spec-prepare-salt
  [spec salt]
  (let [valid-salt (:valid-salt spec spec-always-valid)
        derive-salt (:derive-salt spec (spec-throw-ex
                                        (ex-info "Can't derive salt"
                                                 {:derive-salt :missing})))]
    (if (valid-salt salt)
      salt
      (derive-salt salt))))

(defn- simple-hash
  [spec message len]
  (spec-validate-digest-size spec len)
  (let [digest (byte-array len)
        make-hasher (:factory spec)]
    (doto
        (make-hasher nil nil len)
      (.update (byte-array message) 0 (count message))
      (.doFinal digest 0))
    digest))

(defn- simple-keyed-hash
  [spec key salt message len]
  (spec-validate-digest-size spec len)
  (let [make-hasher (:factory spec)
        
        key (spec-prepare-key spec key)
        salt (spec-prepare-salt spec salt)
        hasher (make-hasher key salt len)

        digest (byte-array len)]
    (doto
        hasher
      (.update (byte-array message) 0 (count message))
      (.doFinal digest 0))
    digest))

(defn- jca-prefix-keyed-hash
  [spec key salt message]
  (let [make-hasher (:factory spec)
        key (spec-prepare-key spec key)
        salt (spec-prepare-salt spec key)]
    (. (doto
           (make-hasher key salt 0)
         (.update (byte-array message) 0 (count message)))
       digest)))

(defn- make-blake2b
  ([len] (Blake2bDigest. len))
  ([key salt len]
   (Blake2bDigest. key len salt nil)))

(defn- make-blake2s
  ([len] (Blake2sDigest. len))
  ([key salt len]
   (Blake2sDigest. key len salt nil)))

(def ^:private blake2b-spec
  {:factory make-blake2b
   :max-digest-size 64
   :valid-digest-size #(<= 1 % 64)})

(def ^:private blake2s-spec
  {:factory make-blake2s
   :max-digest-size 32
   :valid-digest-size #(<= 1 % 32)})

(defn- simple-blake2b
  ([message] (simple-blake2b message (:max-digest-size blake2b-spec)))
  ([message len]
   (simple-hash blake2b-spec message len)))

(defn- simple-blake2s
  ([message] (simple-blake2s message (:max-digest-size blake2s-spec)))
  ([message len]
   (simple-hash blake2s-spec message len)))

(def ^:private keyed-blake2b-spec
  {:factory make-blake2b
   :max-digest-size 64
   :valid-digest-size #(<= 1 % 64)
   :valid-key #(<= 1 (count %) 64)
   :derive-key #(simple-blake2b %)
   :valid-salt #(or (nil? %1) (= (count %1) 16))
   :derive-salt #(simple-blake2b % 16)})

(def ^:private keyed-blake2s-spec
  {:factory make-blake2s
   :max-digest-size 32
   :valid-digest-size #(<= 1 % 64)
   :valid-key #(<= 1 (count %) 32)
   :derive-key #(simple-blake2s (count %))
   :valid-salt #(or (nil? %1) (= (count %1) 8))
   :derive-salt #(simple-blake2s % 8)})

(defn- simple-keyed-blake2b
  ([key message]
   (simple-keyed-blake2b key nil message (:max-digest-size keyed-blake2b-spec)))
  ([key salt message]
   (simple-keyed-blake2b key salt message (:max-digest-size keyed-blake2b-spec)))
  ([key salt message len]
   (simple-keyed-hash keyed-blake2b-spec key salt message len)))

(defn- simple-keyed-blake2s
  ([key message]
   (simple-keyed-blake2s key nil message (:max-digest-size keyed-blake2s-spec)))
  ([key salt message]
   (simple-keyed-blake2s key salt message (:max-digest-size keyed-blake2s-spec)))
  ([key salt message len]
   (simple-keyed-hash keyed-blake2s-spec key salt message len)))

(defn- hmac-factory
  [hmac-name]
  (fn [key salt _]
    (let [key (SecretKeySpec. (byte-array key) hmac-name)]
      (doto
          (Mac/getInstance hmac-name)
        (.init key)
        (when-not (nil? salt)
          (.update (byte-array salt) 0 (count salt)))))))

(defn- create-hmac-spec
  [hash-name hmac-name]
  (let [digest (MessageDigest/getInstance hash-name)
        max-length (.getDigestLength digest)]
    {:factory (hmac-factory hmac-name)
     :max-digest-size max-length
     :valid-digest-size #(= % max-length)}))

(def ^:private hmac-sha2-512-spec
  (create-hmac-spec "SHA-512" "HmacSHA512"))

(def ^:private hmac-sha2-256-spec
  (create-hmac-spec "SHA-256" "HmacSHA256"))

(defn- simple-hmac-sha2-512
  ([key message] (simple-hmac-sha2-512 key nil message))
  ([key salt message]
   (simple-keyed-hash hmac-sha2-512-spec key salt message
                      (:max-digest-size hmac-sha2-512-spec))))

(defn- simple-hmac-sha2-256
  ([key message] (simple-hmac-sha2-256 key nil message))
  ([key salt message]
   (simple-keyed-hash hmac-sha2-256-spec key salt message
                      (:max-digest-size hmac-sha2-256-spec))))

(defn- make-sha3
  ([digest-size]
   (fn [key salt len]
     (make-sha3 digest-size key salt len)))
  ([digest-size key salt _]
   (doto
       (MessageDigest/getInstance (str "SHA3-" digest-size))
     (.update key 0 (count key))
     (when-not (nil? salt)
       (.update salt 0 (count salt))))))

(def ^:private prefix-sha3-512-spec
  {:factory (make-sha3 "512")
   :max-digest-size 64
   :valid-digest-size #(= % 64)})

(def ^:private prefix-sha3-256-spec
  {:factory (make-sha3 "256")
   :max-digest-size 32
   :valid-digest-size #(= % 32)})

(defn- simple-keyed-sha3-512
  ([key message] (simple-keyed-sha3-512 key nil message))
  ([key salt message]
   (jca-prefix-keyed-hash prefix-sha3-512-spec key salt message)))

(defn- simple-keyed-sha3-256
  ([key message] (simple-keyed-sha3-256 key nil message))
  ([key salt message]
   (jca-prefix-keyed-hash prefix-sha3-256-spec key salt message)))

(defn keyed-blake2b
  [in out]
  (go-loop []
    (let [req (<! in)
          key (:key req)
          salt (:salt req)
          msg (:message req)
          len (:digestLength req 64)]
      (>! out (simple-keyed-blake2b key msg len)))
    (recur)))

(defn hmac-sha2-512
  [in out]
  (go-loop []
    (let [req (<! in)
          key (:key req)
          salt (:salt req)
          msg (:message req)]
      (>! out (simple-hmac-sha2-512 key msg)))))

(defn- hash-extend
  [spec]
  (let [digest-size (:max-digest-size spec)
        hash (:hash spec)]
    (fn [key message len]
      (let [nblocks (int (Math/ceil (/ len digest-size)))]
        (loop [out []
               generated 0
               H (hash key (concat [0] message))]
          (if (>= generated nblocks)
            (take len out)
            (recur
             (concat out H)
             (inc generated)
             (hash key (concat [1] H)))))))))

(defn hash-extend-hmac-sha2-512
  [in out]
  (let [hash (hash-extend {:max-digest-size 64
                           :hash simple-hmac-sha2-512})]
    (go-loop []
      (let [req (<! in)
            key (:key req)
            message (:message req)
            length (:length req)]
        (>! out (hash key message length)))
      (recur))))
