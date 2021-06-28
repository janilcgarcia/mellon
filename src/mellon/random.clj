(ns mellon.random
  "This module defines random generation functions for (Cryptographically
  Secure) Pseudo-Random *Byte* Generators.
  
  This module uses and implements the concept of a byte-generator.
  A byte-generator is a function that takes a integral number as argument
  and produces a *vector* of bytes of the same size of output. It is allowed to
  this function to throw an exception in case of generation failure and it is
  to be considered stateful."

  (:import [org.bouncycastle.crypto.digests Blake2xsDigest SHA512tDigest
            Blake2bDigest Blake3Digest]
           [org.bouncycastle.crypto.params Blake3Parameters KeyParameter
            ParametersWithIV ParametersWithSalt]
           [org.bouncycastle.crypto.macs HMac KMAC]
           [org.bouncycastle.crypto.prng
            SP800SecureRandom
            SP800SecureRandomBuilder]
           [org.bouncycastle.crypto.modes OFBBlockCipher]
           [javax.crypto Cipher]
           [javax.crypto.spec SecretKeySpec IvParameterSpec]))

;; Utility functions
(defn- bits->long
  "Convert a big-endian bitvector into a long. "
  [bit-vec]
  (loop [n 0
         v bit-vec]
    (if (empty? v)
      n
      (recur (bit-or (bit-shift-left n 8) ;; shift n by 8 bits
                     (bit-and 0xFF (first v))) ;; bit-or it with the byte
             (rest v)))))

(defn- int->bytes
  "Convert an integer to big-endian bytes"
  [n]
  (let [ba (byte-array 4)]
    (doto (java.nio.ByteBuffer/wrap ba)
      (.order java.nio.ByteOrder/BIG_ENDIAN)
      (.putInt n))
    ba))

(defn- find-highest-bit
  "Find the highest bit in an integer"
  [n]
  (loop [number n
         highest 0]
    (if (= number 0)
      highest
      (recur (unsigned-bit-shift-right number 1) (inc highest)))))

(defn- blake2b
  "Calculate the blake2b hash for the given message. Returns a byte array
  not vector. For internal use. An optional outlen parameter containing the
  digest output length may be provided. Defaults to 64."
  ([msg] (blake2b msg 64))
  ([msg outlen]
   (let [b2 (Blake2bDigest. (* outlen 8))
         out (byte-array outlen)]
     (.update b2 (byte-array msg) 0 (count msg))
     (.doFinal b2 out 0)
     out)))

(defn secure-random
  "Creates a SecureRandom instance. Two arguments maybe provided the first one
  is the algorithm and the second the provider, as specified by the getInstance
  method on the SecureRandom interface."

  ([] (java.security.SecureRandom.))
  ([algo] (java.security.SecureRandom/getInstance algo))
  ([algo provider] (java.security.SecureRandom/getInstance algo provider)))

;; Functions that generate random stuff
(defn rand-bits
  "Generate n random bits. Uses a byte-vector generator (and discards unused
  bits). The bits are generated as big-endian and only consumes from the
  byte generator enough bytes to create the bitvector."
  ([byte-gen] (fn [nbits] (rand-bits byte-gen nbits)))
  ([byte-gen nbits]
   (let [required-bytes (int (/ (+ nbits 7) 8))
         bytes (byte-gen required-bytes)
         last-bits (mod nbits 8)
         mask (dec (bit-shift-left (byte 1) last-bits))]
     (update bytes 0 (fn [n]
                       (if (= last-bits 0)
                         n
                         (bit-and n mask)))))))

(defn rand-double
  "Generates a random number in the interval [0.0, 1.0] using a byte-generator"
  [byte-gen]
  (let [bits (rand-bits byte-gen 63)
        random-long (bits->long bits)]
    (/ (double random-long) Long/MAX_VALUE)))

(defn rand-max-int
  "Based on a byte-generator, creates a new random integral with the max
  value defined by the max-int argument."
  ([byte-gen] (fn [max-int] (rand-max-int byte-gen max-int)))
  ([byte-gen max-int]
   (if (<= max-int 0)
     (throw (IllegalArgumentException. "Max value must be > 0")))
   (let [int-bits (rand-bits byte-gen (find-highest-bit max-int))
         generated (bits->long int-bits)]
     (if (<= generated max-int)
       generated
       (recur byte-gen max-int)))))

(defn rand-in-range
  "Generates a random integral number in the specified range, using a the given
  byte-generator."
  ([byte-gen] (fn [min-value max-value]
                 (rand-in-range byte-gen min-value max-value)))
  ([byte-gen min-value max-value]
   (let [delta (- max-value min-value)
         gdelta (rand-max-int byte-gen delta)]
     (+ min-value gdelta))))

(defn rand-element
  "Choose one among the elements of an nth-able collection randomically
  using the given byte-generator"
  ([byte-gen] (fn [coll] (rand-element byte-gen coll)))
  ([byte-gen coll]
   (let [size (count coll)
         rand-index (rand-max-int byte-gen (dec size))]
     (nth coll rand-index))))

;; Byte generators
;; System
(defn secure-random-byte-generator
  "Creates a byte-generator from a java.security.SecureRandom instance"
  [secure-random]
  (fn [nbytes]
    (let [bytes (byte-array nbytes)]
      (.nextBytes secure-random bytes)
      (vec bytes))))

;; (def ^:private system-random
;;   "Main secure-random, so users may use the default system one"
;;   (secure-random))

;; (def system-byte-generator
;;   "System RNG device-based byte-generator, should be used by default"
;;   (secure-random-byte-generator system-random))

;; SP800
(def ^:private sp800-salt
  "Default application-level salt value when using the SP800 DRBG"
  (byte-array [0x95 0xf5 0xe7 0x75 0x2e 0x11 0x2c 0x64
               0xc6 0x5f 0xef 0x9e 0x39 0x09 0x46 0x38]))


(defn- fixed-entropy-source
  "An entropy source which only provide the given seed in chunks of n bits"
  [n seed]
  ;; Uses atom for mutability
  (let [seed-atom (atom (vec seed))]
    (reify
      org.bouncycastle.crypto.prng.EntropySource
      (entropySize [self] (int n))
      (getEntropy [self]
        (let [nbytes (int (/ (+ n 7) 8))
              entropy (take nbytes @seed-atom)]
          (if (= (count entropy) nbytes)
            (do
              (swap! seed-atom (partial drop nbytes))
              (byte-array entropy))
            (throw (ex-info "No more entropy available" {})))))
      (isPredictionResistant [self] (boolean true)))))

(defn- fixed-entropy-source-provider
  "An entropy source provider that creates ONE fixed-entropy-source"
  [seed]
  (let [seed-atom (atom seed)]
    (reify
      org.bouncycastle.crypto.prng.EntropySourceProvider
      (get [self nbits]
        (let [[s _] (swap-vals! seed-atom (fn [_] nil))]
          (if (nil? s)
            (throw (ex-info (str "Not more entropy available, "
                                 "this provider can be called only once")))

            (fixed-entropy-source nbits s)))))))

(defn sp800-byte-generator
  "Byte-generator based on the SP800-90A DRBG, but only provides as an entropy
  source the provided seed. Uses the HMAC_DRBG construction with
  HMAC(SHA512/256). This is a standardized DRBG.

  For these parameters the seed must be at least 32 bytes.

  The SP800-90A DRBG should be reseed every so often, but this option is
  disabled here, therefore it shouldn't be used to generate too much data."
  ([seed] (sp800-byte-generator seed nil))
  ([seed salt]
   (let [digest (SHA512tDigest. 256)
         mac (HMac. digest)
         nonce (if (nil? salt)
                 sp800-salt
                 (byte-array salt))
         sp800 (.buildHMAC (doto (SP800SecureRandomBuilder.
                                  (fixed-entropy-source-provider seed))
                             (.setEntropyBitsRequired 256)
                             (.setSecurityStrength 256)
                             (.setPersonalizationString (.getBytes "mellon")))
                           mac
                           nonce
                           false)]
     (secure-random-byte-generator sp800))))

;; AES OFB
(defn- cipher-derive-key
  "The AES generator must use a 32 bytes key (it uses a AES-256 block). This
  function transforms a bigger than 32 bytes seed into a 32 bytes key if
  necessary."
  [seed keylen]
  (cond
    (< (count seed) keylen) (throw (ex-info (str "Seed is too weak, there must"
                                                 "be at least " keylen
                                                 " bytes of entropy")
                                            {}))
    (= (count seed) keylen) (byte-array seed)
    :otherwise (blake2b seed keylen)))

(def ^:private cipher-default-iv
  "Default IV for initializaing the AES byte generator, in case no salt is
  provided"
  (byte-array
   [0x67 0xC7 0xBA 0xE3 0x11 0x6B 0x35 0xD0
    0x43 0xB7 0x3E 0xA2 0xC0 0x08 0x0D 0x38]))

(defn- cipher-derive-iv
  "Derives an AES IV from a salt, in case one is present or returns the default
  IV"
  [salt block-size]
  (if (nil? salt)
    (byte-array (take block-size cipher-default-iv))
    (blake2b salt block-size)))

(def ^:private cipher-default-block
  "Block encrypted in the AES byte-generator"
  (byte-array
   [0xE9 0x43 0xDD 0x0E 0x05 0x7E 0x8E 0xB7
    0xA2 0x96 0x3B 0xFD 0xA4 0x0E 0xF9 0x12]))

(defn- jce-aes-engine
  "BouncyCastle BlockCipher implementation delegating to the JCE default
  implementation which can take advantage of AES-NI in many settings.

  Uses the default ECB with no padding algorithm to process blocks, but allows
  the usage of the OFB mode from BouncyCastle which works as a stream cipher
  instead of the default JCE one which works in blocks or truncate blocks."
  []
  (let [jce-aes (atom [nil nil])
        get-aes (fn [] (first @jce-aes))]
    (reify
      org.bouncycastle.crypto.BlockCipher
      (getAlgorithmName [this] "AES")
      (getBlockSize [this] 16)
      (init [this encryption params]
        (let [opmode (if encryption
                       Cipher/ENCRYPT_MODE
                       Cipher/DECRYPT_MODE)
              key-spec (SecretKeySpec. (.getKey params) "AES")]
          (swap! jce-aes (fn [[cipher params]]
                           (if-not (nil? cipher)
                             (do
                               (.init cipher opmode key-spec)
                               [cipher [opmode key-spec]])
                             [(doto (Cipher/getInstance "AES/ECB/NoPadding")
                                (.init opmode key-spec))
                              [opmode key-spec]])))))
      (processBlock [this in in-offset out out-offset]
        (.update (get-aes) in in-offset 16 out out-offset))
      (reset [this]
        (when-not (nil? (get-aes))
          (swap! jce-aes (fn [[_ [opmode key-spec]]]
                           [(doto (Cipher/getInstance "AES/ECB/NoPadding")
                              (.init opmode key-spec))
                            [opmode key-spec]])))))))

(defn- block-cipher-byte-generator
  "Base byte generator based on block cipher"
  [cipher key-size seed salt]
  (let [key (cipher-derive-key seed key-size)
        iv (cipher-derive-iv salt (.getBlockSize cipher))
        cipher (doto (OFBBlockCipher. cipher (* 8 (.getBlockSize cipher)))
                 (.init true (ParametersWithIV. (KeyParameter. key) iv)))]

    (fn [nbytes]
       (let [bytes (byte-array nbytes)]
         (loop [offset 0]
           (let [nbytes-diff (- nbytes offset)
                 step-nbytes (if (> nbytes-diff 16)
                               16
                               nbytes-diff)]
             (if (>= offset nbytes)
               (vec bytes)
               (do
                 (.processBytes cipher cipher-default-block 0 step-nbytes bytes offset)
                 (recur (+ offset step-nbytes))))))))))

(defn aes-byte-generator
  "Creates a byte-generator based on the AES block cipher on OFB mode, which
  essentially makes it into a stream cipher. Encrypts the same block over and
  over to generate the bytes.

  This whole implementation is home-grown, and although it should be safe and
  works as an alternative for the hash-based generators up there, Blake2Xs and
  SP800 should be preferred."
  ([seed] (aes-byte-generator seed nil))
  ([seed salt] (block-cipher-byte-generator (jce-aes-engine) 32 seed salt)))

;; XOF generators
(defn- xof-byte-generator
  "Create a byte generator from a XOF function. The xof argument must an object
  that has a (.doOutput this bytes offset length) method, as defined in the Xof
  interface on the Bouncy Castle library."
  [xof]
  (fn [nbytes]
    (let [bytes (byte-array nbytes)]
      (.doOutput xof bytes 0 nbytes)
      (vec bytes))))

;; Blake2xs
(def ^:private blake2xs-salt
  "Application level salt used in the Blake2XS byte-generator. It is just a
  random byte-array, but it's value must be kept constant so the user can
  always rely on the algorithm to generate the same output for the same seed"
  (byte-array
   [0xCB 0x6F 0x59 0x62 0x23 0xDE 0x94 0x6B
    0x46 0xA8 0x42 0xB4 0x70 0x17 0x24 0xE2]))

(defn blake2xs-byte-generator
  "Byte-generator based on the output of a BLAKE2Xs algorithm. BLAKE2Xs is a
  XOF. The seed must be at least 32 bytes and salt at least 8.
  The salt is optional."
  ([seed] (blake2xs-byte-generator seed nil))
  ([seed salt]
   (let [k (if (> (count seed) 32)
             (blake2b seed 32)
             (byte-array seed))

         s (cond
             (nil? salt) nil
             (= (count salt) 8) (byte-array salt)
             :otherwise (blake2b salt 8))

         b2xs (Blake2xsDigest. Blake2xsDigest/UNKNOWN_DIGEST_LENGTH
                               k s nil)]
     (.update b2xs blake2xs-salt)
     (xof-byte-generator b2xs))))

;; Blake3
(def ^:private blake3-salt
  "Application level salt used in the BLAKE3 byte-generator. It is just a
  random byte-array, but it's value must be kept constant so the user can
  always rely on the algorithm to generate the same output for the same seed"
  (byte-array
   [0x2D 0x21 0x72 0x26 0x60 0xE3 0x2D 0xD1
    0x34 0x21 0xBC 0x5F 0xF3 0x26 0x18 0x03]))

(defn- blake3-prepare-salt
  "Prepare a byte vector to be used as salt in the BLAKE3 function. The salt
  value is a byte-string starting with 0x1 (which indicates it's salt) followed
  by the salt length (32-bit int, big-endian) and the salt itself"
  [salt]
  (byte-array (concat [0x1] (int->bytes (count salt)) salt)))

(defn blake3-byte-generator
  "A byte generator based on the BLAKE3 hash function. BLAKE3 is a XOF hash
  function announced in 2020. It's faster then BLAKE2X and has the desirable
  features of both the BLAKE2X and BLAKE2p variants.

  Here it uses a home-grown salt construction which I hope is secure, but use
  at your own peril. Cryptoanalysis over this is WELCOME. As a consequence,
  this function is subject to change and may cause incovience in the future"
  [seed salt]
  (let [k (byte-array seed)
        s (blake3-prepare-salt salt)
        b3 (doto (Blake3Digest.)
             (.init (Blake3Parameters/key k))
             (.update s 0 (count s))
             (.update blake3-salt 0 (count blake3-salt)))]

    (xof-byte-generator b3)))

;; KMAC
(def ^:private kmac-salt
  "Salt used for the KMAC byte-generator. Just a random vector"
  (byte-array
   [0x41 0xBD 0xCC 0x5B 0xD8 0xDE 0xD7 0x61
    0x82 0xA8 0x89 0x36 0x8F 0x24 0xC6 0x94]))

(defn kmac-byte-generator
  "KMAC (Keccak MAC)-based byte generator. KMAC is also a XOF and this property
  is used to generate an infinite stream of seemly random bytes. This is
  offered as a standardize alternative of Blake2Xs, but this function was not
  designed to be a DRBG and NIST recommends SP800.

  Blake2Xs or SP800 are preferred over this."
  ([seed] (kmac-byte-generator seed nil))
  ([seed salt]
   (let [key (KeyParameter. (byte-array seed))
         kmac (doto (KMAC. 256 (byte-array salt))
                (.init key)
                (.update kmac-salt 0 (count kmac-salt)))]
     (xof-byte-generator kmac))))
