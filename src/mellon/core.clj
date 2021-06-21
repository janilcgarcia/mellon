(ns mellon.core
  (:gen-class)
  (:require [clojure.tools.cli :as cli]
            [clojure.java.io :as io]
            [clojure.string :as s]
            [mellon.generate :as m.gen]
            [mellon.random :as m.rand]))

(def generate-options
  [["-l" "--length LENGTH" "The length (in words of the generated passphrase"
    :default 5
    :parse-fn #(Integer/parseInt %)
    :validate [#(> % 0) "Must be positive"]]
   ["-n" "--number NUMBER" "Number of passphrases to generate"
    :default 1
    :parse-fn #(Integer/parseInt %)
    :validate [#(> % 0) "Must be positive"]]
   ["-d" "--dict FILE" "Dictionary used in the password generation"
    :parse-fn #(io/file %)
    :validate [#(.isFile %) "Must be an existing valid file"]]])

(def derive-options
  [["-o" "--output FILE" "Output dictionary file, must always be provide"
    :parse-fn #(io/file %)
    :validate [#(not (.isDirectory %1)) "This file is a directory, can't go on"]]])

(defn- handle-derive
  [args]
  (let [result (cli/parse-opts args derive-options)
        errors (:errors result)
        args (:arguments result)
        opts (:options result)]
    (if (nil? (:output opts nil))
      (println "Nope"))
    
    (println errors)
    (println (:summary result))
    (println args)
    (println opts)))

(defn- validate-generate
  [args]
  (let [result (cli/parse-opts args generate-options)]
    (when (:errors result)
      (throw (ex-info (s/join "\n" (:errors result))
                      {:validation :generate :errors (:errors result)})))
    (when-not (:arguments result)
      (throw (ex-info "Generate don't take these additional parameters"
                      {:validation :generate :arguments (:arguments result)})))

    (when-not (:dict (:options result))
      (throw (ex-info (str "Generate NEEDs a dictionary file. Dict is not an "
                           "optional argument")
                      {:validation :generate
                       :errors ["Missing dictionary file"]})))

    (:options result)))

(defn- handle-generate
  [args]
  (let [options (validate-generate args)
        pp-gen (m.gen/generate-passphrase m.rand/system-byte-generator
                                          (m.gen/load-dict (:dict options)))]
    (dotimes [_ (:number options)]
      (println (pp-gen (:length options))))))

(defn -main
  [& args]
  (let [mode (cond
               (= (first args) "derive") [:derive (rest args)]
               (= (first args) "generate") [:generate (rest args)]
               :otherwise [:generate args])]

    (if (= (first mode) :derive)
      (handle-derive (second mode))
      (handle-generate (second mode)))))
