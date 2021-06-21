(ns mellon.core
  (:gen-class)
  (:require [clojure.tools.cli :as cli]
            [clojure.java.io :as io]
            [clojure.string :as s]
            [mellon.generate :as m.gen]
            [mellon.random :as m.rand]))

(defn- file-or-stdout
  [file-name]
  (if (= file-name "-")
    *out*
    (io/file file-name)))

(defn- file?
  [f]
  (instance? java.io.File f))

(defn- is-not-directory
  [f]
  (if (file? f)
    (not (.isDirectory f))
    true))

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
    :parse-fn file-or-stdout
    :validate [is-not-directory "This file is a directory, can't go on"]]])

(defn- validate-derive
  [args]
  (let [result (cli/parse-opts args derive-options)]
    (when-let [errors (:errors result)]
      (throw (ex-info (s/join "\n" errors)
                      {:validation :derive
                       :errors errors})))

    (when-not (:output (:options result))
      (throw (ex-info (str "You MUST provide an output file, it can be - to "
                           "output to the stdout")
                      {:validation :derive
                       :missing :output})))

    (when (empty? (:arguments result))
      (throw (ex-info "You must provide at least one input"
                      {:validation :derive
                       :missing :inputs})))

    {:output (:output (:options result))
     :inputs (:arguments result)}))

(defn- handle-derive
  [args]
  (let [validated (validate-derive args)
        output (:output validated)
        inputs (:inputs validated)]
    (println "output:" output)
    (println "inputs:" (s/join ", " inputs))
    (println "This functionality is not implemented yet!")))

(defn- validate-generate
  [args]
  (let [result (cli/parse-opts args generate-options)]
    (when (:errors result)
      (throw (ex-info (s/join "\n" (:errors result))
                      {:validation :generate
                       :errors (:errors result)})))

    (when-not (empty? (:arguments result))
      (println (:arguments result))
      (throw (ex-info "Generate don't take these additional parameters"
                      {:validation :generate :arguments (:arguments result)})))

    (when-not (:dict (:options result) nil)
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
