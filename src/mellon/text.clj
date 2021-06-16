(ns mellon.text
  (:require [clojure.string :as s]))

(let [alpha "\\p{IsAlphabetic}"
      alpha-hyphen (str "[" alpha "-]")
      punctuation "\\p{IsPunctuation}"
      word-re (re-pattern (str "^(" alpha  "+|" alpha alpha-hyphen "*" alpha ")"
                               punctuation "*"))]
  (defn- clean-word
    [word]
    (if-let [[_ clean] (re-matches word-re word)]
      clean
      nil)))

(defn- load-split-text
  [name]
  (filter (comp not nil?)
          (map clean-word
               (s/split (slurp name) (re-pattern "\\s+")))))

(defn- frequency-update-inc
  [value]
  (if (nil? value)
    1
    (+ value 1)))

(defn- frequency-add
  [freq word]
  (update freq word frequency-update-inc))

(defn- descending-value-comparator
  [[_ value]]
  (- value))

(let [words (load-split-text "Apologia.txt")
      freq-map (reduce frequency-add {} (map s/lower-case words))
      sorted-freqs (sort-by descending-value-comparator (vec freq-map))]

  (spit "apologia.dict"
        (s/join "\n" (map first
                          (drop (/ (count sorted-freqs) 5) sorted-freqs)))))
