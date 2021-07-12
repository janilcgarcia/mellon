(ns mellon.javafx
  (:require [cljfx.api :as fx]
            [mellon.generate :as gen]
            [clojure.core.async :refer [go <! >!]]
            [mellon.random :as m.rand]
            [mellon.crypto.jvm :as crypto]
            [mellon.cli :as cli]
            [clojure.string :as s])
  (:import [javafx.application Platform]))

(def *state (atom {}))

(defn- replace-state
  [new-state] (fn [_] new-state))

(defn- on-button-click
  [dict prbg _]
  (go
    (let [passphrase (<! (gen/generate-passphrase prbg dict 4))]
      (swap! *state (replace-state {:passphrase passphrase})))))

(defn root
  [dict prbg {:keys [passphrase]}]
  {:fx/type :stage
   :showing true
   :title "Mellon"
   :width 300
   :height 150
   :scene
   {:fx/type :scene
    :root
    {:fx/type :v-box
     :alignment :center
     :children
     [{:fx/type :label
       :text (or passphrase "Click on the button to generate a new passphrase")}
      {:fx/type :button
       :text "Generate Passphrase"
       :on-action (partial on-button-click dict prbg)}]}}})


(defn make-renderer
  [dict prbg]
  (fx/create-renderer
   :middleware (fx/wrap-map-desc assoc :fx/type (partial root dict prbg))))

(defn -main [& args]
  (let [dict (cli/load-dict "../jvm/apologia.dict")
        prbg (m.rand/->system-prbg
              (let [sysrand (crypto/system-random)]
                (fn [nbytes]
                  (go (sysrand nbytes)))))]
    (Platform/setImplicitExit true)
    (fx/mount-renderer *state (make-renderer dict prbg))))

