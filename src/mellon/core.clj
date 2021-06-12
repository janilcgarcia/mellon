(ns mellon.core
  (:gen-class)
  (:import (java.util.zip ZipFile)
           (java.nio.file Paths))
  (:require [clojure.string :as s]
            [clojure.xml :as xml]
            [clojure.zip :as z]
            [clojure.java.io :as io]))

(defn- nio-path [name]
  (Paths/get name (into-array java.lang.String [])))

(defn- startparse-sax-non-validating [s ch]
  (.. (doto (javax.xml.parsers.SAXParserFactory/newInstance)
        (.setValidating false)
        (.setFeature "http://apache.org/xml/features/nonvalidating/load-dtd-grammar" false)
        (.setFeature "http://apache.org/xml/features/nonvalidating/load-external-dtd" false)
        (.setFeature "http://xml.org/sax/features/validation" false)
        (.setFeature "http://xml.org/sax/features/external-general-entities" false)
        (.setFeature "http://xml.org/sax/features/external-parameter-entities" false))

      (newSAXParser)
      (parse s ch)))

(defn- path-dirname [name]
  (when-let [parent (.getParent (nio-path name))]
    (.toString parent)))

(defn- path-resolve [base & names]
  (.toString (reduce #(.resolve %1 %2) (nio-path base) names)))

(defn zip-file-load [name]
  (ZipFile. name))

(defn zip-entry [file entry-name]
  (.getEntry file entry-name))

(defn zip-entry-to-input-stream [file entry]
  (.getInputStream file entry))

(defn zip-input-stream-from-name [file name]
  (zip-entry-to-input-stream file (zip-entry file name)))

(defn zip-load-xml
  ([file] (fn [name] (zip-load-xml file name)))
  ([file name]
   (-> file
       (zip-input-stream-from-name name)
       (xml/parse startparse-sax-non-validating))))

(defn epub-get-rootfile [container]
  (-> (z/xml-zip container)
      z/down
      z/down
      z/node
      :attrs
      :full-path))

(defn- rootfile-find-manifest [zipper]
  (when-let [node (z/node zipper)]
    (if (= (:tag node) :manifest)
      zipper
      (recur (z/right zipper)))))

(defn- rootfile-find-items [zipper]
  (-> zipper
      z/down
      rootfile-find-manifest
      z/children))

(defn- is-item-content? [item]
  (some? (re-matches (re-pattern ".*\\d+\\.x?html?$") (:href (:attrs item)))))

(defn- item-path
  ([base] (fn [name] (item-path base name)))
  ([base item]
   (let [name (:href (:attrs item))]
     (path-resolve base name))))

(defn epub-get-item-names [file]
  (let [rootfile-name (epub-get-rootfile
                       (zip-load-xml file "META-INF/container.xml"))
        base (path-dirname rootfile-name)
        rootfile (zip-load-xml file rootfile-name)
        rootfile-zipper (z/xml-zip rootfile)
        item-tags (rootfile-find-items rootfile-zipper)]
    (map (item-path base) (filter is-item-content? item-tags))))

(defn epub-get-item-contents [file]
  (let [names (epub-get-item-names file)]
    (map (zip-load-xml file) names)))

(declare xml-tag->str)

(defn- xml-attr->str [[key value]]
  (s/join [" " (subs (str key) 1) "=" value]))

(defn- xml-attrs->str [attrs]
  (if (empty? attrs)
    ""
    (s/join (map xml-attr->str attrs))))

(defn- xml-content->str [content]
  (if (string? content)
    content
    (xml-tag->str content)))

(defn- xml-contents->str [contents]
  (if (empty? contents)
    ""
    (s/join (concat ["\n"] (map xml-content->str contents) ["\n"]))))

(defn- xml-tag->str [root]
  (let [tag-name (subs (str (:tag root)) 1)]
    (s/join ["<" tag-name (xml-attrs->str (:attrs root)) ">"
             (xml-contents->str (:content root))
             "</" tag-name ">\n"])))

(defn- xml-extract-text [root collected]
  (let [node (z/node root)]
    (cond
      (nil? node) collected
      (string? node) (recur (z/next root) (conj collected node))
      ;; I know it reset when it reaches the :html tag again
      (= (:tag node) :html) collected
      :otherwise (recur (z/next root) collected))))

(defn- print-xml [root]
  (println (xml-tag->str root)))

(let [file (zip-file-load "osda.epub")
      a-content (nth (epub-get-item-contents file) 10)]

  (def ttemp-content (-> (z/xml-zip a-content)
                         z/down
                         z/right))
  (spit "SenhorDosAneis1.txt"
   (s/join "\n" (xml-extract-text (-> (z/xml-zip a-content)
                                     z/down
                                     z/right)
                                 []))))
