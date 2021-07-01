(defproject mellon "0.1.0-SNAPSHOT"
  :description "FIXME: write description"
  :url "http://example.com/FIXME"
  :license {:name "EPL-2.0 OR GPL-2.0-or-later WITH Classpath-exception-2.0"
            :url "https://www.eclipse.org/legal/epl-2.0/"}
  :dependencies [[org.clojure/clojure "1.10.3"]
                 [org.bouncycastle/bcprov-jdk15on "1.69"]
                 [org.clojure/tools.cli "1.0.206"]
                 [org.clojure/core.async "1.3.618"]]
  :native-image {:opts ["--verbose"
                        "-H:+ReportExceptionStackTraces"
                        "-H:IncludeResources=.*\\.clj$"
                        "-H:ReflectionConfigurationFiles=agent-result/reflect-config.json"
                        "--report-unsupported-elements-at-runtime"
                        "--initialize-at-run-time=mellon.random$secure_random_byte_generator$fn__530"
                        ;; "--initialize-at-run-time=sun.security.provider.NativePRNG,java.security.SecureRandom"
                        "--initialize-at-build-time"
                        "--no-fallback"]}
  :main mellon.core
  :target-path "target/%s"
  :plugins [[io.taylorwood/lein-native-image "0.3.1"]]
  :profiles {:dev {:global-vars {;*warn-on-reflection* true
                                 *assert* true
                                 }}
             :uberjar {:aot :all
                       :native-image {:jvm-opts ["-Dclojure.compiler.direct-linking=true"]}}})
