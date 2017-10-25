name := "scala-xml-security"

version := "1.2.0-SNAPSHOT"

organization := "com.github.arturopala"

licenses += ("Apache-2.0", url("http://www.apache.org/licenses/LICENSE-2.0"))

startYear := Some(2016)

description := "Scala XML Security - handy wrapper for org.apache.xml.security"

scalaVersion := "2.12.4"

libraryDependencies ++= Seq(
  "commons-codec" % "commons-codec" % "1.11",
  "org.apache.santuario" % "xmlsec" % "2.1.0",
  "org.bouncycastle" % "bcprov-jdk15on" % "1.58",
  "org.bouncycastle" % "bcpkix-jdk15on" % "1.58",
  "org.json4s" %% "json4s-native" % "3.5.3",
  "org.scalatest" %% "scalatest" % "3.0.4" % Test,
  "org.scalacheck" %% "scalacheck" % "1.13.5" % Test
)

import scalariform.formatter.preferences._
import com.typesafe.sbt.SbtScalariform
import com.typesafe.sbt.SbtScalariform.ScalariformKeys

ScalariformKeys.preferences := PreferencesImporterExporter.loadPreferences(baseDirectory.value / "project" / "formatterPreferences.properties" toString)

fork := true

connectInput in run := true

outputStrategy := Some(StdoutOutput)

import de.heikoseeberger.sbtheader.license.Apache2_0

headers := Map(
  "scala" -> Apache2_0("2016", "Artur Opala"),
  "conf" -> Apache2_0("2016", "Artur Opala", "#")
)
