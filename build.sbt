name := "scala-xml-security"

version := "1.2.0-SNAPSHOT"

organization := "com.github.arturopala"

licenses += ("Apache-2.0", url("http://www.apache.org/licenses/LICENSE-2.0"))

startYear := Some(2016)

description := "Scala XML Security - handy wrapper for org.apache.xml.security"

scalaVersion := "3.3.4"

libraryDependencies ++= Seq(
  "commons-codec"        % "commons-codec"        % "1.12",
  "org.apache.santuario" % "xmlsec"               % "2.1.3",
  "org.bouncycastle"     % "bcprov-jdk18on"       % "1.83",
  "org.bouncycastle"     % "bcpkix-jdk18on"       % "1.83",
  "org.json4s"          %% "json4s-native"        % "4.0.7",
  "jakarta.xml.bind"     % "jakarta.xml.bind-api" % "4.0.4",
  "org.scalatest"       %% "scalatest"            % "3.2.19" % Test,
  "org.scalacheck"      %% "scalacheck"           % "1.19.0" % Test
)

fork := true

connectInput in run := true

outputStrategy := Some(StdoutOutput)

scalafmtOnCompile in Compile := true
scalafmtOnCompile in Test := true
