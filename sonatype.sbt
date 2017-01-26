// To sync with Maven central, you need to supply the following information:
pomExtra in Global := {
  <url>github.com/arturopala/scala-xml-security</url>
  <scm>
    <connection>https://github.com/arturopala/scala-xml-security.git</connection>
    <developerConnection>git@github.com:arturopala/scala-xml-security.git</developerConnection>
    <url>github.com/arturopala/scala-xml-security</url>
  </scm>
  <developers>
    <developer>
      <id>arturopala</id>
      <name>Artur Opala</name>
      <url>https://pl.linkedin.com/in/arturopala</url>
    </developer>
  </developers>
}

import ReleaseTransformations._

releaseProcess := Seq[ReleaseStep](
  checkSnapshotDependencies,
  inquireVersions,
  runClean,
  runTest,
  setReleaseVersion,
  commitReleaseVersion,
  tagRelease,
  ReleaseStep(action = Command.process("publishSigned", _)),
  setNextVersion,
  commitNextVersion,
  ReleaseStep(action = Command.process("sonatypeReleaseAll", _)),
  pushChanges
)

releaseUseGlobalVersion := false