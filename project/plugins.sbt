resolvers += Resolver.typesafeRepo("releases")

resolvers += Resolver.sonatypeRepo("releases")

addSbtPlugin("org.scalameta"     % "sbt-scalafmt" % "2.5.6")
addSbtPlugin("de.heikoseeberger" % "sbt-header"   % "5.1.0")
addSbtPlugin("org.xerial.sbt"    % "sbt-sonatype" % "2.5")
addSbtPlugin("com.jsuereth"      % "sbt-pgp"      % "1.1.0")
addSbtPlugin("com.github.gseitz" % "sbt-release"  % "1.0.11")
