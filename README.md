Scala XML Security
==================

[![Build Status](https://semaphoreci.com/api/v1/arturopala/scala-xml-security/branches/master/badge.svg)](https://semaphoreci.com/arturopala/scala-xml-security)

Main Features
=============

-   sign xml document, 
-   validate signature on xml document, 
-   encrypt xml document, 
-   decrypt xml document

Installation
============
Add the following line to your project description in `build.sbt`:
```
libraryDependencies += "com.github.arturopala" % "scala-xml-security_2.11" % "1.0.0"
```

You can find available versions here:

[http://search.maven.org/#search|ga|1|a:"scala-xml-security_2.11"](http://search.maven.org/#search%7Cga%7C1%7Ca%3A%22scala-xml-security_2.11%22)

Usage
=====

Parse XML as a Document (DOM)
-------------------------
API:
```scala
def parseDocument(document: String): Try[Document]
```
Example:
```scala
import scala.util.Try
import org.w3c.dom.Document
import com.github.arturopala.xmlsecurity.XmlUtils

val xml: String = "<hello world="!"></hello>" //some XML
val dom: Try[Document] = XmlUtils.parseDocument(xml)
```

Load schema and validate XML document
---------------------
API:
```scala
def loadSchema(schemaUrl: URL*): Try[Schema]
def validateDocument(schema: Schema)(dom: Document): Try[Document]
```
Example:
```scala
import java.net.URL
import scala.util.Try
import org.w3c.dom.Document
import com.github.arturopala.xmlsecurity.XmlUtils

def getResource(r: String): URL = classOf[Document].getResource(r)
val xml: String = ??? //some XML
val document: Try[Document] = for {
  schema    <- XmlUtils.loadSchema(
                  getResource("/saml-schema-protocol-2.0.xsd"), // relevant schemas
                  getResource("/saml-schema-assertion-2.0.xsd"),
                  getResource("/xenc-schema.xsd"),
                  getResource("/xmldsig-core-schema.xsd")
               )
  dom       <- XmlUtils.parseDocument(xml)
  validated <- XmlUtils.validateDocument(schema)(dom)
} yield validated
```

Sign XML document
-----------------
API:
```scala
def signDocument(
    signatureAlgorithm: String,
    digestAlgorithm:    String,
    privateKey:         PrivateKey,
    publicKey:          Option[PublicKey] = None)(dom: Document): Try[Document]
    
def signDocument(
    signatureAlgorithm: String,
    digestAlgorithm:    String,
    privateKey:         PrivateKey,
    cert:               X509Certificate)(dom: Document): Try[Document]
```
Example:
```scala
import java.security.KeyPair
import javax.security.cert.X509Certificate
import scala.util.Try
import org.w3c.dom.Document
import com.github.arturopala.xmlsecurity.{XmlUtils,XmlSecurity}

val keyPair: KeyPair = ???
val cerificate: X509Certificate = ???
val xml: String = "<hello world="!"></hello>" //some XML
val document: Try[Document] = for {
  dom     <- XmlUtils.parseDocument(xml)
  signed  <- XmlSecurity.signDocument(
                "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
                "http://www.w3.org/2001/04/xmlenc#sha256",
                keyPair.getPrivate,
                certificate
             )(dom)
} yield signed
```

Validate XML signature
----------------------
API:
```scala
def validateSignature: Document => Try[Document]
def validateSignature(publicKey: PublicKey): Document => Try[Document]
def validateSignature(keySelector: KeySelector)(dom: Document): Try[Document]
```
Example:
```scala
import scala.util.Try
import org.w3c.dom.Document
import com.github.arturopala.xmlsecurity.{XmlUtils,XmlSecurity}

val xml: String = ??? // some signed XML
val document: Try[Document] = for {
  dom     <- XmlUtils.parseDocument(xml)
  valid  <- XmlSecurity.validateSignature(dom)
} yield valid
```

Encrypt XML document
--------------------
API:
```scala
def encryptDocument(
    cert:                X509Certificate,
    encryptionAlgorithm: String,
    keyWrapAlgorithm:    String,
    digestAlgorithm:     String,
    mgfAlgorithm:        String          = null,
    oaepParams:          Array[Byte]     = null)(dom: Document): Try[Document]
```
Example:
```scala
import scala.util.Try
import org.w3c.dom.Document
import javax.security.cert.X509Certificate
import com.github.arturopala.xmlsecurity.{XmlUtils,XmlSecurity}

val cerificate: X509Certificate = ???
val xml: String = ??? // some XML
val document: Try[Document] = for {
  dom       <- XmlUtils.parseDocument(xml)
  encrypted <- XmlSecurity.encryptDocument(
                  certificate,
                  "http://www.w3.org/2001/04/xmlenc#aes256-cbc",
                  "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p",
                  "http://www.w3.org/2001/04/xmlenc#sha256"
               )(dom)
} yield encrypted
```

Decrypt XML document
--------------------
API:
```scala
def decryptDocument(key: Key)(dom: Document): Try[Document]
```
Example:
```scala
import scala.util.Try
import org.w3c.dom.Document
import java.security.KeyPair
import com.github.arturopala.xmlsecurity.{XmlUtils,XmlSecurity}

val keyPair: KeyPair = ???
val xml: String = ??? // some XML
val document: Try[Document] = for {
  dom       <- XmlUtils.parseDocument(xml)
  decrypted <- XmlSecurity.decryptDocument(keyPair.getPrivate)(dom)
} yield decrypted
```


