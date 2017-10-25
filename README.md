Scala XML Security
==================

[![Build Status](https://semaphoreci.com/api/v1/arturopala/scala-xml-security/branches/master/badge.svg)](https://semaphoreci.com/arturopala/scala-xml-security)

Dealing with XML signatures or encryption requires usually a lot of magic config code followed by copy-pasted boilerplate. This small library wraps for you all the necessary configuration and logic to finally expose simple but essential API.

Main Features
=============

-   **signature** creation and validation, 
-   **encryption** of XML document, 
-   **decryption** of XML document

Installation
============
Add the following line to your project description in `build.sbt`:
```
libraryDependencies += "com.github.arturopala" % "scala-xml-security_2.12" % "1.2.0"
```

You can find available versions here:

[http://search.maven.org/#search|ga|1|scala-xml-security](http://search.maven.org/#search%7Cga%7C1%7Cscala-xml-security)

Dependencies
------------
This library brings into your project few transitive dependencies:
-   org.apache.santuario:xmlsec - [Apache XML Security utils](http://santuario.apache.org/javaindex.html)
-   org.bouncycastle:bcprov-jdk15on - [Cryptography provider](https://www.bouncycastle.org/)
-   org.bouncycastle:bcpkix-jdk15on - [PKI support](https://www.bouncycastle.org/)
-   org.json4s:json4s-native - [Scala JSON library](https://github.com/json4s/json4s)
-   commons-codec:commons-codec - [Apache Commons Codec](https://commons.apache.org/proper/commons-codec/)

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
  dom    <- XmlUtils.parseDocument(xml)
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

Handy implicit methods - DOM api extensions
-----------------------------------------------

```scala
import com.github.arturopala.xmlsecurity.XmlOps._
```

### org.w3c.dom.Document

```scala
def selectNodes(query: String, ns: Option[NamespaceContext] = None): Seq[Node]
def getTagTextContent(tag: String): Option[String]
def getAttributeValue(tag: String, attribute: String): Option[String]
def copy: Document
```

### org.w3c.dom.NodeList

```scala
def toSeq: Seq[Node]
```

### org.w3c.dom.Node

```scala
def children: Seq[Node]
def attributes: collection.Map[String, String]
def toJson: org.json4s.JObject
```

Document rendering
------------------
API:
```scala
def printDocument(dom: Document): Try[String]
def prettyPrint(indent: Int)(dom: Document): Try[String]
```
