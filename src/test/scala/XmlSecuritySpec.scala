package com.github.arturopala.xmlsecurity

import org.scalatest.{FeatureSpec, Matchers, Inside}
import util.{Success, Failure}
import java.security.Key
import java.security.KeyStore
import java.security.PrivateKey
import java.security.PublicKey
import java.security.cert.Certificate
import org.json4s._
import org.json4s.JsonDSL._
import org.json4s.DefaultFormats
import java.net.URL
import javax.xml.namespace.NamespaceContext

class XmlSecuritySpec extends FeatureSpec with Matchers with Inside with KeyUtils {

  def read(resource: String) = {
    val is = classOf[String].getResourceAsStream(resource)
    io.Source.fromInputStream(is).mkString
  }

  val request = read("/sample_01.xml")
  val response = read("/sample_02.xml")
  val decryptedResponse = read("/sample_03.xml")

  import XmlOps._
  import XmlUtils._
  import XmlSecurity._

  feature("xml document parsing") {
    scenario("should parse valid xml document") {
      val result = XmlUtils.parseDocument(response)
      inside(result) {
        case Failure(e) => fail(e)
        case Success(dom) =>
          dom.getElementsByTagName("samlp:StatusCode").getLength shouldBe 1
      }
    }
  }

  feature("xml schema validation") {
    scenario("should validate document using xsd schema") {
      def getResource(r: String): URL = classOf[XmlSecuritySpec].getResource(r)
      val schema = XmlUtils.loadSchema(
        getResource("/saml-schema-protocol-2.0.xsd"),
        getResource("/saml-schema-assertion-2.0.xsd"),
        getResource("/xenc-schema.xsd"),
        getResource("/xmldsig-core-schema.xsd")) match {
          case Success(s) => s
          case Failure(e) => throw new Exception("Could not read schema", e)
        }
      parseDocument(response) flatMap validateDocument(schema) match {
        case Failure(e) => fail(e)
        case Success(dom) =>
          dom.getAttributeValue("samlp:StatusCode", "Value") shouldBe Some("urn:oasis:names:tc:SAML:2.0:status:Success")
      }
    }
  }

  feature("xml querying by xpath") {
    scenario("should select list of nodes") {
      parseDocument(response) map (_.selectNodes("/samlp:Response/samlp:Status/samlp:StatusCode", Some(Namespaces.NS_CONTEXT))) match {
        case Failure(e) => fail(e)
        case Success(nodes) =>
          nodes.head.getAttributes.getNamedItem("Value").getNodeValue shouldBe "urn:oasis:names:tc:SAML:2.0:status:Success"
      }
    }
  }

  import java.security.Key
  import org.apache.xml.security.encryption.EncryptedKey
  val keyPair = generateKeyPair()
  val cert = X509CertUtil.generateCertificate("CN=Test", keyPair, 10, "SHA256withRSA")

  feature("xml encrypting and decrypting") {
    scenario("should encrypt and decrypt xml document using aes256-cbc") {
      val result = parseDocument(request) flatMap encryptDocument(
        cert,
        "http://www.w3.org/2001/04/xmlenc#aes256-cbc",
        "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p",
        "http://www.w3.org/2001/04/xmlenc#sha256")
      result match {
        case Failure(e) => fail(e)
        case Success(dom) =>
          dom.getAttributeValue("xenc:EncryptionMethod", "Algorithm") shouldBe Some("http://www.w3.org/2001/04/xmlenc#aes256-cbc")
          dom.getAttributeValue("ds:DigestMethod", "Algorithm") shouldBe Some("http://www.w3.org/2001/04/xmlenc#sha256")
          decryptDocument(keyPair.getPrivate)(dom) match {
            case Failure(e) => fail(e)
            case Success(dom2) =>
              dom2.getAttributeValue("samlp:NameIDPolicy", "Format") shouldBe Some("urn:oasis:names:tc:SAML:2.0:nameid-format:transient")
          }
      }
    }

    scenario("should decrypt sample saml response document") {
      val is = classOf[XmlSecuritySpec].getResourceAsStream(s"/test.pfx")
      val keyStore: KeyStore = KeyStore.getInstance("PKCS12")
      keyStore.load(is, "Solutions2016".toCharArray())
      val key: Key = keyStore.getKey("lp-21eff765-f9eb-4768-9294-1977d25f8c4a", "Solutions2016".toCharArray());
      val cert: Certificate = keyStore.getCertificate("lp-21eff765-f9eb-4768-9294-1977d25f8c4a")
      val result = parseDocument(response) flatMap decryptDocument(key) match {
        case Failure(e) => fail(e)
        case Success(dom) =>
          dom.getElementsByTagName("NameID").item(0).getTextContent shouldBe "artur.opala@siili.com"
      }
    }
  }

  feature("xml signature validation") {
    scenario("should sign and validate document using private and public keys") {
      parseDocument(request)
        .flatMap(signDocument(
          "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
          "http://www.w3.org/2001/04/xmlenc#sha256",
          keyPair.getPrivate,
          Some(keyPair.getPublic)))
        .flatMap(validateSignature) match {
          case Failure(e)   => fail(e)
          case Success(dom) => assert(true)
        }
    }
    scenario("should sign and validate document using private key and X509 certificate") {
      parseDocument(request)
        .flatMap(signDocument(
          "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
          "http://www.w3.org/2001/04/xmlenc#sha256",
          keyPair.getPrivate,
          cert))
        .flatMap(validateSignature) match {
          case Failure(e)   => fail(e)
          case Success(dom) => assert(true)
        }
    }
    scenario("should remove signature from document") {
      parseDocument(decryptedResponse)
        .flatMap(removeSignature) match {
          case Failure(e) => fail(e)
          case Success(dom) =>
            dom.getElementsByTagNameNS(javax.xml.crypto.dsig.XMLSignature.XMLNS, "Signature").getLength shouldBe 0
        }
    }
  }

  feature("xml ops") {
    implicit val formats = DefaultFormats
    scenario("should convert xml to json") {
      parseDocument(request).map(_.getDocumentElement.toJson) match {
        case Failure(e) => fail(e)
        case Success(json) =>
          (json \ "samlp:AuthnRequest" \ "ID").extract[String] shouldBe "identifier_1"
          (json \ "samlp:AuthnRequest" \ "samlp:NameIDPolicy" \ "AllowCreate").extract[String] shouldBe "true"
          (json \ "samlp:AuthnRequest" \ "saml:Issuer" \ "textContent").extract[String] shouldBe "https://sp.example.com/SAML2"
      }
    }
  }
}

object Namespaces {
  val NS_SAML = "urn:oasis:names:tc:SAML:2.0:assertion"
  val NS_SAMLP = "urn:oasis:names:tc:SAML:2.0:protocol"
  val NS_SOAP = "http://schemas.xmlsoap.org/soap/envelope/"
  val NS_MD = "urn:oasis:names:tc:SAML:2.0:metadata"
  val NS_XS = "http://www.w3.org/2001/XMLSchema"
  val NS_XSI = "http://www.w3.org/2001/XMLSchema-instance"
  val NS_XENC = "http://www.w3.org/2001/04/xmlenc#"
  val NS_DS = "http://www.w3.org/2000/09/xmldsig#"

  val NS_CONTEXT: NamespaceContext = new NamespaceContext() {
    def getNamespaceURI(prefix: String): String = prefix match {
      case "samlp"  => NS_SAMLP
      case "samlp2" => NS_SAMLP
      case "saml"   => NS_SAML
      case "saml2"  => NS_SAML
      case "ds"     => NS_DS
      case "xenc"   => NS_XENC
      case "xs"     => NS_XS
      case "xsi"    => NS_XSI
      case "md"     => NS_MD
      case _        => null
    }

    def getPrefix(namespaceURI: String): String = namespaceURI match {
      case NS_SAMLP => "samlp"
      case NS_SAML  => "saml"
      case NS_DS    => "ds"
      case NS_XENC  => "xenc"
      case NS_XS    => "xs"
      case NS_XSI   => "xsi"
      case NS_MD    => "md"
      case _        => null
    }
    def getPrefixes(namespaceURI: String): java.util.Iterator[_] = null
  }
}

object X509CertUtil {

  import sun.security.x509._
  import java.security.cert._
  import java.security._
  import java.math.BigInteger
  import java.util.Date
  import java.io.IOException

  /**
    * Create a self-signed X.509 Certificate
    * @param dn the X.509 Distinguished Name, eg "CN=Test, L=London, C=GB"
    * @param pair the KeyPair
    * @param days how many days from now the Certificate is valid for
    * @param algorithm the signing algorithm, eg "SHA1withRSA" or "SHA256withRSA"
    * @see http://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html
    */
  def generateCertificate(dn: String, pair: KeyPair, days: Int, algorithm: String): X509Certificate = {
    val privkey: PrivateKey = pair.getPrivate()
    val info: X509CertInfo = new X509CertInfo()
    val from: Date = new Date()
    val to: Date = new Date(from.getTime() + days * 86400000l)
    val interval: CertificateValidity = new CertificateValidity(from, to)
    val sn: BigInteger = new BigInteger(64, new SecureRandom())
    val owner: X500Name = new X500Name(dn)

    info.set(X509CertInfo.VALIDITY, interval)
    info.set(X509CertInfo.SERIAL_NUMBER, new CertificateSerialNumber(sn))
    try {
      info.set(X509CertInfo.SUBJECT, new CertificateSubjectName(owner))
      info.set(X509CertInfo.ISSUER, new CertificateIssuerName(owner))
    }
    catch {
      case e: java.security.cert.CertificateException =>
        info.set(X509CertInfo.SUBJECT, owner)
        info.set(X509CertInfo.ISSUER, owner)
    }
    info.set(X509CertInfo.KEY, new CertificateX509Key(pair.getPublic()))
    info.set(X509CertInfo.VERSION, new CertificateVersion(CertificateVersion.V3))
    val algo: AlgorithmId = new AlgorithmId(AlgorithmId.md5WithRSAEncryption_oid)
    info.set(X509CertInfo.ALGORITHM_ID, new CertificateAlgorithmId(algo))

    val cert: X509CertImpl = new X509CertImpl(info)
    cert.sign(privkey, algorithm)

    val algo2 = cert.get(X509CertImpl.SIG_ALG).asInstanceOf[AlgorithmId]
    info.set(CertificateAlgorithmId.NAME + "." + CertificateAlgorithmId.ALGORITHM, algo2)
    val cert2 = new X509CertImpl(info)
    cert2.sign(privkey, algorithm)
    cert2
  }
}