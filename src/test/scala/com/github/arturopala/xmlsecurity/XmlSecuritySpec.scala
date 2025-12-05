package com.github.arturopala.xmlsecurity

import javax.xml.namespace.NamespaceContext

object Namespaces {

  val NS_SAML  = "urn:oasis:names:tc:SAML:2.0:assertion"
  val NS_SAMLP = "urn:oasis:names:tc:SAML:2.0:protocol"
  val NS_SOAP  = "http://schemas.xmlsoap.org/soap/envelope/"
  val NS_MD    = "urn:oasis:names:tc:SAML:2.0:metadata"
  val NS_XS    = "http://www.w3.org/2001/XMLSchema"
  val NS_XSI   = "http://www.w3.org/2001/XMLSchema-instance"
  val NS_XENC  = "http://www.w3.org/2001/04/xmlenc#"
  val NS_DS    = "http://www.w3.org/2000/09/xmldsig#"

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

    def getPrefixes(namespaceURI: String): java.util.Iterator[String] = null
  }
}

// object X509CertUtil {

//   import java.math.BigInteger
//   import java.security._
//   import java.security.cert._
//   import java.util.Date

//   import sun.security.x509._

//   /** Create a self-signed X.509 Certificate
//     * @param dn
//     *   the X.509 Distinguished Name, eg "CN=Test, L=London, C=GB"
//     * @param pair
//     *   the KeyPair
//     * @param days
//     *   how many days from now the Certificate is valid for
//     * @param algorithm
//     *   the signing algorithm, eg "SHA1withRSA" or "SHA256withRSA"
//     * @see
//     *   http://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html
//     */
//   def generateCertificate(dn: String, pair: KeyPair, days: Int, algorithm: String): X509Certificate = {
//     val privkey: PrivateKey           = pair.getPrivate()
//     val info: X509CertInfo            = new X509CertInfo()
//     val from: Date                    = new Date()
//     val to: Date                      = new Date(from.getTime() + days * 86400000L)
//     val interval: CertificateValidity = new CertificateValidity(from, to)
//     val sn: BigInteger                = new BigInteger(64, new SecureRandom())
//     val owner: X500Name               = new X500Name(dn)

//     info.set(X509CertInfo.VALIDITY, interval)
//     info.set(X509CertInfo.SERIAL_NUMBER, new CertificateSerialNumber(sn))
//     try {
//       info.set(X509CertInfo.SUBJECT, new CertificateSubjectName(owner))
//       info.set(X509CertInfo.ISSUER, new CertificateIssuerName(owner))
//     } catch {
//       case e: java.security.cert.CertificateException =>
//         info.set(X509CertInfo.SUBJECT, owner)
//         info.set(X509CertInfo.ISSUER, owner)
//     }
//     info.set(X509CertInfo.KEY, new CertificateX509Key(pair.getPublic()))
//     info.set(X509CertInfo.VERSION, new CertificateVersion(CertificateVersion.V3))
//     val algo: AlgorithmId = new AlgorithmId(AlgorithmId.md5WithRSAEncryption_oid)
//     info.set(X509CertInfo.ALGORITHM_ID, new CertificateAlgorithmId(algo))

//     val cert: X509CertImpl = new X509CertImpl(info)
//     cert.sign(privkey, algorithm)

//     val algo2 = cert.get(X509CertImpl.SIG_ALG).asInstanceOf[AlgorithmId]
//     info.set(CertificateAlgorithmId.NAME + "." + CertificateAlgorithmId.ALGORITHM, algo2)
//     val cert2 = new X509CertImpl(info)
//     cert2.sign(privkey, algorithm)
//     cert2
//   }
// }
