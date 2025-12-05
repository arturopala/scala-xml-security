package com.github.arturopala.xmlsecurity

import java.security.cert.X509Certificate
import java.security.{Key, PrivateKey, PublicKey}

import javax.crypto.KeyGenerator
import javax.xml.crypto.dsig.dom.DOMValidateContext
import javax.xml.crypto.dsig.keyinfo.KeyValue
import javax.xml.crypto.dsig.{Reference, XMLSignature, XMLSignatureFactory}
import javax.xml.crypto._
import org.apache.xml.security.encryption.{EncryptedData, EncryptedKey, XMLCipher}
import org.apache.xml.security.keys.KeyInfo
import org.apache.xml.security.keys.content.X509Data
import org.apache.xml.security.utils.EncryptionConstants
import org.w3c.dom.{Document, Element, Node}
import scala.jdk.CollectionConverters.*

import scala.util.Try

// scalastyle:off null
object XmlSecurity {

  import XmlOps._

  org.apache.xml.security.Init.init()

  lazy val xmlSignatureFactory: XMLSignatureFactory = XMLSignatureFactory.getInstance("DOM")

  def signDocument(
    signatureAlgorithm: String,
    digestAlgorithm: String,
    privateKey: PrivateKey,
    publicKey: Option[PublicKey] = None
  )(dom: Document): Try[Document] = Try {
    import org.apache.xml.security.signature.XMLSignature
    import org.apache.xml.security.transforms.Transforms
    val newDom                 = dom.copy
    val sig: XMLSignature      =
      new XMLSignature(newDom, "", signatureAlgorithm, Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS)
    val root: Element          = newDom.getDocumentElement()
    root.appendChild(sig.getElement())
    val transforms: Transforms = new Transforms(newDom)
    transforms.addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE)
    transforms.addTransform(Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS)
    sig.addDocument("", transforms, digestAlgorithm)
    publicKey foreach sig.addKeyInfo
    sig.sign(privateKey)
    newDom
  }

  def signDocument(signatureAlgorithm: String, digestAlgorithm: String, privateKey: PrivateKey, cert: X509Certificate)(
    dom: Document
  ): Try[Document] = Try {
    import org.apache.xml.security.signature.XMLSignature
    import org.apache.xml.security.transforms.Transforms
    val newDom                                   = dom.copy
    val sig: XMLSignature                        =
      new XMLSignature(newDom, "", signatureAlgorithm, Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS)
    val root: Element                            = newDom.getDocumentElement()
    root.appendChild(sig.getElement())
    val transforms: Transforms                   = new Transforms(newDom)
    transforms.addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE)
    transforms.addTransform(Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS)
    sig.addDocument("", transforms, digestAlgorithm)
    sig.addKeyInfo(cert)
    val ki: org.apache.xml.security.keys.KeyInfo = sig.getKeyInfo()
    ki.itemX509Data(0).addSubjectName(cert.getSubjectX500Principal().getName())
    ki.itemX509Data(0).addIssuerSerial(cert.getIssuerX500Principal().getName(), cert.getSerialNumber())
    sig.sign(privateKey)
    newDom
  }

  def validateSignature: Document => Try[Document] = validateSignature(KEY_SELECTOR) _

  def validateSignature(publicKey: PublicKey): Document => Try[Document] =
    validateSignature(KeySelector.singletonKeySelector(publicKey)) _

  def validateSignature(keySelector: KeySelector)(dom: Document): Try[Document] = Try {
    val validate                         = validateSignatureOfNode(keySelector) _
    val result: Either[String, Document] = dom
      .getElementsByTagNameNS(XMLSignature.XMLNS, "Signature")
      .toSeq
      .foldLeft[Either[String, Document]](Right(dom)) {
        case (Right(document), node) => validate(document, node)
        case (Left(failures), node)  =>
          validate(dom, node) match {
            case Left(failure) => Left(failures + failure)
            case right         => right
          }
      }
    result match {
      case Right(document) => document
      case Left(failures)  => throw new Exception(failures)
    }
  }

  def validateSignatureOfNode(
    keySelector: KeySelector
  )(dom: Document, signatureNode: Node): Either[String, Document] = {
    val valContext: DOMValidateContext = new DOMValidateContext(keySelector, signatureNode)
    dom.selectNodes("//*[@ID]") foreach { node =>
      valContext.setIdAttributeNS(node.asInstanceOf[Element], null, "ID")
    }
    val signature: XMLSignature        = xmlSignatureFactory.unmarshalXMLSignature(valContext)
    val result                         = signature.validate(valContext)
    if (result) {
      Right(dom)
    } else {
      val sb = new StringBuilder("Signature validation FAILED; ")
      val sv = signature.getSignatureValue().validate(valContext)
      sb.append("status: " + sv)
      if (!sv) {
        signature.getSignedInfo().getReferences().asScala.foreach { item =>
          val ref = item.asInstanceOf[Reference]
          sb.append(s"; reference ${ref.getId}:${ref.getURI} status: " + ref.validate(valContext))
        }
      }
      Left(sb.toString)
    }
  }

  def removeSignature(dom: Document): Try[Document] = Try {
    val newDom = dom.copy
    newDom
      .getElementsByTagNameNS(XMLSignature.XMLNS, "Signature")
      .toSeq
      .foreach(node => Option(node.getParentNode).foreach(_.removeChild(node)))
    newDom
  }

  private val KEY_SELECTOR = new KeySelector {
    import javax.xml.crypto.dsig.keyinfo.KeyInfo
    def select(
      keyInfo: KeyInfo,
      purpose: KeySelector.Purpose,
      method: AlgorithmMethod,
      context: XMLCryptoContext
    ): KeySelectorResult = {
      if (keyInfo == null) throw new KeySelectorException("Missing <ds:KeyInfo> element")
      keySelectorResult(extractKey(keyInfo))
    }

    def extractKey(keyInfo: KeyInfo): PublicKey =
      keyInfo
        .getContent()
        .asScala
        .map(_.asInstanceOf[XMLStructure] match {
          case k: KeyValue                                   => k.getPublicKey
          case xdata: javax.xml.crypto.dsig.keyinfo.X509Data =>
            xdata.getContent().asScala.collectFirst { case cert: X509Certificate =>
              cert.getPublicKey
            } getOrElse {
              throw new Exception("X509 certificate not found")
            }
          case k                                             => throw new Exception(s"Key type not supported $k")
        })
        .head

    def keySelectorResult(key: PublicKey): KeySelectorResult = new KeySelectorResult {
      def getKey(): Key = key
    }
  }

  def decryptDocument(key: Key)(dom: Document): Try[Document] = Try {
    val newDom = dom.copy
    newDom
      .getElementsByTagNameNS(EncryptionConstants.EncryptionSpecNS, EncryptionConstants._TAG_ENCRYPTEDDATA)
      .toSeq
      .map(_.asInstanceOf[Element])
      .foreach { (encryptedDataElement: Element) =>
        val cipher: XMLCipher            = XMLCipher.getInstance()
        cipher.init(XMLCipher.DECRYPT_MODE, null)
        val encryptedData: EncryptedData = cipher.loadEncryptedData(newDom, encryptedDataElement)
        val ki: KeyInfo                  = encryptedData.getKeyInfo()
        val encryptedKey: EncryptedKey   = ki.itemEncryptedKey(0)
        val cipher2: XMLCipher           = XMLCipher.getInstance()
        cipher2.init(XMLCipher.UNWRAP_MODE, key)
        val sessionKey: Key              = cipher2.decryptKey(encryptedKey, encryptedData.getEncryptionMethod().getAlgorithm())
        cipher.init(XMLCipher.DECRYPT_MODE, sessionKey)
        cipher.doFinal(newDom, encryptedDataElement)
      }
    newDom
  }

  def encryptDocument(
    cert: X509Certificate,
    encryptionAlgorithm: String,
    keyWrapAlgorithm: String,
    digestAlgorithm: String,
    mgfAlgorithm: String = null,
    oaepParams: Array[Byte] = null
  )(dom: Document): Try[Document] = Try {
    val newDom                       = dom.copy
    val sessionKey: Key              = getSessionKey(encryptionAlgorithm)
    val encryptedKey: EncryptedKey   =
      createEncryptedKey(newDom, cert, sessionKey, keyWrapAlgorithm, digestAlgorithm, mgfAlgorithm, oaepParams)
    val cipher: XMLCipher            = XMLCipher.getInstance(encryptionAlgorithm)
    cipher.init(XMLCipher.ENCRYPT_MODE, sessionKey)
    val encryptedData: EncryptedData = cipher.getEncryptedData()
    val builderKeyInfo: KeyInfo      = encryptedData.getKeyInfo() match {
      case null =>
        val ki = new KeyInfo(newDom)
        encryptedData.setKeyInfo(ki)
        ki
      case ki   => ki
    }
    builderKeyInfo.add(encryptedKey)
    cipher.doFinal(newDom, newDom.getDocumentElement())
  }

  private def createEncryptedKey(
    dom: Document,
    cert: X509Certificate,
    sessionKey: Key,
    keyWrapAlgorithm: String,
    digestAlgorithm: String,
    mgfAlgorithm: String = null,
    oaepParams: Array[Byte] = null
  ): EncryptedKey = {
    val cipher: XMLCipher          = XMLCipher.getInstance(keyWrapAlgorithm, null, digestAlgorithm)
    cipher.init(XMLCipher.WRAP_MODE, cert.getPublicKey())
    val encryptedKey: EncryptedKey = cipher.encryptKey(dom, sessionKey, mgfAlgorithm, oaepParams)
    val builderKeyInfo: KeyInfo    = encryptedKey.getKeyInfo() match {
      case null =>
        val ki = new KeyInfo(dom)
        encryptedKey.setKeyInfo(ki)
        ki
      case ki   => ki
    }
    val x509Data: X509Data         = new X509Data(dom)
    x509Data.addCertificate(cert)
    builderKeyInfo.add(x509Data)
    encryptedKey
  }

  // scalastyle:off magic.number
  private def getSessionKey(encryptionAlgorithm: String): Key = {
    val keyGen: KeyGenerator = KeyGenerator.getInstance("AES");
    if (encryptionAlgorithm.contains("128")) {
      keyGen.init(128)
    } else if (encryptionAlgorithm.contains("192")) {
      keyGen.init(192)
    } else if (encryptionAlgorithm.contains("256")) {
      keyGen.init(256)
    }
    keyGen.generateKey()
  }
  // scalastyle:on magic.number
}
