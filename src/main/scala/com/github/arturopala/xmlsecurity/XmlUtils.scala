package com.github.arturopala.xmlsecurity

import java.io.{ByteArrayInputStream, StringWriter}
import java.net.URL

import javax.xml.transform.dom.DOMSource
import javax.xml.transform.stream.{StreamResult, StreamSource}
import javax.xml.transform.{OutputKeys, Source, Transformer, TransformerFactory}
import javax.xml.validation.{Schema, Validator}
import javax.xml.xpath.{XPath, XPathConstants}
import org.w3c.dom.{Document, Node, NodeList}

import scala.util.Try

object XmlUtils {

  import XmlOps._

  def loadSchema(schemaUrl: URL*): Try[Schema] = Try {
    import javax.xml.validation.SchemaFactory
    val schemaFactory: SchemaFactory = SchemaFactory.newInstance(javax.xml.XMLConstants.W3C_XML_SCHEMA_NS_URI)
    schemaFactory.newSchema(schemaUrl.map(url => new StreamSource(url.toExternalForm)).toArray[Source])
  }

  def parseDocument(document: String): Try[Document] = Try {
    documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(document.getBytes("utf-8")))
  }

  def validateDocument(schema: Schema)(dom: Document): Try[Document] = Try {
    val validator: Validator          = schema.newValidator()
    val errorHandler: XMLErrorHandler = new XMLErrorHandler()
    validator.setErrorHandler(errorHandler)
    validator.validate(new DOMSource(dom))
    if (errorHandler.hasError) {
      throw new Exception("Invalid XML: " + errorHandler.getLog)
    }
    dom
  }

  def compactDocument(dom: Document): Try[Document] = Try {
    val clonedDom = dom.copy
    trimWhitespace(clonedDom.getDocumentElement)
    clonedDom
  }

  def prettyPrint(indent: Int)(dom: Document): Try[String] = Try {
    val xPath: XPath       = xpathFactory.newXPath()
    val nodeList: NodeList = xPath
      .evaluate("//text()[normalize-space()='']", dom, XPathConstants.NODESET)
      .asInstanceOf[NodeList]

    for (i <- 0 until nodeList.getLength()) {
      val node: Node = nodeList.item(i)
      node.getParentNode().removeChild(node)
    }

    val transformerFactory: TransformerFactory = TransformerFactory.newInstance()
    val transformer: Transformer               = transformerFactory.newTransformer()
    transformer.setOutputProperty(OutputKeys.ENCODING, "UTF-8")
    transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes")
    transformer.setOutputProperty(OutputKeys.INDENT, "yes")
    transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", s"$indent");
    val stringWriter: StringWriter             = new StringWriter()
    transformer.transform(new DOMSource(dom), new StreamResult(stringWriter))
    stringWriter.toString
  }

  def printDocument(dom: Document, omitXmlDec: Boolean = true): Try[String] = Try {
    val clonedDom                              = dom.copy
    trimWhitespace(clonedDom.getDocumentElement)
    val xPath: XPath                           = xpathFactory.newXPath()
    val transformerFactory: TransformerFactory = TransformerFactory.newInstance()
    val transformer: Transformer               = transformerFactory.newTransformer()
    transformer.setOutputProperty(OutputKeys.ENCODING, "UTF-8")
    transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, if (omitXmlDec) "yes" else "no")
    val stringWriter: StringWriter             = new StringWriter()
    transformer.transform(new DOMSource(clonedDom), new StreamResult(stringWriter))
    stringWriter.toString
  }

  private def trimWhitespace(node: Node): Unit =
    node.getChildNodes.toSeq.foreach { child =>
      if (child.getNodeType == Node.TEXT_NODE) {
        child.setTextContent(child.getTextContent().trim())
      }
      trimWhitespace(child)
    }

  private class XMLErrorHandler extends org.xml.sax.helpers.DefaultHandler {
    import org.xml.sax.SAXParseException

    private val log = scala.collection.mutable.ListBuffer[String]()

    override def error(e: SAXParseException): Unit =
      log += ("ERROR: " + e.getMessage())

    override def fatalError(e: SAXParseException): Unit =
      log += ("FATAL: " + e.getMessage())

    override def warning(e: SAXParseException) =
      log += ("WARNING: " + e.getMessage())

    def hasError: Boolean = !log.isEmpty
    def getLog: String    = log.mkString(" ")
  }
}
