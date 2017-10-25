/*
 * Copyright 2016 Artur Opala
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.github.arturopala.xmlsecurity

import java.net.URL
import java.io.ByteArrayInputStream
import java.io.StringWriter
import javax.xml.transform.{Transformer, TransformerFactory, Source, OutputKeys}
import javax.xml.transform.stream.StreamSource
import javax.xml.transform.stream.StreamResult
import javax.xml.transform.dom.DOMSource
import javax.xml.validation.Schema
import javax.xml.validation.Validator
import javax.xml.xpath.{XPath, XPathConstants, XPathExpression, XPathExpressionException}
import org.w3c.dom.{Document, Element, Attr, Node, NodeList, Text}
import scala.util.{Try, Success, Failure}

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
    val validator: Validator = schema.newValidator()
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
    val xPath: XPath = xpathFactory.newXPath()
    val nodeList: NodeList = xPath
      .evaluate("//text()[normalize-space()='']", dom, XPathConstants.NODESET)
      .asInstanceOf[NodeList]

    for (i <- 0 until nodeList.getLength()) {
      val node: Node = nodeList.item(i)
      node.getParentNode().removeChild(node)
    }

    val transformerFactory: TransformerFactory = TransformerFactory.newInstance()
    val transformer: Transformer = transformerFactory.newTransformer()
    transformer.setOutputProperty(OutputKeys.ENCODING, "UTF-8")
    transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes")
    transformer.setOutputProperty(OutputKeys.INDENT, "yes")
    transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", s"$indent");
    val stringWriter: StringWriter = new StringWriter()
    transformer.transform(new DOMSource(dom), new StreamResult(stringWriter))
    stringWriter.toString
  }

  def printDocument(dom: Document, omitXmlDec: Boolean = true): Try[String] = Try {
    val clonedDom = dom.copy
    trimWhitespace(clonedDom.getDocumentElement)
    val xPath: XPath = xpathFactory.newXPath()
    val transformerFactory: TransformerFactory = TransformerFactory.newInstance()
    val transformer: Transformer = transformerFactory.newTransformer()
    transformer.setOutputProperty(OutputKeys.ENCODING, "UTF-8")
    transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, if (omitXmlDec) "yes" else "no")
    val stringWriter: StringWriter = new StringWriter()
    transformer.transform(new DOMSource(clonedDom), new StreamResult(stringWriter))
    stringWriter.toString
  }

  private def trimWhitespace(node: Node): Unit = {
    node.getChildNodes.toSeq.foreach {
      child =>
        if (child.getNodeType == Node.TEXT_NODE) {
          child.setTextContent(child.getTextContent().trim())
        }
        trimWhitespace(child)
    }
  }

  private class XMLErrorHandler extends org.xml.sax.helpers.DefaultHandler {
    import org.xml.sax.SAXParseException

    private val log = scala.collection.mutable.ListBuffer[String]()

    override def error(e: SAXParseException): Unit = {
      log += ("ERROR: " + e.getMessage())
    }

    override def fatalError(e: SAXParseException): Unit = {
      log += ("FATAL: " + e.getMessage())
    }

    override def warning(e: SAXParseException) {
      log += ("WARNING: " + e.getMessage())
    }

    def hasError: Boolean = !log.isEmpty
    def getLog: String = log.mkString(" ")
  }
}
