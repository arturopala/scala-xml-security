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

import javax.xml.namespace.NamespaceContext
import javax.xml.parsers.{DocumentBuilderFactory}
import javax.xml.xpath.{XPath, XPathConstants, XPathExpression, XPathExpressionException}
import javax.xml.xpath.XPathFactory
import org.w3c.dom.{Document, Element, Attr, Node, NodeList, Text}

object XmlOps {

  val documentBuilderFactory: DocumentBuilderFactory = DocumentBuilderFactory.newInstance()
  documentBuilderFactory.setNamespaceAware(true)
  lazy val xpathFactory: XPathFactory = XPathFactory.newInstance()

  implicit class DocumentOps(val dom: Document) extends AnyVal {

    def selectNodes(query: String, ns: Option[NamespaceContext] = None): NodeSeq = {
      val xpath: XPath = xpathFactory.newXPath()
      ns.foreach(xpath.setNamespaceContext)
      val nodelist = xpath.evaluate(query, dom, XPathConstants.NODESET).asInstanceOf[NodeList]
      NodeSeq(nodelist)
    }

    def getTagTextContent(tag: String): Option[String] = {
      dom.getElementsByTagName(tag) match {
        case nl if nl.getLength > 0 =>
          Option(nl.item(0))
            .map(_.getTextContent)
        case _ => None
      }
    }

    def getAttributeValue(tag: String, attribute: String): Option[String] = {
      dom.getElementsByTagName(tag) match {
        case nl if nl.getLength > 0 =>
          Option(nl.item(0))
            .map(_.getAttributes.getNamedItem(attribute))
            .map(_.getNodeValue)
        case _ => None
      }
    }

    def copy: Document = {
      val cloned: Document = documentBuilderFactory.newDocumentBuilder().newDocument()
      cloned.appendChild(cloned.importNode(dom.getDocumentElement(), true))
      cloned
    }
  }

  implicit class NodeListOps(val nodeList: NodeList) extends AnyVal {
    def toSeq: NodeSeq = NodeSeq(nodeList)
  }

  implicit class NodeOps(val node: Node) extends AnyVal {

    def children: NodeSeq = NodeSeq(node.getChildNodes)

    def attributes: collection.Map[String, String] = new collection.DefaultMap[String, String] {
      val attrs = node.getAttributes
      val length = Option(attrs).map(_.getLength).getOrElse(0)
      def get(name: String): Option[String] = Option(attrs).map(_.getNamedItem(name)).map(_.asInstanceOf[Attr].getValue)
      def iterator: Iterator[(String, String)] = new Iterator[(String, String)] {
        var pos = 0
        val maxPos = Option(attrs).map(_.getLength).getOrElse(0)
        def hasNext: Boolean = pos < maxPos
        def next: (String, String) = {
          if (pos >= maxPos) throw new java.util.NoSuchElementException()
          val attr: Attr = attrs.item(pos).asInstanceOf[Attr]
          pos = pos + 1
          (attr.getName, attr.getValue)
        }
      }
    }

    def toJson: org.json4s.JObject = {
      import org.json4s.JsonAST.JValue
      import org.json4s.JsonDSL._
      import org.json4s.{DefaultFormats, JArray, JObject, JString, JNothing}
      node match {
        case elem: Element =>
          val attributes: List[(String, JValue)] = elem.attributes.map({ case (k, v) => (k, JString(v)) }).toList
          val children: List[(String, JValue)] = elem.children.flatMap(_.toJson.obj).toList
          JObject(elem.getTagName -> JObject(attributes ++ children))
        case text: Text =>
          JObject("textContent" -> JString(text.getWholeText))
        case _ =>
          JObject()
      }
    }
  }

  case class NodeSeq(nodeList: NodeList) extends collection.Seq[Node] {
    def length: Int = Option(nodeList).map(_.getLength).getOrElse(0)
    def apply(i: Int): Node = nodeList.item(i)
    def iterator: Iterator[Node] = new Iterator[Node] {
      var pos = 0
      val maxPos = Option(nodeList).map(_.getLength).getOrElse(0)
      def hasNext: Boolean = pos < maxPos
      def next: Node = {
        if (pos >= maxPos) throw new java.util.NoSuchElementException()
        val item = nodeList.item(pos)
        pos = pos + 1
        item
      }
    }
  }
}
