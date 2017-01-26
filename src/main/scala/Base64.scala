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

import java.nio.charset.Charset

import org.json4s._
import org.json4s.native.Serialization._

trait Base64 {
  def encodeBase64URLSafe(string: String): String = {
    org.apache.commons.codec.binary.Base64.encodeBase64URLSafeString(string.getBytes("UTF-8"))
  }

  def encodeBase64(string: String): String = {
    org.apache.commons.codec.binary.Base64.encodeBase64String(string.getBytes("UTF-8"))
  }

  def encodeBase64URLSafe(json: JValue): String = {
    import org.json4s.native.Serialization
    import org.json4s.native.Serialization.{write}
    implicit val formats = Serialization.formats(NoTypeHints)
    encodeBase64URLSafe(write(json))
  }

  def decodeBase64URLSafe(string: String): String = {
    new String(org.apache.commons.codec.binary.Base64.decodeBase64(string), Charset.forName("UTF-8"))
  }

  def decodeBase64(string: String): String = {
    new String(org.apache.commons.codec.binary.Base64.decodeBase64(string), Charset.forName("UTF-8"))
  }

  def decodeBase64URLSafeAsBytes(string: String): Array[Byte] = {
    org.apache.commons.codec.binary.Base64.decodeBase64(string)
  }

  def encodeBase64URLSafe(binary: Array[Byte]): String = {
    org.apache.commons.codec.binary.Base64.encodeBase64URLSafeString(binary)
  }

  def encodeBase64(binary: Array[Byte]): String = {
    org.apache.commons.codec.binary.Base64.encodeBase64String(binary)
  }

  def encodeBase64URLSafeAsBytes(string: String): Array[Byte] = {
    org.apache.commons.codec.binary.Base64.encodeBase64URLSafe(string.getBytes("UTF-8"))
  }
}

object Base64 extends Base64
