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

import java.io._
import java.security._
import java.security.spec.{PKCS8EncodedKeySpec, X509EncodedKeySpec}
import javax.xml.bind.DatatypeConverter

import org.bouncycastle.openssl.{PEMParser, PEMWriter}

trait KeyUtils extends Base64 {

  def exportPublicKeyAsDER(publicKey: PublicKey): String = {
    DatatypeConverter.printBase64Binary(publicKey.getEncoded)
  }

  def exportPrivateKeyAsPEM(privateKey: PrivateKey): String = {
    val pemStrWriter = new StringWriter();
    val pemWriter = new PEMWriter(pemStrWriter);
    pemWriter.writeObject(privateKey);
    pemWriter.flush();
    pemWriter.close();

    pemStrWriter.toString
  }

  def parsePrivateKeyFromPEM(privateKeyString: String): PrivateKey = {
    Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    val pemStrReader = new StringReader(privateKeyString)
    val pemReader = new PEMParser(pemStrReader)
    val keyPair = pemReader.readObject()
    keyPair.asInstanceOf[KeyPair].getPrivate
  }

  def createKeyPairBase64AsDER(): (String, String) = {
    val (publicKey, privateKey) = createKeyPair()

    (DatatypeConverter.printBase64Binary(publicKey.getEncoded), DatatypeConverter.printBase64Binary(privateKey.getEncoded))
  }

  def generateKeyPair(): KeyPair = {
    val gen = KeyPairGenerator.getInstance("RSA")
    val random = SecureRandom.getInstance("SHA1PRNG")
    gen.initialize(2048, random)
    gen.generateKeyPair()
  }

  def createKeyPair(): (PublicKey, PrivateKey) = {
    val pair = generateKeyPair()
    (pair.getPublic, pair.getPrivate)
  }

  def parsePrivateKeyFromDER(privateKey: String): PrivateKey = {
    val keyFactory = KeyFactory.getInstance("RSA")
    val keySpec = new PKCS8EncodedKeySpec(decodeBase64URLSafeAsBytes(privateKey))
    keyFactory.generatePrivate(keySpec)
  }

  def parsePublicKeyFromDER(publicKey: String): PublicKey = {
    val keyFactory = KeyFactory.getInstance("RSA")
    val keySpec = new X509EncodedKeySpec(decodeBase64URLSafeAsBytes(publicKey))
    keyFactory.generatePublic(keySpec)
  }

  def signSHA256(payload: String, privateKey: PrivateKey): String = {
    val signature = Signature.getInstance("SHA256withRSA")
    signature.initSign(privateKey)
    signature.update(payload.getBytes("UTF-8"))
    encodeBase64URLSafe(signature.sign())
  }

  def verifySignature(payload: String, signature: String, key: PublicKey): Boolean = {
    val signatureToVerify = Signature.getInstance("SHA256withRSA")
    signatureToVerify.initVerify(key)
    signatureToVerify.update(payload.getBytes("UTF-8"))
    signatureToVerify.verify(decodeBase64URLSafeAsBytes(signature))
  }

}

object KeyUtils extends KeyUtils
