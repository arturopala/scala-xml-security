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

import java.security.{PrivateKey, PublicKey}

import org.json4s.JsonAST.JObject
import org.json4s.jackson.JsonMethods._
import org.json4s.{DefaultFormats, Formats}

import scala.util.{Failure, Success, Try}

trait JsonWebToken extends KeyUtils {
  private implicit val jsonFormats: Formats = DefaultFormats

  case class Token(header: JObject, claims: JObject, payload: String, signature: String)

  def decode(jwt: String): Try[Token] = {
    split(jwt) flatMap {
      case (header, claims, signature) => Try {
        Token(
          header    = parse(decodeBase64URLSafe(header)).asInstanceOf[JObject],
          claims    = parse(decodeBase64URLSafe(claims)).asInstanceOf[JObject],
          payload   = header + "." + claims,
          signature = signature)
      }
    }
  }

  object Claims {
    def unapply(token: Token): Option[(String, String, String, Long)] = {
      for {
        iss <- (token.claims \ "iss").extractOpt[String]
        sub <- (token.claims \ "sub").extractOpt[String]
        aud <- (token.claims \ "aud").extractOpt[String]
        exp <- (token.claims \ "exp").extractOpt[Long]
      } yield (iss, sub, aud, exp)
    }
  }

  def encodeAsRS256(claims: String, privateKey: PrivateKey): String = {
    val header = """{"alg":"RS256","type":"jws"}"""
    val payload = encodeBase64URLSafe(header) + "." + encodeBase64URLSafe(claims)
    payload + "." + signSHA256(payload, privateKey)
  }

  def verify(publicKeyProvider: String => Option[PublicKey])(token: Token): Try[Token] = Try {
    (token.header \ "alg").extract[String] match {
      case "RS256" =>
        val issuer = (token.claims \ "iss").extract[String]
        publicKeyProvider(issuer) match {
          case Some(key) => verifySignature(token.payload, token.signature, key) match {
            case true  => token
            case false => throw new Exception("signature verification failed")
          }
          case None => throw new Exception(s"no public key is found for issuer $issuer")
        }
      case alg => throw new Exception(s"unsupported signature algorithm $alg, change to RS256")
    }
  }

  private[xmlsecurity] def split(jwt: String): Try[(String, String, String)] = {
    jwt.split("\\.") match {
      case Array(s1, s2, s3) => Success(s1, s2, s3)
      case x                 => Failure(new IllegalStateException(s"jwt is malformed, cannot split header, claims and signature"))
    }
  }
}

object JsonWebToken extends JsonWebToken