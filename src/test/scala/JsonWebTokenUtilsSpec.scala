package com.github.arturopala.xmlsecurity

import java.security.PublicKey

import org.json4s.{DefaultFormats, _}
import org.scalatest.{FlatSpec, Matchers}

import scala.util.Success

class JsonWebTokenSpec extends FlatSpec with Matchers with KeyUtils {

  private implicit val jsonFormats: Formats = DefaultFormats
  val (publicKey, privateKey) = createKeyPairBase64AsDER()
  val claims =
    """{
      |          "iss": "555555556",
      |          "iat": 1455539324,
      |          "exp": 1581683324,
      |          "aud": "verkkopalvelu",
      |          "sub": "123412341"
      |}""".stripMargin

  val jwt = JsonWebToken.encodeAsRS256(claims, parsePrivateKeyFromDER(privateKey))

  "JsonWebToken" should "split jwt into header, claims and signature" in {
    val jwt: String = "ye6356453%%^.UWYEUYWUYE7326746&^.77382784373"
    JsonWebToken.split(jwt) shouldBe Success("ye6356453%%^", "UWYEUYWUYE7326746&^", "77382784373")
  }

  it should "decode JWT" in {
    JsonWebToken.decode(jwt) match {
      case Success(JsonWebToken.Token(header, claims, payload, signature)) =>
        (claims \ "iss").extract[String] shouldBe "555555556"
        (claims \ "iat").extract[Long] shouldBe 1455539324
        (claims \ "exp").extract[Long] shouldBe 1581683324
        (claims \ "aud").extract[String] shouldBe "verkkopalvelu"
        (claims \ "sub").extract[String] shouldBe "123412341"
      case _ => fail
    }
  }

  it should "verify valid JWT token" in {
    val publicKeyProvider: String => Option[PublicKey] = {
      case "555555556" => Some(parsePublicKeyFromDER(publicKey))
      case _           => None
    }

    val token = JsonWebToken.decode(jwt)
    val result = JsonWebToken.verify(publicKeyProvider)(token.get)
    result shouldBe token
  }

  it should "fail when JWT token issuer has no public key" in {
    val publicKeyProvider: String => Option[PublicKey] = {
      case _ => None
    }

    val token = JsonWebToken.decode(jwt)
    val result = JsonWebToken.verify(publicKeyProvider)(token.get)
    an[Exception] should be thrownBy result.get
  }

  it should "reject invalid JWT token" in {
    val tamperedClaims =
      s"""{
            "iss": "555555556",
            "iat": 1455539324,
            "exp": 1581683324,
            "aud": "verkkopalvelu",
            "sub": "4444444"
        }"""
    val invalidJWT = JsonWebToken.encodeAsRS256(tamperedClaims, parsePrivateKeyFromDER(privateKey))

    val publicKeyProvider: String => Option[PublicKey] = {
      case "555555556" => Some(parsePublicKeyFromDER(publicKey))
      case _           => None
    }
    val Success((headerOK, claimOK, signatureOK)) = JsonWebToken.split(jwt)
    val Success((headerTampered, claimTampered, notImportantSignature)) = JsonWebToken.split(invalidJWT)

    val token = JsonWebToken.decode(headerTampered + "." + claimTampered + "." + signatureOK)
    val result = JsonWebToken.verify(publicKeyProvider)(token.get)
    an[Exception] should be thrownBy result.get
  }
  val privateKeyFromOpenSSL =
    """MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQC54fVIy/ewG1Ie
      |gdhI7CKCHS3lkSSwQv6P6Of2/Y8H6LRxH0LUd3inAH6aMW2/WMqit8iOJ0m7cNFZ
      |90tp+ihp2HjcWRdpFa+qLu8Cm7M1M6RSrsRz3ZGZvaFua0f9GcqxJUpT8wuCg6PY
      |w0FDD7YOetB1DD1uDWlc6jglBAw1H0+ldWdyyezip8Cx8RLuSN9BRISd11+evR97
      |NRv1gkPwdX3Ns3aj+7nZbuc+PGMcYQToCgL/Q7ypGf1UiizFhdm1OomIYwSZPeyi
      |EknSPSetexQ85yb4GpuDO2CjFYD6HEuJi13X98aJfpdVLYxXqhrl2Gdn6u+IuywP
      |VKWWzLoLAgMBAAECggEBAI5R5T3BfXlG0c8t122t7pX0xWlZgd+6y7FfwAsqBFMn
      |5tAeAUsv1h73j/d7FO5Gi4+ea1370sZDEOdzIjiYIk04QwFi7Tu2MPN6T+GNWN7J
      |FW2BBkU4RfySZoFmfo3ZK4oKZSh1lEBvjgmvJc60vs3DVsvnfTk/54YOhsJAoSAh
      |9GcoXb3Yv1DYm5hSCsL2hjr6AVYUbNfmAWc6cIoNaiTmf36GTAD/VNh1frDgzb2G
      |Uh0vnJDUrghjL9Cr314xNjMUT4C4iH/LCwZYP2+qPwS1hkrx3Ncz8Rwx4U7mWZy8
      |4L6nJpzj2W7nBi9Y9AkMT4op+t2uslD2QHYpZgbaHoECgYEA6B/rR+qquljo0DmT
      |D0EHYTHuU/xnvp6tJ05XQUpbFubfj9ZjQR7YA+N/WREk0fPQxNyLfXQmHtuN9fEN
      |+ZYJKSy++b56/VTEaF56S7X/5+YqD2XctbpPVR3Tz3meEdILy75ti/P3kPZmVT1r
      |XdIq6aZuB5XXZz/4ebJnwVtscasCgYEAzQBwWrOl85Ak2fTFtXNFoQfLgp3gTapJ
      |NJW9pHGYJmdIYS5FeNuUBf/Xf9vFdxDkAPfiWHDgLPm2ZLuIxUqlc4Yc4PldDFEO
      |4lMbZYufyvEOk+IHg9ZVwfZAOWVs0dx+WCosqOb6WciZuiB/TL6n8/uAl7fTEMfQ
      |VO+f0nyJOSECgYEAmJEaMKuhyVdUtj+RU+5W7mBGGDeG7LgYcQRBv20iz7uxZzXv
      |CMdADdZCRoVJISHSrwGSQUPNJm0CMotctxYRMVnyr+2tosJLUZn/YbHe4EncjUBT
      |P7KUIAq5w91YsrfO/vxLvjf9GO+KtS3oWsMfZ3D3Us7+xCM8qqhDH8h6T38CgYEA
      |gxVOwpCxAsce6Ud8zIPC+C710LWG4eKLINbHBsmkEppkS8+8mIU/Z36qm5U59OKW
      |CJB46Th0AA5EtLC9yfnrRa1x9eE9wExsige+MvZO3QO64JDdYU3CVF5Tvt+974tg
      |NpvxJqdbWeHNepihDb+zwW0GUv02NzqtWkJHHd6IGEECgYA4xDixZajpouA1q5F7
      |uSf3Lyf8xOGyDRSct1S3Smwq32j+qRmHHJN1zfXnLdNYDS10Um30/D3uWppXZIGl
      |PThFjZiJ/qS/Z9fJV+fKJLwMFLcGWwQ84mKiRlhx3Ez4pVySOALJJxmvFYDs4JSR
      |WuWYq1BRCyXM9+S5BcSeQa5wEw==""".stripMargin

  val publicKeyFromOpenSSL =
    """MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAueH1SMv3sBtSHoHYSOwi
      |gh0t5ZEksEL+j+jn9v2PB+i0cR9C1Hd4pwB+mjFtv1jKorfIjidJu3DRWfdLafoo
      |adh43FkXaRWvqi7vApuzNTOkUq7Ec92Rmb2hbmtH/RnKsSVKU/MLgoOj2MNBQw+2
      |DnrQdQw9bg1pXOo4JQQMNR9PpXVncsns4qfAsfES7kjfQUSEnddfnr0fezUb9YJD
      |8HV9zbN2o/u52W7nPjxjHGEE6AoC/0O8qRn9VIosxYXZtTqJiGMEmT3sohJJ0j0n
      |rXsUPOcm+BqbgztgoxWA+hxLiYtd1/fGiX6XVS2MV6oa5dhnZ+rviLssD1Sllsy6
      |CwIDAQAB""".stripMargin

  val referentialJWTsignedByPrivateKeyFromOpenSSL = "eyJhbGciOiJSUzI1NiIsInR5cGUiOiJqd3MifQ.eyJpc3MiOiI1NTU1NT" +
    "U1NTYiLCJpYXQiOjE0NTU1MzkzMjQsImV4cCI6MTU4MTY4MzMyNCwiYXVkIjoidmVya2tv" +
    "cGFsdmVsdSIsInN1YiI6IjEyMzQxMjM0MSJ9.LWcVhS9Sp1Aairf442DAw7s97qNcLIiwl" +
    "rucX2KqOofc5IQEMAS8knZGZDbXlmQSwIV4ncI6TRl6OUZItOsRqyDpL9GV5Kh1OeGO-SY" +
    "oSqkbyfxmany5S00Tb0ZiGWilJ-3573akmiDAKn-i0u3ka8CX2wocyjctnb90gIeH_nlxe" +
    "MYEGZSFSpQ-0gpa9uf9hCk346uSNnK_lZC37u5TYPsZG3h1J1fdqsu47dKF1b6Ymp5lTLK" +
    "Hj6CKgtQGNJD3C1CusrHmjqmQh1C5iKN6XmbAVDgSupi1oza37tt-HnpZ6F34nTM9PBM_5" +
    "JhUTEARNgpHbfz2ZTcS3Xe7pj-o1A"

  it should "validate referential jwt signed by private key generated by [openssl]" in {
    val publicKeyProvider: String => Option[PublicKey] = {
      case "555555556" =>
        Some(parsePublicKeyFromDER(publicKeyFromOpenSSL))
      case _ => None
    }

    val token = JsonWebToken.decode(referentialJWTsignedByPrivateKeyFromOpenSSL)
    val result = JsonWebToken.verify(publicKeyProvider)(token.get)
    result shouldBe token
  }

  it should "generate same jwt as referential service [jwt.io] using same private key and payload" in {
    val jwt = JsonWebToken.encodeAsRS256(claims.stripMargin.replace(" ", "").replace("\n", ""), parsePrivateKeyFromDER(privateKeyFromOpenSSL))

    jwt shouldBe referentialJWTsignedByPrivateKeyFromOpenSSL
  }
}