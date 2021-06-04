package code.util

import java.security.cert.{CertificateExpiredException, CertificateNotYetValidException, X509Certificate}

import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.util.X509CertUtils
import net.liftweb.common.{Box, Failure, Full}

object X509 {

  /**
    * The certificate must be validated before it may be used.
    * @param encodedCert PEM (BASE64) encoded certificates, suitable for copy and paste operations.
    * @return Full(true) or an Failure
    */
  def validate(encodedCert: String): Box[Boolean] = {
    // Parse X.509 certificate
    val cert: X509Certificate = X509CertUtils.parse(encodedCert)
    if (cert == null) {
      // Parsing failed
      Failure(X509ParsingFailed)
    } else {
      try {
        cert.checkValidity()
        Full(true)
      }
      catch {
        case _: CertificateExpiredException =>
          Failure(X509CertificateExpired)
        case _: CertificateNotYetValidException =>
          Failure(X509CertificateNotYetValid)
      }
    }
  }

  def pemToRsaJwk(encodedCert: String) = {
    // Parse X.509 certificate
    val cert = X509CertUtils.parse(encodedCert)
    // Retrieve public key as RSA JWK
    val rsaJWK = RSAKey.parse(cert)
    rsaJWK
  }

  // X.509
  val X509GeneralError = "OBP-20300: PEM Encoded Certificate issue."
  val X509ParsingFailed = "OBP-20301: Parsing failed for PEM Encoded Certificate."
  val X509CertificateExpired = "OBP-20302: PEM Encoded Certificate expired."
  val X509CertificateNotYetValid = "OBP-20303: PEM Encoded Certificate not yet valid."
  val X509CannotGetRSAPublicKey = "OBP-20304: RSA public key cannot be found at PEM Encoded Certificate."
  val X509CannotGetECPublicKey = "OBP-20305: EC public key cannot be found at PEM Encoded Certificate."
  val X509CannotGetCertificate = "OBP-20306: PEM Encoded Certificate cannot be found at request header."
  val X509ActionIsNotAllowed = "OBP-20307: PEM Encoded Certificate does not provide the proper role for the action has been taken."
  val X509ThereAreNoPsd2Roles = "OBP-20308: PEM Encoded Certificate does not contain PSD2 roles."
  val X509CannotGetPublicKey = "OBP-20309: Public key cannot be found in the PEM Encoded Certificate."
  val X509PublicKeyCannotVerify = "OBP-20310: Certificate's public key cannot be used to verify signed request."
  val X509RequestIsNotSigned = "OBP-20311: The Request is not signed."
  
}
