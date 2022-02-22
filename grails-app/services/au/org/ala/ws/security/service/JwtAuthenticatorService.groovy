package au.org.ala.ws.security.service

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.jwk.source.RemoteJWKSet
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier
import com.nimbusds.jose.proc.JWSKeySelector
import com.nimbusds.jose.proc.JWSVerificationKeySelector
import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier
import com.nimbusds.jwt.proc.DefaultJWTProcessor
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata
import org.pac4j.core.config.Config
import org.pac4j.jwt.config.signature.ECSignatureConfiguration
import org.pac4j.jwt.config.signature.RSASignatureConfiguration
import org.pac4j.jwt.config.signature.SecretSignatureConfiguration
import org.pac4j.oidc.config.OidcConfiguration
import org.springframework.beans.factory.annotation.Autowired


class JwtAuthenticatorService {

//    @Autowired(required = false)
//    Config config
//
//    @Autowired(required = false)
//    JWKSet jwkSet

//    JwtAuthenticator jwtAuthenticator() {
//        if (config instanceof OidcConfiguration) {
//            def metadata = (config as OidcConfiguration).findProviderMetadata()
//            return getJwtAuthenticator(metadata)
//        } else {
//            throw new RuntimeException("OIDC Config not available")
//        }
//    }

    /**
     * Configure a JWT authenticator based on OIDC metadata.
     * TODO extract this so that it can mocked for testing.
     * @param metadata The OIDC metadata
     * @return A JwtAuthenticator configured from the JWKSet in the metadata
     */
//    private JwtAuthenticator getJwtAuthenticator(OIDCProviderMetadata metadata) {
////        def vks = new JWSVerificationKeySelector(metadata.IDTokenJWSAlgs.toSet(), new RemoteJWKSet(metadata.JWKSetURI.toURL(), null))
////        vks.
////        metadata.IDTokenJWSAlgs
////        metadata.IDTokenJWEAlgs
//
//
//        def signatureConfigs = []
//        def encryptConfigs = []
//        def jwkset = JWKSet.load(metadata.JWKSetURI.toURL())
//
//        jwkset.keys.each { jwk ->
//            def algo = jwk.algorithm
//            switch (algo) {
//                case JWSAlgorithm:
//                    def signatureConfig
//                    if (JWSAlgorithm.Family.RSA.contains(algo)) {
//                        signatureConfig = new RSASignatureConfiguration(jwk.toRSAKey().toKeyPair(), (JWSAlgorithm) algo)
//                    } else if (JWSAlgorithm.Family.EC.contains(algo)) {
//                        signatureConfig = new ECSignatureConfiguration(jwk.toECKey().toKeyPair(), (JWSAlgorithm) algo)
//                    } else if (JWSAlgorithm.Family.HMAC_SHA.contains(algo)) {
//                        // TODO This should never hit?  Provide HMAC password via config instead?
//                        signatureConfig = new SecretSignatureConfiguration(jwk.toOctetSequenceKey().toByteArray(), (JWSAlgorithm) algo)
//                    }
//                    if (signatureConfig) {
//                        signatureConfigs.add(signatureConfig)
//                    }
//                    break
//                    // TODO JWT Encryption
////                    case JWEAlgorithm:
////                        def encryptionConfig
////                        if (JWEAlgorithm.Family.RSA.contains(algo)) {
////                            encryptionConfig = new RSAEncryptionConfiguration(jwk.toRSAKey().toKeyPair(), (JWEAlgorithm)algo, null)
////                        }
////                    case EncryptionMethod:
//            }
//
//        }
////        SignatureConfiguration.
////        return new JwtAuthenticator(metadata.IDTokenJWSAlgs,metadata.IDTokenJWEAlgs)
//        return new JwtAuthenticator(signatureConfigs, encryptConfigs)
//    }

}
