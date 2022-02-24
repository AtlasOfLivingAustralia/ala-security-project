package au.org.ala.ws.security

import com.google.common.io.Resources
import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import groovy.time.TimeCategory

class JwtUtils {

    static JWKSet jwkSet(String name) {
        JWKSet.load(Resources.getResource(name).newInputStream())
    }

    static String generateJwt(JWKSet jwkSet, Set<String> scopes = ['read:userdetails']) {
        def header = new JWSHeader(JWSAlgorithm.RS256, new JOSEObjectType("jwt"), null, null, null, null, null, null, null, null, "test", true, null, null)
        def claimsSet = generateClaims(scopes).build()
        def signedJWT = new SignedJWT(header, claimsSet)
        signedJWT.sign(new RSASSASigner(jwkSet.getKeyByKeyId('test').toRSAKey()))
        signedJWT.serialize(false)
    }

    static String generateJwt(JWKSet jwkSet, JWTClaimsSet claimsSet) {
        def header = new JWSHeader(JWSAlgorithm.RS256, new JOSEObjectType("jwt"), null, null, null, null, null, null, null, null, "test", true, null, null)
        def signedJWT = new SignedJWT(header, claimsSet)
        signedJWT.sign(new RSASSASigner(jwkSet.getKeyByKeyId('test').toRSAKey()))
        signedJWT.serialize(false)
    }

    static JWTClaimsSet.Builder generateClaims(
            Set<String> scopes = ['read:userdetails'],
            String subject = 'sub',
            String issuer = 'http://localhost',
            String audience = 'some-aud',
            Date notBefore = new Date(),
            Date issueTime = new Date(),
            Date expiration = use(TimeCategory) { new Date() + 1.minute }
    ) {
        new JWTClaimsSet.Builder()
                .subject(subject)
                .issuer(issuer)
                .claim('scope',scopes)
                .notBeforeTime(notBefore)
                .expirationTime(expiration)
                .audience(audience)
                .issueTime(issueTime)
                .claim('cid', 'some-client-id')
                .claim('cit', 'client_id')
                .claim('jti', 'asdfasdfgafgadfg')
                .claim('scp', scopes)
    }
}
