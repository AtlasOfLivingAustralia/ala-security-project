package au.org.ala.ws.security.service

import au.ala.org.ws.security.AuthenticatedUser
import com.auth0.jwk.Jwk
import com.auth0.jwk.JwkProvider
import com.auth0.jwk.UrlJwkProvider
import com.auth0.jwt.JWT
import com.auth0.jwt.algorithms.Algorithm
import com.auth0.jwt.exceptions.SignatureVerificationException
import com.auth0.jwt.interfaces.DecodedJWT
import org.springframework.beans.factory.annotation.Value

import java.security.interfaces.RSAPublicKey

class JwtCheckService {

    @Value('${jwk.url}')
    String jwkUrl

    def serviceMethod() {}

    /**
     * Verifies the signature of a JWT and retrieves the user information.
     *
     * @param authorizationHeader
     * @return
     */
    AuthenticatedUser checkJWT(String authorizationHeader) {

        // https://auth0.com/docs/security/tokens/json-web-tokens/validate-json-web-tokens
        String token = authorizationHeader.substring(7)

        // decode and verify
        DecodedJWT jwt = JWT.decode(token);
        JwkProvider provider = new UrlJwkProvider(new URL(jwkUrl));
        String keyId = jwt.getKeyId();
        Jwk jwk = provider.get(keyId);
        Algorithm algorithm = Algorithm.RSA256((RSAPublicKey) jwk.getPublicKey(), null);

        try {
            algorithm.verify(jwt);
            List roles = jwt.getClaims().get("role").asList(String.class)
            String email = jwt.getClaims().get("email")
            String userId = jwt.getClaims().get("userid")
            new AuthenticatedUser(email:email, userId: userId, roles: roles)
        } catch (SignatureVerificationException e){
            log.error("Verify of JWT failed")
            null
        }
    }
}
