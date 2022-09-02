package au.org.ala.ws.security.authenticator

import au.org.ala.ws.security.JwtProperties
import au.org.ala.ws.security.profile.AlaOidcUserProfile

import com.nimbusds.jose.JOSEException
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.jwk.source.RemoteJWKSet
import com.nimbusds.jose.proc.BadJOSEException
import com.nimbusds.jose.proc.JWSKeySelector
import com.nimbusds.jose.proc.JWSVerificationKeySelector
import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jwt.JWT
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.JWTParser
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier
import com.nimbusds.jwt.proc.DefaultJWTProcessor
import com.nimbusds.oauth2.sdk.Scope
import com.nimbusds.oauth2.sdk.token.BearerAccessToken

import groovy.util.logging.Slf4j

import org.pac4j.core.context.WebContext
import org.pac4j.core.context.session.SessionStore
import org.pac4j.core.credentials.Credentials
import org.pac4j.core.credentials.TokenCredentials
import org.pac4j.core.exception.CredentialsException
import org.pac4j.oidc.config.OidcConfiguration
import org.pac4j.oidc.credentials.OidcCredentials
import org.pac4j.oidc.credentials.authenticator.UserInfoOidcAuthenticator
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.stereotype.Component

import java.text.ParseException

/**
 * Authenticator for JWT access_token based on the Pac4j {@link org.pac4j.oidc.credentials.authenticator.UserInfoOidcAuthenticator},
 * But instead it of using the userInfo endpoint to validate the access_token it uses OIDC metadata to get key information to validate JWT.
 * The scope parameter of {@link com.nimbusds.oauth2.sdk.token.AccessToken} from the {@link org.pac4j.oidc.credentials.OidcCredentials} is updated with the scope from the validated JWT access_token.
 * The credentials.userProfile is set to an instance of {@link AlaOidcUserProfile} a wrapped {@link org.pac4j.oidc.profile.OidcProfile} from the OIDC UserInfo endpoint.
 */
@Slf4j
@Component
class AlaOidcAuthenticator extends UserInfoOidcAuthenticator {

    private String issuer
    private List<JWSAlgorithm> expectedJWSAlgs
    private JWKSource<SecurityContext> keySource

    @Autowired
    JwtProperties jwtProperties

    AlaOidcAuthenticator(final OidcConfiguration configuration) {

        super(configuration)
    }

    @Override
    protected void internalInit(boolean forceReinit) {

        super.internalInit(forceReinit)

        if (forceReinit || this.issuer == null) {
            this.issuer = configuration.findProviderMetadata().issuer
            this.expectedJWSAlgs = configuration.findProviderMetadata().userInfoJWSAlgs
            this.keySource = new RemoteJWKSet(configuration.findProviderMetadata().JWKSetURI.toURL(), configuration.findResourceRetriever())
        }
    }

    @Override
    void validate(Credentials cred, WebContext context, SessionStore sessionStore) {

        init()

        final OidcCredentials credentials = (OidcCredentials) cred
        final String accessToken = credentials.accessToken as String
        final JWT jwt
        try {
            jwt = JWTParser.parse(accessToken)
        } catch (ParseException e) {
            throw new CredentialsException("Cannot decrypt / verify JWT", e)
        }

        // Create a JWT processor for the access tokens
        ConfigurableJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>()

        // Set the required "typ" header "at+jwt" for access tokens issued by the
        // Connect2id server, may not be set by other servers
//        jwtProcessor.setJWSTypeVerifier(new DefaultJOSEObjectTypeVerifier<>(new JOSEObjectType(jwtType)));

// The expected JWS algorithm of the access tokens (agreed out-of-band)
//        JWSAlgorithm expectedJWSAlg = JWSAlgorithm.RS256;

        // Configure the JWT processor with a key selector to feed matching public
        // RSA keys sourced from the JWK set URL
        JWSKeySelector<SecurityContext> keySelector =
                new JWSVerificationKeySelector<>(expectedJWSAlgs.toSet(), keySource)

//        JWEKeySelector<SecurityContext> jweKeySelector =
//                new JWEDecryptionKeySelector<>(expectedJWSAlgs, keySource);

        jwtProcessor.JWSKeySelector = keySelector
//        jwtProcessor.setJWEDecrypterFactory();

        // Set the required JWT claims for access tokens issued by the server
        // TODO externalise the required claims
        jwtProcessor.JWTClaimsSetVerifier = new DefaultJWTClaimsVerifier(
                new JWTClaimsSet.Builder().issuer(issuer).build(),
                jwtProperties.requiredClaims.toSet())

        try {

            JWTClaimsSet claimsSet = jwtProcessor.process(jwt, null)

            Scope scope = Scope.parse(claimsSet.getClaim(OidcConfiguration.SCOPE))
            credentials.accessToken = new BearerAccessToken(accessToken, 0L, scope)

        } catch (BadJOSEException e) {
            throw new CredentialsException("JWT Verification failed: " + accessToken, e)
        } catch (JOSEException e) {
            throw new CredentialsException("Internal error parsing token: " + accessToken, e)
        }

        if (jwtProperties.requiredScopes) {

            if (!jwtProperties.requiredScopes.every {requiredScope -> credentials.accessToken.scope.any {scope -> requiredScope == scope.value } }) {

                log.info "access_token scopes '${ credentials.accessToken.scope}' is missing required scopes ${jwtProperties.requiredScopes}"
                throw new CredentialsException("access_token with scope '${credentials.accessToken.scope}' is missing required scopes ${jwtProperties.requiredScopes}")
            }

        }

        if (credentials.accessToken.scope?.contains('profile')) {

            TokenCredentials tokenCredentials = new TokenCredentials(accessToken)
            super.validate(tokenCredentials, context, sessionStore)

            cred.userProfile = new AlaOidcUserProfile(tokenCredentials.userProfile)
        }
    }

    @Override
    String toString() {
        final StringBuilder sb = new StringBuilder("AlaOidcAuthenticator{")
        sb.append("issuer='").append(issuer).append('\'')
//        sb.append(", jwtType='").append(jwtType).append('\'')
        sb.append(", expectedJWSAlgs=").append(expectedJWSAlgs)
        sb.append(", keySource=").append(keySource)
//        sb.append(", realmName='").append(realmName).append('\'')
//        sb.append(", expirationTime=").append(expirationTime)
//        sb.append(", identifierGenerator=").append(identifierGenerator)
        sb.append('}')
        return sb.toString()
    }
}
