package au.org.ala.ws.security.authenticator

import au.org.ala.ws.security.profile.AlaOidcUserProfile
import au.org.ala.ws.security.profile.AlaUserProfile
import com.nimbusds.jose.JOSEException
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.source.JWKSource
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
import com.nimbusds.oauth2.sdk.id.Issuer
import com.nimbusds.oauth2.sdk.token.BearerAccessToken

import groovy.util.logging.Slf4j
import org.pac4j.core.authorization.generator.AuthorizationGenerator
import org.pac4j.core.context.WebContext
import org.pac4j.core.context.session.SessionStore
import org.pac4j.core.credentials.Credentials
import org.pac4j.core.credentials.TokenCredentials
import org.pac4j.core.exception.CredentialsException
import org.pac4j.core.profile.UserProfile
import org.pac4j.core.util.CommonHelper
import org.pac4j.oidc.config.OidcConfiguration
import org.pac4j.oidc.credentials.OidcCredentials
import org.pac4j.oidc.credentials.authenticator.UserInfoOidcAuthenticator

import java.text.ParseException
import java.util.stream.Collectors
import java.util.stream.Stream

/**
 * Authenticator for JWT access_token based on the Pac4j {@link org.pac4j.oidc.credentials.authenticator.UserInfoOidcAuthenticator},
 * But instead it of using the userInfo endpoint to validate the access_token it uses OIDC metadata to get key information to validate JWT.
 * The scope parameter of {@link com.nimbusds.oauth2.sdk.token.AccessToken} from the {@link org.pac4j.oidc.credentials.OidcCredentials} is updated with the scope from the validated JWT access_token.
 * The credentials.userProfile is set to an instance of {@link AlaOidcUserProfile} a wrapped {@link org.pac4j.oidc.profile.OidcProfile} from the OIDC UserInfo endpoint.
 */
@Slf4j
class AlaOidcAuthenticator extends UserInfoOidcAuthenticator {

    Issuer issuer
    Set<JWSAlgorithm> expectedJWSAlgs
    JWKSource<SecurityContext> keySource
    AuthorizationGenerator authorizationGenerator

    List<String> requiredClaims
    List<String> requiredScopes

    List<String> accessTokenRoleClaims
    String rolePrefix = ''
    boolean roleToUppercase = true

    AlaOidcAuthenticator(final OidcConfiguration configuration) {

        super(configuration)
    }

    @Override
    protected void internalInit(boolean forceReinit) {

        super.internalInit(forceReinit)

        CommonHelper.assertNotNull('issuer', issuer)
        CommonHelper.assertTrue(CommonHelper.isNotEmpty(expectedJWSAlgs), 'expectedJWSAlgs cannot be empty')
        CommonHelper.assertNotNull('keySource', keySource)
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
                new JWSVerificationKeySelector<>(expectedJWSAlgs, keySource)

//        JWEKeySelector<SecurityContext> jweKeySelector =
//                new JWEDecryptionKeySelector<>(expectedJWSAlgs, keySource);

        jwtProcessor.JWSKeySelector = keySelector
//        jwtProcessor.setJWEDecrypterFactory();

        // Set the required JWT claims for access tokens issued by the server
        // TODO externalise the required claims
        jwtProcessor.JWTClaimsSetVerifier = new DefaultJWTClaimsVerifier(
                new JWTClaimsSet.Builder().issuer(issuer.value).build(),
                requiredClaims?.toSet())

        Collection<String> accessTokenRoles

        try {

            JWTClaimsSet claimsSet = jwtProcessor.process(jwt, null)

            accessTokenRoles = getRoles(claimsSet)

            Scope scope = Scope.parse(claimsSet.getClaim(OidcConfiguration.SCOPE))
            credentials.accessToken = new BearerAccessToken(accessToken, 0L, scope)

        } catch (BadJOSEException e) {
            throw new CredentialsException("JWT Verification failed: " + accessToken, e)
        } catch (JOSEException e) {
            throw new CredentialsException("Internal error parsing token: " + accessToken, e)
        }

        if (requiredScopes) {

            if (!requiredScopes.every {requiredScope -> credentials.accessToken.scope.any {scope -> requiredScope == scope.value } }) {

                log.info "access_token scopes '${ credentials.accessToken.scope}' is missing required scopes ${requiredScopes}"
                throw new CredentialsException("access_token with scope '${credentials.accessToken.scope}' is missing required scopes ${requiredScopes}")
            }
        }

        if (credentials.accessToken.scope?.contains('profile')) {

            TokenCredentials tokenCredentials = new TokenCredentials(accessToken)
            super.validate(tokenCredentials, context, sessionStore)

            UserProfile profile = tokenCredentials.userProfile

            if (authorizationGenerator) {
                cred.userProfile = authorizationGenerator.generate(context, sessionStore, profile)
                                .map(this::generateAlaUserProfile)
                                .get()
            } else {
                cred.userProfile = generateAlaUserProfile(profile)
            }

            if (accessTokenRoles) {
                cred.userProfile.addRoles(accessTokenRoles)
            }

        } else if (accessTokenRoles) {

            AlaOidcUserProfile alaOidcUserProfile = new AlaOidcUserProfile()
            alaOidcUserProfile.addRoles(accessTokenRoles)

            cred.userProfile = alaOidcUserProfile
        }
    }

    AlaUserProfile generateAlaUserProfile(UserProfile profile) {

        AlaOidcUserProfile alaOidcUserProfile = new AlaOidcUserProfile()
        alaOidcUserProfile.addAttributes(profile.attributes)
        alaOidcUserProfile.roles = profile.roles
        alaOidcUserProfile.permissions = profile.permissions

        return alaOidcUserProfile
    }

    Collection<String> getRoles(JWTClaimsSet claimsSet) {

        if (!accessTokenRoleClaims) {
            return null
        }

        Stream<String> roles = accessTokenRoleClaims.stream()
                .map(claimsSet::getClaim)
                .filter(Objects::nonNull)
                .flatMap { Object roleClaim ->
                    if (roleClaim instanceof String) {
                        Stream.of(roleClaim.split(','))
                    } else if (roleClaim.getClass().isArray() && roleClaim.getClass().getComponentType().isAssignableFrom(String.class)) {
                        Stream.of(roleClaim)
                    } else if (Collection.class.isAssignableFrom(roleClaim.getClass())) {
                        ((Collection) roleClaim).stream()
                    }
                }

        if (this.rolePrefix) {
            roles = roles.map { String role -> this.rolePrefix + role }
        }

        if (this.roleToUppercase) {
            roles = roles.map { String role -> role.toUpperCase() }
        }

        return roles.collect(Collectors.toSet())
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
